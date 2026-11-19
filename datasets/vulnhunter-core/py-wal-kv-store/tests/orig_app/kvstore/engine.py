"""Storage engine coordinating WAL persistence, MVCC state, checkpoints, and ACLs."""

from __future__ import annotations

import base64
import hashlib
import json
import os
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType

from .acl import ACLIndex, PolicyRule, Principal, SYSTEM_PRINCIPAL, canonical_policy_key
from .mvcc import MVCCStore, is_system_key, normalize_namespace_prefix, validate_data_key, validate_system_key
from .snapshot import Snapshot
from .tx import Transaction, TransactionStateError
from .wal import RecordType, WAL, WALCorruptionError

CHECKPOINT_FORMAT = "vkv-checkpoint-v1"
CHECKPOINT_FILENAME = "checkpoint.json"
WAL_FILENAME = "wal.log"


@dataclass(frozen=True)
class EngineConfig:
    data_dir: Path
    sync_on_commit: bool = True


def _checkpoint_digest(payload_obj: dict[str, object]) -> str:
    return hashlib.sha256(json.dumps(payload_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


class Engine:
    """Embedded transactional MVCC key-value and namespace policy engine."""

    def __init__(self, config: EngineConfig) -> None:
        self._config = config
        self._data_dir = Path(config.data_dir)
        self._data_dir.mkdir(parents=True, exist_ok=True)
        self._mvcc, self._acl = MVCCStore(), ACLIndex()
        self._active_txs: dict[int, Transaction] = {}
        self._active_snapshots: set[Snapshot] = set()
        self._min_retained_ts, self._closed = 0, False

        cp_ts, cp_next_tx, cp_next_lsn = self._load_checkpoint_if_present()
        self._wal = WAL(self._data_dir / WAL_FILENAME)
        try:
            report = self._wal.recover()
            self._wal.advance_lsn_floor(cp_next_lsn)
            for batch in report.committed:
                ops = [
                    (rec.key, rec.value if rec.rec_type == RecordType.PUT else b"", rec.rec_type == RecordType.DELETE)
                    for rec in batch.records if rec.rec_type in (RecordType.PUT, RecordType.DELETE)
                ]
                self._mvcc.apply_recovered_batch(batch.tx_id, batch.commit_ts, ops)
            self._mvcc.set_counters(latest_ts=max(cp_ts, report.checkpoint_ts), next_tx_id=max(cp_next_tx, report.next_tx_id))
            self._min_retained_ts = max(cp_ts, report.checkpoint_ts)
            self._rebuild_acl_from_mvcc()
        except Exception:
            self._wal.close()
            raise

    @classmethod
    def open(cls, data_dir: str | Path, *, sync_on_commit: bool = True) -> Engine:
        return cls(EngineConfig(data_dir=Path(data_dir), sync_on_commit=sync_on_commit))

    @property
    def data_dir(self) -> Path:
        return self._data_dir

    @property
    def latest_ts(self) -> int:
        return self._mvcc.latest_ts

    @property
    def closed(self) -> bool:
        return self._closed

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("Engine is closed")

    def _rebuild_acl_from_mvcc(self) -> None:
        self._acl.rebuild(dict(self._mvcc.scan_at("@acl/", self._mvcc.latest_ts, include_system=True)))

    def _load_checkpoint_if_present(self) -> tuple[int, int, int]:
        cp_path = self._data_dir / CHECKPOINT_FILENAME
        if not cp_path.is_file():
            return 0, 1, 1
        try:
            doc = json.loads(cp_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise WALCorruptionError(f"Failed to parse checkpoint file: {exc}") from exc
        if not isinstance(doc, dict) or doc.get("format") != CHECKPOINT_FORMAT:
            raise WALCorruptionError("Unsupported or malformed checkpoint header")
        expected_sha = doc.get("sha256")
        body = {k: v for k, v in doc.items() if k != "sha256"}
        if not isinstance(expected_sha, str) or _checkpoint_digest(body) != expected_sha:
            raise WALCorruptionError("Checkpoint integrity digest mismatch")
        cp_ts, next_tx_id, next_lsn = int(body.get("checkpoint_ts", 0)), int(body.get("next_tx_id", 1)), int(body.get("next_lsn", 1))
        raw_entries = body.get("entries")
        if not isinstance(raw_entries, dict):
            raise WALCorruptionError("Invalid checkpoint entries table")
        decoded = {
            key: (int(item["ts"]), base64.b64decode(item["value_b64"].encode("ascii")))
            for key, item in raw_entries.items()
        }
        self._mvcc.load_checkpoint_entries(decoded, checkpoint_ts=cp_ts, next_tx_id=next_tx_id)
        return cp_ts, next_tx_id, next_lsn

    def _on_tx_finished(self, tx_id: int, _committed: bool) -> None:
        self._active_txs.pop(tx_id, None)

    def _on_snapshot_closed(self, snap: Snapshot) -> None:
        self._active_snapshots.discard(snap)

    def begin(self, principal: Principal = SYSTEM_PRINCIPAL) -> Transaction:
        self._ensure_open()
        tx = Transaction(
            self._mvcc, self._wal, self._acl, principal=principal,
            sync_on_commit=self._config.sync_on_commit, on_finish=self._on_tx_finished,
        )
        self._active_txs[tx.tx_id] = tx
        return tx

    def transaction(self, principal: Principal = SYSTEM_PRINCIPAL) -> Transaction:
        return self.begin(principal=principal)

    def snapshot(self, read_ts: int | None = None, *, principal: Principal = SYSTEM_PRINCIPAL) -> Snapshot:
        self._ensure_open()
        target_ts = self._mvcc.latest_ts if read_ts is None else read_ts
        if target_ts < self._min_retained_ts or target_ts > self._mvcc.latest_ts:
            raise ValueError(f"Requested read_ts={target_ts} outside [{self._min_retained_ts}, {self._mvcc.latest_ts}]")
        snap = Snapshot(self._mvcc, target_ts, principal=principal, on_close=self._on_snapshot_closed)
        self._active_snapshots.add(snap)
        return snap

    def min_active_snapshot_ts(self) -> int:
        open_ts = [s.read_ts for s in self._active_snapshots if not s.closed]
        return min(open_ts) if open_ts else self._mvcc.latest_ts

    def check_access(self, principal: Principal, path: str, permission: str) -> bool:
        self._ensure_open()
        return self._acl.check(principal, path, permission)

    def get(self, key: str, *, principal: Principal = SYSTEM_PRINCIPAL) -> bytes | None:
        self._ensure_open()
        ts = self._mvcc.latest_ts
        if is_system_key(key):
            norm_key = validate_system_key(key)
            raw = self._mvcc.get_at(norm_key, ts)
            if not principal.is_system:
                target = PolicyRule.from_json_bytes(norm_key, raw).prefix if raw is not None else "/"
                self._acl.require(principal, target, "grant")
            return raw
        norm_key = validate_data_key(key)
        self._acl.require(principal, norm_key, "read")
        return self._mvcc.get_at(norm_key, ts)

    def put(self, key: str, value: bytes | bytearray | str, *, principal: Principal = SYSTEM_PRINCIPAL) -> int:
        with self.transaction(principal=principal) as tx:
            tx.put(key, value)
        assert tx.commit_ts is not None
        return tx.commit_ts

    def delete(self, key: str, *, principal: Principal = SYSTEM_PRINCIPAL) -> bool:
        with self.transaction(principal=principal) as tx:
            return tx.delete(key)

    def scan(self, prefix: str = "/", *, principal: Principal = SYSTEM_PRINCIPAL) -> list[tuple[str, bytes]]:
        self._ensure_open()
        norm_prefix = normalize_namespace_prefix(prefix)
        self._acl.require(principal, norm_prefix, "list")
        rows = self._mvcc.scan_at(norm_prefix, self._mvcc.latest_ts, include_system=False)
        return rows if principal.is_system else [(k, v) for k, v in rows if self._acl.check(principal, k, "read")]

    def grant_policy(
        self, policy_id: str, *, prefix: str, permissions: Iterable[str],
        subject: str | None = None, role: str | None = None, effect: str = "allow", principal: Principal = SYSTEM_PRINCIPAL,
    ) -> int:
        with self.transaction(principal=principal) as tx:
            tx.set_policy(policy_id, prefix=prefix, permissions=permissions, subject=subject, role=role, effect=effect)
        assert tx.commit_ts is not None
        return tx.commit_ts

    def revoke_policy(self, policy_id: str, *, principal: Principal = SYSTEM_PRINCIPAL) -> bool:
        with self.transaction(principal=principal) as tx:
            return tx.delete(canonical_policy_key(policy_id))

    def checkpoint(self) -> dict[str, int]:
        self._ensure_open()
        if self._active_txs:
            raise TransactionStateError("Cannot run checkpoint while write transactions are active")
        watermark = self.min_active_snapshot_ts()
        pruned = self._mvcc.compact(watermark)
        live_entries = self._mvcc.export_live_entries()
        cp_ts, next_lsn = self._mvcc.latest_ts, self._wal.next_lsn
        serialized = {
            k: {"ts": ver_ts, "value_b64": base64.b64encode(val).decode("ascii")}
            for k, (ver_ts, val) in sorted(live_entries.items())
        }
        body: dict[str, object] = {
            "format": CHECKPOINT_FORMAT, "checkpoint_ts": cp_ts,
            "next_tx_id": self._mvcc.next_tx_id, "next_lsn": next_lsn, "entries": serialized,
        }
        doc = {**body, "sha256": _checkpoint_digest(body)}
        cp_path = self._data_dir / CHECKPOINT_FILENAME
        tmp_path = cp_path.with_suffix(".json.tmp")
        tmp_path.write_text(json.dumps(doc, indent=2, sort_keys=True), encoding="utf-8")
        os.replace(tmp_path, cp_path)
        self._wal.reset(cp_ts, next_lsn=next_lsn)
        self._min_retained_ts = watermark
        self._rebuild_acl_from_mvcc()
        return {"checkpoint_ts": cp_ts, "watermark_ts": watermark, "pruned_versions": pruned, "live_keys": len(live_entries)}

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._active_txs.clear()
            for snap in list(self._active_snapshots):
                snap.close()
            self._wal.close()

    def __enter__(self) -> Engine:
        self._ensure_open()
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None) -> None:
        self.close()
