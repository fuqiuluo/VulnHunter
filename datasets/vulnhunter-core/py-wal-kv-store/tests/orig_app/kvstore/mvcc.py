"""Multi-version concurrency control store with snapshot reads and compaction."""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass

SYSTEM_ACL_PREFIX = "@acl/"


class KeyValidationError(ValueError):
    """Raised when a namespace path or system key violates formatting rules."""


class WriteConflictError(RuntimeError):
    """Raised under Snapshot Isolation when concurrent transactions modify the same key."""


def is_system_key(key: str) -> bool:
    return isinstance(key, str) and key.startswith(SYSTEM_ACL_PREFIX)


def _check_segment_chars(seg: str, full_key: str) -> None:
    if not seg or seg in (".", ".."):
        raise KeyValidationError(f"Invalid path segment {seg!r} in {full_key!r}")
    if any(ord(ch) < 33 or ord(ch) == 127 or ch.isspace() for ch in seg):
        raise KeyValidationError(f"Illegal character in key {full_key!r}")


def normalize_namespace_prefix(prefix: str) -> str:
    if not isinstance(prefix, str) or not prefix.startswith("/"):
        raise KeyValidationError(f"Namespace prefix must start with '/': {prefix!r}")
    if prefix == "/":
        return "/"
    trimmed = prefix[:-1] if prefix.endswith("/") else prefix
    if not trimmed or trimmed == "/":
        raise KeyValidationError(f"Malformed namespace prefix: {prefix!r}")
    parts = trimmed.split("/")[1:]
    for seg in parts:
        _check_segment_chars(seg, prefix)
    return "/" + "/".join(parts)


def validate_data_key(key: str) -> str:
    if not isinstance(key, str) or not key.startswith("/") or key == "/" or key.endswith("/"):
        raise KeyValidationError(f"Invalid data key: {key!r}")
    for seg in key.split("/")[1:]:
        _check_segment_chars(seg, key)
    return key


def validate_system_key(key: str) -> str:
    if not is_system_key(key) or key.endswith("/"):
        raise KeyValidationError(f"Malformed system key: {key!r}")
    rest = key[len(SYSTEM_ACL_PREFIX) :]
    if not rest:
        raise KeyValidationError(f"System key missing identifier: {key!r}")
    for seg in rest.split("/"):
        _check_segment_chars(seg, key)
    return key


def _matches_namespace_prefix(key: str, norm_prefix: str) -> bool:
    if norm_prefix == "/":
        return key.startswith("/") and len(key) > 1
    return key == norm_prefix or key.startswith(norm_prefix + "/")


@dataclass(frozen=True)
class Version:
    ts: int
    tx_id: int
    value: bytes
    deleted: bool = False


@dataclass(frozen=True)
class StagedWrite:
    seq: int
    key: str
    value: bytes
    deleted: bool = False


class MVCCStore:
    """In-memory versioned key-value store backing transactions and snapshots."""

    def __init__(self) -> None:
        self._versions: dict[str, list[Version]] = {}
        self._latest_ts: int = 0
        self._next_tx_id: int = 1
        self._tx_start_ts: dict[int, int] = {}
        self._tx_writes: dict[int, list[StagedWrite]] = {}
        self._tx_seq_counter: dict[int, int] = {}

    @property
    def latest_ts(self) -> int:
        return self._latest_ts

    @property
    def next_tx_id(self) -> int:
        return self._next_tx_id

    def set_counters(self, *, latest_ts: int | None = None, next_tx_id: int | None = None) -> None:
        if latest_ts is not None and latest_ts > self._latest_ts:
            self._latest_ts = latest_ts
        if next_tx_id is not None and next_tx_id > self._next_tx_id:
            self._next_tx_id = next_tx_id

    def active_tx_ids(self) -> frozenset[int]:
        return frozenset(self._tx_writes.keys())

    def begin_tx(self) -> tuple[int, int]:
        tx_id, start_ts = self._next_tx_id, self._latest_ts
        self._next_tx_id += 1
        self._tx_start_ts[tx_id] = start_ts
        self._tx_writes[tx_id] = []
        self._tx_seq_counter[tx_id] = 0
        return tx_id, start_ts

    def _require_active_tx(self, tx_id: int) -> list[StagedWrite]:
        writes = self._tx_writes.get(tx_id)
        if writes is None:
            raise KeyError(f"Transaction {tx_id} is not active")
        return writes

    def stage_put(self, tx_id: int, key: str, value: bytes) -> StagedWrite:
        writes = self._require_active_tx(tx_id)
        self._tx_seq_counter[tx_id] += 1
        entry = StagedWrite(seq=self._tx_seq_counter[tx_id], key=key, value=bytes(value), deleted=False)
        writes.append(entry)
        return entry

    def stage_delete(self, tx_id: int, key: str) -> StagedWrite:
        writes = self._require_active_tx(tx_id)
        self._tx_seq_counter[tx_id] += 1
        entry = StagedWrite(seq=self._tx_seq_counter[tx_id], key=key, value=b"", deleted=True)
        writes.append(entry)
        return entry

    def tx_marker(self, tx_id: int) -> int:
        return len(self._require_active_tx(tx_id))

    def rollback_tx_to(self, tx_id: int, marker: int) -> list[StagedWrite]:
        writes = self._require_active_tx(tx_id)
        if marker < 0 or marker > len(writes):
            raise ValueError(f"Invalid savepoint marker {marker} for transaction {tx_id}")
        discarded = writes[marker:]
        del writes[marker:]
        return discarded

    def get_at(self, key: str, read_ts: int) -> bytes | None:
        for ver in reversed(self._versions.get(key, ())):
            if ver.ts <= read_ts:
                return None if ver.deleted else ver.value
        return None

    def get_in_tx(self, tx_id: int, key: str) -> bytes | None:
        for sw in reversed(self._require_active_tx(tx_id)):
            if sw.key == key:
                return None if sw.deleted else sw.value
        return self.get_at(key, self._tx_start_ts[tx_id])

    def scan_at(self, prefix: str = "/", read_ts: int | None = None, *, include_system: bool = False) -> list[tuple[str, bytes]]:
        target_ts = self._latest_ts if read_ts is None else read_ts
        if include_system and prefix.startswith(SYSTEM_ACL_PREFIX):
            return [
                (k, val) for k in sorted(self._versions.keys())
                if k.startswith(prefix) and (val := self.get_at(k, target_ts)) is not None
            ]
        norm_prefix = normalize_namespace_prefix(prefix)
        return [
            (k, val) for k in sorted(self._versions.keys())
            if not is_system_key(k) and _matches_namespace_prefix(k, norm_prefix) and (val := self.get_at(k, target_ts)) is not None
        ]

    def scan_in_tx(self, tx_id: int, prefix: str = "/", *, include_system: bool = False) -> list[tuple[str, bytes]]:
        writes = self._require_active_tx(tx_id)
        merged = dict(self.scan_at(prefix, self._tx_start_ts[tx_id], include_system=include_system))
        norm_prefix = prefix if (include_system and prefix.startswith(SYSTEM_ACL_PREFIX)) else normalize_namespace_prefix(prefix)
        for sw in writes:
            matches = sw.key.startswith(prefix) if (include_system and prefix.startswith(SYSTEM_ACL_PREFIX)) else (not is_system_key(sw.key) and _matches_namespace_prefix(sw.key, norm_prefix))
            if matches:
                if sw.deleted:
                    merged.pop(sw.key, None)
                else:
                    merged[sw.key] = sw.value
        return sorted(merged.items())

    def check_conflicts(self, tx_id: int) -> None:
        writes = self._require_active_tx(tx_id)
        start_ts = self._tx_start_ts[tx_id]
        for key in {sw.key for sw in writes}:
            chain = self._versions.get(key)
            if chain and chain[-1].ts > start_ts:
                raise WriteConflictError(f"Concurrent modification conflict on key {key!r} after ts={start_ts}")

    def commit_tx(self, tx_id: int, *, commit_ts: int | None = None) -> tuple[int, dict[str, StagedWrite]]:
        self.check_conflicts(tx_id)
        writes = self._tx_writes.pop(tx_id)
        self._tx_start_ts.pop(tx_id, None)
        self._tx_seq_counter.pop(tx_id, None)
        final_by_key = {sw.key: sw for sw in writes}
        ts = commit_ts if commit_ts is not None else (self._latest_ts + 1)
        if ts < self._latest_ts:
            raise ValueError(f"Non-monotonic commit timestamp {ts} < {self._latest_ts}")
        self._latest_ts = ts
        for key, sw in final_by_key.items():
            self._versions.setdefault(key, []).append(Version(ts=ts, tx_id=tx_id, value=sw.value, deleted=sw.deleted))
        return ts, final_by_key

    def abort_tx(self, tx_id: int) -> None:
        self._tx_writes.pop(tx_id, None)
        self._tx_start_ts.pop(tx_id, None)
        self._tx_seq_counter.pop(tx_id, None)

    def apply_recovered_batch(self, tx_id: int, commit_ts: int, operations: Iterable[tuple[str, bytes, bool]]) -> None:
        for key, (val, deleted) in {k: (bytes(v), bool(d)) for k, v, d in operations}.items():
            self._versions.setdefault(key, []).append(Version(ts=commit_ts, tx_id=tx_id, value=val, deleted=deleted))
        self._latest_ts = max(self._latest_ts, commit_ts)
        self._next_tx_id = max(self._next_tx_id, tx_id + 1)

    def compact(self, watermark_ts: int) -> int:
        removed = 0
        empty_keys: list[str] = []
        for key, chain in self._versions.items():
            filtered = [v for v in chain if not (v.deleted and v.ts < watermark_ts)]
            removed += len(chain) - len(filtered)
            if not filtered:
                empty_keys.append(key)
                continue
            below = [v for v in filtered if v.ts <= watermark_ts]
            above = [v for v in filtered if v.ts > watermark_ts]
            kept = (below[-1:] if below else []) + above
            removed += len(filtered) - len(kept)
            if kept:
                self._versions[key] = kept
            else:
                empty_keys.append(key)
        for key in empty_keys:
            del self._versions[key]
        return removed

    def version_count(self) -> int:
        return sum(len(chain) for chain in self._versions.values())

    def export_live_entries(self) -> dict[str, tuple[int, bytes]]:
        return {k: (c[-1].ts, c[-1].value) for k, c in self._versions.items() if c and not c[-1].deleted}

    def load_checkpoint_entries(self, entries: Mapping[str, tuple[int, bytes]], *, checkpoint_ts: int, next_tx_id: int = 1) -> None:
        self._versions = {k: [Version(ts=ts, tx_id=0, value=bytes(val), deleted=False)] for k, (ts, val) in entries.items()}
        self._latest_ts = max(0, checkpoint_ts)
        self._next_tx_id = max(1, next_tx_id)
