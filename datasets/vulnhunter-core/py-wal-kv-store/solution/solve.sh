#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/app}"
cd "$APP_DIR"

# 1. Write technical review report
cat > "$APP_DIR/report.json" <<'EOF'
{
  "files": [
    "kvstore/acl.py",
    "kvstore/tx.py",
    "kvstore/engine.py",
    "kvstore/wal.py",
    "kvstore/mvcc.py"
  ],
  "findings": [
    "ACLIndex.capture_snapshot and restore_snapshot perform shallow copies of per-prefix PolicyRule lists while Transaction.savepoint/rollback_to omit ACL state restoration and mutate the shared engine ACLIndex directly, allowing rolled-back savepoint grants or aborted policy updates on existing buckets to persist in memory.",
    "WAL._frame_checksum hashes only payload[:key_len] instead of the full key+value frame bytes, missing value corruption, and WAL.recover stages pre-commit operations in a single shared list without isolating by tx_id or advancing next_lsn/next_tx_id past all replayed frames, allowing uncommitted interleaved records to materialize on reopen.",
    "MVCCStore.compact filters out tombstone versions with ts < watermark_ts prior to pruning older versions beneath them, uncovering shadowed historical live values and revoked ACL policies during checkpoint compaction and subsequent reopens."
  ],
  "summary": "Isolated transactional ACL mutations with deep-copied savepoint and abort snapshots synced to committed MVCC state, extended WAL CRC32 verification over full frame payloads with per-transaction recovery staging and monotonic LSN/tx_id tracking, and fixed MVCC watermark compaction so tombstones prune older shadowed versions before reclaiming dead keys."
}
EOF

# 2. Update kvstore/acl.py: deep-copy rule buckets on snapshot/restore and add clone()
cat > "$APP_DIR/kvstore/acl.py" <<'EOF'
"""Hierarchical namespace access control policies and compiled prefix index."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field

from .mvcc import (
    SYSTEM_ACL_PREFIX, KeyValidationError, is_system_key,
    normalize_namespace_prefix, validate_system_key,
)

VALID_PERMISSIONS: frozenset[str] = frozenset({"read", "write", "delete", "list", "grant"})
VALID_EFFECTS: frozenset[str] = frozenset({"allow", "deny"})


class AccessDeniedError(PermissionError):
    """Raised when a principal lacks the required capability on a namespace path."""


class PolicyValidationError(ValueError):
    """Raised when an ACL policy document or identifier is malformed."""


def path_segments(path: str) -> tuple[str, ...]:
    norm = normalize_namespace_prefix(path)
    return () if norm == "/" else tuple(norm.split("/")[1:])


def path_matches_prefix(path: str, prefix: str) -> bool:
    p_segs, k_segs = path_segments(prefix), path_segments(path)
    return len(k_segs) >= len(p_segs) and k_segs[: len(p_segs)] == p_segs


def canonical_policy_key(policy_id: str) -> str:
    if not isinstance(policy_id, str) or not policy_id.strip():
        raise PolicyValidationError("Policy identifier must be a non-empty string")
    candidate = policy_id if is_system_key(policy_id) else f"{SYSTEM_ACL_PREFIX}policies/{policy_id.lstrip('/')}"
    try:
        return validate_system_key(candidate)
    except KeyValidationError as exc:
        raise PolicyValidationError(str(exc)) from exc


@dataclass(frozen=True)
class Principal:
    subject: str
    roles: frozenset[str] = field(default_factory=frozenset)
    is_system: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.subject, str) or not self.subject.strip():
            raise ValueError("Principal subject must be a non-empty string")
        if not isinstance(self.roles, frozenset):
            object.__setattr__(self, "roles", frozenset(self.roles))
        if any(not isinstance(r, str) or not r.strip() for r in self.roles):
            raise ValueError("Principal role names must be non-empty strings")

    @classmethod
    def user(cls, subject: str, roles: Iterable[str] = ()) -> Principal:
        return cls(subject=subject, roles=frozenset(roles), is_system=False)


SYSTEM_PRINCIPAL = Principal(subject="system", roles=frozenset({"system"}), is_system=True)


@dataclass(frozen=True)
class PolicyRule:
    key: str
    prefix: str
    permissions: frozenset[str]
    subject: str | None = None
    role: str | None = None
    effect: str = "allow"

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "key", validate_system_key(self.key))
            object.__setattr__(self, "prefix", normalize_namespace_prefix(self.prefix))
        except KeyValidationError as exc:
            raise PolicyValidationError(str(exc)) from exc
        if not isinstance(self.permissions, frozenset):
            object.__setattr__(self, "permissions", frozenset(self.permissions))
        if not self.permissions or (self.permissions - VALID_PERMISSIONS):
            raise PolicyValidationError("Policy permissions must be a non-empty valid capability set")
        has_subj = self.subject is not None and bool(self.subject.strip())
        has_role = self.role is not None and bool(self.role.strip())
        if not has_subj and not has_role:
            raise PolicyValidationError("Policy must target at least one subject or role")
        if (self.subject is not None and not has_subj) or (self.role is not None and not has_role):
            raise PolicyValidationError("Policy subject/role cannot be blank")
        if self.effect not in VALID_EFFECTS:
            raise PolicyValidationError(f"Invalid policy effect {self.effect!r}")

    def to_json_bytes(self) -> bytes:
        doc: dict[str, object] = {"prefix": self.prefix, "permissions": sorted(self.permissions), "effect": self.effect}
        if self.subject is not None:
            doc["subject"] = self.subject
        if self.role is not None:
            doc["role"] = self.role
        return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_json_bytes(cls, key: str, raw: bytes) -> PolicyRule:
        try:
            doc = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise PolicyValidationError(f"Invalid JSON policy at {key!r}: {exc}") from exc
        if not isinstance(doc, dict):
            raise PolicyValidationError(f"Policy document at {key!r} must be a JSON object")
        raw_perms, prefix, effect = doc.get("permissions"), doc.get("prefix"), doc.get("effect", "allow")
        subject, role = doc.get("subject"), doc.get("role")
        if not isinstance(raw_perms, list) or not all(isinstance(p, str) for p in raw_perms):
            raise PolicyValidationError(f"Policy at {key!r} must contain string list 'permissions'")
        if not isinstance(prefix, str) or not isinstance(effect, str):
            raise PolicyValidationError(f"Policy at {key!r} has invalid 'prefix' or 'effect'")
        if (subject is not None and not isinstance(subject, str)) or (role is not None and not isinstance(role, str)):
            raise PolicyValidationError(f"Policy at {key!r} has non-string 'subject' or 'role'")
        return cls(key=key, prefix=prefix, permissions=frozenset(raw_perms), subject=subject, role=role, effect=effect)


@dataclass
class ACLSnapshot:
    policies: dict[str, PolicyRule]
    subject_index: dict[str, dict[tuple[str, ...], list[PolicyRule]]]
    role_index: dict[str, dict[tuple[str, ...], list[PolicyRule]]]


def _deep_copy_index(
    src: dict[str, dict[tuple[str, ...], list[PolicyRule]]]
) -> dict[str, dict[tuple[str, ...], list[PolicyRule]]]:
    return {
        target: {segs: list(rules) for segs, rules in prefixes.items()}
        for target, prefixes in src.items()
    }


class ACLIndex:
    """Compiled prefix-indexed ACL evaluator for subjects and roles."""

    def __init__(self) -> None:
        self._policies: dict[str, PolicyRule] = {}
        self._subject_index: dict[str, dict[tuple[str, ...], list[PolicyRule]]] = {}
        self._role_index: dict[str, dict[tuple[str, ...], list[PolicyRule]]] = {}

    @staticmethod
    def _remove_from_map(index_map: dict[str, dict[tuple[str, ...], list[PolicyRule]]], target: str, segs: tuple[str, ...], key: str) -> None:
        prefixes = index_map.get(target)
        if prefixes and segs in prefixes:
            bucket = prefixes[segs]
            bucket[:] = [r for r in bucket if r.key != key]
            if not bucket:
                del prefixes[segs]
            if not prefixes:
                del index_map[target]

    def _index_rule(self, rule: PolicyRule) -> None:
        segs = path_segments(rule.prefix)
        if rule.subject is not None:
            self._subject_index.setdefault(rule.subject, {}).setdefault(segs, []).append(rule)
        if rule.role is not None:
            self._role_index.setdefault(rule.role, {}).setdefault(segs, []).append(rule)

    def _unindex_rule(self, rule: PolicyRule) -> None:
        segs = path_segments(rule.prefix)
        if rule.subject is not None:
            self._remove_from_map(self._subject_index, rule.subject, segs, rule.key)
        if rule.role is not None:
            self._remove_from_map(self._role_index, rule.role, segs, rule.key)

    def put_policy(self, key: str, rule: PolicyRule) -> PolicyRule | None:
        norm_key = validate_system_key(key)
        if rule.key != norm_key:
            rule = PolicyRule(key=norm_key, prefix=rule.prefix, permissions=rule.permissions, subject=rule.subject, role=rule.role, effect=rule.effect)
        prev = self._policies.get(norm_key)
        if prev is not None:
            self._unindex_rule(prev)
        self._policies[norm_key] = rule
        self._index_rule(rule)
        return prev

    def put_raw_policy(self, key: str, raw: bytes) -> PolicyRule:
        rule = PolicyRule.from_json_bytes(key, raw)
        self.put_policy(rule.key, rule)
        return rule

    def remove_policy(self, key: str) -> PolicyRule | None:
        prev = self._policies.pop(validate_system_key(key), None)
        if prev is not None:
            self._unindex_rule(prev)
        return prev

    def get_policy(self, key: str) -> PolicyRule | None:
        return self._policies.get(key)

    def list_policies(self, prefix: str = "/") -> list[PolicyRule]:
        norm = normalize_namespace_prefix(prefix)
        return [
            self._policies[k] for k in sorted(self._policies.keys())
            if path_matches_prefix(self._policies[k].prefix, norm) or path_matches_prefix(norm, self._policies[k].prefix)
        ]

    def clear(self) -> None:
        self._policies.clear()
        self._subject_index.clear()
        self._role_index.clear()

    def rebuild(self, raw_entries: Mapping[str, bytes]) -> None:
        self.clear()
        for key in sorted(raw_entries.keys()):
            if is_system_key(key):
                self.put_raw_policy(key, raw_entries[key])

    def capture_snapshot(self) -> ACLSnapshot:
        return ACLSnapshot(
            policies=dict(self._policies),
            subject_index=_deep_copy_index(self._subject_index),
            role_index=_deep_copy_index(self._role_index),
        )

    def restore_snapshot(self, snap: ACLSnapshot) -> None:
        self._policies = dict(snap.policies)
        self._subject_index = _deep_copy_index(snap.subject_index)
        self._role_index = _deep_copy_index(snap.role_index)

    def clone(self) -> ACLIndex:
        cloned = ACLIndex()
        cloned.restore_snapshot(self.capture_snapshot())
        return cloned

    def effective_permissions(self, principal: Principal, path: str) -> frozenset[str]:
        if principal.is_system:
            return VALID_PERMISSIONS
        segs = path_segments(path)
        allowed, denied = set[str](), set[str]()
        subj_map = self._subject_index.get(principal.subject)
        for depth in range(len(segs) + 1):
            ancestor = segs[:depth]
            if subj_map:
                for rule in subj_map.get(ancestor, ()):
                    (denied if rule.effect == "deny" else allowed).update(rule.permissions)
            for role in principal.roles:
                role_map = self._role_index.get(role)
                if role_map:
                    for rule in role_map.get(ancestor, ()):
                        (denied if rule.effect == "deny" else allowed).update(rule.permissions)
        return frozenset(allowed - denied)

    def check(self, principal: Principal, path: str, permission: str) -> bool:
        if permission not in VALID_PERMISSIONS:
            raise ValueError(f"Unknown permission {permission!r}")
        return True if principal.is_system else (permission in self.effective_permissions(principal, path))

    def require(self, principal: Principal, path: str, permission: str) -> None:
        if not self.check(principal, path, permission):
            raise AccessDeniedError(f"Principal {principal.subject!r} denied {permission!r} on {path!r}")
EOF

# 3. Update kvstore/tx.py: snapshot and restore ACLIndex state across nested savepoints
cat > "$APP_DIR/kvstore/tx.py" <<'EOF'
"""Transactional execution with nested savepoints and namespace authorization."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from types import TracebackType

from .acl import ACLIndex, ACLSnapshot, PolicyRule, Principal, SYSTEM_PRINCIPAL, canonical_policy_key
from .mvcc import (
    MVCCStore, WriteConflictError, is_system_key,
    normalize_namespace_prefix, validate_data_key, validate_system_key,
)
from .wal import RecordType, WAL


class TransactionStateError(RuntimeError):
    """Raised when an operation is attempted on an inactive or invalid transaction state."""


@dataclass
class _Savepoint:
    name: str
    mvcc_marker: int
    acl_snapshot: ACLSnapshot


def _coerce_bytes(value: bytes | bytearray | str) -> bytes:
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    raise TypeError(f"Expected bytes or str value, got {type(value).__name__}")


class Transaction:
    """Read-write MVCC transaction supporting nested savepoints and policy updates."""

    def __init__(
        self, mvcc: MVCCStore, wal: WAL, acl_index: ACLIndex, principal: Principal = SYSTEM_PRINCIPAL,
        *, sync_on_commit: bool = True, on_finish: Callable[[int, bool], None] | None = None,
    ) -> None:
        self._mvcc, self._wal, self._acl = mvcc, wal, acl_index
        self._principal, self._sync_on_commit, self._on_finish = principal, sync_on_commit, on_finish
        self._tx_id, self._start_ts = self._mvcc.begin_tx()
        self._state = "active"
        self._commit_ts: int | None = None
        self._initial_acl = self._acl.capture_snapshot()
        self._savepoints: list[_Savepoint] = []
        self._wal.append(RecordType.BEGIN, tx_id=self._tx_id)

    @property
    def tx_id(self) -> int:
        return self._tx_id

    @property
    def start_ts(self) -> int:
        return self._start_ts

    @property
    def state(self) -> str:
        return self._state

    @property
    def commit_ts(self) -> int | None:
        return self._commit_ts

    @property
    def principal(self) -> Principal:
        return self._principal

    def _ensure_active(self) -> None:
        if self._state != "active":
            raise TransactionStateError(f"Transaction {self._tx_id} is already {self._state}")

    def _effective_principal(self, override: Principal | None) -> Principal:
        return self._principal if override is None else override

    def check_access(self, principal: Principal, path: str, permission: str) -> bool:
        self._ensure_active()
        return self._acl.check(principal, path, permission)

    def get(self, key: str, *, principal: Principal | None = None) -> bytes | None:
        self._ensure_active()
        actor = self._effective_principal(principal)
        if is_system_key(key):
            norm_key = validate_system_key(key)
            raw = self._mvcc.get_in_tx(self._tx_id, norm_key)
            if not actor.is_system:
                target = PolicyRule.from_json_bytes(norm_key, raw).prefix if raw is not None else "/"
                self._acl.require(actor, target, "grant")
            return raw
        norm_key = validate_data_key(key)
        self._acl.require(actor, norm_key, "read")
        return self._mvcc.get_in_tx(self._tx_id, norm_key)

    def put(self, key: str, value: bytes | bytearray | str, *, principal: Principal | None = None) -> None:
        self._ensure_active()
        actor, raw_val = self._effective_principal(principal), _coerce_bytes(value)
        if is_system_key(key):
            norm_key = validate_system_key(key)
            new_rule = PolicyRule.from_json_bytes(norm_key, raw_val)
            if not actor.is_system:
                self._acl.require(actor, new_rule.prefix, "grant")
                existing_rule = self._acl.get_policy(norm_key)
                if existing_rule is not None:
                    self._acl.require(actor, existing_rule.prefix, "grant")
            canonical_bytes = new_rule.to_json_bytes()
            self._mvcc.stage_put(self._tx_id, norm_key, canonical_bytes)
            self._wal.append(RecordType.PUT, tx_id=self._tx_id, key=norm_key, value=canonical_bytes)
            self._acl.put_policy(norm_key, new_rule)
            return
        norm_key = validate_data_key(key)
        self._acl.require(actor, norm_key, "write")
        self._mvcc.stage_put(self._tx_id, norm_key, raw_val)
        self._wal.append(RecordType.PUT, tx_id=self._tx_id, key=norm_key, value=raw_val)

    def delete(self, key: str, *, principal: Principal | None = None) -> bool:
        self._ensure_active()
        actor = self._effective_principal(principal)
        if is_system_key(key):
            norm_key = validate_system_key(key)
            existing_raw = self._mvcc.get_in_tx(self._tx_id, norm_key)
            if existing_raw is None:
                if not actor.is_system:
                    self._acl.require(actor, "/", "grant")
                return False
            if not actor.is_system:
                self._acl.require(actor, PolicyRule.from_json_bytes(norm_key, existing_raw).prefix, "grant")
            self._mvcc.stage_delete(self._tx_id, norm_key)
            self._wal.append(RecordType.DELETE, tx_id=self._tx_id, key=norm_key)
            self._acl.remove_policy(norm_key)
            return True
        norm_key = validate_data_key(key)
        self._acl.require(actor, norm_key, "delete")
        if self._mvcc.get_in_tx(self._tx_id, norm_key) is None:
            return False
        self._mvcc.stage_delete(self._tx_id, norm_key)
        self._wal.append(RecordType.DELETE, tx_id=self._tx_id, key=norm_key)
        return True

    def scan(self, prefix: str = "/", *, principal: Principal | None = None) -> list[tuple[str, bytes]]:
        self._ensure_active()
        actor, norm_prefix = self._effective_principal(principal), normalize_namespace_prefix(prefix)
        self._acl.require(actor, norm_prefix, "list")
        rows = self._mvcc.scan_in_tx(self._tx_id, norm_prefix, include_system=False)
        return rows if actor.is_system else [(k, v) for k, v in rows if self._acl.check(actor, k, "read")]

    def set_policy(
        self, policy_id: str, *, prefix: str, permissions: Iterable[str],
        subject: str | None = None, role: str | None = None, effect: str = "allow", principal: Principal | None = None,
    ) -> str:
        self._ensure_active()
        pol_key = canonical_policy_key(policy_id)
        rule = PolicyRule(key=pol_key, prefix=prefix, permissions=frozenset(permissions), subject=subject, role=role, effect=effect)
        self.put(pol_key, rule.to_json_bytes(), principal=principal)
        return pol_key

    def remove_policy(self, policy_id: str, *, principal: Principal | None = None) -> bool:
        self._ensure_active()
        return self.delete(canonical_policy_key(policy_id), principal=principal)

    def savepoint(self, name: str) -> None:
        self._ensure_active()
        if not isinstance(name, str) or not name.strip():
            raise TransactionStateError("Savepoint name must be a non-empty string")
        self._wal.append(RecordType.SAVEPOINT, tx_id=self._tx_id, key=name)
        self._savepoints.append(
            _Savepoint(
                name=name,
                mvcc_marker=self._mvcc.tx_marker(self._tx_id),
                acl_snapshot=self._acl.capture_snapshot(),
            )
        )

    def rollback_to(self, name: str) -> None:
        self._ensure_active()
        for idx in range(len(self._savepoints) - 1, -1, -1):
            sp = self._savepoints[idx]
            if sp.name == name:
                del self._savepoints[idx + 1 :]
                self._mvcc.rollback_tx_to(self._tx_id, sp.mvcc_marker)
                self._acl.restore_snapshot(sp.acl_snapshot)
                self._wal.append(RecordType.ROLLBACK_SP, tx_id=self._tx_id, key=name)
                return
        raise TransactionStateError(f"Unknown savepoint {name!r} in transaction {self._tx_id}")

    def release_savepoint(self, name: str) -> None:
        self._ensure_active()
        for idx in range(len(self._savepoints) - 1, -1, -1):
            if self._savepoints[idx].name == name:
                del self._savepoints[idx:]
                return
        raise TransactionStateError(f"Unknown savepoint {name!r} in transaction {self._tx_id}")

    def commit(self) -> int:
        self._ensure_active()
        try:
            self._mvcc.check_conflicts(self._tx_id)
        except WriteConflictError:
            self.abort()
            raise
        next_ts = self._mvcc.latest_ts + 1
        self._wal.append(RecordType.COMMIT, tx_id=self._tx_id, ts=next_ts)
        if self._sync_on_commit:
            self._wal.sync()
        committed_ts, _ = self._mvcc.commit_tx(self._tx_id, commit_ts=next_ts)
        self._savepoints.clear()
        self._state, self._commit_ts = "committed", committed_ts
        if self._on_finish is not None:
            self._on_finish(self._tx_id, True)
        return committed_ts

    def abort(self) -> None:
        if self._state == "aborted":
            return
        if self._state != "active":
            raise TransactionStateError(f"Cannot abort transaction {self._tx_id} in state {self._state!r}")
        self._wal.append(RecordType.ABORT, tx_id=self._tx_id)
        self._mvcc.abort_tx(self._tx_id)
        self._acl.restore_snapshot(self._initial_acl)
        self._savepoints.clear()
        self._state = "aborted"
        if self._on_finish is not None:
            self._on_finish(self._tx_id, False)

    def __enter__(self) -> Transaction:
        self._ensure_active()
        return self

    def __exit__(self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None) -> None:
        if self._state == "active":
            self.abort() if exc_type is not None else self.commit()
EOF

# 4. Update kvstore/engine.py: isolate uncommitted transaction ACL views and sync committed ACLs
cat > "$APP_DIR/kvstore/engine.py" <<'EOF'
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

    def _on_tx_finished(self, tx_id: int, committed: bool) -> None:
        self._active_txs.pop(tx_id, None)
        if committed:
            self._rebuild_acl_from_mvcc()

    def _on_snapshot_closed(self, snap: Snapshot) -> None:
        self._active_snapshots.discard(snap)

    def begin(self, principal: Principal = SYSTEM_PRINCIPAL) -> Transaction:
        self._ensure_open()
        tx = Transaction(
            self._mvcc, self._wal, self._acl.clone(), principal=principal,
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
EOF

# 5. Update kvstore/wal.py: full-payload CRC32 and per-transaction recovery staging
cat > "$APP_DIR/kvstore/wal.py" <<'EOF'
"""Binary write-ahead log with framed records and reopen recovery."""

from __future__ import annotations

import os
import struct
import zlib
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path

WAL_MAGIC = b"VKVWAL01"
WAL_VERSION = 1

FILE_HEADER_STRUCT = struct.Struct(">8sHHQ")
FRAME_META_STRUCT = struct.Struct(">BQQQII")
CRC_STRUCT = struct.Struct(">I")
FRAME_HEADER_SIZE = FRAME_META_STRUCT.size + CRC_STRUCT.size

MAX_KEY_BYTES = 4096
MAX_VAL_BYTES = 16 * 1024 * 1024


class WALError(RuntimeError):
    """Base error for write-ahead log operations."""


class WALCorruptionError(WALError):
    """Raised when a WAL header or record frame fails structural validation."""


class RecordType(IntEnum):
    BEGIN = 1
    PUT = 2
    DELETE = 3
    SAVEPOINT = 4
    ROLLBACK_SP = 5
    COMMIT = 6
    ABORT = 7
    CHECKPOINT = 8


@dataclass(frozen=True)
class WALRecord:
    rec_type: RecordType
    lsn: int
    tx_id: int
    ts: int
    key: str
    value: bytes = b""


@dataclass
class CommittedBatch:
    tx_id: int
    commit_ts: int
    records: list[WALRecord]


@dataclass
class RecoveryReport:
    checkpoint_ts: int
    committed: list[CommittedBatch]
    next_lsn: int
    next_tx_id: int
    replayed_frames: int
    truncated_bytes: int


@dataclass
class _TxReplayBuffer:
    ops: list[WALRecord] = field(default_factory=list)
    savepoints: list[tuple[str, int]] = field(default_factory=list)


def _frame_checksum(meta: bytes, payload: bytes, key_len: int = 0) -> int:
    _ = key_len
    crc = zlib.crc32(meta)
    return zlib.crc32(payload, crc) & 0xFFFFFFFF


class WAL:
    """Manages binary framed write-ahead logging and startup log replay."""

    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._fd: int | None = None
        self._next_lsn: int = 1
        self._checkpoint_ts: int = 0
        self._open_or_init()

    @property
    def path(self) -> Path:
        return self._path

    @property
    def next_lsn(self) -> int:
        return self._next_lsn

    @property
    def checkpoint_ts(self) -> int:
        return self._checkpoint_ts

    def advance_lsn_floor(self, min_next_lsn: int) -> None:
        if min_next_lsn > self._next_lsn:
            self._next_lsn = min_next_lsn

    def _open_or_init(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self._path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            size = os.fstat(fd).st_size
            if size == 0:
                self._write_all(fd, FILE_HEADER_STRUCT.pack(WAL_MAGIC, WAL_VERSION, 0, 0))
                os.fsync(fd)
            elif size < FILE_HEADER_STRUCT.size:
                raise WALCorruptionError("Truncated WAL file header")
            else:
                magic, version, _flags, cp_ts = FILE_HEADER_STRUCT.unpack(os.pread(fd, FILE_HEADER_STRUCT.size, 0))
                if magic != WAL_MAGIC or version != WAL_VERSION:
                    raise WALCorruptionError("Unrecognized WAL magic or format version")
                self._checkpoint_ts = cp_ts
                os.lseek(fd, 0, os.SEEK_END)
        except Exception:
            os.close(fd)
            raise
        self._fd = fd

    @staticmethod
    def _write_all(fd: int, data: bytes) -> None:
        view, written = memoryview(data), 0
        while written < len(view):
            n = os.write(fd, view[written:])
            if n <= 0:
                raise WALError("Short write while appending to WAL")
            written += n

    def _require_fd(self) -> int:
        if self._fd is None:
            raise WALError("WAL is closed")
        return self._fd

    def append(self, rec_type: RecordType, *, tx_id: int, ts: int = 0, key: str = "", value: bytes = b"") -> WALRecord:
        fd = self._require_fd()
        key_bytes = key.encode("utf-8")
        if len(key_bytes) > MAX_KEY_BYTES or len(value) > MAX_VAL_BYTES:
            raise WALError("Key or value exceeds maximum frame size")
        lsn = self._next_lsn
        self._next_lsn += 1
        payload = key_bytes + value
        meta = FRAME_META_STRUCT.pack(int(rec_type), lsn, tx_id, ts, len(key_bytes), len(value))
        crc = _frame_checksum(meta, payload, len(key_bytes))
        os.lseek(fd, 0, os.SEEK_END)
        self._write_all(fd, meta + CRC_STRUCT.pack(crc) + payload)
        return WALRecord(rec_type=rec_type, lsn=lsn, tx_id=tx_id, ts=ts, key=key, value=value)

    def sync(self) -> None:
        os.fsync(self._require_fd())

    def recover(self) -> RecoveryReport:
        fd = self._require_fd()
        total_size = os.fstat(fd).st_size
        if total_size < FILE_HEADER_STRUCT.size:
            raise WALCorruptionError("WAL file smaller than header")
        magic, version, _flags, cp_ts = FILE_HEADER_STRUCT.unpack(os.pread(fd, FILE_HEADER_STRUCT.size, 0))
        if magic != WAL_MAGIC or version != WAL_VERSION:
            raise WALCorruptionError("Invalid WAL header magic or version")
        self._checkpoint_ts = cp_ts

        offset, replayed, truncated_bytes = FILE_HEADER_STRUCT.size, 0, 0
        active_txs: dict[int, _TxReplayBuffer] = {}
        committed: list[CommittedBatch] = []
        max_lsn = 0
        max_tx_id = 0

        while offset < total_size:
            raw_frame_hdr = os.pread(fd, FRAME_HEADER_SIZE, offset)
            if len(raw_frame_hdr) < FRAME_HEADER_SIZE:
                truncated_bytes = total_size - offset
                os.ftruncate(fd, offset)
                break
            meta_bytes = raw_frame_hdr[: FRAME_META_STRUCT.size]
            (expected_crc,) = CRC_STRUCT.unpack(raw_frame_hdr[FRAME_META_STRUCT.size :])
            raw_type, lsn, tx_id, ts, key_len, val_len = FRAME_META_STRUCT.unpack(meta_bytes)
            try:
                rec_type = RecordType(raw_type)
            except ValueError as exc:
                raise WALCorruptionError(f"Unknown record type {raw_type} at {offset}") from exc
            if key_len > MAX_KEY_BYTES or val_len > MAX_VAL_BYTES:
                raise WALCorruptionError(f"Oversized frame lengths at offset {offset}")

            payload_len = key_len + val_len
            payload = os.pread(fd, payload_len, offset + FRAME_HEADER_SIZE)
            if len(payload) < payload_len:
                truncated_bytes = total_size - offset
                os.ftruncate(fd, offset)
                break
            if _frame_checksum(meta_bytes, payload, key_len) != expected_crc:
                raise WALCorruptionError(f"Frame checksum mismatch at offset {offset} (lsn={lsn})")
            try:
                key = payload[:key_len].decode("utf-8")
            except UnicodeDecodeError as exc:
                raise WALCorruptionError(f"Invalid UTF-8 key in WAL at offset {offset}") from exc

            rec = WALRecord(rec_type, lsn, tx_id, ts, key, payload[key_len:])
            offset += FRAME_HEADER_SIZE + payload_len
            replayed += 1
            max_lsn = max(max_lsn, lsn)
            max_tx_id = max(max_tx_id, tx_id)

            if rec_type == RecordType.BEGIN:
                active_txs[tx_id] = _TxReplayBuffer()
            elif rec_type in (RecordType.PUT, RecordType.DELETE):
                active_txs.setdefault(tx_id, _TxReplayBuffer()).ops.append(rec)
            elif rec_type == RecordType.SAVEPOINT:
                buf = active_txs.setdefault(tx_id, _TxReplayBuffer())
                buf.savepoints.append((rec.key, len(buf.ops)))
            elif rec_type == RecordType.ROLLBACK_SP:
                buf = active_txs.get(tx_id)
                if buf is not None:
                    for idx in range(len(buf.savepoints) - 1, -1, -1):
                        if buf.savepoints[idx][0] == rec.key:
                            del buf.ops[buf.savepoints[idx][1] :]
                            del buf.savepoints[idx + 1 :]
                            break
            elif rec_type == RecordType.ABORT:
                active_txs.pop(tx_id, None)
            elif rec_type == RecordType.COMMIT:
                buf = active_txs.pop(tx_id, None)
                committed.append(
                    CommittedBatch(rec.tx_id, rec.ts, list(buf.ops) if buf is not None else [])
                )

        active_txs.clear()
        os.lseek(fd, offset, os.SEEK_SET)
        self._next_lsn = max(1, max_lsn + 1)
        return RecoveryReport(cp_ts, committed, self._next_lsn, max(1, max_tx_id + 1), replayed, truncated_bytes)

    def reset(self, checkpoint_ts: int, *, next_lsn: int | None = None) -> None:
        fd = self._require_fd()
        retained_lsn = next_lsn if next_lsn is not None else self._next_lsn
        tmp_path = self._path.with_suffix(self._path.suffix + ".tmp")
        tmp_fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            self._write_all(tmp_fd, FILE_HEADER_STRUCT.pack(WAL_MAGIC, WAL_VERSION, 0, checkpoint_ts))
            os.fsync(tmp_fd)
        finally:
            os.close(tmp_fd)
        os.replace(tmp_path, self._path)
        os.close(fd)
        self._fd = os.open(self._path, os.O_RDWR, 0o600)
        os.lseek(self._fd, 0, os.SEEK_END)
        self._checkpoint_ts = checkpoint_ts
        self._next_lsn = max(1, retained_lsn)

    def close(self) -> None:
        if self._fd is not None:
            fd, self._fd = self._fd, None
            os.close(fd)
EOF

# 6. Update kvstore/mvcc.py: preserve tombstone ordering during watermark compaction
cat > "$APP_DIR/kvstore/mvcc.py" <<'EOF'
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
            below = [v for v in chain if v.ts <= watermark_ts]
            above = [v for v in chain if v.ts > watermark_ts]
            if not below:
                continue
            anchor = below[-1]
            if anchor.deleted and not above:
                removed += len(chain)
                empty_keys.append(key)
                continue
            kept = [anchor, *above]
            removed += len(chain) - len(kept)
            self._versions[key] = kept
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
EOF

# 7. Extend tests/test_store.py with regression coverage for all 3 state-consistency fixes
cat > "$APP_DIR/tests/test_store.py" <<'EOF'
"""Functional and regression unit tests for the kvstore engine."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from kvstore import (
    AccessDeniedError,
    Engine,
    KeyValidationError,
    Principal,
    WALCorruptionError,
    WriteConflictError,
)


class TestKVStoreBaseline(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.data_dir = Path(self._tmp.name) / "store"

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_basic_crud_and_reopen(self) -> None:
        with Engine.open(self.data_dir) as eng:
            eng.put("/orgs/acme/projects/billing/secrets/api_key", b"sk-live-001")
            eng.put("/orgs/acme/projects/billing/config/region", "us-east-1")
            self.assertEqual(eng.get("/orgs/acme/projects/billing/secrets/api_key"), b"sk-live-001")

        with Engine.open(self.data_dir) as reopened:
            self.assertEqual(reopened.get("/orgs/acme/projects/billing/secrets/api_key"), b"sk-live-001")
            self.assertEqual(reopened.get("/orgs/acme/projects/billing/config/region"), b"us-east-1")

    def test_namespace_validation(self) -> None:
        with Engine.open(self.data_dir) as eng:
            for invalid in ("orgs/acme/k", "/orgs//acme/k", "/orgs/../k", "/orgs/acme/"):
                with self.assertRaises(KeyValidationError):
                    eng.put(invalid, b"val")

    def test_atomic_bootstrap_policy_and_secret_in_single_tx(self) -> None:
        alice = Principal.user("alice", roles=["billing-dev"])
        iam_admin = Principal.user("iam-admin")

        with Engine.open(self.data_dir) as eng:
            eng.grant_policy("iam-root", prefix="/orgs/acme", permissions=["grant"], subject="iam-admin")
            with eng.transaction(principal=iam_admin) as tx:
                tx.set_policy(
                    "billing-dev-rw",
                    prefix="/orgs/acme/projects/billing",
                    permissions=["read", "write", "list"],
                    role="billing-dev",
                )
                tx.put("/orgs/acme/projects/billing/secrets/db_url", b"postgres://db/billing", principal=alice)

            self.assertEqual(
                eng.get("/orgs/acme/projects/billing/secrets/db_url", principal=alice),
                b"postgres://db/billing",
            )
            with self.assertRaises(AccessDeniedError):
                eng.put("/orgs/acme/projects/other/secrets/s1", b"x", principal=alice)

    def test_nested_savepoints_on_kv_values(self) -> None:
        with Engine.open(self.data_dir) as eng:
            tx = eng.begin()
            tx.put("/orgs/acme/config/a", b"1")
            tx.savepoint("sp1")
            tx.put("/orgs/acme/config/b", b"2")
            tx.release_savepoint("sp1")
            tx.savepoint("sp2")
            tx.put("/orgs/acme/config/c", b"3")
            tx.put("/orgs/acme/config/b", b"overwritten")
            tx.rollback_to("sp2")
            tx.commit()

            self.assertEqual(eng.get("/orgs/acme/config/a"), b"1")
            self.assertEqual(eng.get("/orgs/acme/config/b"), b"2")
            self.assertIsNone(eng.get("/orgs/acme/config/c"))

    def test_snapshot_isolation_and_write_conflict(self) -> None:
        with Engine.open(self.data_dir) as eng:
            eng.put("/orgs/acme/config/version", b"v1")
            snap_before = eng.snapshot()

            tx1 = eng.begin()
            tx2 = eng.begin()
            tx1.put("/orgs/acme/config/version", b"v2")
            tx2.put("/orgs/acme/config/version", b"v3")
            tx1.commit()
            with self.assertRaises(WriteConflictError):
                tx2.commit()

            snap_after = eng.snapshot()
            self.assertEqual(snap_before.get("/orgs/acme/config/version"), b"v1")
            self.assertEqual(snap_after.get("/orgs/acme/config/version"), b"v2")
            snap_before.close()
            snap_after.close()

    def test_checkpoint_persists_live_entries(self) -> None:
        with Engine.open(self.data_dir) as eng:
            eng.put("/orgs/acme/secrets/k1", b"one")
            eng.put("/orgs/acme/secrets/k1", b"two")
            eng.put("/orgs/acme/secrets/k2", b"keep")
            stats = eng.checkpoint()
            self.assertGreaterEqual(stats["pruned_versions"], 1)

        with Engine.open(self.data_dir) as reopened:
            self.assertEqual(reopened.get("/orgs/acme/secrets/k1"), b"two")
            self.assertEqual(reopened.get("/orgs/acme/secrets/k2"), b"keep")

    def test_acl_savepoint_rollback_and_abort_do_not_retain_grants(self) -> None:
        alice = Principal.user("alice", roles=["ops"])
        bob = Principal.user("bob")
        with Engine.open(self.data_dir) as eng:
            eng.grant_policy("alice-base-read", prefix="/orgs/acme", permissions=["read"], subject="alice")
            eng.put("/orgs/acme/doc", b"initial")

            tx = eng.begin()
            tx.savepoint("sp1")
            tx.set_policy("ops-proj", prefix="/orgs/acme/proj", permissions=["read", "write"], role="ops")
            tx.put("/orgs/acme/proj/s1", b"ok", principal=alice)
            tx.release_savepoint("sp1")

            tx.savepoint("sp2")
            tx.set_policy("alice-root-write", prefix="/orgs/acme", permissions=["write", "delete"], subject="alice")
            tx.set_policy("bob-proj-read", prefix="/orgs/acme/proj", permissions=["read"], subject="bob")
            tx.rollback_to("sp2")
            self.assertFalse(tx.check_access(alice, "/orgs/acme/doc", "write"))
            self.assertFalse(tx.check_access(bob, "/orgs/acme/proj/s1", "read"))
            tx.commit()

            self.assertEqual(eng.get("/orgs/acme/proj/s1", principal=alice), b"ok")
            with self.assertRaises(AccessDeniedError):
                eng.put("/orgs/acme/doc", b"unauthorized", principal=alice)
            with self.assertRaises(AccessDeniedError):
                eng.get("/orgs/acme/proj/s1", principal=bob)

            tx_abort = eng.begin()
            tx_abort.set_policy("alice-abort-write", prefix="/orgs/acme", permissions=["write"], subject="alice")
            tx_abort.abort()
            with self.assertRaises(AccessDeniedError):
                eng.put("/orgs/acme/doc", b"still-unauthorized", principal=alice)

    def test_wal_value_crc_and_interleaved_uncommitted_recovery(self) -> None:
        crc_dir = Path(self._tmp.name) / "crc_store"
        with Engine.open(crc_dir) as eng:
            eng.put("/orgs/acme/secrets/k", b"integrity-protected-secret-value")

        wal_file = crc_dir / "wal.log"
        data = bytearray(wal_file.read_bytes())
        idx = data.find(b"integrity-protected-secret-value")
        self.assertGreaterEqual(idx, 0)
        data[idx] ^= 0x01
        wal_file.write_bytes(bytes(data))
        with self.assertRaises(WALCorruptionError):
            Engine.open(crc_dir)

        rec_dir = Path(self._tmp.name) / "rec_store"
        eng = Engine.open(rec_dir)
        tx1 = eng.begin()
        tx1.put("/orgs/acme/secrets/uncommitted", b"leak")
        tx2 = eng.begin()
        tx2.put("/orgs/acme/secrets/committed", b"durable")
        tx2.commit()
        tx3 = eng.begin()
        tx3.put("/orgs/acme/secrets/torn", b"partial-tail-bytes")
        eng.close()

        rec_wal = rec_dir / "wal.log"
        with open(rec_wal, "r+b") as fh:
            fh.truncate(rec_wal.stat().st_size - 5)

        with Engine.open(rec_dir) as reopened:
            self.assertEqual(reopened.get("/orgs/acme/secrets/committed"), b"durable")
            self.assertIsNone(reopened.get("/orgs/acme/secrets/uncommitted"))
            self.assertIsNone(reopened.get("/orgs/acme/secrets/torn"))
            reopened.put("/orgs/acme/secrets/after", b"next")

        with Engine.open(rec_dir) as reopened2:
            self.assertEqual(reopened2.get("/orgs/acme/secrets/after"), b"next")

    def test_mvcc_tombstone_compaction_does_not_resurrect_deleted_versions(self) -> None:
        bob = Principal.user("bob")
        with Engine.open(self.data_dir) as eng:
            eng.put("/orgs/acme/secrets/old", b"v1-revoked")
            eng.grant_policy("bob-read", prefix="/orgs/acme/secrets", permissions=["read"], subject="bob")
            eng.delete("/orgs/acme/secrets/old")
            eng.revoke_policy("bob-read")
            eng.put("/orgs/acme/secrets/current", b"v2-live")

            snap = eng.snapshot()
            eng.put("/orgs/acme/secrets/extra", b"v3")
            eng.checkpoint()

            self.assertIsNone(snap.get("/orgs/acme/secrets/old"))
            self.assertFalse(snap.check_access(bob, "/orgs/acme/secrets/current", "read"))
            self.assertIsNone(eng.get("/orgs/acme/secrets/old"))
            self.assertFalse(eng.check_access(bob, "/orgs/acme/secrets/current", "read"))
            snap.close()
            eng.checkpoint()

        with Engine.open(self.data_dir) as reopened:
            self.assertIsNone(reopened.get("/orgs/acme/secrets/old"))
            self.assertFalse(reopened.check_access(bob, "/orgs/acme/secrets/current", "read"))
            self.assertEqual(reopened.get("/orgs/acme/secrets/current"), b"v2-live")


if __name__ == "__main__":
    unittest.main()
EOF
