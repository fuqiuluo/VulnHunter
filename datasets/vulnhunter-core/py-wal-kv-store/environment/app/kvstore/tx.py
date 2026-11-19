"""Transactional execution with nested savepoints and namespace authorization."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from types import TracebackType

from .acl import ACLIndex, PolicyRule, Principal, SYSTEM_PRINCIPAL, canonical_policy_key
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
        self._savepoints.append(_Savepoint(name=name, mvcc_marker=self._mvcc.tx_marker(self._tx_id)))

    def rollback_to(self, name: str) -> None:
        self._ensure_active()
        for idx in range(len(self._savepoints) - 1, -1, -1):
            sp = self._savepoints[idx]
            if sp.name == name:
                del self._savepoints[idx + 1 :]
                self._mvcc.rollback_tx_to(self._tx_id, sp.mvcc_marker)
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
