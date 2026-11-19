"""Immutable point-in-time MVCC snapshot reader with historical ACL enforcement."""

from __future__ import annotations

from collections.abc import Callable
from types import TracebackType

from .acl import ACLIndex, PolicyRule, Principal, SYSTEM_PRINCIPAL
from .mvcc import (
    MVCCStore, is_system_key, normalize_namespace_prefix, validate_data_key, validate_system_key,
)


class Snapshot:
    """Consistent read-only view of data and policies at a fixed MVCC timestamp."""

    def __init__(
        self,
        mvcc: MVCCStore,
        read_ts: int,
        principal: Principal = SYSTEM_PRINCIPAL,
        *,
        on_close: Callable[[Snapshot], None] | None = None,
    ) -> None:
        self._mvcc = mvcc
        self._read_ts = read_ts
        self._principal = principal
        self._on_close = on_close
        self._closed = False

    @property
    def read_ts(self) -> int:
        return self._read_ts

    @property
    def principal(self) -> Principal:
        return self._principal

    @property
    def closed(self) -> bool:
        return self._closed

    def _ensure_open(self) -> None:
        if self._closed:
            raise RuntimeError("Snapshot is closed")

    def _effective_principal(self, override: Principal | None) -> Principal:
        return self._principal if override is None else override

    def _acl_at_snapshot(self) -> ACLIndex:
        idx = ACLIndex()
        idx.rebuild(dict(self._mvcc.scan_at("@acl/", self._read_ts, include_system=True)))
        return idx

    def check_access(self, principal: Principal, path: str, permission: str) -> bool:
        self._ensure_open()
        return True if principal.is_system else self._acl_at_snapshot().check(principal, path, permission)

    def get(self, key: str, *, principal: Principal | None = None) -> bytes | None:
        self._ensure_open()
        actor = self._effective_principal(principal)
        acl = self._acl_at_snapshot()

        if is_system_key(key):
            norm_key = validate_system_key(key)
            raw = self._mvcc.get_at(norm_key, self._read_ts)
            if not actor.is_system:
                target = PolicyRule.from_json_bytes(norm_key, raw).prefix if raw is not None else "/"
                acl.require(actor, target, "grant")
            return raw

        norm_key = validate_data_key(key)
        acl.require(actor, norm_key, "read")
        return self._mvcc.get_at(norm_key, self._read_ts)

    def scan(
        self, prefix: str = "/", *, principal: Principal | None = None
    ) -> list[tuple[str, bytes]]:
        self._ensure_open()
        actor = self._effective_principal(principal)
        norm_prefix = normalize_namespace_prefix(prefix)
        acl = self._acl_at_snapshot()
        acl.require(actor, norm_prefix, "list")
        rows = self._mvcc.scan_at(norm_prefix, self._read_ts, include_system=False)
        return rows if actor.is_system else [(k, v) for k, v in rows if acl.check(actor, k, "read")]

    def export_namespace(
        self, prefix: str = "/", *, principal: Principal | None = None
    ) -> dict[str, bytes]:
        return dict(self.scan(prefix, principal=principal))

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            if self._on_close is not None:
                self._on_close(self)

    def __enter__(self) -> Snapshot:
        self._ensure_open()
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        self.close()
