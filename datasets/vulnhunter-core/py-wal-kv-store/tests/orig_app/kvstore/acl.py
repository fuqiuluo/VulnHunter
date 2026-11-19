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
            subject_index={s: dict(prefixes) for s, prefixes in self._subject_index.items()},
            role_index={r: dict(prefixes) for r, prefixes in self._role_index.items()},
        )

    def restore_snapshot(self, snap: ACLSnapshot) -> None:
        self._policies = dict(snap.policies)
        self._subject_index = {s: dict(prefixes) for s, prefixes in snap.subject_index.items()}
        self._role_index = {r: dict(prefixes) for r, prefixes in snap.role_index.items()}

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
