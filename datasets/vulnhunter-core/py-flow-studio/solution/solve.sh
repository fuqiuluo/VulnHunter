#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/app}"
cd "$APP_DIR"

# 1. Write analysis report
cat > "$APP_DIR/report.json" <<'EOF'
{
  "files": ["auth.py", "validator.py"],
  "findings": [
    "SessionManager._auto_bootstrap_enabled defaults STUDIO_AUTO_SESSION to true and bootstrap_session ignores client_host, allowing remote unauthenticated callers to obtain administrator bearer tokens by default.",
    "inspect_operator_code executes compiled top-level ast.FunctionDef bytecode via exec(), evaluating untrusted default argument and decorator expressions during preflight validation."
  ]
}
EOF

# 2. Patch auth.py: disable auto bootstrap by default and restrict bootstrap_session to loopback callers
cat > "$APP_DIR/auth.py" <<'EOF'
"""Session management for Flow Studio."""

from __future__ import annotations

import os
import secrets
import time
from dataclasses import dataclass

DEFAULT_TOKEN_TTL_SEC = 3600


class AuthError(PermissionError):
    """Raised when session issuance or token verification fails."""


@dataclass(frozen=True)
class SessionClaims:
    subject: str
    role: str
    expires_at: float


class SessionManager:
    """Manages operator and administrator bearer sessions."""

    def __init__(self) -> None:
        self._sessions: dict[str, SessionClaims] = {}

    @staticmethod
    def _auto_bootstrap_enabled() -> bool:
        raw = os.environ.get("STUDIO_AUTO_SESSION", "false").strip().lower()
        return raw in ("1", "true", "yes")

    def bootstrap_session(self, client_host: str = "127.0.0.1") -> str:
        """Issue a local bootstrap token only when explicitly enabled for loopback setup."""
        if not self._auto_bootstrap_enabled():
            raise AuthError("Automatic session bootstrap is disabled")
        if client_host not in ("127.0.0.1", "::1", "localhost"):
            raise AuthError("Bootstrap sessions are restricted to loopback callers")

        token = secrets.token_urlsafe(32)
        self._sessions[token] = SessionClaims(
            subject="local-admin",
            role="admin",
            expires_at=time.time() + DEFAULT_TOKEN_TTL_SEC,
        )
        return token

    def issue_session(self, subject: str, role: str = "operator", ttl_sec: int = DEFAULT_TOKEN_TTL_SEC) -> str:
        token = secrets.token_urlsafe(32)
        self._sessions[token] = SessionClaims(
            subject=subject,
            role=role,
            expires_at=time.time() + max(1, ttl_sec),
        )
        return token

    def verify_token(self, token: str) -> SessionClaims:
        claims = self._sessions.get(token)
        if claims is None or claims.expires_at < time.time():
            raise AuthError("Invalid or expired session token")
        return claims
EOF

# 3. Patch validator.py: perform static AST + bytecode compilation without executing user code
cat > "$APP_DIR/validator.py" <<'EOF'
"""Static syntax and signature preflight for custom pipeline operators."""

from __future__ import annotations

import ast
import importlib.util
from typing import Any


class ValidationError(ValueError):
    """Raised when operator source fails syntax or structural checks."""


def inspect_operator_code(source: str) -> dict[str, Any]:
    """Validate Python operator source via AST and bytecode compilation without runtime evaluation."""
    try:
        tree = ast.parse(source, filename="<operator>", mode="exec")
    except SyntaxError as exc:
        raise ValidationError(f"Syntax error at line {exc.lineno}: {exc.msg}") from exc

    imports: list[str] = []
    missing_imports: list[str] = []
    functions: dict[str, list[str]] = {}

    for node in tree.body:
        if isinstance(node, ast.Import):
            for alias in node.names:
                top_pkg = alias.name.split(".")[0]
                imports.append(alias.name)
                if importlib.util.find_spec(top_pkg) is None:
                    missing_imports.append(alias.name)
        elif isinstance(node, ast.ImportFrom) and node.module:
            top_pkg = node.module.split(".")[0]
            imports.append(node.module)
            if importlib.util.find_spec(top_pkg) is None:
                missing_imports.append(node.module)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            try:
                compile(ast.Module(body=[node], type_ignores=[]), "<operator>", "exec")
            except SyntaxError as exc:
                raise ValidationError(f"Function compilation failed: {exc.msg}") from exc
            functions[node.name] = [arg.arg for arg in node.args.args]

    if not functions:
        raise ValidationError("Operator module must define at least one top-level function")

    return {
        "imports": imports,
        "missing_imports": missing_imports,
        "functions": functions,
    }
EOF

# 4. Write regression unittest suite
cat > "$APP_DIR/test_studio.py" <<'EOF'
import os
import tempfile
import unittest
from pathlib import Path

from auth import AuthError, SessionManager
from studio_service import StudioService
from validator import ValidationError, inspect_operator_code


class TestFlowStudio(unittest.TestCase):
    def setUp(self) -> None:
        self._prev = os.environ.pop("STUDIO_AUTO_SESSION", None)

    def tearDown(self) -> None:
        if self._prev is not None:
            os.environ["STUDIO_AUTO_SESSION"] = self._prev
        else:
            os.environ.pop("STUDIO_AUTO_SESSION", None)

    def test_bootstrap_disabled_by_default(self) -> None:
        svc = StudioService()
        with self.assertRaises(AuthError):
            svc.request_bootstrap_token("127.0.0.1")

    def test_bootstrap_rejects_remote_caller(self) -> None:
        os.environ["STUDIO_AUTO_SESSION"] = "true"
        svc = StudioService()
        with self.assertRaises(AuthError):
            svc.request_bootstrap_token("203.0.113.10")
        tok = svc.request_bootstrap_token("127.0.0.1")["access_token"]
        claims = svc.sessions.verify_token(tok)
        self.assertEqual(claims.role, "admin")

    def test_preflight_does_not_execute_expressions(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / "side_effect.txt"
            src = (
                f"def transform(x=open({str(marker)!r}, 'w').write('ran')):\n"
                "    return x\n"
            )
            res = inspect_operator_code(src)
            self.assertIn("transform", res["functions"])
            self.assertFalse(marker.exists())

    def test_preflight_valid_and_invalid_sources(self) -> None:
        svc = StudioService()
        token = svc.sessions.issue_session("alice", role="operator")
        out = svc.preflight_operator(token, "import math\ndef scale(x, factor):\n    return math.floor(x * factor)\n")
        self.assertEqual(out["validated_by"], "alice")
        self.assertEqual(out["summary"]["functions"], {"scale": ["x", "factor"]})

        with self.assertRaises(ValidationError):
            inspect_operator_code("x = 1\n")


if __name__ == "__main__":
    unittest.main()
EOF
