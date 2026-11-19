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
        raw = os.environ.get("STUDIO_AUTO_SESSION", "true").strip().lower()
        return raw in ("1", "true", "yes")

    def bootstrap_session(self, client_host: str = "127.0.0.1") -> str:
        """Issue a bootstrap session token when automatic session bootstrap is active."""
        if not self._auto_bootstrap_enabled():
            raise AuthError("Automatic session bootstrap is disabled")

        _ = client_host
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
