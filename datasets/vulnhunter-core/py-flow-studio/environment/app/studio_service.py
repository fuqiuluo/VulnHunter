"""Pipeline studio service coordinator."""

from __future__ import annotations

from typing import Any

from auth import SessionManager
from validator import inspect_operator_code


class StudioService:
    """Coordinates authenticated operator source preflight requests."""

    def __init__(self, sessions: SessionManager | None = None) -> None:
        self.sessions = sessions or SessionManager()

    def request_bootstrap_token(self, client_host: str = "127.0.0.1") -> dict[str, str]:
        token = self.sessions.bootstrap_session(client_host=client_host)
        return {"access_token": token, "token_type": "bearer"}

    def preflight_operator(self, bearer_token: str, source: str) -> dict[str, Any]:
        claims = self.sessions.verify_token(bearer_token)
        summary = inspect_operator_code(source)
        return {
            "validated_by": claims.subject,
            "role": claims.role,
            "summary": summary,
        }
