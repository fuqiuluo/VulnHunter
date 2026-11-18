"""Outbound webhook preview client.

Fetches short UTF-8 text previews from public internet HTTP/HTTPS endpoints
(or origins explicitly listed in the comma-separated `WEBHOOK_TRUSTED_ORIGINS`
environment variable as `scheme://host:port`), raising `URLPolicyError` for any
unsupported or non-public destination.
"""

from __future__ import annotations

import os
import urllib.parse
import urllib.request

MAX_PREVIEW_BYTES = 4096


class URLPolicyError(ValueError):
    """Raised when a target URL is not permitted by outbound client policy."""


def _trusted_origins() -> set[str]:
    raw = os.environ.get("WEBHOOK_TRUSTED_ORIGINS", "")
    origins: set[str] = set()
    for item in raw.split(","):
        cleaned = item.strip().rstrip("/").lower()
        if cleaned:
            origins.add(cleaned)
    return origins


def _origin_key(parsed: urllib.parse.SplitResult) -> str:
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port or (443 if scheme == "https" else 80)
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{scheme}://{host}:{port}"


def validate_target_url(url: str) -> None:
    """Validate that `url` complies with outbound destination rules."""
    parsed = urllib.parse.urlsplit(url)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise URLPolicyError(f"Unsupported URL scheme: {scheme!r}")

    if not parsed.hostname:
        raise URLPolicyError("URL is missing a hostname")

    if _origin_key(parsed) in _trusted_origins():
        return

    host = parsed.hostname.lower()
    blocked_exact = {"localhost", "127.0.0.1", "::1"}
    blocked_prefixes = ("10.", "192.168.", "172.16.")

    if host in blocked_exact or host.startswith(blocked_prefixes):
        raise URLPolicyError(f"Target host {host!r} is restricted")


def fetch_webhook_preview(url: str, timeout: float = 3.0) -> str:
    """Validate `url` and return up to MAX_PREVIEW_BYTES of UTF-8 text."""
    validate_target_url(url)
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "WebhookPreviewClient/1.0"},
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read(MAX_PREVIEW_BYTES)
        return body.decode("utf-8", errors="replace")
