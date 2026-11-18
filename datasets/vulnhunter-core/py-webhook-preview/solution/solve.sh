#!/usr/bin/env bash
set -euo pipefail

APP_DIR="${APP_DIR:-/app}"
cd "$APP_DIR"

cat > "$APP_DIR/report.json" <<'EOF'
{
  "file": "webhook_service.py",
  "findings": [
    "validate_target_url only checks incomplete string prefixes instead of resolving addresses and verifying ip_address.is_global",
    "fetch_webhook_preview follows HTTP redirects automatically without re-validating redirect target URLs"
  ]
}
EOF

cat > "$APP_DIR/webhook_service.py" <<'PY'
"""Outbound webhook preview client."""

from __future__ import annotations

import ipaddress
import os
import socket
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
    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise URLPolicyError("Invalid port in URL") from exc
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{scheme}://{host}:{port}"


def _is_permitted_ip(addr_str: str) -> bool:
    ip_obj = ipaddress.ip_address(addr_str)
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        ip_obj = ip_obj.ipv4_mapped
    return (
        ip_obj.is_global
        and not ip_obj.is_loopback
        and not ip_obj.is_private
        and not ip_obj.is_link_local
        and not ip_obj.is_multicast
        and not ip_obj.is_reserved
        and not ip_obj.is_unspecified
    )


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

    host = parsed.hostname
    port = parsed.port or (443 if scheme == "https" else 80)

    try:
        ip_lit = ipaddress.ip_address(host)
    except ValueError:
        ip_lit = None

    if ip_lit is not None:
        if not _is_permitted_ip(str(ip_lit)):
            raise URLPolicyError(f"Non-global IP address blocked: {host!r}")
        return

    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise URLPolicyError(f"Unable to resolve hostname {host!r}") from exc

    if not infos:
        raise URLPolicyError(f"No network addresses resolved for {host!r}")

    for family, _, _, _, sockaddr in infos:
        if family in (socket.AF_INET, socket.AF_INET6):
            resolved_ip = sockaddr[0].split("%", 1)[0]
            if not _is_permitted_ip(resolved_ip):
                raise URLPolicyError(f"Resolved non-global IP blocked: {resolved_ip}")


class _ValidatedRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        resolved_target = urllib.parse.urljoin(req.full_url, newurl)
        validate_target_url(resolved_target)
        return super().redirect_request(req, fp, code, msg, headers, resolved_target)


def fetch_webhook_preview(url: str, timeout: float = 3.0) -> str:
    """Validate `url` (and all redirects) and return up to MAX_PREVIEW_BYTES of text."""
    validate_target_url(url)
    opener = urllib.request.build_opener(_ValidatedRedirectHandler())
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "WebhookPreviewClient/1.0"},
        method="GET",
    )
    with opener.open(req, timeout=timeout) as resp:
        body = resp.read(MAX_PREVIEW_BYTES)
        return body.decode("utf-8", errors="replace")
PY

cat > "$APP_DIR/test_webhook.py" <<'PY'
import http.server
import os
import threading
import unittest

import webhook_service


class _SilentHandler(http.server.BaseHTTPRequestHandler):
    redirect_to = ""

    def do_GET(self):
        if self.path == "/bounce":
            self.send_response(302)
            self.send_header("Location", self.redirect_to)
            self.end_headers()
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"preview-ok")

    def log_message(self, fmt, *args):
        pass


class WebhookPolicyTests(unittest.TestCase):
    def test_blocks_non_global_addresses(self):
        os.environ["WEBHOOK_TRUSTED_ORIGINS"] = ""
        for bad_url in (
            "http://127.0.0.2:8080/status",
            "http://0.0.0.0:8080/status",
            "http://169.254.169.254/metadata",
            "http://172.31.0.5/internal",
            "http://[::ffff:127.0.0.1]:8080/status",
        ):
            with self.subTest(url=bad_url):
                with self.assertRaises(webhook_service.URLPolicyError):
                    webhook_service.validate_target_url(bad_url)

    def test_allows_global_public_ip(self):
        os.environ["WEBHOOK_TRUSTED_ORIGINS"] = ""
        webhook_service.validate_target_url("https://93.184.216.34/webhook")

    def test_blocks_redirect_to_untrusted_loopback(self):
        internal_srv = http.server.HTTPServer(("127.0.0.1", 0), _SilentHandler)
        relay_srv = http.server.HTTPServer(("127.0.0.1", 0), _SilentHandler)
        int_port = internal_srv.server_port
        relay_port = relay_srv.server_port
        _SilentHandler.redirect_to = f"http://127.0.0.1:{int_port}/secret"

        t1 = threading.Thread(target=internal_srv.serve_forever, daemon=True)
        t2 = threading.Thread(target=relay_srv.serve_forever, daemon=True)
        t1.start()
        t2.start()
        try:
            os.environ["WEBHOOK_TRUSTED_ORIGINS"] = f"http://127.0.0.1:{relay_port}"
            self.assertEqual(
                webhook_service.fetch_webhook_preview(f"http://127.0.0.1:{relay_port}/ok"),
                "preview-ok",
            )
            with self.assertRaises(webhook_service.URLPolicyError):
                webhook_service.fetch_webhook_preview(f"http://127.0.0.1:{relay_port}/bounce")
        finally:
            os.environ["WEBHOOK_TRUSTED_ORIGINS"] = ""
            relay_srv.shutdown()
            internal_srv.shutdown()
            relay_srv.server_close()
            internal_srv.server_close()


if __name__ == "__main__":
    unittest.main()
PY
