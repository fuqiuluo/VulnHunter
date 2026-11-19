#!/usr/bin/env python3
"""Deterministic verifier for task: py-webhook-preview."""

from __future__ import annotations

import argparse
import http.server
import importlib.util
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
from pathlib import Path


def load_module(mod_name: str, file_path: Path):
    spec = importlib.util.spec_from_file_location(mod_name, file_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Cannot load module from {file_path}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[mod_name] = mod
    spec.loader.exec_module(mod)
    return mod


def check_report(app_dir: Path) -> tuple[bool, str]:
    report_path = app_dir / "report.json"
    if not report_path.is_file():
        return False, "Missing /app/report.json"
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return False, f"Invalid JSON in report.json: {exc}"

    rel_file = str(data.get("file", "")).strip().lstrip("./")
    findings = data.get("findings") or []
    if not rel_file.endswith("webhook_service.py"):
        return False, f"Expected file webhook_service.py, got {rel_file!r}"
    if not isinstance(findings, list) or len(findings) < 2:
        return False, "Expected at least 2 documented findings in report.json"
    return True, "Analysis report validated"


def check_regression_suite(app_dir: Path, orig_service: Path) -> tuple[bool, str]:
    suite_file = app_dir / "test_webhook.py"
    if not suite_file.is_file():
        return False, "Missing /app/test_webhook.py"

    env = os.environ.copy()
    env["PYTHONPATH"] = str(app_dir)
    pass_run = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", str(app_dir), "-p", "test_webhook.py", "-v"],
        capture_output=True,
        text=True,
        env=env,
        timeout=20,
    )
    if pass_run.returncode != 0:
        return False, f"test_webhook.py failed against updated service:\n{pass_run.stderr}"

    with tempfile.TemporaryDirectory() as tmp_str:
        tmp = Path(tmp_str)
        shutil.copy2(orig_service, tmp / "webhook_service.py")
        shutil.copy2(suite_file, tmp / "test_webhook.py")
        env_orig = os.environ.copy()
        env_orig["PYTHONPATH"] = str(tmp)
        fail_run = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", str(tmp), "-p", "test_webhook.py"],
            capture_output=True,
            text=True,
            env=env_orig,
            timeout=20,
        )
        if fail_run.returncode == 0:
            return False, "test_webhook.py unexpectedly passed on original unmodified webhook_service.py"

    return True, "Test suite passes on updated code and catches issues on original code"


def check_runtime_policy(app_dir: Path) -> tuple[bool, str]:
    ws = load_module("updated_webhook_service", app_dir / "webhook_service.py")
    blocked_exc = getattr(ws, "URLPolicyError", None)
    if blocked_exc is None:
        return False, "URLPolicyError missing from webhook_service.py"

    os.environ["WEBHOOK_TRUSTED_ORIGINS"] = ""

    for pub_url in ("https://93.184.216.34/hook", "http://1.1.1.1:8080/ping"):
        try:
            ws.validate_target_url(pub_url)
        except Exception as exc:
            return False, f"Public URL {pub_url} was unexpectedly rejected: {exc}"

    restricted_urls = [
        "file:///etc/hostname",
        "gopher://127.0.0.1:6379/_INFO",
        "http://127.0.0.1:8080/admin",
        "http://127.0.0.2:8080/admin",
        "http://0.0.0.0:8080/admin",
        "http://[::1]:8080/admin",
        "http://[::ffff:127.0.0.1]:8080/admin",
        "http://169.254.169.254/latest/meta-data/",
        "http://10.10.1.5/internal",
        "http://172.31.16.8/internal",
        "http://192.168.1.1/internal",
    ]
    for bad_url in restricted_urls:
        try:
            ws.validate_target_url(bad_url)
            return False, f"Restricted URL {bad_url} was NOT blocked by validate_target_url"
        except blocked_exc:
            pass
        except Exception as exc:
            return False, f"Restricted URL {bad_url} raised {type(exc).__name__} instead of URLPolicyError"

    live_token = secrets.token_hex(16)
    internal_hits = {"count": 0}

    class InternalHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            internal_hits["count"] += 1
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"INTERNAL_SENSITIVE_DATA")

        def log_message(self, fmt, *args):
            pass

    internal_srv = http.server.HTTPServer(("127.0.0.1", 0), InternalHandler)
    int_port = internal_srv.server_port

    class PartnerRelayHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/direct":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(f"PARTNER_OK:{live_token}".encode("utf-8"))
            elif self.path == "/hop-allowed":
                self.send_response(302)
                self.send_header("Location", "/direct")
                self.end_headers()
            elif self.path == "/hop-internal":
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{int_port}/secret")
                self.end_headers()
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, fmt, *args):
            pass

    relay_srv = http.server.HTTPServer(("127.0.0.1", 0), PartnerRelayHandler)
    relay_port = relay_srv.server_port

    t_int = threading.Thread(target=internal_srv.serve_forever, daemon=True)
    t_rel = threading.Thread(target=relay_srv.serve_forever, daemon=True)
    t_int.start()
    t_rel.start()

    try:
        os.environ["WEBHOOK_TRUSTED_ORIGINS"] = f"http://127.0.0.1:{relay_port}"

        direct_body = ws.fetch_webhook_preview(f"http://127.0.0.1:{relay_port}/direct")
        if direct_body != f"PARTNER_OK:{live_token}":
            return False, f"Unexpected direct preview response: {direct_body!r}"

        hop_ok_body = ws.fetch_webhook_preview(f"http://127.0.0.1:{relay_port}/hop-allowed")
        if hop_ok_body != f"PARTNER_OK:{live_token}":
            return False, f"Allowed same-origin redirect failed: {hop_ok_body!r}"

        try:
            ws.fetch_webhook_preview(f"http://127.0.0.1:{relay_port}/hop-internal")
            return False, "Redirect from trusted origin to untrusted loopback port was NOT blocked"
        except blocked_exc:
            pass

        if internal_hits["count"] > 0:
            return False, "Untrusted internal server received an HTTP request despite policy check"
    finally:
        os.environ["WEBHOOK_TRUSTED_ORIGINS"] = ""
        relay_srv.shutdown()
        internal_srv.shutdown()
        relay_srv.server_close()
        internal_srv.server_close()

    return True, "All IP canonicalization, scheme, trusted-origin, and redirect checks passed"


def verify(app_dir: Path, tests_dir: Path) -> tuple[bool, dict[str, object]]:
    details: dict[str, object] = {}

    ok_rep, msg_rep = check_report(app_dir)
    details["report"] = {"passed": ok_rep, "message": msg_rep}
    if not ok_rep:
        return False, details

    ok_pol, msg_pol = check_runtime_policy(app_dir)
    details["runtime_policy"] = {"passed": ok_pol, "message": msg_pol}
    if not ok_pol:
        return False, details

    ok_reg, msg_reg = check_regression_suite(app_dir, tests_dir / "orig_webhook_service.py")
    details["regression_suite"] = {"passed": ok_reg, "message": msg_reg}
    if not ok_reg:
        return False, details

    return True, details


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--app-dir", default=os.environ.get("APP_DIR", "/app"))
    parser.add_argument("--reward-dir", default=os.environ.get("REWARD_DIR", "/logs/verifier"))
    args = parser.parse_args()

    app_dir = Path(args.app_dir).resolve()
    tests_dir = Path(__file__).resolve().parent
    reward_dir = Path(args.reward_dir)
    reward_dir.mkdir(parents=True, exist_ok=True)

    passed, details = verify(app_dir, tests_dir)
    (reward_dir / "details.json").write_text(json.dumps(details, indent=2), encoding="utf-8")
    print(json.dumps({"passed": passed, "details": details}, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
