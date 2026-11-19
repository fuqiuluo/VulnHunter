#!/usr/bin/env python3
"""Deterministic verifier for task: py-flow-studio."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def load_app_modules(app_dir: Path):
    """Load auth, validator, and studio_service cleanly with sys.modules registered."""
    saved_path = list(sys.path)
    saved_mods = {k: sys.modules.pop(k, None) for k in ("auth", "validator", "studio_service")}
    try:
        sys.path.insert(0, str(app_dir))
        loaded = {}
        for name in ("auth", "validator", "studio_service"):
            spec = importlib.util.spec_from_file_location(name, app_dir / f"{name}.py")
            if spec is None or spec.loader is None:
                raise RuntimeError(f"Cannot load {name}.py from {app_dir}")
            mod = importlib.util.module_from_spec(spec)
            sys.modules[name] = mod
            spec.loader.exec_module(mod)
            loaded[name] = mod
        return loaded["auth"], loaded["validator"], loaded["studio_service"]
    finally:
        sys.path[:] = saved_path
        for k, prev in saved_mods.items():
            if prev is None:
                sys.modules.pop(k, None)
            else:
                sys.modules[k] = prev


def check_report(app_dir: Path) -> tuple[bool, str]:
    report_path = app_dir / "report.json"
    if not report_path.is_file():
        return False, "Missing /app/report.json"
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return False, f"Invalid JSON in report.json: {exc}"

    raw_files = data.get("files")
    if isinstance(raw_files, str):
        raw_files = [raw_files]
    elif not isinstance(raw_files, list):
        raw_file = data.get("file")
        raw_files = [raw_file] if isinstance(raw_file, str) else []
    names = {Path(str(item).strip()).name for item in raw_files if str(item).strip()}
    if not ({"auth.py", "validator.py"} <= names):
        return False, f"Expected report.json files to cover auth.py and validator.py, got {sorted(names)}"

    findings = data.get("findings")
    if not isinstance(findings, list) or len(findings) < 2:
        return False, "Expected at least 2 documented findings in report.json"
    for item in findings:
        text = str(item).strip()
        if len(text) < 12 or "placeholder" in text.lower():
            return False, f"Finding entry is empty, too brief, or a placeholder: {text!r}"

    return True, "Analysis report validated"


def check_regression_suite(app_dir: Path, orig_app: Path) -> tuple[bool, str]:
    suite_file = app_dir / "test_studio.py"
    if not suite_file.is_file():
        return False, "Missing /app/test_studio.py"

    env = os.environ.copy()
    env["PYTHONPATH"] = str(app_dir)
    env.pop("STUDIO_AUTO_SESSION", None)
    pass_run = subprocess.run(
        [sys.executable, "-m", "unittest", "discover", "-s", str(app_dir), "-p", "test_studio.py", "-v"],
        capture_output=True,
        text=True,
        env=env,
        timeout=20,
    )
    if pass_run.returncode != 0:
        return False, f"test_studio.py failed against updated modules:\n{pass_run.stderr}"

    with tempfile.TemporaryDirectory() as tmp_str:
        tmp = Path(tmp_str)
        for mod_name in ("auth.py", "validator.py", "studio_service.py"):
            shutil.copy2(orig_app / mod_name, tmp / mod_name)
        shutil.copy2(suite_file, tmp / "test_studio.py")
        env_orig = os.environ.copy()
        env_orig["PYTHONPATH"] = str(tmp)
        env_orig.pop("STUDIO_AUTO_SESSION", None)
        fail_run = subprocess.run(
            [sys.executable, "-m", "unittest", "discover", "-s", str(tmp), "-p", "test_studio.py"],
            capture_output=True,
            text=True,
            env=env_orig,
            timeout=20,
        )
        if fail_run.returncode == 0:
            return False, "test_studio.py unexpectedly passed against original unmodified modules"

    return True, "Test suite passes on updated code and fails on original unmodified code"


def check_runtime_policy(app_dir: Path) -> tuple[bool, str]:
    auth_mod, val_mod, svc_mod = load_app_modules(app_dir)
    AuthError = getattr(auth_mod, "AuthError", None)
    SessionManager = getattr(auth_mod, "SessionManager", None)
    ValidationError = getattr(val_mod, "ValidationError", None)
    inspect_operator_code = getattr(val_mod, "inspect_operator_code", None)
    StudioService = getattr(svc_mod, "StudioService", None)

    if not all([AuthError, SessionManager, ValidationError, inspect_operator_code, StudioService]):
        return False, "Required public symbols missing from auth.py / validator.py / studio_service.py"

    prev_env = os.environ.pop("STUDIO_AUTO_SESSION", None)
    try:
        # 1. Auto bootstrap must be disabled by default
        svc = StudioService()
        try:
            svc.request_bootstrap_token("127.0.0.1")
            return False, "Bootstrap token succeeded when STUDIO_AUTO_SESSION was unset"
        except AuthError:
            pass

        # 2. Even when enabled, non-loopback callers must be rejected
        os.environ["STUDIO_AUTO_SESSION"] = "true"
        for remote_host in ("203.0.113.10", "0.0.0.0", "127.0.0.1.example.com", "10.0.0.5", ""):
            try:
                svc.request_bootstrap_token(remote_host)
                return False, f"Bootstrap token unexpectedly accepted remote client_host={remote_host!r}"
            except AuthError:
                pass

        # 3. Loopback bootstrap succeeds when explicitly enabled
        boot = svc.request_bootstrap_token("127.0.0.1")
        tok = boot.get("access_token", "")
        claims = svc.sessions.verify_token(tok)
        if claims.role != "admin":
            return False, f"Expected admin role for loopback bootstrap, got {claims.role!r}"

        # 4. Regular session issuance and verification
        op_tok = svc.sessions.issue_session("operator-1", role="operator", ttl_sec=60)
        op_claims = svc.sessions.verify_token(op_tok)
        if op_claims.subject != "operator-1" or op_claims.role != "operator":
            return False, "issue_session/verify_token returned unexpected claims"
        try:
            svc.sessions.verify_token("nonexistent-token")
            return False, "verify_token accepted invalid token"
        except AuthError:
            pass

        # 5. Preflight validation must NOT execute default-arg or decorator expressions
        with tempfile.TemporaryDirectory() as tmp_str:
            m1 = Path(tmp_str) / "m1.flag"
            m2 = Path(tmp_str) / "m2.flag"
            default_arg_src = (
                f"def op_default(x=open({str(m1)!r}, 'w').write('hit')):\n"
                "    return x\n"
            )
            decorator_src = (
                f"@(lambda fn: (open({str(m2)!r}, 'w').write('hit'), fn)[1])\n"
                "def op_dec(val):\n"
                "    return val\n"
            )
            for label, src, marker in [
                ("default_arg_eval", default_arg_src, m1),
                ("decorator_eval", decorator_src, m2),
            ]:
                try:
                    inspect_operator_code(src)
                except ValidationError:
                    # Rejecting suspicious constructs statically is also acceptable if never executed
                    pass
                if marker.exists():
                    return False, f"inspect_operator_code executed untrusted code during {label}"

        # 6. Legitimate operator inspection + error cases
        valid_src = (
            "import json\n"
            "import nonexistent_pkg_vh_999\n"
            "def run_step(record, threshold=10):\n"
            "    return json.dumps({'ok': record > threshold})\n"
        )
        preflight = svc.preflight_operator(op_tok, valid_src)
        summary = preflight.get("summary") or {}
        if summary.get("functions") != {"run_step": ["record", "threshold"]}:
            return False, f"Unexpected functions metadata: {summary}"
        if "json" not in (summary.get("imports") or []):
            return False, f"Expected 'json' in imports: {summary}"
        if "nonexistent_pkg_vh_999" not in (summary.get("missing_imports") or []):
            return False, f"Expected missing import to be reported: {summary}"

        for bad_label, bad_src in [
            ("syntax_error", "def broken(:\n    pass\n"),
            ("no_function", "VALUE = 42\n"),
        ]:
            try:
                inspect_operator_code(bad_src)
                return False, f"inspect_operator_code unexpectedly accepted {bad_label}"
            except ValidationError:
                pass

    finally:
        if prev_env is not None:
            os.environ["STUDIO_AUTO_SESSION"] = prev_env
        else:
            os.environ.pop("STUDIO_AUTO_SESSION", None)

    return True, "All session auth and static preflight runtime checks passed"


def verify(app_dir: Path, tests_dir: Path) -> tuple[bool, dict[str, object]]:
    results: dict[str, object] = {}

    ok_rep, msg_rep = check_report(app_dir)
    results["report"] = {"passed": ok_rep, "message": msg_rep}
    if not ok_rep:
        return False, results

    ok_suite, msg_suite = check_regression_suite(app_dir, tests_dir / "orig_app")
    results["regression_suite"] = {"passed": ok_suite, "message": msg_suite}
    if not ok_suite:
        return False, results

    ok_pol, msg_pol = check_runtime_policy(app_dir)
    results["runtime_policy"] = {"passed": ok_pol, "message": msg_pol}
    if not ok_pol:
        return False, results

    return True, results


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
