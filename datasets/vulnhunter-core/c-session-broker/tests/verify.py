#!/usr/bin/env python3
"""Deterministic verifier for task: c-session-broker."""

from __future__ import annotations

import argparse
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

SB_WIRE_MAGIC = 0x5342524B
SB_CTL_ESC = 0xFE
SB_CTL_SUB_BEGIN = 0xF0
SB_CTL_SUB_END = 0xF1
SB_OPT_TERM_TYPE = 0x18
SB_OPT_SESSION_ENV = 0x27

ACCEPTED_FILES = {
    "template.c",
    "negotiator.c",
    "dispatcher.c",
    "cli.c",
    "session_broker.h",
}
ACCEPTED_FUNCS = {
    "sb_expand_invocation",
    "sb_lookup_short_var",
    "sb_negotiate_stream",
    "sb_parse_env_suboption",
    "sb_split_argv",
    "sb_dispatch_login",
    "main",
}


def encode_subopt(opt: int, payload: bytes) -> bytes:
    escaped = bytearray()
    for b in payload:
        escaped.append(b)
        if b == SB_CTL_ESC:
            escaped.append(SB_CTL_ESC)
    return bytes([SB_CTL_ESC, SB_CTL_SUB_BEGIN, opt]) + bytes(escaped) + bytes([SB_CTL_ESC, SB_CTL_SUB_END])


def build_handshake(
    session_id: int,
    env_vars: list[tuple[str, str]] | None = None,
    term_type: str | None = None,
    magic: int = SB_WIRE_MAGIC,
) -> bytes:
    parts = [struct.pack("<IIII", magic, session_id, 0, 0)]
    if term_type is not None:
        parts.append(encode_subopt(SB_OPT_TERM_TYPE, term_type.encode("latin-1")))
    if env_vars:
        env_blob = bytearray()
        for k, v in env_vars:
            env_blob.append(0x00)
            env_blob.extend(k.encode("latin-1"))
            env_blob.append(0x01)
            env_blob.extend(v.encode("latin-1"))
        parts.append(encode_subopt(SB_OPT_SESSION_ENV, bytes(env_blob)))
    return b"".join(parts)


def compile_broker(src_dir: Path, include_dir: Path, out_bin: Path) -> None:
    cmd = [
        "gcc",
        "-std=c11",
        "-Wall",
        "-Wextra",
        "-O2",
        f"-I{include_dir}",
        str(src_dir / "negotiator.c"),
        str(src_dir / "template.c"),
        str(src_dir / "dispatcher.c"),
        str(src_dir / "cli.c"),
        "-o",
        str(out_bin),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"Compilation failed for {src_dir}:\n{res.stderr}")


def run_broker(bin_path: Path, sample_file: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(bin_path), str(sample_file)],
        capture_output=True,
        text=True,
        timeout=15,
    )


def check_report(app_dir: Path) -> tuple[bool, str]:
    report_path = app_dir / "report.json"
    if not report_path.is_file():
        return False, "Missing /app/report.json"
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return False, f"Invalid JSON in report.json: {exc}"

    raw_file = str(data.get("file", "")).strip()
    file_tokens = {Path(tok).name for tok in re.findall(r"[\w./-]+\.[A-Za-z0-9]+", raw_file)}
    raw_func = str(data.get("function", "")).strip()
    func_tokens = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", raw_func))
    summary = str(data.get("summary", "")).strip()

    if not (file_tokens & ACCEPTED_FILES):
        return False, f"Unexpected file '{raw_file}', expected one of {sorted(ACCEPTED_FILES)}"
    if not (func_tokens & ACCEPTED_FUNCS):
        return False, f"Unexpected function '{raw_func}', expected one of {sorted(ACCEPTED_FUNCS)}"
    if len(summary) < 12 or "placeholder" in summary.lower():
        return False, "Report summary is empty, too brief, or still a placeholder"
    return True, "Report accurately identifies target file and function"


def verify(app_dir: Path, tests_dir: Path) -> tuple[bool, dict[str, object]]:
    results: dict[str, object] = {}

    ok_rep, msg_rep = check_report(app_dir)
    results["report"] = {"passed": ok_rep, "message": msg_rep}
    if not ok_rep:
        return False, results

    sample_path = app_dir / "sample.bin"
    if not sample_path.is_file():
        results["sample"] = {"passed": False, "message": "Missing /app/sample.bin"}
        return False, results
    sz = sample_path.stat().st_size
    if sz == 0 or sz > 512 * 1024:
        results["sample"] = {"passed": False, "message": f"sample.bin size {sz} out of bounds (1..524288)"}
        return False, results

    if not (app_dir / "build" / "broker_cli").is_file():
        results["build"] = {"passed": False, "message": "Missing rebuilt /app/build/broker_cli"}
        return False, results

    orig_app = tests_dir / "orig_app"

    with tempfile.TemporaryDirectory() as tmp_str:
        tmp = Path(tmp_str)
        orig_bin = tmp / "orig_broker_cli"
        patched_bin = tmp / "patched_broker_cli"

        compile_broker(orig_app / "src", orig_app / "include", orig_bin)

        # 1. Verify sample.bin triggers unauthorized preauth or admin privilege on original broker
        orig_run = run_broker(orig_bin, sample_path)
        unauthorized_orig = (
            orig_run.returncode == 0
            and ("preauth=1" in orig_run.stdout or "role=admin" in orig_run.stdout or "principal=root" in orig_run.stdout)
        )
        if not unauthorized_orig:
            results["sample"] = {
                "passed": False,
                "message": f"sample.bin did not demonstrate unauthorized preauth/admin session on original broker (rc={orig_run.returncode}, out={orig_run.stdout.strip()!r})",
            }
            return False, results
        results["sample"] = {
            "passed": True,
            "message": f"sample.bin triggered unauthorized session on original broker: {orig_run.stdout.strip()}",
        }

        # 2. Recompile patched broker and verify public API signatures remain intact
        try:
            compile_broker(app_dir / "src", app_dir / "include", patched_bin)
        except RuntimeError as exc:
            results["patch_build"] = {"passed": False, "message": str(exc)}
            return False, results

        # 3. Updated broker must reject sample.bin (and never emit preauth=1 or role=admin)
        patched_sample = run_broker(patched_bin, sample_path)
        if (
            patched_sample.returncode != 1
            or "preauth=1" in patched_sample.stdout
            or "role=admin" in patched_sample.stdout
        ):
            results["patch_sample"] = {
                "passed": False,
                "message": f"Updated broker did not reject sample.bin cleanly (rc={patched_sample.returncode}, out={patched_sample.stdout.strip()!r})",
            }
            return False, results
        results["patch_sample"] = {"passed": True, "message": "Updated broker rejected sample.bin cleanly"}

        # 4. Functional regression tests
        func_cases = [
            (
                "default_guest",
                build_handshake(101),
                0,
                "OK session=101 principal=guest role=standard preauth=0",
            ),
            (
                "valid_operator_with_ticket",
                build_handshake(102, env_vars=[("USER", "alice"), ("TICKET", "valid-session-ticket")], term_type="xterm-256color"),
                0,
                "OK session=102 principal=alice role=standard preauth=0",
            ),
            (
                "operator_missing_ticket",
                build_handshake(103, env_vars=[("USER", "alice")]),
                1,
                "",
            ),
            (
                "root_even_with_ticket",
                build_handshake(104, env_vars=[("USER", "root"), ("TICKET", "valid-session-ticket")]),
                1,
                "",
            ),
        ]
        for label, blob, exp_rc, exp_out in func_cases:
            f_in = tmp / f"{label}.bin"
            f_in.write_bytes(blob)
            proc = run_broker(patched_bin, f_in)
            if proc.returncode != exp_rc or (exp_out and exp_out not in proc.stdout):
                results["functional"] = {
                    "passed": False,
                    "message": f"Case '{label}' failed (rc={proc.returncode}, expected {exp_rc}, out={proc.stdout.strip()!r})",
                }
                return False, results
        results["functional"] = {"passed": True, "message": "All legitimate guest/operator/rejection checks passed"}

        # 5. Adversarial option-injection regression matrix
        adversarial = [
            ("user_dash_f_root", build_handshake(201, env_vars=[("USER", "-f root")])),
            ("user_dash_f_alice", build_handshake(202, env_vars=[("USER", "-f alice")])),
            ("user_leading_dash", build_handshake(203, env_vars=[("USER", "-froot")])),
            ("user_quoted_flag", build_handshake(204, env_vars=[("USER", "'-f' root")])),
            ("user_multi_space", build_handshake(205, env_vars=[("USER", "  -f   root")])),
            ("term_inject_flag", build_handshake(206, term_type="vt220 -f root")),
            ("term_leading_dash", build_handshake(207, term_type="-f")),
            ("bad_magic", build_handshake(208, magic=0xDEADBEEF)),
        ]
        for label, blob in adversarial:
            f_bad = tmp / f"adv_{label}.bin"
            f_bad.write_bytes(blob)
            proc = run_broker(patched_bin, f_bad)
            if proc.returncode != 1 or "preauth=1" in proc.stdout or "role=admin" in proc.stdout:
                results["adversarial"] = {
                    "passed": False,
                    "message": f"Adversarial case '{label}' was not rejected (rc={proc.returncode}, out={proc.stdout.strip()!r})",
                }
                return False, results
        results["adversarial"] = {"passed": True, "message": "All option-injection and malformed handshake tests cleanly rejected"}

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
