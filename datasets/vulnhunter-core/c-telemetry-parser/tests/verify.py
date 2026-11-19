#!/usr/bin/env python3
"""Deterministic verifier for task: c-telemetry-parser."""

from __future__ import annotations

import argparse
import json
import os
import re
import resource
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

PKT_MAGIC = 0x5648504B


def fnv1a_64(data: bytes) -> int:
    h = 14695981039346656037
    for b in data:
        h ^= b
        h = (h * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return h


def build_bundle(
    session_id: int,
    chunk_count: int,
    chunk_size: int,
    fill_byte: int = 0x42,
    magic: int = PKT_MAGIC,
    bad_seq_at: int | None = None,
    truncate_bytes: int = 0,
) -> tuple[bytes, bytes]:
    parts = [struct.pack("<IIIHH", magic, session_id, 0, chunk_count, chunk_size)]
    raw_payload = bytearray()
    for i in range(chunk_count):
        seq = (i + 7) if bad_seq_at == i else i
        chunk = bytes([((fill_byte + i) & 0xFF)]) * chunk_size
        parts.append(struct.pack("<H", seq))
        parts.append(chunk)
        raw_payload.extend(chunk)
    wire = b"".join(parts)
    if truncate_bytes > 0:
        wire = wire[:-truncate_bytes]
    return wire, bytes(raw_payload)


def supports_asan() -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        c_file = Path(tmp) / "probe.c"
        bin_file = Path(tmp) / "probe"
        c_file.write_text("int main(void){return 0;}\n", encoding="utf-8")
        res = subprocess.run(
            ["gcc", "-fsanitize=address", str(c_file), "-o", str(bin_file)],
            capture_output=True,
        )
        return res.returncode == 0


def compile_binary(parser_c: Path, cli_c: Path, include_dir: Path, out_bin: Path, use_asan: bool) -> None:
    cmd = ["gcc", "-Wall", "-Wextra", "-O1", "-g", f"-I{include_dir}"]
    if use_asan:
        cmd += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
    cmd += [str(parser_c), str(cli_c), "-o", str(out_bin)]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"Compilation failed for {parser_c}:\n{res.stderr}")


def _disable_core_dumps() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def run_cli(bin_path: Path, input_file: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "detect_leaks=0:exitcode=99:abort_on_error=0"
    env["UBSAN_OPTIONS"] = "print_stacktrace=1:exitcode=98"
    return subprocess.run(
        [str(bin_path), str(input_file)],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(bin_path.parent),
        preexec_fn=_disable_core_dumps,
        timeout=15,
    )


def did_crash(proc: subprocess.CompletedProcess[str]) -> bool:
    if proc.returncode < 0 or proc.returncode in (98, 99) or proc.returncode >= 128:
        return True
    if "AddressSanitizer" in proc.stderr or "Segmentation fault" in proc.stderr:
        return True
    return False


def check_report(app_dir: Path) -> tuple[bool, str]:
    report_path = app_dir / "report.json"
    if not report_path.is_file():
        return False, "Missing /app/report.json"
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return False, f"Invalid JSON in report.json: {exc}"

    rel_file = str(data.get("file", "")).strip().lstrip("./")
    raw_func = str(data.get("function", "")).strip()
    func_tokens = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", raw_func))
    summary = str(data.get("summary", "")).strip()

    if "pkt_parser.c" not in rel_file:
        return False, f"Unexpected file '{rel_file}', expected src/pkt_parser.c"
    if "pkt_parse_bundle" not in func_tokens:
        return False, f"Unexpected function '{raw_func}', expected pkt_parse_bundle"
    if len(summary) < 10:
        return False, "Report summary is empty or too brief"
    return True, "Report accurately identifies target file and function"


def verify(app_dir: Path, tests_dir: Path) -> tuple[bool, dict[str, object]]:
    results: dict[str, object] = {}

    ok_report, msg_report = check_report(app_dir)
    results["report"] = {"passed": ok_report, "message": msg_report}
    if not ok_report:
        return False, results

    sample_path = app_dir / "sample.bin"
    if not sample_path.is_file():
        results["sample"] = {"passed": False, "message": "Missing /app/sample.bin"}
        return False, results
    sample_size = sample_path.stat().st_size
    if sample_size == 0 or sample_size > 512 * 1024:
        results["sample"] = {"passed": False, "message": f"sample.bin size {sample_size} out of bounds (1..524288)"}
        return False, results

    use_asan = supports_asan()
    results["asan_enabled"] = use_asan

    with tempfile.TemporaryDirectory() as tmp_str:
        tmp = Path(tmp_str)
        unpatched_bin = tmp / "unpatched_cli"
        patched_bin = tmp / "patched_cli"

        # 1. Verify sample.bin triggers memory corruption on the original unpatched parser
        compile_binary(
            tests_dir / "orig_pkt_parser.c",
            app_dir / "src" / "cli.c",
            app_dir / "include",
            unpatched_bin,
            use_asan=use_asan,
        )
        unpatched_run = run_cli(unpatched_bin, sample_path)
        if not did_crash(unpatched_run):
            results["sample"] = {
                "passed": False,
                "message": f"sample.bin did not trigger failure on unpatched binary (rc={unpatched_run.returncode})",
            }
            return False, results
        results["sample"] = {
            "passed": True,
            "message": f"sample.bin triggered failure on unpatched binary (rc={unpatched_run.returncode})",
        }

        # 2. Recompile updated source from /app/src/pkt_parser.c and verify safety + correctness
        try:
            compile_binary(
                app_dir / "src" / "pkt_parser.c",
                app_dir / "src" / "cli.c",
                app_dir / "include",
                patched_bin,
                use_asan=use_asan,
            )
        except RuntimeError as exc:
            results["patch_build"] = {"passed": False, "message": str(exc)}
            return False, results

        if not (app_dir / "build" / "pkt_cli").is_file():
            results["patch_build"] = {"passed": False, "message": "Missing rebuilt /app/build/pkt_cli"}
            return False, results

        # 2a. Updated binary must NOT crash on sample.bin
        patched_sample_run = run_cli(patched_bin, sample_path)
        if did_crash(patched_sample_run) or patched_sample_run.returncode not in (0, 1):
            results["patch_sample_safety"] = {
                "passed": False,
                "message": f"Updated binary crashed or returned unexpected code on sample.bin (rc={patched_sample_run.returncode})",
            }
            return False, results

        # 2b. Functional tests (including >64 KiB payloads)
        valid_cases = [
            ("small_bundle", 101, 4, 128),
            ("boundary_64k", 202, 256, 256),
            ("large_200k", 303, 800, 256),
        ]
        for label, sid, c_cnt, c_sz in valid_cases:
            wire, raw_payload = build_bundle(sid, c_cnt, c_sz)
            case_file = tmp / f"{label}.bin"
            case_file.write_bytes(wire)
            proc = run_cli(patched_bin, case_file)
            expected_line = f"OK session={sid} bytes={len(raw_payload)} fnv1a={fnv1a_64(raw_payload):016x}"
            if did_crash(proc) or proc.returncode != 0 or expected_line not in proc.stdout:
                results["patch_functional"] = {
                    "passed": False,
                    "case": label,
                    "expected": expected_line,
                    "stdout": proc.stdout.strip(),
                    "rc": proc.returncode,
                }
                return False, results

        # 2c. Negative / malformed tests must return exit code 1 cleanly without crashing
        bad_cases = [
            ("bad_magic", build_bundle(1, 2, 32, magic=0xDEADBEEF)[0]),
            ("bad_seq", build_bundle(1, 8, 64, bad_seq_at=3)[0]),
            ("truncated", build_bundle(1, 16, 128, truncate_bytes=20)[0]),
            ("exceed_max_payload", struct.pack("<IIIHH", PKT_MAGIC, 1, 0, 1024, 2048)),
        ]
        for label, wire in bad_cases:
            case_file = tmp / f"bad_{label}.bin"
            case_file.write_bytes(wire)
            proc = run_cli(patched_bin, case_file)
            if did_crash(proc) or proc.returncode != 1:
                results["patch_negative"] = {
                    "passed": False,
                    "case": label,
                    "rc": proc.returncode,
                }
                return False, results

        results["patch"] = {"passed": True, "message": "All safety, boundary (>64 KiB), and negative checks passed"}

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
