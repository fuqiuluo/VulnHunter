#!/usr/bin/env python3
"""Deterministic and multi-threaded verifier for task: c-vm-mmu."""

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

VMM_TRACE_MAGIC = 0x314D4D56

VMM_SLOT_READ   = 1 << 0
VMM_SLOT_WRITE  = 1 << 1
VMM_SLOT_EXEC   = 1 << 2
VMM_SLOT_COW    = 1 << 3
VMM_SLOT_BACKED = 1 << 4

VMM_OP_GUEST_LOAD     = 0x01
VMM_OP_GUEST_STORE    = 0x02
VMM_OP_HOST_DMA_WRITE = 0x03
VMM_OP_HOST_PATCH     = 0x04
VMM_OP_BALLOON_ZAP    = 0x05
VMM_OP_PROTECT_SLOT   = 0x06

VMM_CMD_ALLOW_FAULT   = 0x01

ACCEPTED_FILES = {"vmm_pin.c", "vmm_fault.c"}
ACCEPTED_FUNCS = {
    "populate_s2_leaf",
    "walk_s2_leaf",
    "pin_single_gpa",
    "vmm_pin_gpa_pages",
    "vmm_host_write_gpa",
    "vmm_resolve_s2_fault",
}


def pack_trace(seed: int, slots: list[tuple], workers: list[tuple]) -> bytes:
    parts = [struct.pack("<IIHHIQ", VMM_TRACE_MAGIC, seed, len(slots), len(workers), 0, 0)]
    for sid, flags, base_gpa, npages, img_base in slots:
        parts.append(struct.pack("<IIQII", sid, flags, base_gpa, npages, img_base))
    for wid, repeat, cmds in workers:
        parts.append(struct.pack("<IIII", wid, repeat, len(cmds), 0))
        for opc, cflags, clen, aux, gpa, pat in cmds:
            parts.append(struct.pack("<BBHIQQ", opc, cflags, clen, aux, gpa, pat))
    return b"".join(parts)


def build_deterministic_cli_case() -> bytes:
    slots = [
        (0, VMM_SLOT_READ | VMM_SLOT_EXEC | VMM_SLOT_COW | VMM_SLOT_BACKED, 0x10000, 4, 2),
        (1, VMM_SLOT_READ | VMM_SLOT_WRITE | VMM_SLOT_COW | VMM_SLOT_BACKED, 0x20000, 4, 12),
        (2, VMM_SLOT_READ | VMM_SLOT_WRITE | VMM_SLOT_BACKED, 0x30000, 2, 96),
    ]
    cmds = [
        (VMM_OP_GUEST_LOAD, 0, 128, 0, 0x10000, 0),
        (VMM_OP_HOST_PATCH, 0, 64, 0, 0x10040, 0xCAFEBABE11223344),
        (VMM_OP_GUEST_STORE, VMM_CMD_ALLOW_FAULT, 32, 0, 0x10040, 0xBAD0BAD0BAD0BAD0),
        (VMM_OP_GUEST_STORE, 0, 256, 0, 0x20100, 0x0102030405060708),
        (VMM_OP_HOST_DMA_WRITE, 0, 128, 0, 0x21000, 0x8877665544332211),
        (VMM_OP_BALLOON_ZAP, 0, 1, 0, 0x21000, 0),
        (VMM_OP_PROTECT_SLOT, 0, 0, 1, 0, VMM_SLOT_READ),
        (VMM_OP_GUEST_STORE, VMM_CMD_ALLOW_FAULT, 16, 0, 0x20100, 0x9999999999999999),
        (VMM_OP_GUEST_STORE, 0, 64, 0, 0x30000, 0x55AA55AA55AA55AA),
    ]
    return pack_trace(0x20260419, slots, [(0, 1, cmds)])


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
    if len(summary) < 15:
        return False, "Report summary is empty or too brief"
    return True, "Report identifies target MMU source file and routine"


def build_orig_probe(tests_dir: Path, out_dir: Path) -> Path:
    orig_app = tests_dir / "orig_app"
    src_files = [
        orig_app / "src" / "vmm_phys.c",
        orig_app / "src" / "vmm_image.c",
        orig_app / "src" / "vmm_tlb.c",
        orig_app / "src" / "vmm_mmu.c",
        orig_app / "src" / "vmm_fault.c",
        orig_app / "src" / "vmm_pin.c",
        orig_app / "src" / "vmm_trace.c",
    ]
    probe_bin = out_dir / "orig_probe"
    cmd = [
        "gcc",
        "-std=c11",
        "-O2",
        "-pthread",
        "-D_POSIX_C_SOURCE=200809L",
        f"-I{orig_app / 'include'}",
        str(tests_dir / "probe_runner.c"),
        *[str(s) for s in src_files],
        "-Wl,--wrap=vmm_resolve_s2_fault",
        "-o",
        str(probe_bin),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"Failed to compile orig_probe:\n{res.stderr}")
    return probe_bin


def build_updated_probe(tests_dir: Path, app_dir: Path, out_dir: Path) -> Path:
    lib_a = app_dir / "build" / "libvmmmu.a"
    probe_bin = out_dir / "upd_probe"
    cmd = [
        "gcc",
        "-std=c11",
        "-O2",
        "-pthread",
        "-D_POSIX_C_SOURCE=200809L",
        f"-I{app_dir / 'include'}",
        str(tests_dir / "probe_runner.c"),
        str(lib_a),
        "-Wl,--wrap=vmm_resolve_s2_fault",
        "-o",
        str(probe_bin),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"Failed to link upd_probe against {lib_a}:\n{res.stderr}")
    return probe_bin


def run_json_cmd(cmd: list[str], timeout: float = 30.0) -> dict[str, object]:
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    if res.returncode != 0:
        return {"rc": res.returncode, "stderr": res.stderr.strip()}
    return json.loads(res.stdout.strip())


def verify(app_dir: Path, tests_dir: Path) -> tuple[bool, dict[str, object]]:
    results: dict[str, object] = {}

    ok_rep, msg_rep = check_report(app_dir)
    results["report"] = {"passed": ok_rep, "message": msg_rep}
    if not ok_rep:
        return False, results

    # Rebuild /app via make to ensure source changes match binary artifacts
    build_res = subprocess.run(["make", "-C", str(app_dir), "all"], capture_output=True, text=True)
    if build_res.returncode != 0:
        results["build"] = {"passed": False, "message": build_res.stderr.strip()}
        return False, results

    lib_a = app_dir / "build" / "libvmmmu.a"
    cli_bin = app_dir / "build" / "mmu_cli"
    if not lib_a.is_file() or not cli_bin.is_file():
        results["build"] = {"passed": False, "message": "Missing build/libvmmmu.a or build/mmu_cli"}
        return False, results

    with tempfile.TemporaryDirectory() as tmp_str:
        tmp = Path(tmp_str)
        orig_probe = build_orig_probe(tests_dir, tmp)
        try:
            upd_probe = build_updated_probe(tests_dir, app_dir, tmp)
        except Exception as exc:
            results["build"] = {"passed": False, "message": str(exc)}
            return False, results

        # 1. Run deterministic 2-way & 3-way hooked interleavings + 4-thread stress + functional invariants
        audit_res = run_json_cmd([str(upd_probe), "audit"], timeout=35.0)
        if not audit_res.get("passed"):
            results["audit_suite"] = audit_res
            return False, results
        results["audit_suite"] = audit_res

        # 2. Verify CLI compatibility on deterministic functional trace against reference digest
        det_file = tmp / "det.bin"
        det_file.write_bytes(build_deterministic_cli_case())
        ref_det = run_json_cmd([str(orig_probe), "trace", str(det_file)], timeout=15.0)
        got_det = run_json_cmd([str(upd_probe), "trace", str(det_file)], timeout=15.0)
        cli_det = subprocess.run([str(cli_bin), str(det_file)], capture_output=True, text=True, timeout=15.0)

        exp_frag = f"guest_digest={ref_det['guest_digest']} img_digest={ref_det['baseline_ro_digest']}"
        if (
            got_det.get("status") != 0
            or got_det.get("ro_corrupted") != 0
            or got_det.get("guest_digest") != ref_det.get("guest_digest")
            or cli_det.returncode != 0
            or exp_frag not in cli_det.stdout
        ):
            results["cli_regression"] = {
                "passed": False,
                "expected": ref_det,
                "got": got_det,
                "cli_stdout": cli_det.stdout.strip(),
            }
            return False, results

        results["cli_regression"] = {"passed": True}

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
