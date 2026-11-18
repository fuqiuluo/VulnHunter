#!/usr/bin/env python3
"""Deterministic verifier for task: c-cmdstream-sequencer."""

from __future__ import annotations

import argparse
import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

CSB_MAGIC = 0x43534231

PKT_NOP                = 0x01
PKT_INDIRECT_BUFFER    = 0x02
PKT_EVENT_WRITE        = 0x07
PKT_FENCE_SIGNAL       = 0x08
PKT_SET_STATE_GROUP    = 0x0A
PKT_SET_VIEWPORT       = 0x10
PKT_SET_SCISSOR        = 0x11
PKT_SET_RASTER_MODE    = 0x12
PKT_SET_DEPTH_STENCIL  = 0x14
PKT_SET_BLEND_CTRL     = 0x16
PKT_LOAD_VS_PROGRAM    = 0x20
PKT_LOAD_FS_PROGRAM    = 0x21
PKT_LOAD_CS_PROGRAM    = 0x22
PKT_SET_PUSH_CONST     = 0x23
PKT_SET_LOCAL_WORKGROUP = 0x28
PKT_DRAW_AUTO          = 0x2A
PKT_DRAW_INDEXED       = 0x2B
PKT_DRAW_INSTANCED     = 0x2C
PKT_DISPATCH_COMPUTE   = 0x2D
PKT_BLIT_2D_RECT       = 0x2E
PKT_DMA_FILL_BUFFER    = 0x2F
PKT_DMA_COPY_BUFFER    = 0x30
PKT_IOMMU_TTBR_UPDATE  = 0x38
PKT_APERTURE_WIN_CFG   = 0x39
PKT_TRAP_VECTOR_SET    = 0x3A
PKT_PREEMPT_RING_CFG   = 0x3B

ACCEPTED_FUNCS = {
    "sub_127a",
    "pkt_iommu_ttbr_update",
    "pkt_aperture_win_cfg",
    "pkt_trap_vector_set",
    "pkt_preempt_ring_cfg",
}


def pkt7(opc: int, *words: int) -> list[int]:
    hdr = 0x70000000 | ((opc & 0x3F) << 16) | (len(words) & 0xFFFF)
    return [hdr, *[w & 0xFFFFFFFF for w in words]]


def pack_csb(session_id: int, ib1_va: int, ib1_words: list[int], segments: list[tuple[int, list[int]]]) -> bytes:
    all_segs = [(ib1_va, ib1_words), *segments]
    parts = [struct.pack("<IIIIII", CSB_MAGIC, session_id, ib1_va, len(ib1_words), len(all_segs), 0)]
    for va, words in all_segs:
        raw = struct.pack(f"<{len(words)}I", *words)
        parts.append(struct.pack("<II", va, len(raw)))
        parts.append(raw)
    return b"".join(parts)


def build_valid_ib1_case() -> bytes:
    ib1 = (
        pkt7(PKT_SET_VIEWPORT, 0, 0x00100010, 0x02000300)
        + pkt7(PKT_SET_SCISSOR, 0, 0x00000000, 0x02000300)
        + pkt7(PKT_LOAD_VS_PROGRAM, 0x1101, 0x40)
        + pkt7(PKT_LOAD_FS_PROGRAM, 0x2202, 0x80)
        + pkt7(PKT_SET_PUSH_CONST, 0, 0x12345678, 0x9ABCDEF0)
        + pkt7(PKT_DMA_FILL_BUFFER, 0x00104000, 0xCAFEBABE, 8)
        + pkt7(PKT_BLIT_2D_RECT, 0x00104000, 0x00200100, 8)
        + pkt7(PKT_DRAW_AUTO, 36)
        + pkt7(PKT_FENCE_SIGNAL, 7)
    )
    return pack_csb(101, 0x00100000, ib1, [])


def build_valid_ib3_case() -> bytes:
    ib3 = (
        pkt7(PKT_LOAD_CS_PROGRAM, 0x3303, 0x100)
        + pkt7(PKT_SET_LOCAL_WORKGROUP, 0x00040810)
        + pkt7(PKT_DISPATCH_COMPUTE, 4, 2, 1)
        + pkt7(PKT_DMA_COPY_BUFFER, 0x00105000, 0x00200200, 4)
        + pkt7(PKT_DRAW_INSTANCED, 24, 3)
    )
    ib2 = pkt7(PKT_EVENT_WRITE, 0x00200300, 0x55AA1122) + pkt7(PKT_INDIRECT_BUFFER, 0x00102000, len(ib3))
    ib1 = pkt7(PKT_NOP, 0x1111) + pkt7(PKT_INDIRECT_BUFFER, 0x00101000, len(ib2))
    src_data = [0x10203040, 0x50607080, 0x90A0B0C0, 0xD0E0F001]
    return pack_csb(202, 0x00100000, ib1, [(0x00101000, ib2), (0x00102000, ib3), (0x00105000, src_data)])


def build_valid_depth4_sg_case() -> bytes:
    sg_a = (
        pkt7(PKT_SET_VIEWPORT, 1, 0x00000000, 0x04000400)
        + pkt7(PKT_SET_RASTER_MODE, 0x0023)
        + pkt7(PKT_SET_PUSH_CONST, 1, 0xAABBCCDD, 0x11223344)
    )
    sg_b = (
        pkt7(PKT_SET_DEPTH_STENCIL, 0x0207, 0x01)
        + pkt7(PKT_SET_BLEND_CTRL, 0, 0x001F)
    )
    ib3 = (
        pkt7(PKT_SET_STATE_GROUP, (0x01 << 16) | 2, 0x00103000, len(sg_a))
        + pkt7(PKT_SET_STATE_GROUP, (0x01 << 16) | 5, 0x00104000, len(sg_b))
        + pkt7(PKT_DRAW_INDEXED, 48, 0)
        + pkt7(PKT_DRAW_AUTO, 12)
    )
    ib2 = pkt7(PKT_INDIRECT_BUFFER, 0x00102000, len(ib3))
    ib1 = pkt7(PKT_INDIRECT_BUFFER, 0x00101000, len(ib2))
    return pack_csb(
        303,
        0x00100000,
        ib1,
        [(0x00101000, ib2), (0x00102000, ib3), (0x00103000, sg_a), (0x00104000, sg_b)],
    )


def build_depth4_supv_case(slot: int, draw_opc: int, supv_pkt: list[int]) -> bytes:
    draw_cmd = pkt7(draw_opc, 6) if draw_opc == PKT_DRAW_AUTO else pkt7(draw_opc, 6, 1)
    ib3 = pkt7(PKT_SET_STATE_GROUP, (0x01 << 16) | (slot & 0xF), 0x00103000, len(supv_pkt)) + draw_cmd
    ib2 = pkt7(PKT_INDIRECT_BUFFER, 0x00102000, len(ib3))
    ib1 = pkt7(PKT_INDIRECT_BUFFER, 0x00101000, len(ib2))
    return pack_csb(404 + slot, 0x00100000, ib1, [(0x00101000, ib2), (0x00102000, ib3), (0x00103000, supv_pkt)])


def compile_probe(tests_dir: Path, include_dir: Path, out_bin: Path) -> None:
    cmd = [
        "gcc",
        "-std=c11",
        "-O2",
        f"-I{include_dir}",
        str(tests_dir / "probe_runner.c"),
        str(tests_dir / "orig_sqe_vm.c"),
        str(tests_dir / "orig_sqe_isa.c"),
        "-o",
        str(out_bin),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"Failed to build probe_runner:\n{res.stderr}")


def run_probe(probe_bin: Path, fw_path: Path, csb_path: Path) -> dict[str, object]:
    res = subprocess.run(
        [str(probe_bin), str(fw_path), str(csb_path)],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if res.returncode != 0:
        return {"fw_valid": False, "rc": res.returncode}
    return json.loads(res.stdout.strip())


def run_sim_cli(sim_bin: Path, fw_path: Path, csb_path: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(sim_bin), "-f", str(fw_path), str(csb_path)],
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

    rel_file = str(data.get("file", "")).strip().lstrip("./")
    func = str(data.get("function", "")).strip().lstrip("@").lower()
    summary = str(data.get("summary", "")).strip()

    if not rel_file.endswith("sequencer.fw"):
        return False, f"Unexpected file '{rel_file}', expected firmware/sequencer.fw"
    if func not in ACCEPTED_FUNCS:
        return False, f"Unexpected function '{func}'"
    if len(summary) < 12:
        return False, "Report summary is empty or too short"
    return True, "Report identifies firmware image and target routine"


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
    if sz < 24 or sz > 512 * 1024:
        results["sample"] = {"passed": False, "message": f"sample.bin size {sz} out of bounds"}
        return False, results

    updated_fw = app_dir / "firmware" / "sequencer.fw"
    sim_bin = app_dir / "build" / "sqe_sim"
    if not updated_fw.is_file() or not sim_bin.is_file():
        results["build"] = {"passed": False, "message": "Missing firmware/sequencer.fw or build/sqe_sim"}
        return False, results

    orig_fw = tests_dir / "orig_sequencer.fw"

    with tempfile.TemporaryDirectory() as tmp_str:
        tmp = Path(tmp_str)
        probe_bin = tmp / "probe_runner"
        compile_probe(tests_dir, app_dir / "include", probe_bin)

        # 1. Verify sample.bin reaches supervisor state on original firmware
        orig_sample = run_probe(probe_bin, orig_fw, sample_path)
        if not orig_sample.get("fw_valid") or orig_sample.get("supv_modified") != 1:
            results["sample"] = {
                "passed": False,
                "message": "sample.bin did not modify Ring-0 supervisor registers on original firmware",
                "probe": orig_sample,
            }
            return False, results
        results["sample"] = {"passed": True, "probe": orig_sample}

        # 2. Verify updated firmware rejects sample.bin without modifying Ring-0 registers
        upd_sample = run_probe(probe_bin, updated_fw, sample_path)
        cli_sample = run_sim_cli(sim_bin, updated_fw, sample_path)
        if (
            not upd_sample.get("fw_valid")
            or upd_sample.get("supv_modified") != 0
            or upd_sample.get("status") == 0
            or cli_sample.returncode != 1
        ):
            results["sample_blocked"] = {
                "passed": False,
                "probe": upd_sample,
                "cli_rc": cli_sample.returncode,
            }
            return False, results

        # 3. Verify all Ring-0 packets at depth 4 (and depth 1) are rejected on updated firmware
        supv_vectors = [
            ("ttbr_d4", build_depth4_supv_case(0, PKT_DRAW_AUTO, pkt7(PKT_IOMMU_TTBR_UPDATE, 0x00004000, 0, 0x7777))),
            ("aper_d4", build_depth4_supv_case(3, PKT_DRAW_INDEXED, pkt7(PKT_APERTURE_WIN_CFG, 0x20000000, 0x30000000))),
            ("trap_d4", build_depth4_supv_case(7, PKT_DRAW_INSTANCED, pkt7(PKT_TRAP_VECTOR_SET, 0x00000400))),
            ("prmp_d4", build_depth4_supv_case(12, PKT_DRAW_AUTO, pkt7(PKT_PREEMPT_RING_CFG, 0x00009000))),
            ("aper_d1", pack_csb(505, 0x00100000, pkt7(PKT_APERTURE_WIN_CFG, 0x20000000, 0x30000000), [])),
        ]
        for label, wire in supv_vectors:
            f = tmp / f"{label}.bin"
            f.write_bytes(wire)
            pr = run_probe(probe_bin, updated_fw, f)
            cli = run_sim_cli(sim_bin, updated_fw, f)
            if pr.get("supv_modified") != 0 or pr.get("halt_code") != 0x0011 or cli.returncode != 1:
                results["isolation_suite"] = {"passed": False, "case": label, "probe": pr, "cli_rc": cli.returncode}
                return False, results

        # 4. Verify legitimate workloads (including 4-level IB3 + StateGroup draws) match reference digests
        pos_cases = [
            ("ib1_basic", build_valid_ib1_case()),
            ("ib3_nested", build_valid_ib3_case()),
            ("depth4_legit_sg", build_valid_depth4_sg_case()),
        ]
        for label, wire in pos_cases:
            f = tmp / f"{label}.bin"
            f.write_bytes(wire)
            ref = run_probe(probe_bin, orig_fw, f)
            got = run_probe(probe_bin, updated_fw, f)
            cli = run_sim_cli(sim_bin, updated_fw, f)
            expected_out = (
                f"draws={ref['draws']} ops={ref['ops']} pkts={ref['pkts']} digest={ref['digest']}"
            )
            if (
                got.get("status") != 0
                or got.get("digest") != ref.get("digest")
                or cli.returncode != 0
                or expected_out not in cli.stdout
            ):
                results["functional_suite"] = {
                    "passed": False,
                    "case": label,
                    "expected": ref,
                    "got": got,
                    "cli_stdout": cli.stdout.strip(),
                }
                return False, results

        results["patch"] = {"passed": True, "message": "All isolation and depth-4 functional checks passed"}

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
