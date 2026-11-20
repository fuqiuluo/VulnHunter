#!/usr/bin/env python3
"""Deterministic verifier for task: py-wasm-aot-validator."""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

CORE_FILES = {"validator.py", "binary_decoder.py", "executor.py", "linker.py"}

HIDDEN_UNITTEST = r'''
import unittest

from wasm_sandbox import (
    DecodeError,
    FuncRefHandle,
    FuncType,
    HostFunc,
    Limits,
    LinkError,
    Linker,
    MemoryInstance,
    ModuleBuilder,
    TableInstance,
    TrapError,
    ValType,
    ValidationError,
    decode_module,
    validate_module,
)
from wasm_sandbox.types import TableType


class HiddenWasmSoundnessSuite(unittest.TestCase):
    def test_01_functional_parity_loops_blocks_and_multi_module(self) -> None:
        # Valid block-param loop (`loop (param i32) (result i32)`) + valid inner polymorphic unreachable
        mb = ModuleBuilder()
        t_step = mb.add_type([ValType.I32], [ValType.I32])
        mb.add_func(
            t_step,
            [(1, ValType.I32)],
            [
                ("i32.const", 0),
                ("local.set", 1),
                ("local.get", 0),
                ("loop", t_step),  # consumes 1 i32 param, label expects 1 i32!
                ("local.tee", 0),
                ("i32.eqz",),
                ("if", None),
                ("local.get", 1),
                ("return",),
                # Polymorphic unreachable ops strictly within this `if` frame
                ("i64.const", 123),
                ("drop",),
                ("end",),
                ("local.get", 1),
                ("local.get", 0),
                ("i32.add",),
                ("local.set", 1),
                ("local.get", 0),
                ("i32.const", 1),
                ("i32.sub",),
                ("br", 0),  # passes 1 i32 back to loop header!
                ("end",),
            ],
            export_as="sum_to",
        )
        inst = Linker().instantiate(decode_module(mb.to_bytes()))
        self.assertEqual(inst.invoke("sum_to", [0]), 0)
        self.assertEqual(inst.invoke("sum_to", [10]), 55)

        # Valid single-sided `if (param i32) (result i32)` (since params == results!)
        mb2 = ModuleBuilder()
        t_id = mb2.add_type([ValType.I32, ValType.I32], [ValType.I32])
        t_step2 = mb2.add_type([ValType.I32], [ValType.I32])
        mb2.add_func(
            t_id,
            [],
            [
                ("local.get", 0),
                ("local.get", 1),
                ("if", t_step2),
                ("i32.const", 100),
                ("i32.add",),
                ("end",),
            ],
            export_as="cond_bump",
        )
        inst2 = Linker().instantiate(decode_module(mb2.to_bytes()))
        self.assertEqual(inst2.invoke("cond_bump", [7, 0]), 7)
        self.assertEqual(inst2.invoke("cond_bump", [7, 1]), 107)

        # Valid canonical 5-byte LEB128 boundary values (`0xFFFFFFFF` u32, `-1` and `-0x80000000` s32)
        mb3 = ModuleBuilder()
        t_c = mb3.add_type([], [ValType.I32])
        mb3.add_func(
            t_c,
            [],
            [
                ("i32.const", -0x80000000),
                ("i32.const", 0x7FFFFFFF),
                ("i32.add",),
            ],
            export_as="limits_sum",
        )
        inst3 = Linker().instantiate(decode_module(mb3.to_bytes()))
        self.assertEqual(inst3.invoke("limits_sum", []), -1)

    def test_02_defect1_polymorphic_frame_floor_and_one_armed_if(self) -> None:
        # 1A: Inner `block [] -> []` executes `unreachable; drop` while outer stack holds an `i64`!
        # Must NOT pop the outer `i64` below `frame.start_height`!
        mb_escape = ModuleBuilder()
        t_void_i32 = mb_escape.add_type([], [ValType.I32])
        mb_escape.add_func(
            t_void_i32,
            [],
            [
                ("i64.const", 999),
                ("i32.const", 7),
                ("block", None),
                ("unreachable",),
                ("drop",),
                ("drop",),
                ("end",),
            ],
            export_as="bad_floor",
        )
        with self.assertRaises(ValidationError, msg="Unreachable inner block popped outer operand stack!"):
            validate_module(decode_module(mb_escape.to_bytes()))

        # 1B: Single-sided `if` without `else` producing `[i64]` from `[]`
        mb_if_no_else = ModuleBuilder()
        t_i32_i64 = mb_if_no_else.add_type([ValType.I32], [ValType.I64])
        mb_if_no_else.add_func(
            t_i32_i64,
            [],
            [
                ("local.get", 0),
                ("if", ValType.I64),
                ("i64.const", 42),
                ("end",),
            ],
            export_as="missing_else",
        )
        with self.assertRaises(ValidationError, msg="if (result i64) without else must fail validation!"):
            validate_module(decode_module(mb_if_no_else.to_bytes()))

        # 1C: Single-sided `if (param i32) (result i64)` without `else` (param != result)
        mb_if_mismatch = ModuleBuilder()
        sig_p_r = mb_if_mismatch.add_type([ValType.I32], [ValType.I64])
        mb_if_mismatch.add_func(
            sig_p_r,
            [],
            [
                ("local.get", 0),
                ("i32.const", 0),
                ("if", sig_p_r),
                ("drop",),
                ("i64.const", 1),
                ("end",),
            ],
            export_as="mismatch_else",
        )
        with self.assertRaises(ValidationError):
            validate_module(decode_module(mb_if_mismatch.to_bytes()))

    def test_03_defect2_br_table_loop_arity_and_type_transmutation(self) -> None:
        # 2A: `br_table` mixing `block (result i32)` (label_types=[i32]) with `loop (result i32)` (label_types=[]!)
        mb_loop_br = ModuleBuilder()
        t_fn = mb_loop_br.add_type([ValType.I32], [ValType.I32])
        mb_loop_br.add_func(
            t_fn,
            [],
            [
                ("block", ValType.I32),
                ("loop", ValType.I32),
                ("i32.const", 99),
                ("local.get", 0),
                ("br_table", [0], 1),  # target 0 is loop (expects []), default 1 is block (expects [i32])!
                ("end",),
                ("end",),
            ],
            export_as="bad_loop_br_table",
        )
        with self.assertRaises(ValidationError, msg="br_table confused loop result_types with loop param_types!"):
            validate_module(decode_module(mb_loop_br.to_bytes()))

        # 2B: `br_table` transmuting `i64` into `funcref` via arity-only target comparison!
        mb_transmute = ModuleBuilder()
        t_forge = mb_transmute.add_type([ValType.I32], [ValType.FUNCREF])
        mb_transmute.add_func(
            t_forge,
            [],
            [
                ("block", ValType.FUNCREF),
                ("block", ValType.I64),
                ("i64.const", 0xDEADBEEF),
                ("local.get", 0),
                ("br_table", [1], 0),  # target 1 expects FUNCREF, default 0 expects I64!
                ("end",),
                ("drop",),
                ("ref.null", ValType.FUNCREF),
                ("end",),
            ],
            export_as="forge_ref",
        )
        with self.assertRaises(ValidationError, msg="br_table allowed i64 -> funcref type transmutation!"):
            validate_module(decode_module(mb_transmute.to_bytes()))

    def test_04_defect3_canonical_leb128_and_ea_wraparound(self) -> None:
        # 3A: Overlong 6-byte u32 LEB128 & invalid 5th-byte spare bits in u32/s32
        mb = ModuleBuilder()
        t_v = mb.add_type([], [ValType.I32])
        mb.add_memory(1)
        # `0x28` = i32.load, align=0 (`\x00`), followed by 6-byte overlong u32 offset `0x80 0x80 0x80 0x80 0x80 0x00`
        mb.add_func(
            t_v,
            [],
            [
                ("i32.const", 0),
                ("raw", b"\x28\x00\x80\x80\x80\x80\x80\x00"),
            ],
        )
        with self.assertRaises(DecodeError, msg="Accepted 6-byte overlong u32 LEB128!"):
            decode_module(mb.to_bytes())

        # 5th byte of u32 with non-zero upper nibble (`0x10` -> bit 32 set = 2^32!)
        mb_u32_hi = ModuleBuilder()
        t_v2 = mb_u32_hi.add_type([], [ValType.I32])
        mb_u32_hi.add_memory(1)
        mb_u32_hi.add_func(
            t_v2,
            [],
            [
                ("i32.const", 0),
                ("raw", b"\x28\x00\x80\x80\x80\x80\x10"),
            ],
        )
        with self.assertRaises(DecodeError, msg="Accepted 33-bit u32 LEB128 spare bits!"):
            decode_module(mb_u32_hi.to_bytes())

        # 5th byte of s32 `i32.const` (`0x41`) with invalid sign-extension spare bits (`0x10` when bit 0x08 is 0)
        mb_s32_bad = ModuleBuilder()
        t_v3 = mb_s32_bad.add_type([], [ValType.I32])
        mb_s32_bad.add_func(t_v3, [], [("raw", b"\x41\x80\x80\x80\x80\x10")])
        with self.assertRaises(DecodeError, msg="Accepted invalid s32 5th-byte sign-extension bits!"):
            decode_module(mb_s32_bad.to_bytes())

        # 3B: Effective address `uint32(base_addr) + uint32(offset)` MUST NOT wrap modulo 2^32!
        mb_mem = ModuleBuilder()
        t_rw = mb_mem.add_type([ValType.I32], [ValType.I32])
        mb_mem.add_memory(1, 1)
        mb_mem.add_data(0, [("i32.const", 16)], (0x11223344).to_bytes(4, "little"))
        mb_mem.add_func(
            t_rw,
            [],
            [
                ("local.get", 0),
                ("i32.load", 2, 0x20),  # offset = 32; with base = 0xFFFFFFF0 (-16), ea = 0x100000010 -> MUST TRAP!
            ],
            export_as="load_off",
        )
        mb_mem.add_func(
            mb_mem.add_type([ValType.I32, ValType.I32], []),
            [],
            [
                ("local.get", 0),
                ("local.get", 1),
                ("i32.store", 2, 0x20),
            ],
            export_as="store_off",
        )
        inst = Linker().instantiate(decode_module(mb_mem.to_bytes()))
        self.assertEqual(inst.invoke("load_off", [0]), 0)
        with self.assertRaises(TrapError, msg="i32.load wrapped base+offset modulo 2^32 instead of trapping!"):
            inst.invoke("load_off", [-16])
        with self.assertRaises(TrapError, msg="i32.store wrapped base+offset modulo 2^32 instead of trapping!"):
            inst.invoke("store_off", [-16, 0x77777777])

    def test_05_defect4_call_indirect_signature_and_atomic_instantiation(self) -> None:
        # 4A: `call_indirect` must enforce full `FuncType` equality, not merely param/result counts!
        mb = ModuleBuilder()
        t_i64_fn = mb.add_type([ValType.I64], [ValType.I64])
        t_ref_fn = mb.add_type([ValType.FUNCREF], [ValType.FUNCREF])
        t_entry = mb.add_type([], [ValType.I32])

        fn_id64 = mb.add_func(t_i64_fn, [], [("local.get", 0)])
        mb.add_table(2)
        mb.add_elem(0, [("i32.const", 0)], [fn_id64])
        mb.add_func(
            t_entry,
            [],
            [
                ("ref.null", ValType.FUNCREF),
                ("i32.const", 0),
                ("call_indirect", t_ref_fn, 0),  # slot 0 has (i64)->i64, NOT (funcref)->funcref!
                ("ref.is_null",),
            ],
            export_as="bad_indirect",
        )
        inst = Linker().instantiate(decode_module(mb.to_bytes()))
        with self.assertRaises(TrapError, msg="call_indirect allowed (i64)->i64 to be invoked as (funcref)->funcref!"):
            inst.invoke("bad_indirect", [])

        # 4B: Atomic segment validation before mutating imported shared Memory and Table!
        shared_mem = MemoryInstance(Limits(1, 2))
        shared_mem.data[0:6] = b"INTACT"
        shared_tab = TableInstance(TableType(ValType.FUNCREF, Limits(2, 4)))
        sentinel_fn = HostFunc(FuncType((), ()), lambda: None, "sentinel")
        shared_tab.elements[0] = FuncRefHandle(sentinel_fn, "sentinel")

        mb_bad_link = ModuleBuilder()
        t_noop = mb_bad_link.add_type([], [])
        mb_bad_link.add_import_memory("host", "mem", Limits(1, 2))
        mb_bad_link.add_import_table("host", "tab", TableType(ValType.FUNCREF, Limits(2, 4)))
        f0 = mb_bad_link.add_func(t_noop, [], [])
        # Segment 1 fits, Segment 2 overflows memory (65536 bytes)!
        mb_bad_link.add_elem(0, [("i32.const", 0)], [f0])
        mb_bad_link.add_data(0, [("i32.const", 0)], b"CORRUPT")
        mb_bad_link.add_data(0, [("i32.const", 65530)], b"OVERFLOW_PAST_64K")

        linker = Linker()
        linker.define("host", "mem", shared_mem)
        linker.define("host", "tab", shared_tab)
        with self.assertRaises((LinkError, TrapError)):
            linker.instantiate(decode_module(mb_bad_link.to_bytes()))

        self.assertEqual(bytes(shared_mem.data[0:6]), b"INTACT", "Failed instantiation partially mutated imported Memory!")
        self.assertEqual(shared_tab.elements[0], FuncRefHandle(sentinel_fn, "sentinel"), "Failed instantiation partially mutated imported Table!")


if __name__ == "__main__":
    unittest.main()
'''


def check_report(app_dir: Path) -> tuple[bool, str]:
    report_path = app_dir / "report.json"
    if not report_path.is_file():
        return False, "Missing /app/report.json"
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return False, f"Invalid JSON in report.json: {exc}"

    if not isinstance(data, dict):
        return False, "report.json root must be a JSON object"

    raw_blobs: list[str] = []
    for key in ("files", "file"):
        val = data.get(key)
        if isinstance(val, str):
            raw_blobs.append(val)
        elif isinstance(val, list):
            raw_blobs.extend(json.dumps(x) if isinstance(x, dict) else str(x) for x in val)

    findings = data.get("findings")
    if isinstance(findings, list):
        for item in findings:
            raw_blobs.append(json.dumps(item) if isinstance(item, dict) else str(item))

    mentioned = {
        Path(tok).name
        for blob in raw_blobs
        for tok in re.findall(r"[\w./-]+\.py", blob)
    }
    matched_core = mentioned & CORE_FILES
    if len(matched_core) < 3:
        return False, f"Expected report.json to reference at least 3 core modules from {sorted(CORE_FILES)}, got {sorted(mentioned)}"

    if not isinstance(findings, list) or len(findings) < 3:
        return False, "Expected at least 3 documented findings in report.json"
    for item in findings:
        txt = json.dumps(item) if isinstance(item, dict) else str(item)
        if len(txt.strip()) < 20 or "placeholder" in txt.lower():
            return False, f"Finding entry is too brief or invalid: {txt!r}"

    summary = data.get("summary")
    if not isinstance(summary, str) or len(summary.strip()) < 15:
        return False, "Expected a non-empty 'summary' string in report.json"

    return True, f"Report validated (covered {sorted(matched_core)})"


def run_unittest(work_dir: Path, pattern: str = "test_*.py") -> tuple[int, str]:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(work_dir)
    try:
        proc = subprocess.run(
            ["python3", "-m", "unittest", "discover", "-s", "tests", "-p", pattern],
            cwd=str(work_dir),
            env=env,
            capture_output=True,
            text=True,
            timeout=45,
        )
        return proc.returncode, (proc.stdout + "\n" + proc.stderr).strip()
    except subprocess.TimeoutExpired:
        return 124, "unittest timed out after 45s"


def verify(app_dir: Path, orig_dir: Path) -> tuple[bool, dict]:
    details: dict = {}

    ok_rep, msg_rep = check_report(app_dir)
    details["report"] = {"passed": ok_rep, "message": msg_rep}
    if not ok_rep:
        return False, details

    with tempfile.TemporaryDirectory() as tmp_str:
        tmp = Path(tmp_str)

        # 1. Run agent's own test suite in isolated copy
        patched_copy = tmp / "patched_app"
        shutil.copytree(app_dir, patched_copy, ignore=shutil.ignore_patterns("__pycache__"))
        rc_pass, out_pass = run_unittest(patched_copy)
        if rc_pass != 0:
            details["agent_tests"] = {
                "passed": False,
                "message": f"Agent test suite failed against updated /app:\n{out_pass[-1500:]}",
            }
            return False, details

        # 2. Run agent's tests against original unpatched wasm_sandbox/
        orig_check = tmp / "orig_check"
        shutil.copytree(orig_dir, orig_check, ignore=shutil.ignore_patterns("__pycache__"))
        if (patched_copy / "tests").is_dir():
            shutil.rmtree(orig_check / "tests", ignore_errors=True)
            shutil.copytree(patched_copy / "tests", orig_check / "tests")
        rc_orig, _ = run_unittest(orig_check)
        if rc_orig == 0:
            details["agent_tests"] = {
                "passed": False,
                "message": "Agent test suite unexpectedly passed against unmodified original wasm_sandbox/",
            }
            return False, details
        details["agent_tests"] = {
            "passed": True,
            "message": "Agent regression tests pass on hardened code and fail on original code",
        }

        # 3. Run hidden deterministic soundness suite
        hidden_file = patched_copy / "tests" / "test_vh_hidden_soundness.py"
        hidden_file.write_text(HIDDEN_UNITTEST, encoding="utf-8")
        rc_hid, out_hid = run_unittest(patched_copy, pattern="test_vh_hidden_soundness.py")
        if rc_hid != 0:
            details["soundness_suite"] = {
                "passed": False,
                "message": f"Hidden soundness suite failed:\n{out_hid[-1800:]}",
            }
            return False, details

        details["soundness_suite"] = {
            "passed": True,
            "message": "All 5 functional, polymorphic-stack, br_table, LEB128/EA-bounds, and call_indirect/linker checks passed",
        }

    return True, details


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--app-dir", default=os.environ.get("APP_DIR", "/app"))
    parser.add_argument("--reward-dir", default=os.environ.get("REWARD_DIR", "/logs/verifier"))
    args = parser.parse_args()

    app_dir = Path(args.app_dir).resolve()
    orig_dir = Path(__file__).resolve().parent / "orig_app"
    reward_dir = Path(args.reward_dir).resolve()
    reward_dir.mkdir(parents=True, exist_ok=True)

    passed, details = verify(app_dir, orig_dir)
    (reward_dir / "details.json").write_text(json.dumps({"passed": passed, "details": details}, indent=2), encoding="utf-8")
    print(json.dumps({"passed": passed, "details": details}, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
