#!/usr/bin/env python3
"""Deterministic verifier for task: c-ebpf-verifier-sandbox."""

from __future__ import annotations

import argparse
import json
import os
import re
import resource
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

BPFS_MAGIC = 0x53465042
BPFS_VERSION = 1

CLS_LD = 0x00
CLS_LDX = 0x01
CLS_ST = 0x02
CLS_STX = 0x03
CLS_ALU32 = 0x04
CLS_JMP64 = 0x05
CLS_JMP32 = 0x06
CLS_ALU64 = 0x07

BPF_K = 0x00
BPF_X = 0x08

BPF_W = 0x00
BPF_H = 0x08
BPF_B = 0x10
BPF_DW = 0x18
BPF_MEM_MODE = 0x60
OP_LDDW_IMM = 0x18

ALU_ADD = 0x00
ALU_SUB = 0x10
ALU_MUL = 0x20
ALU_DIV = 0x30
ALU_OR = 0x40
ALU_AND = 0x50
ALU_LSH = 0x60
ALU_RSH = 0x70
ALU_NEG = 0x80
ALU_MOD = 0x90
ALU_XOR = 0xA0
ALU_MOV = 0xB0
ALU_ARSH = 0xC0

JMP_JA = 0x00
JMP_JEQ = 0x10
JMP_JGT = 0x20
JMP_JGE = 0x30
JMP_JSET = 0x40
JMP_JNE = 0x50
JMP_JSGT = 0x60
JMP_JSGE = 0x70
JMP_JLT = 0xA0
JMP_JLE = 0xB0
JMP_JSLT = 0xC0
JMP_JSLE = 0xD0

OP_CALL_HELPER = 0x85
OP_CALL_REL = 0x8D
OP_EXIT = 0x95

HELPER_MAP_LOOKUP_ELEM = 1
HELPER_MAP_UPDATE_ELEM = 2
HELPER_PKT_RESIZE = 3
HELPER_CSUM_FOLD = 4

CTX_DATA = 0
CTX_PKT_LEN = 8

R0, R1, R2, R3, R4, R5, R6, R7, R8, R9, R10 = range(11)

CORE_FILES = {"bounds.c", "cfg.c", "verifier_mem.c", "verifier.c"}
ALL_APP_FILES = {
    "bpf_vm.h",
    "bounds.c",
    "cfg.c",
    "verifier_mem.c",
    "verifier.c",
    "interp.c",
    "loader.c",
    "cli.c",
}


def insn(op: int, dst: int = 0, src: int = 0, off: int = 0, imm: int = 0) -> bytes:
    if imm >= 0x80000000:
        imm -= 0x100000000
    return struct.pack("<BBhi", op & 0xFF, ((src & 0xF) << 4) | (dst & 0xF), off, imm)


def alu64_k(op: int, dst: int, imm: int) -> bytes:
    return insn(CLS_ALU64 | BPF_K | op, dst, 0, 0, imm)


def alu64_x(op: int, dst: int, src: int) -> bytes:
    return insn(CLS_ALU64 | BPF_X | op, dst, src, 0, 0)


def alu32_k(op: int, dst: int, imm: int) -> bytes:
    return insn(CLS_ALU32 | BPF_K | op, dst, 0, 0, imm)


def alu32_x(op: int, dst: int, src: int) -> bytes:
    return insn(CLS_ALU32 | BPF_X | op, dst, src, 0, 0)


def jmp64_k(op: int, dst: int, imm: int, off: int) -> bytes:
    return insn(CLS_JMP64 | BPF_K | op, dst, 0, off, imm)


def jmp64_x(op: int, dst: int, src: int, off: int) -> bytes:
    return insn(CLS_JMP64 | BPF_X | op, dst, src, off, 0)


def jmp32_k(op: int, dst: int, imm: int, off: int) -> bytes:
    return insn(CLS_JMP32 | BPF_K | op, dst, 0, off, imm)


def jmp_ja(off: int) -> bytes:
    return insn(CLS_JMP64 | BPF_K | JMP_JA, 0, 0, off, 0)


def ldx(sz: int, dst: int, src: int, off: int) -> bytes:
    return insn(CLS_LDX | sz | BPF_MEM_MODE, dst, src, off, 0)


def stx(sz: int, dst: int, src: int, off: int) -> bytes:
    return insn(CLS_STX | sz | BPF_MEM_MODE, dst, src, off, 0)


def st_imm(sz: int, dst: int, off: int, imm: int) -> bytes:
    return insn(CLS_ST | sz | BPF_MEM_MODE, dst, 0, off, imm)


def lddw(dst: int, val64: int) -> list[bytes]:
    lo = val64 & 0xFFFFFFFF
    hi = (val64 >> 32) & 0xFFFFFFFF
    return [insn(OP_LDDW_IMM, dst, 0, 0, lo), insn(0, 0, 0, 0, hi)]


def call_helper(hid: int) -> bytes:
    return insn(OP_CALL_HELPER, 0, 0, 0, hid)


def call_rel(rel_off: int) -> bytes:
    return insn(OP_CALL_REL, 0, 1, 0, rel_off)


def exit_insn() -> bytes:
    return insn(OP_EXIT, 0, 0, 0, 0)


def pack_suite(
    cases: list[tuple[str, list[bytes], list[tuple[int, int, int]], bytes, list[tuple[int, int, bytes]]]]
) -> bytes:
    parts = [struct.pack("<III", BPFS_MAGIC, BPFS_VERSION, len(cases))]
    for name, insns_list, maps, pkt, seeds in cases:
        nb = name.encode("ascii")
        parts.append(struct.pack("<H", len(nb)) + nb)
        parts.append(struct.pack("<IIII", len(insns_list), len(maps), len(pkt), len(seeds)))
        for ks, vs, me in maps:
            parts.append(struct.pack("<III", ks, vs, me))
        parts.extend(insns_list)
        parts.append(pkt)
        for mid, key, val in seeds:
            parts.append(struct.pack("<III", mid, key, len(val)) + val)
    return b"".join(parts)


def _disable_core_dumps() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def san_env() -> dict[str, str]:
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "detect_leaks=1:exitcode=99:abort_on_error=0"
    env["UBSAN_OPTIONS"] = "print_stacktrace=1:exitcode=98:halt_on_error=1"
    return env


def detect_san_compiler() -> tuple[str, bool]:
    for cc in ("gcc", "clang"):
        if not shutil.which(cc):
            continue
        with tempfile.TemporaryDirectory() as tmp:
            probe_c = Path(tmp) / "probe.c"
            probe_bin = Path(tmp) / "probe"
            probe_c.write_text("int main(void){return 0;}\n", encoding="utf-8")
            res = subprocess.run(
                [cc, "-std=c11", "-fsanitize=address,undefined", str(probe_c), "-o", str(probe_bin)],
                capture_output=True,
                text=True,
            )
            if res.returncode == 0:
                return cc, True
    return "gcc", False


def binary_has_asan(bin_path: Path) -> bool:
    raw = bin_path.read_bytes()
    return b"__asan_init" in raw or b"__asan_" in raw


def compile_cli_from_tree(tree_dir: Path, out_bin: Path, cc: str, use_san: bool) -> None:
    srcs = sorted(str(p) for p in (tree_dir / "src").glob("*.c"))
    if not srcs:
        raise RuntimeError(f"No C sources in {tree_dir / 'src'}")
    cmd = [cc, "-std=c11", "-Wall", "-Wextra", "-O1", "-g", f"-I{tree_dir / 'include'}"]
    if use_san:
        cmd += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
    cmd += srcs + ["-o", str(out_bin)]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    if res.returncode != 0:
        raise RuntimeError(f"Compilation failed for {tree_dir}:\n{res.stderr}")


def run_cmd_safe(cmd: list[str], cwd: Path | None = None, timeout: float = 30.0) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            env=san_env(),
            capture_output=True,
            text=True,
            preexec_fn=_disable_core_dumps,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        out_s = exc.stdout.decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        err_s = exc.stderr.decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return subprocess.CompletedProcess(cmd, returncode=124, stdout=out_s, stderr=err_s + "\nTIMEOUT")


def did_sanitizer_or_crash(proc: subprocess.CompletedProcess[str]) -> bool:
    if proc.returncode < 0 or proc.returncode in (98, 99, 124) or proc.returncode >= 128:
        return True
    for marker in (
        "AddressSanitizer",
        "LeakSanitizer",
        "UndefinedBehaviorSanitizer",
        "runtime error:",
        "Segmentation fault",
    ):
        if marker in proc.stderr:
            return True
    return False


def _extract_basenames(raw: str) -> set[str]:
    return {Path(m).name for m in re.findall(r"[\w./-]+\.[ch]\b", raw)}


def check_report(app_dir: Path) -> tuple[bool, str]:
    report_path = app_dir / "report.json"
    if not report_path.is_file():
        return False, "Missing /app/report.json"
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return False, f"Invalid JSON in /app/report.json: {exc}"
    if not isinstance(data, dict):
        return False, "/app/report.json root must be a JSON object"

    mentioned: set[str] = set()
    raw_files = data.get("files")
    if isinstance(raw_files, list):
        for item in raw_files:
            mentioned |= _extract_basenames(str(item))
    elif isinstance(raw_files, str):
        mentioned |= _extract_basenames(raw_files)

    if isinstance(data.get("file"), str):
        mentioned |= _extract_basenames(data["file"])

    findings_raw = data.get("findings")
    valid_findings = 0
    if isinstance(findings_raw, list):
        for entry in findings_raw:
            if isinstance(entry, dict):
                for fk in ("file", "files", "path", "location"):
                    if fk in entry:
                        mentioned |= _extract_basenames(str(entry[fk]))
                desc = " ".join(
                    str(entry.get(k, "")).strip()
                    for k in ("issue", "description", "summary", "detail", "finding", "root_cause", "fix", "remediation")
                ).strip()
                mentioned |= _extract_basenames(desc)
                if len(desc) >= 12 or str(entry.get("function", "")).strip():
                    valid_findings += 1
            elif isinstance(entry, str) and len(entry.strip()) >= 12:
                mentioned |= _extract_basenames(entry)
                valid_findings += 1

    summary = str(data.get("summary", "")).strip()
    mentioned |= _extract_basenames(summary)

    if valid_findings < 3:
        return False, f"Report must document >= 3 substantive findings (got {valid_findings})"
    if len(summary) < 15 or "placeholder" in summary.lower():
        return False, "Report summary is missing, too brief, or placeholder text"

    core_hits = mentioned & CORE_FILES
    if len(core_hits) < 2:
        return (
            False,
            f"Report must identify >= 2 core verifier source files from {sorted(CORE_FILES)} (got {sorted(mentioned & ALL_APP_FILES)})",
        )
    return True, f"Report accepted (core_files={sorted(core_hits)}, findings={valid_findings})"


def build_legitimate_cases() -> list[tuple[str, list[bytes], list[tuple[int, int, int]], bytes, list[tuple[int, int, bytes]]]]:
    # 1. ALU32/64 bitops + high-bit 32-bit signed branch (JSLT32 < 0) + LDDW
    c1_insns = [
        alu64_x(ALU_MOV, R6, R1),
        ldx(BPF_DW, R2, R6, CTX_PKT_LEN),
        jmp64_k(JMP_JGE, R2, 8, 2),
        alu64_k(ALU_MOV, R0, 0),
        exit_insn(),
        ldx(BPF_DW, R7, R6, CTX_DATA),
        ldx(BPF_W, R3, R7, 0),              # r3 = 0x80000005
        alu32_k(ALU_ADD, R3, 3),            # r3 = 0x80000008 (zero-extended)
        jmp32_k(JMP_JSLT, R3, 0, 2),        # (int32_t)0x80000008 < 0 -> taken!
        alu64_k(ALU_MOV, R0, 99),
        exit_insn(),
        alu64_k(ALU_RSH, R3, 28),           # 0x80000008 >> 28 == 8
        *lddw(R4, 0x0102030405060700),
        alu64_x(ALU_OR, R4, R3),            # 0x0102030405060708
        alu64_x(ALU_MOV, R0, R4),
        exit_insn(),
    ]
    c1_pkt = struct.pack("<II", 0x80000005, 0x11223344)

    # 2. Diamond CFG where branch 1 has wider valid offset [0, 15] and branch 2 has narrower [0, 7] (subsumed),
    #    followed by a second diamond where branch 1 has [0, 7] and branch 2 has [0, 15] (not subsumed, re-verified OK!)
    c2_insns = [
        alu64_x(ALU_MOV, R6, R1),
        ldx(BPF_DW, R2, R6, CTX_PKT_LEN),
        jmp64_k(JMP_JGE, R2, 8, 2),
        alu64_k(ALU_MOV, R0, 0),
        exit_insn(),
        st_imm(BPF_W, R10, -4, 0),
        alu64_k(ALU_MOV, R1, 0),
        alu64_x(ALU_MOV, R2, R10),
        alu64_k(ALU_ADD, R2, -4),
        call_helper(HELPER_MAP_LOOKUP_ELEM),
        jmp64_k(JMP_JNE, R0, 0, 2),
        alu64_k(ALU_MOV, R0, 0),
        exit_insn(),
        alu64_x(ALU_MOV, R8, R0),           # r8 = base map_ptr (64B)
        ldx(BPF_DW, R7, R6, CTX_DATA),
        ldx(BPF_B, R2, R7, 0),
        ldx(BPF_B, R3, R7, 1),
        # Diamond A: fallthrough [0,7], taken [0,15] -> both valid inside 64B!
        jmp64_k(JMP_JNE, R2, 0, 3),
        alu64_k(ALU_AND, R3, 7),
        alu64_x(ALU_ADD, R0, R3),
        jmp_ja(2),
        alu64_k(ALU_AND, R3, 15),
        alu64_x(ALU_ADD, R0, R3),
        ldx(BPF_DW, R9, R0, 0),             # join A: max end = 15 + 8 = 23 <= 64
        # Diamond B: fallthrough [0,15], taken [0,7] -> subsumed cleanly!
        alu64_x(ALU_MOV, R4, R8),
        ldx(BPF_B, R5, R7, 2),
        jmp64_k(JMP_JNE, R2, 1, 3),
        alu64_k(ALU_AND, R5, 15),
        alu64_x(ALU_ADD, R4, R5),
        jmp_ja(2),
        alu64_k(ALU_AND, R5, 7),
        alu64_x(ALU_ADD, R4, R5),
        ldx(BPF_DW, R0, R4, 0),
        alu64_x(ALU_ADD, R0, R9),
        exit_insn(),
    ]
    c2_seed = bytearray(64)
    struct.pack_into("<Q", c2_seed, 12, 700)
    struct.pack_into("<Q", c2_seed, 4, 300)
    c2_pkt = bytes([1, 12, 4, 0, 0, 0, 0, 0])

    # 3. Caller stack pointer (frame_owner == 0) preserved in R6 and passed in R1 across nested OP_CALL_REL
    #    (depth 0 -> 1 -> 2), plus HELPER_PKT_RESIZE + fresh CTX->data reload + HELPER_MAP_UPDATE_ELEM + CSUM
    c3_insns = [
        # main (pc 0..24)
        alu64_x(ALU_MOV, R7, R1),           # 0: r7 = ctx
        st_imm(BPF_DW, R10, -16, 100),      # 1: caller stack [r10-16] = 100
        alu64_x(ALU_MOV, R6, R10),          # 2: r6 = caller R10 (frame_owner=0)
        alu64_k(ALU_ADD, R6, -16),          # 3: r6 = &caller_stack[-16]
        alu64_x(ALU_MOV, R1, R6),           # 4: r1 = &caller_stack[-16]
        call_rel(20),                       # 5: call sub1 (pc = 6 + 20 = 26)
        ldx(BPF_DW, R8, R6, 0),             # 6: r8 = caller_stack[-16] (updated by sub1/sub2!)
        alu64_x(ALU_ADD, R8, R0),           # 7: r8 += r0
        alu64_x(ALU_MOV, R1, R7),           # 8: r1 = ctx
        alu64_k(ALU_MOV, R2, 24),           # 9: new_len = 24
        call_helper(HELPER_PKT_RESIZE),     # 10: resize packet to 24B
        ldx(BPF_DW, R9, R7, CTX_DATA),      # 11: fresh ctx->data reload
        stx(BPF_DW, R9, R8, 16),            # 12: *(u64*)(pkt + 16) = r8
        st_imm(BPF_W, R10, -24, 0),         # 13: key = 0 at [r10-24]
        alu64_k(ALU_MOV, R1, 0),            # 14: map_id = 0
        alu64_x(ALU_MOV, R2, R10),          # 15
        alu64_k(ALU_ADD, R2, -24),          # 16: r2 = &key
        alu64_x(ALU_MOV, R3, R9),           # 17: r3 = pkt (24B map value!)
        call_helper(HELPER_MAP_UPDATE_ELEM),# 18: map_update_elem(0, &key, pkt)
        alu64_x(ALU_MOV, R1, R9),           # 19: r1 = pkt
        alu64_k(ALU_MOV, R2, 24),           # 20: len = 24
        call_helper(HELPER_CSUM_FOLD),      # 21: r0 = csum(pkt, 24)
        alu64_k(ALU_LSH, R8, 16),           # 22
        alu64_x(ALU_OR, R0, R8),            # 23
        exit_insn(),                        # 24
        nop_pad := alu64_k(ALU_MOV, R0, 0), # 25 (unreachable pad)
        # sub1 (pc 26..32): spills caller ptr R1 to sub1 stack, calls sub2, writes to caller stack
        stx(BPF_DW, R10, R1, -8),           # 26: spill caller stack ptr to sub1[-8]
        call_rel(5),                        # 27: call sub2 (pc = 28 + 5 = 33)
        ldx(BPF_DW, R2, R10, -8),           # 28: reload caller stack ptr (frame_owner=0)
        ldx(BPF_DW, R3, R2, 0),             # 29: r3 = 100
        alu64_x(ALU_ADD, R3, R0),           # 30: r3 = 100 + 23 = 123
        stx(BPF_DW, R2, R3, 0),             # 31: caller_stack[-16] = 123
        exit_insn(),                        # 32: returns R0 = 23, R6 still &caller_stack[-16]
        # sub2 (pc 33..34)
        alu64_k(ALU_MOV, R0, 23),           # 33
        exit_insn(),                        # 34
    ]
    _ = nop_pad
    c3_pkt = b"ABCDEFGH01234567"

    return [
        ("legit_alu32_bitops_jslt32", c1_insns, [], c1_pkt, []),
        ("legit_diamond_var_offsets", c2_insns, [(4, 64, 2)], c2_pkt, [(0, 0, bytes(c2_seed))]),
        ("legit_nested_caller_stack_resize", c3_insns, [(4, 24, 2)], c3_pkt, []),
    ]


def build_soundness_cases() -> list[tuple[str, list[bytes], list[tuple[int, int, int]], bytes, list[tuple[int, int, bytes]]]]:
    # Preamble that looks up map 0 (64-byte value) at key=0 into non-null R0, and saves ctx in R6
    def map0_preamble() -> list[bytes]:
        return [
            alu64_x(ALU_MOV, R6, R1),
            st_imm(BPF_W, R10, -4, 0),
            alu64_k(ALU_MOV, R1, 0),
            alu64_x(ALU_MOV, R2, R10),
            alu64_k(ALU_ADD, R2, -4),
            call_helper(HELPER_MAP_LOOKUP_ELEM),
            jmp64_k(JMP_JNE, R0, 0, 2),
            alu64_k(ALU_MOV, R0, 0),
            exit_insn(),
        ]

    # Issue 1A: ALU32 MOV 0x80000000 zero-extends to +2147483648 in 64-bit, but buggy sync_alu32_bounds
    # sets smin64=smax64=-2147483648 -> ARSH64 63 produces -1 in verifier vs 0 at runtime -> +512 OOB!
    s1a = map0_preamble() + [
        alu32_k(ALU_MOV, R2, 0x80000000),
        alu64_k(ALU_ARSH, R2, 63),
        alu64_k(ALU_ADD, R2, 1),
        alu64_k(ALU_LSH, R2, 9),            # verifier: 0, runtime: 512
        alu64_x(ALU_ADD, R0, R2),
        ldx(BPF_DW, R0, R0, 0),             # OOB read at map_val + 512 (map value is 64B)
        exit_insn(),
    ]

    # Issue 1B: JMP32_JSLT_K < 0 on zero-extended LDX_W [pkt+0] (0x80000010) sets smin64..smax64
    # negative in refine_cond32 -> ARSH64 63 yields -1 in verifier vs 0 at runtime -> +512 OOB!
    s1b = map0_preamble() + [
        ldx(BPF_DW, R2, R6, CTX_PKT_LEN),
        jmp64_k(JMP_JGE, R2, 4, 2),
        alu64_k(ALU_MOV, R0, 0),
        exit_insn(),
        ldx(BPF_DW, R7, R6, CTX_DATA),
        ldx(BPF_W, R2, R7, 0),              # runtime: 0x0000000080000010 (not via ALU32!)
        jmp32_k(JMP_JSLT, R2, 0, 2),        # taken at runtime ((int32_t)0x80000010 < 0)
        alu64_k(ALU_MOV, R0, 0),
        exit_insn(),
        alu64_k(ALU_ARSH, R2, 63),          # verifier: -1, runtime: 0
        alu64_k(ALU_ADD, R2, 1),            # verifier: 0, runtime: 1
        alu64_k(ALU_LSH, R2, 9),            # verifier: 0, runtime: 512
        alu64_x(ALU_ADD, R0, R2),
        st_imm(BPF_DW, R0, 0, 0x1337),      # OOB write at map_val + 512!
        alu64_k(ALU_MOV, R0, 1),
        exit_insn(),
    ]
    s1b_pkt = struct.pack("<I", 0x80000010)

    # Issue 2A: state_subsumes ignores idx_umax on pointer registers at CFG join point!
    s2a = map0_preamble() + [
        ldx(BPF_DW, R2, R6, CTX_PKT_LEN),
        jmp64_k(JMP_JGE, R2, 8, 2),
        alu64_k(ALU_MOV, R0, 0),
        exit_insn(),
        ldx(BPF_DW, R7, R6, CTX_DATA),
        ldx(BPF_W, R2, R7, 0),              # runtime: 1
        ldx(BPF_W, R3, R7, 4),              # runtime: 512
        jmp64_k(JMP_JNE, R2, 0, 5),         # fallthrough explored first, taken at runtime
        alu64_k(ALU_AND, R3, 7),            # idx_umax = 7
        alu64_x(ALU_ADD, R0, R3),
        alu64_k(ALU_MOV, R2, 0),
        alu64_k(ALU_MOV, R3, 0),
        jmp_ja(4),
        alu64_k(ALU_AND, R3, 1023),         # idx_umax = 1023 (runtime 512)
        alu64_x(ALU_ADD, R0, R3),
        alu64_k(ALU_MOV, R2, 0),
        alu64_k(ALU_MOV, R3, 0),
        ldx(BPF_DW, R0, R0, 0),             # join: OOB read at map_val + 512!
        exit_insn(),
    ]
    s2a_pkt = struct.pack("<II", 1, 512)

    # Issue 2B: Partial 32-bit scalar write (STX_W [R10 - 8], R_scalar) onto spilled pointer slot
    # fails to clear STACK_SPILL_PTR, letting LDX_DW reload a corrupted host pointer!
    s2b = map0_preamble() + [
        stx(BPF_DW, R10, R0, -8),           # spill map_ptr to [R10 - 8]
        alu64_k(ALU_MOV, R2, 0),
        stx(BPF_W, R10, R2, -8),            # partial 32-bit scalar write clobbers low 32 bits of pointer!
        ldx(BPF_DW, R3, R10, -8),           # reloads corrupted pointer
        ldx(BPF_DW, R0, R3, 0),             # wild/corrupted pointer dereference!
        exit_insn(),
    ]

    # Issue 2C: Partial 32-bit write to upper half [R10 - 4] of spilled pointer slot!
    s2c = map0_preamble() + [
        stx(BPF_DW, R10, R0, -8),
        st_imm(BPF_W, R10, -4, 0x7FFFdead), # clobbers high 32 bits of spilled pointer!
        ldx(BPF_DW, R3, R10, -8),
        ldx(BPF_DW, R0, R3, 0),
        exit_insn(),
    ]

    # Issue 3A: Subprogram stack-frame pointer escape via R0 across OP_CALL_REL / OP_EXIT
    s3a = [
        call_rel(2),                        # 0 -> call sub1 (pc=3)
        ldx(BPF_DW, R0, R0, -8),            # 1: UAF read on freed sub1 stack!
        exit_insn(),                        # 2
        st_imm(BPF_DW, R10, -8, 0x42),      # 3: sub1 initializes its own stack[-8]
        alu64_x(ALU_MOV, R0, R10),          # 4: leaks sub1 R10 in R0
        exit_insn(),                        # 5
    ]

    # Issue 3B: Subprogram stack-frame pointer escape via callee-saved R6 AND via caller stack spill!
    s3b = [
        alu64_x(ALU_MOV, R1, R10),          # 0
        alu64_k(ALU_ADD, R1, -8),           # 1: r1 = &caller_stack[-8]
        call_rel(3),                        # 2 -> call sub1 (pc=6)
        ldx(BPF_DW, R2, R10, -8),           # 3: reload escaped sub1 stack ptr from caller stack spill
        ldx(BPF_DW, R0, R6, -16),           # 4: UAF read via R6 (or R2) on freed sub1 stack!
        exit_insn(),                        # 5
        st_imm(BPF_DW, R10, -16, 0x99),     # 6: sub1 initializes its stack[-16]
        alu64_x(ALU_MOV, R6, R10),          # 7: leaks sub1 R10 in R6
        stx(BPF_DW, R1, R6, 0),             # 8: ALSO spills sub1 R10 into caller's stack[-8]
        alu64_k(ALU_MOV, R0, 0),            # 9
        exit_insn(),                        # 10
    ]

    # Issue 3C: Pure caller-stack-spill escape (R0=0, R6 untouched, sub1 R10 spilled into caller stack!)
    s3c = [
        alu64_x(ALU_MOV, R1, R10),          # 0
        alu64_k(ALU_ADD, R1, -8),           # 1: r1 = &caller_stack[-8]
        call_rel(3),                        # 2 -> call sub1 (pc=6)
        ldx(BPF_DW, R2, R10, -8),           # 3: reload escaped sub1 R10 from caller stack!
        ldx(BPF_DW, R0, R2, -16),           # 4: UAF read on freed sub1 stack!
        exit_insn(),                        # 5
        st_imm(BPF_DW, R10, -16, 0x77),     # 6
        alu64_x(ALU_MOV, R2, R10),          # 7: r2 = sub1 R10 (caller-saved scratch)
        stx(BPF_DW, R1, R2, 0),             # 8: spill sub1 R10 into caller stack[-8]!
        alu64_k(ALU_MOV, R0, 0),            # 9
        exit_insn(),                        # 10
    ]

    # Issue 4A: HELPER_PKT_RESIZE forgets spilled REG_PKT_PTR in same frame stack
    s4a = [
        alu64_x(ALU_MOV, R6, R1),
        ldx(BPF_DW, R2, R6, CTX_PKT_LEN),
        jmp64_k(JMP_JGE, R2, 16, 2),
        alu64_k(ALU_MOV, R0, 0),
        exit_insn(),
        ldx(BPF_DW, R3, R6, CTX_DATA),
        stx(BPF_DW, R10, R3, -8),           # spill old REG_PKT_PTR to [R10 - 8]
        alu64_x(ALU_MOV, R1, R6),
        alu64_k(ALU_MOV, R2, 64),
        call_helper(HELPER_PKT_RESIZE),     # frees old_pkt!
        ldx(BPF_DW, R4, R10, -8),           # reloads stale old_pkt pointer!
        ldx(BPF_DW, R0, R4, 0),             # UAF read on freed old_pkt!
        exit_insn(),
    ]

    # Issue 4B: HELPER_PKT_RESIZE called inside subprogram forgets spilled REG_PKT_PTR in caller frame stack!
    s4b = [
        alu64_x(ALU_MOV, R6, R1),           # 0: r6 = ctx
        ldx(BPF_DW, R2, R6, CTX_PKT_LEN),   # 1
        jmp64_k(JMP_JGE, R2, 16, 2),        # 2
        alu64_k(ALU_MOV, R0, 0),            # 3
        exit_insn(),                        # 4
        ldx(BPF_DW, R3, R6, CTX_DATA),      # 5: r3 = old pkt
        stx(BPF_DW, R10, R3, -8),           # 6: spill old pkt in caller frame 0 stack!
        alu64_x(ALU_MOV, R1, R6),           # 7: r1 = ctx
        call_rel(3),                        # 8 -> call sub_resize (pc=12)
        ldx(BPF_DW, R4, R10, -8),           # 9: reload stale old_pkt from frame 0 stack!
        ldx(BPF_DW, R0, R4, 0),             # 10: UAF read on freed old_pkt!
        exit_insn(),                        # 11
        # sub_resize (pc 12..15)
        alu64_k(ALU_MOV, R2, 64),           # 12
        call_helper(HELPER_PKT_RESIZE),     # 13: frees old_pkt inside frame 1!
        alu64_k(ALU_MOV, R0, 0),            # 14
        exit_insn(),                        # 15
    ]

    pkt16 = b"0123456789abcdef"
    maps_64 = [(4, 64, 2)]
    return [
        ("s1a_alu32_mov_arsh64_oob", s1a, maps_64, pkt16, []),
        ("s1b_jmp32_jslt_deadbranch_oob", s1b, maps_64, s1b_pkt, []),
        ("s2a_pruning_idx_umax_oob", s2a, maps_64, s2a_pkt, []),
        ("s2b_partial_spill_write_lo", s2b, maps_64, pkt16, []),
        ("s2c_partial_spill_write_hi", s2c, maps_64, pkt16, []),
        ("s3a_subprog_r0_stack_escape", s3a, [], pkt16, []),
        ("s3b_subprog_r6_stack_escape", s3b, [], pkt16, []),
        ("s3c_subprog_caller_spill_escape", s3c, [], pkt16, []),
        ("s4a_pkt_resize_same_frame_spill", s4a, [], pkt16, []),
        ("s4b_pkt_resize_caller_frame_spill", s4b, [], pkt16, []),
    ]


def verify(app_dir: Path, orig_dir: Path) -> tuple[bool, dict[str, object]]:
    details: dict[str, object] = {}

    ok_rep, msg_rep = check_report(app_dir)
    details["report"] = {"passed": ok_rep, "message": msg_rep}
    if not ok_rep:
        return False, details

    makefile = app_dir / "Makefile"
    if not makefile.is_file() or "-fsanitize=address,undefined" not in makefile.read_text(encoding="utf-8"):
        details["makefile"] = {"passed": False, "message": "Makefile missing or sanitizer flags altered"}
        return False, details

    cc, use_san = detect_san_compiler()
    details["toolchain"] = {"compiler": cc, "sanitizers": use_san}

    with tempfile.TemporaryDirectory() as tmp_str:
        tmp = Path(tmp_str)

        # 1. Clean rebuild and test on isolated copy of /app (plus check /app/build/bpf_cli)
        build_app = run_cmd_safe(["make", "-C", str(app_dir), "clean", "all", "test"], timeout=90.0)
        if build_app.returncode != 0 or did_sanitizer_or_crash(build_app):
            details["app_build_and_test"] = {
                "passed": False,
                "rc": build_app.returncode,
                "output": (build_app.stdout + "\n" + build_app.stderr)[-1200:],
            }
            return False, details

        app_cli = app_dir / "build" / "bpf_cli"
        if not app_cli.is_file() or not os.access(app_cli, os.X_OK):
            details["app_build_and_test"] = {"passed": False, "message": "Missing executable /app/build/bpf_cli"}
            return False, details
        if use_san and not binary_has_asan(app_cli):
            details["app_build_and_test"] = {
                "passed": False,
                "message": "/app/build/bpf_cli was not linked with AddressSanitizer (__asan_init missing)",
            }
            return False, details
        details["app_build_and_test"] = {"passed": True, "message": "make clean all test succeeded with ASan/UBSan"}

        # 2. Verify agent's updated /app/tests fails against unmodified orig_app
        orig_check = tmp / "orig_with_agent_tests"
        shutil.copytree(orig_dir, orig_check, ignore=shutil.ignore_patterns("build"))
        if (app_dir / "tests").is_dir():
            shutil.rmtree(orig_check / "tests", ignore_errors=True)
            shutil.copytree(app_dir / "tests", orig_check / "tests")
        orig_test_run = run_cmd_safe(["make", "-C", str(orig_check), "clean", "all", "test"], timeout=60.0)
        if orig_test_run.returncode == 0 and not did_sanitizer_or_crash(orig_test_run):
            details["regression_tests"] = {
                "passed": False,
                "message": "Agent tests in /app/tests passed on unmodified original code (missing regression coverage)",
            }
            return False, details
        details["regression_tests"] = {
            "passed": True,
            "message": "Agent tests pass on updated /app and fail on unmodified orig_app",
        }

        # 3. Compile fresh orig_cli and patched_cli directly from sources
        orig_cli = tmp / "orig_bpf_cli"
        patched_cli = tmp / "patched_bpf_cli"
        try:
            compile_cli_from_tree(orig_dir, orig_cli, cc=cc, use_san=use_san)
            compile_cli_from_tree(app_dir, patched_cli, cc=cc, use_san=use_san)
        except RuntimeError as exc:
            details["verifier_compile"] = {"passed": False, "message": str(exc)}
            return False, details

        # 4. Run rich legitimate suite and verify exact parity with reference execution
        legit_suite_file = tmp / "legit_suite.bin"
        legit_cases = build_legitimate_cases()
        legit_suite_file.write_bytes(pack_suite(legit_cases))

        ref_legit = run_cmd_safe([str(orig_cli), "--strict", str(legit_suite_file)])
        got_legit = run_cmd_safe([str(patched_cli), "--strict", str(legit_suite_file)])
        got_app_cli = run_cmd_safe([str(app_cli), "--strict", str(legit_suite_file)])

        if (
            ref_legit.returncode != 0
            or did_sanitizer_or_crash(ref_legit)
            or got_legit.returncode != 0
            or did_sanitizer_or_crash(got_legit)
            or got_legit.stdout != ref_legit.stdout
            or got_app_cli.returncode != 0
            or got_app_cli.stdout != ref_legit.stdout
        ):
            details["legitimate_programs"] = {
                "passed": False,
                "expected_stdout": ref_legit.stdout,
                "patched_stdout": got_legit.stdout,
                "patched_stderr": got_legit.stderr[:500],
            }
            return False, details
        details["legitimate_programs"] = {
            "passed": True,
            "cases_verified": len(legit_cases),
            "message": "All valid ALU32/64, diamond-CFG, nested-call, map, and pkt_resize programs verified & matched exact digests",
        }

        # 5. Run all 10 soundness cases across all 4 bug families (both confirming orig_app failure & patched rejection)
        for case_tuple in build_soundness_cases():
            cname = case_tuple[0]
            cfile = tmp / f"{cname}.bin"
            cfile.write_bytes(pack_suite([case_tuple]))

            # Confirm orig_app accepted the unsound program and triggered ASan / crash
            orig_res = run_cmd_safe([str(orig_cli), str(cfile)], timeout=15.0)
            orig_falsely_accepted_and_crashed = (
                "verify=REJECT" not in orig_res.stdout and did_sanitizer_or_crash(orig_res)
            )
            if not orig_falsely_accepted_and_crashed:
                details["soundness_suite"] = {
                    "passed": False,
                    "case": cname,
                    "message": "Internal baseline sanity failure on orig_app",
                    "orig_rc": orig_res.returncode,
                    "orig_stdout": orig_res.stdout,
                    "orig_stderr": orig_res.stderr[:400],
                }
                return False, details

            # Patched binary must cleanly reject in bpf_verify_program() with zero sanitizer errors
            patched_res = run_cmd_safe([str(patched_cli), str(cfile)], timeout=15.0)
            patched_strict = run_cmd_safe([str(patched_cli), "--strict", str(cfile)], timeout=15.0)
            expected_prefix = f"case=0 name={cname} verify=REJECT "
            if (
                did_sanitizer_or_crash(patched_res)
                or patched_res.returncode != 0
                or not patched_res.stdout.startswith(expected_prefix)
                or did_sanitizer_or_crash(patched_strict)
                or patched_strict.returncode != 1
            ):
                details["soundness_suite"] = {
                    "passed": False,
                    "case": cname,
                    "rc": patched_res.returncode,
                    "stdout": patched_res.stdout,
                    "stderr": patched_res.stderr[:500],
                }
                return False, details

        details["soundness_suite"] = {
            "passed": True,
            "cases_checked": 10,
            "message": "All 10 soundness adversarial bytecode programs across all 4 invariant families cleanly rejected",
        }

    return True, details


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--app-dir", default=os.environ.get("APP_DIR", "/app"))
    parser.add_argument("--reward-dir", default=os.environ.get("REWARD_DIR", "/logs/verifier"))
    args = parser.parse_args()

    app_dir = Path(args.app_dir).resolve()
    reward_dir = Path(args.reward_dir).resolve()
    orig_dir = Path(__file__).resolve().parent / "orig_app"
    reward_dir.mkdir(parents=True, exist_ok=True)

    passed, details = verify(app_dir, orig_dir)
    out = {"passed": passed, "details": details}
    (reward_dir / "details.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    print(json.dumps(out, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
