#!/usr/bin/env python3
"""Deterministic ASan/UBSan + protocol-state verifier for task: cpp-quic-stream-mux."""

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

WIRE_MAGIC = 0x58554D51
WIRE_VERSION = 1

FLAG_AUTO_CREDIT = 0x01
FLAG_ENFORCE_POLICY = 0x02

FT_STREAM = 0x01
FT_RESET_STREAM = 0x02
FT_STOP_SENDING = 0x03
FT_MAX_DATA = 0x04
FT_MAX_STREAMS = 0x05
FT_STREAM_DATA_BLOCKED = 0x06
FT_TICK_TIMER = 0x07
FT_CONN_CLOSE = 0x08

ACCEPTED_FILES = {
    "mux_engine.hpp",
    "connection.cpp",
    "stream.cpp",
    "reassembler.cpp",
    "flow_control.cpp",
    "timer_wheel.cpp",
    "wire_codec.cpp",
}


def fnv1a_64(data: bytes) -> int:
    h = 14695981039346656037
    for b in data:
        h ^= b
        h = (h * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return h


def expected_mux_digest(completed_streams: list[tuple[int, bytes]]) -> str:
    buf = bytearray()
    for stream_id, payload in sorted(completed_streams, key=lambda item: item[0]):
        buf += struct.pack("<QQQ", stream_id, len(payload), fnv1a_64(payload))
    return f"{fnv1a_64(bytes(buf)):016x}"


def pack_script(
    frames: list[bytes],
    *,
    local_role: int = 1,
    flags: int = FLAG_AUTO_CREDIT,
    max_data: int = 65536,
    max_stream_bidi: int = 16384,
    max_stream_uni: int = 16384,
    max_streams_bidi: int = 2,
    max_streams_uni: int = 2,
    drain_timeout_ms: int = 200,
    denied_tag: int = 0,
) -> bytes:
    header = struct.pack(
        "<IHBBQQQIIIII",
        WIRE_MAGIC,
        WIRE_VERSION,
        local_role,
        flags,
        max_data,
        max_stream_bidi,
        max_stream_uni,
        max_streams_bidi,
        max_streams_uni,
        drain_timeout_ms,
        denied_tag,
        len(frames),
    )
    return header + b"".join(frames)


def f_stream(stream_id: int, offset: int, payload: bytes, fin: bool = False) -> bytes:
    return struct.pack("<BBQQI", FT_STREAM, 1 if fin else 0, stream_id, offset, len(payload)) + payload


def f_reset(stream_id: int, err_code: int, final_size: int) -> bytes:
    return struct.pack("<BBQQQ", FT_RESET_STREAM, 0, stream_id, err_code, final_size)


def f_stop_sending(stream_id: int, err_code: int, local: bool = False) -> bytes:
    return struct.pack("<BBQQ", FT_STOP_SENDING, 1 if local else 0, stream_id, err_code)


def f_max_data(limit: int, peer: bool = False) -> bytes:
    return struct.pack("<BBQ", FT_MAX_DATA, 1 if peer else 0, limit)


def f_max_streams(limit: int, uni: bool = False) -> bytes:
    return struct.pack("<BBQ", FT_MAX_STREAMS, 1 if uni else 0, limit)


def f_blocked(stream_id: int, limit: int, auto_grant: bool = False) -> bytes:
    return struct.pack("<BBQQ", FT_STREAM_DATA_BLOCKED, 1 if auto_grant else 0, stream_id, limit)


def f_tick(delta_ms: int) -> bytes:
    return struct.pack("<BBQ", FT_TICK_TIMER, 0, delta_ms)


def f_close(err_code: int = 0, reason: bytes = b"", app: bool = False) -> bytes:
    return struct.pack("<BBQI", FT_CONN_CLOSE, 1 if app else 0, err_code, len(reason)) + reason


def supports_asan() -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        cpp = Path(tmp) / "probe.cpp"
        out = Path(tmp) / "probe"
        cpp.write_text("int main(){return 0;}\n", encoding="utf-8")
        res = subprocess.run(
            ["g++", "-std=c++20", "-fsanitize=address,undefined", str(cpp), "-o", str(out)],
            capture_output=True,
        )
        return res.returncode == 0


def binary_has_sanitizer(bin_path: Path) -> bool:
    raw = bin_path.read_bytes()
    return (b"__asan_" in raw or b"libasan" in raw) and (b"__ubsan_" in raw or b"libubsan" in raw)


def compile_verified_cli(app_dir: Path, out_bin: Path, use_asan: bool) -> None:
    src_dir = app_dir / "src"
    inc_dir = app_dir / "include"
    cpp_files = sorted(str(p) for p in src_dir.glob("*.cpp"))
    if not cpp_files:
        raise RuntimeError(f"No C++ source files found in {src_dir}")

    cmd = ["g++", "-std=c++20", "-Wall", "-Wextra", "-O1", "-g", f"-I{inc_dir}"]
    if use_asan:
        cmd += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
    else:
        cmd += ["-fno-omit-frame-pointer"]
    cmd += cpp_files + ["-o", str(out_bin)]

    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"Verifier compilation failed:\n{res.stderr}")


def _disable_core_dumps() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def run_cli(bin_path: Path, script_file: Path) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "detect_leaks=0:exitcode=99:abort_on_error=0"
    env["UBSAN_OPTIONS"] = "print_stacktrace=1:exitcode=98"
    env["MALLOC_PERTURB_"] = "170"
    env["GLIBC_TUNABLES"] = "glibc.malloc.perturb=170"
    return subprocess.run(
        [str(bin_path), str(script_file)],
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
    err = proc.stderr
    return (
        "AddressSanitizer" in err
        or "UndefinedBehaviorSanitizer" in err
        or "runtime error:" in err
        or "Segmentation fault" in err
    )


def parse_kv_line(stdout: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for tok in stdout.strip().split():
        if "=" in tok:
            k, v = tok.split("=", 1)
            fields[k] = v
    return fields


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

    raw_file_blobs: list[str] = []
    if "files" in data:
        files_val = data["files"]
        if isinstance(files_val, list):
            raw_file_blobs.extend(str(item) for item in files_val)
        else:
            raw_file_blobs.append(str(files_val))
    if "file" in data:
        raw_file_blobs.append(str(data["file"]))

    text_chunks: list[str] = []
    if isinstance(data.get("summary"), str) and data["summary"].strip():
        text_chunks.append(data["summary"].strip())

    findings = data.get("findings")
    if isinstance(findings, list):
        for item in findings:
            if isinstance(item, str) and item.strip():
                text_chunks.append(item.strip())
            elif isinstance(item, dict):
                for fk in ("file", "files", "path", "location"):
                    if fk in item:
                        raw_file_blobs.append(str(item[fk]))
                for tk in ("summary", "description", "finding", "detail", "issue", "message"):
                    if tk in item and str(item[tk]).strip():
                        text_chunks.append(str(item[tk]).strip())
                if not text_chunks:
                    text_chunks.append(json.dumps(item))
    elif isinstance(findings, str) and findings.strip():
        text_chunks.append(findings.strip())

    joined_files = " ".join(raw_file_blobs)
    file_tokens = {Path(tok).name for tok in re.findall(r"[\w./-]+\.(?:cpp|hpp|h|cc)", joined_files)}
    if not file_tokens:
        joined_all = " ".join(text_chunks)
        file_tokens = {Path(tok).name for tok in re.findall(r"[\w./-]+\.(?:cpp|hpp|h|cc)", joined_all)}

    if not (file_tokens & ACCEPTED_FILES):
        return False, f"Report does not cite any target engine source/header file from {sorted(ACCEPTED_FILES)}"

    combined_text = " ".join(text_chunks).strip()
    if len(combined_text) < 20:
        return False, "Report findings/summary text is missing or too brief"

    return True, f"Valid report referencing {sorted(file_tokens & ACCEPTED_FILES)}"


def verify(app_dir: Path) -> tuple[bool, dict[str, object]]:
    results: dict[str, object] = {}

    ok_rep, msg_rep = check_report(app_dir)
    results["report"] = {"passed": ok_rep, "message": msg_rep}
    if not ok_rep:
        return False, results

    app_bin = app_dir / "build" / "mux_cli"
    if not app_bin.is_file():
        results["build"] = {"passed": False, "message": "Missing /app/build/mux_cli"}
        return False, results

    rebuild = subprocess.run(["make", "-C", str(app_dir), "clean", "all"], capture_output=True, text=True)
    if rebuild.returncode != 0 or not app_bin.is_file():
        results["build"] = {
            "passed": False,
            "message": f"make -C /app clean all failed (rc={rebuild.returncode}):\n{rebuild.stderr[:400]}",
        }
        return False, results

    use_asan = supports_asan()
    results["asan_enabled"] = use_asan
    if use_asan and not binary_has_sanitizer(app_bin):
        results["build"] = {
            "passed": False,
            "message": "/app/build/mux_cli is missing AddressSanitizer/UBSan instrumentation",
        }
        return False, results

    with tempfile.TemporaryDirectory() as tmp_str:
        tmp = Path(tmp_str)
        patched_bin = tmp / "verified_mux_cli"
        try:
            compile_verified_cli(app_dir, patched_bin, use_asan=use_asan)
        except RuntimeError as exc:
            results["build"] = {"passed": False, "message": str(exc)}
            return False, results

        results["build"] = {"passed": True, "message": "Rebuilt mux_cli cleanly with required instrumentation"}

        deny_tag = int.from_bytes(b"DENY", "little")

        # 1. Functional parity suite
        p_s0 = b"Alpha-Bidi-Stream-Zero"
        p_s4 = b"Bravo-Bidi-Stream-Four!!"
        p_s2 = b"Charlie-Uni-Stream-Two"
        script_f1 = pack_script(
            [
                f_stream(0, 0, p_s0[:10], fin=False),
                f_stream(2, 0, p_s2[:12], fin=False),
                f_stream(4, 0, p_s4, fin=True),
                f_stream(0, 10, p_s0[10:], fin=True),
                f_stream(2, 12, p_s2[12:], fin=True),
            ],
            max_streams_bidi=2,
            max_streams_uni=2,
        )

        p_ooo = b"0123456789abcdefghijABCDEFGHIJklmnop"
        script_f2 = pack_script(
            [
                f_stream(0, 24, p_ooo[24:36], fin=False),
                f_stream(0, 12, p_ooo[12:24], fin=False),
                f_stream(4, 0, b"", fin=True),
                f_stream(0, 0, p_ooo[0:12], fin=False),
                f_stream(0, 36, b"", fin=True),
            ],
            max_streams_bidi=3,
        )

        p_dup = b"RetransmitCheck123"
        p_bridge2 = b"ABCDEFGHIJKLMNOP"
        p_bridge3 = b"0123456789abcdefghij"
        script_f3 = pack_script(
            [
                # Stream 0: duplicate, left-overlap, and interior subset retransmissions
                f_stream(0, 0, p_dup[0:8], fin=False),
                f_stream(0, 0, p_dup[0:8], fin=False),
                f_stream(0, 10, p_dup[10:18], fin=True),
                f_stream(0, 4, p_dup[4:12], fin=False),
                f_stream(0, 6, p_dup[6:14], fin=False),
                # Stream 4: two buffered islands [4,8) and [12,16) bridged by [2,14), then [0,2)
                f_stream(4, 4, p_bridge2[4:8], fin=False),
                f_stream(4, 12, p_bridge2[12:16], fin=True),
                f_stream(4, 2, p_bridge2[2:14], fin=False),
                f_stream(4, 0, p_bridge2[0:2], fin=False),
                # Stream 8: three buffered islands [3,6), [9,12), [15,20) bridged by [1,17), then [0,1)
                f_stream(8, 3, p_bridge3[3:6], fin=False),
                f_stream(8, 9, p_bridge3[9:12], fin=False),
                f_stream(8, 15, p_bridge3[15:20], fin=True),
                f_stream(8, 1, p_bridge3[1:17], fin=False),
                f_stream(8, 0, p_bridge3[0:1], fin=False),
            ],
            max_streams_bidi=3,
        )

        # Peer STOP_SENDING followed by valid RESET_STREAM on stream 0, and upload completion on stream 4 & 8
        p_half4 = b"HELLO WORLD"
        p_half8 = b"CREDIT_REPLENISHED"
        script_f4 = pack_script(
            [
                f_stream(0, 0, b"DATA", fin=False),
                f_stop_sending(0, 3, local=False),
                f_reset(0, 5, 6),
                f_stream(4, 0, b"HELLO", fin=False),
                f_stop_sending(4, 3, local=False),
                f_stream(4, 5, b" WORLD", fin=True),
                f_stream(8, 0, p_half8, fin=True),
            ],
            max_streams_bidi=2,
        )

        # Local policy reject + peer RESET_STREAM before drain expiry + TICK_TIMER + subsequent streams + CONN_CLOSE
        p_ok4 = b"OKAY_ONE"
        p_ok8 = b"OKAY_TWO"
        script_f5 = pack_script(
            [
                f_stream(0, 0, b"DENY_RPC", fin=False),
                f_reset(0, 1, 8),
                f_stream(4, 0, p_ok4, fin=True),
                f_tick(250),
                f_stream(8, 0, p_ok8, fin=True),
                f_close(0, b"clean"),
            ],
            flags=FLAG_AUTO_CREDIT | FLAG_ENFORCE_POLICY,
            max_streams_bidi=2,
            drain_timeout_ms=200,
            denied_tag=deny_tag,
        )

        # Local policy reject with NO peer RESET_STREAM -> retired via drain timer expiry on TICK_TIMER
        script_f6 = pack_script(
            [
                f_stream(0, 0, b"DENY_SILENT", fin=False),
                f_tick(250),
                f_stream(4, 0, p_ok4, fin=True),
                f_stream(8, 0, p_ok8, fin=True),
            ],
            flags=FLAG_AUTO_CREDIT | FLAG_ENFORCE_POLICY,
            max_streams_bidi=2,
            drain_timeout_ms=200,
            denied_tag=deny_tag,
        )

        # Window updates (MAX_DATA, MAX_STREAMS, STREAM_DATA_BLOCKED auto-grant) + implicit stream opening
        p_imp0 = b"ImplicitZero"
        p_imp4 = b"ExpandedStreamWindowPayload!"
        script_f7 = pack_script(
            [
                f_max_data(128, peer=False),
                f_max_streams(3, uni=False),
                f_stream(4, 0, p_imp4[:8], fin=False),
                f_blocked(4, 64, auto_grant=True),
                f_stream(4, 8, p_imp4[8:], fin=True),
                f_blocked(0, 32, auto_grant=True),
                f_stream(0, 0, p_imp0, fin=True),
            ],
            flags=FLAG_AUTO_CREDIT,
            max_data=32,
            max_stream_bidi=8,
            max_streams_bidi=1,
        )

        functional_cases = [
            (
                "f1_inorder_multiplex_bidi_uni",
                script_f1,
                expected_mux_digest([(0, p_s0), (2, p_s2), (4, p_s4)]),
                {"completed": "3", "retired": "3", "conn_recv": str(len(p_s0) + len(p_s4) + len(p_s2)), "max_bidi": "4", "max_uni": "3", "drains": "0"},
            ),
            (
                "f2_ooo_reassembly_and_zero_len_fin",
                script_f2,
                expected_mux_digest([(0, p_ooo), (4, b"")]),
                {"completed": "2", "retired": "2", "conn_recv": str(len(p_ooo)), "max_bidi": "5", "drains": "0"},
            ),
            (
                "f3_retransmissions_and_bridge_overlaps",
                script_f3,
                expected_mux_digest([(0, p_dup), (4, p_bridge2), (8, p_bridge3)]),
                {"completed": "3", "retired": "3", "conn_recv": str(len(p_dup) + len(p_bridge2) + len(p_bridge3)), "max_bidi": "6", "drains": "0"},
            ),
            (
                "f4_peer_stop_sending_half_close_and_reset",
                script_f4,
                expected_mux_digest([(4, p_half4), (8, p_half8)]),
                {"completed": "2", "retired": "3", "conn_recv": str(6 + len(p_half4) + len(p_half8)), "max_bidi": "5", "drains": "0"},
            ),
            (
                "f5_local_policy_reject_then_peer_reset_before_drain",
                script_f5,
                expected_mux_digest([(4, p_ok4), (8, p_ok8)]),
                {"completed": "2", "retired": "3", "conn_recv": "24", "max_bidi": "5", "drains": "0"},
            ),
            (
                "f6_local_policy_reject_drain_timeout_expiry",
                script_f6,
                expected_mux_digest([(4, p_ok4), (8, p_ok8)]),
                {"completed": "2", "retired": "3", "conn_recv": "27", "max_bidi": "5", "drains": "1"},
            ),
            (
                "f7_control_frames_and_implicit_open",
                script_f7,
                expected_mux_digest([(0, p_imp0), (4, p_imp4)]),
                {"completed": "2", "retired": "2", "conn_recv": str(len(p_imp0) + len(p_imp4)), "max_bidi": "5", "drains": "0"},
            ),
        ]

        for label, blob, exp_hash, exp_fields in functional_cases:
            f_path = tmp / f"{label}.qmux"
            f_path.write_bytes(blob)
            proc = run_cli(patched_bin, f_path)
            if did_crash(proc) or proc.returncode != 0:
                results["functional"] = {
                    "passed": False,
                    "message": f"Valid case '{label}' failed/crashed (rc={proc.returncode}): out={proc.stdout!r} err={proc.stderr[:300]!r}",
                }
                return False, results

            kv = parse_kv_line(proc.stdout)
            if kv.get("status") != "ok" or kv.get("fnv1a") != exp_hash:
                results["functional"] = {
                    "passed": False,
                    "message": f"Valid case '{label}' digest mismatch (expected fnv1a={exp_hash}, got {proc.stdout.strip()!r})",
                }
                return False, results

            for k, v in exp_fields.items():
                if kv.get(k) != v:
                    results["functional"] = {
                        "passed": False,
                        "message": f"Valid case '{label}' counter '{k}' mismatch (expected {v}, got {kv.get(k)!r} in {proc.stdout.strip()!r})",
                    }
                    return False, results

        results["functional"] = {
            "passed": True,
            "message": f"All {len(functional_cases)} functional multiplex/reassembly/half-close/drain tests matched exact digests and counters",
        }

        # 2. Adversarial protocol & memory-safety suite (all must exit 1 cleanly without crashing)
        adversarial_cases = [
            (
                "a1_reject_unreset_concurrency_limit",
                pack_script(
                    [
                        f_stream(0, 0, b"DENY1234", fin=False),
                        f_stream(4, 0, b"ACTIVE_1", fin=False),
                        f_stream(8, 0, b"OVER_LIM", fin=False),
                    ],
                    flags=FLAG_AUTO_CREDIT | FLAG_ENFORCE_POLICY,
                    max_streams_bidi=2,
                    denied_tag=deny_tag,
                ),
            ),
            (
                "a2_reject_plus_reset_double_credit_overflow",
                pack_script(
                    [
                        f_stream(0, 0, b"DENY1234", fin=False),
                        f_reset(0, 1, 8),
                        f_stream(4, 0, b"ACTIVE_1", fin=False),
                        f_tick(250),
                        f_stream(8, 0, b"ACTIVE_2", fin=False),
                        f_stream(12, 0, b"ACTIVE_3", fin=False),
                    ],
                    flags=FLAG_AUTO_CREDIT | FLAG_ENFORCE_POLICY,
                    max_streams_bidi=2,
                    denied_tag=deny_tag,
                ),
            ),
            (
                "a3_explicit_local_stop_sending_reset_uaf_and_limit",
                pack_script(
                    [
                        f_stream(0, 0, b"HELLO", fin=False),
                        f_stop_sending(0, 42, local=True),
                        f_reset(0, 42, 5),
                        f_stream(4, 0, b"ACTIVE_1", fin=False),
                        f_tick(250),
                        f_stream(8, 0, b"ACTIVE_2", fin=False),
                        f_stream(12, 0, b"ACTIVE_3", fin=False),
                    ],
                    flags=FLAG_AUTO_CREDIT,
                    max_streams_bidi=2,
                ),
            ),
            (
                "a4_reset_smaller_than_highest_conn_window_underflow",
                pack_script(
                    [
                        f_stream(0, 0, b"A" * 600, fin=False),
                        f_reset(0, 1, 100),
                        f_stream(4, 0, b"B" * 800, fin=True),
                    ],
                    flags=FLAG_AUTO_CREDIT,
                    max_data=1000,
                    max_stream_bidi=1024,
                    max_streams_bidi=2,
                ),
            ),
            (
                "a5_ooo_fin_then_reset_changes_final_size_upward",
                pack_script(
                    [
                        f_stream(0, 100, b"Z" * 20, fin=True),
                        f_reset(0, 1, 200),
                    ],
                    max_streams_bidi=2,
                ),
            ),
            (
                "a6_ooo_fin_then_reset_changes_final_size_downward",
                pack_script(
                    [
                        f_stream(0, 100, b"Z" * 20, fin=True),
                        f_reset(0, 1, 110),
                    ],
                    max_streams_bidi=2,
                ),
            ),
            (
                "a7_ooo_segment_then_fin_below_highest",
                pack_script(
                    [
                        f_stream(0, 80, b"X" * 40, fin=False),
                        f_stream(0, 0, b"Y" * 50, fin=True),
                    ],
                    max_streams_bidi=2,
                ),
            ),
            (
                "a8_stream_offset_plus_len_u64_wrap",
                pack_script(
                    [
                        f_stream(0, 0xFFFFFFFFFFFFFFFC, b"12345678", fin=False),
                    ],
                    max_streams_bidi=2,
                ),
            ),
            (
                "a9_stream_offset_exceeds_quic_varint_62bit",
                pack_script(
                    [
                        f_stream(0, (1 << 62) - 2, b"12345678", fin=False),
                    ],
                    max_data=(1 << 62) - 1,
                    max_stream_bidi=(1 << 62) - 1,
                    max_streams_bidi=2,
                ),
            ),
            (
                "a10_conn_max_data_exceeded",
                pack_script(
                    [
                        f_stream(0, 0, b"A" * 40, fin=True),
                        f_stream(4, 0, b"B" * 40, fin=True),
                    ],
                    max_data=64,
                    max_stream_bidi=64,
                    max_streams_bidi=2,
                ),
            ),
            (
                "a11_peer_stream_on_server_uni",
                pack_script(
                    [
                        f_stream(3, 0, b"INVALID_DIR", fin=True),
                    ],
                    max_streams_bidi=2,
                    max_streams_uni=2,
                ),
            ),
            (
                "a12_peer_stop_sending_on_peer_uni",
                pack_script(
                    [
                        f_stream(2, 0, b"UNI_DATA", fin=False),
                        f_stop_sending(2, 7, local=False),
                    ],
                    max_streams_bidi=2,
                    max_streams_uni=2,
                ),
            ),
        ]

        for label, blob in adversarial_cases:
            f_bad = tmp / f"{label}.qmux"
            f_bad.write_bytes(blob)
            proc = run_cli(patched_bin, f_bad)
            if did_crash(proc) or proc.returncode != 1:
                results["adversarial"] = {
                    "passed": False,
                    "message": f"Adversarial case '{label}' was not cleanly rejected (rc={proc.returncode}, crashed={did_crash(proc)}): out={proc.stdout!r} err={proc.stderr[:300]!r}",
                }
                return False, results

        results["adversarial"] = {
            "passed": True,
            "message": f"All {len(adversarial_cases)} adversarial state-machine, credit, and final_size cases cleanly rejected without sanitizer errors",
        }

    return True, results


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--app-dir", default=os.environ.get("APP_DIR", "/app"))
    parser.add_argument("--reward-dir", default=os.environ.get("REWARD_DIR", "/logs/verifier"))
    args = parser.parse_args()

    app_dir = Path(args.app_dir).resolve()
    reward_dir = Path(args.reward_dir)
    reward_dir.mkdir(parents=True, exist_ok=True)

    passed, details = verify(app_dir)
    (reward_dir / "details.json").write_text(json.dumps(details, indent=2), encoding="utf-8")
    print(json.dumps({"passed": passed, "details": details}, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
