#!/usr/bin/env python3
"""Deterministic verifier for task: cpp-http2-hpack-framer."""

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

CORE_FILES = {"hpack_codec.cpp", "hpack_table.cpp", "h2_connection.cpp", "header_validator.cpp", "huffman.cpp"}

HIDDEN_CPP_HARNESS = r"""
#include "h2_framer.hpp"

#include <cassert>
#include <cstdint>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

void check_cond(bool cond, const std::string& msg) {
    if (!cond) {
        throw std::runtime_error(msg);
    }
}

void append_bytes(std::vector<uint8_t>& dst, const std::vector<uint8_t>& src) {
    dst.insert(dst.end(), src.begin(), src.end());
}

std::vector<uint8_t> client_preface_with_settings() {
    std::vector<uint8_t> wire(h2::kClientConnectionPreface.begin(), h2::kClientConnectionPreface.end());
    append_bytes(wire, h2::H2ServerConnection::serialize_frame(h2::FrameType::SETTINGS, 0, 0, {}));
    return wire;
}

void push_hpack_str(std::vector<uint8_t>& out, std::string_view s, bool huff = false) {
    if (huff) {
        auto enc = h2::huffman_encode(s);
        h2::encode_prefixed_int(out, 0x80u, 7, enc.size());
        out.insert(out.end(), enc.begin(), enc.end());
    } else {
        h2::encode_prefixed_int(out, 0x00u, 7, s.size());
        out.insert(out.end(), s.begin(), s.end());
    }
}

// 1. Functional parity: dynamic table indexing, lowered + acknowledged table size update, valid trailers, flow control
void test_group_functional() {
    h2::H2ServerConnection conn;
    std::vector<uint8_t> wire = client_preface_with_settings();

    // Server lowers header table limit to 128 -> peer signals size update 128 at start of next HEADERS block
    conn.set_local_header_table_limit(128);
    std::vector<uint8_t> hb1;
    h2::encode_prefixed_int(hb1, 0x20u, 5, 128);  // Dynamic Table Size Update = 128
    auto req1 = h2::HpackEncoder::encode_literal_block(
        {
            {":method", "POST"},
            {":scheme", "https"},
            {":authority", "edge.internal"},
            {":path", "/v2/upload"},
            {"te", "trailers"},
            {"content-length", "5"},
            {"x-custom-long-header-alpha", "value-1"},
        },
        true,
        true);
    append_bytes(hb1, req1);
    append_bytes(wire, h2::H2ServerConnection::serialize_frame(h2::FrameType::HEADERS, h2::FrameFlags::END_HEADERS, 1, hb1));
    append_bytes(wire, h2::H2ServerConnection::serialize_frame(h2::FrameType::DATA, 0, 1, {'h', 'e', 'l', 'l', 'o'}));
    auto tr1 = h2::HpackEncoder::encode_literal_block({{"x-checksum", "ok"}}, false, true);
    append_bytes(
        wire,
        h2::H2ServerConnection::serialize_frame(
            h2::FrameType::HEADERS,
            h2::FrameFlags::END_HEADERS | h2::FrameFlags::END_STREAM,
            1,
            tr1));

    // Server shrinks to 64 then raises to 192 -> RFC 7541 §4.2 peer emits 64 then 192 at start of next block
    check_cond(conn.receive_bytes(wire) == h2::ErrorCode::NO_ERROR, "Valid stream 1 failed");
    conn.set_local_header_table_limit(64);
    conn.set_local_header_table_limit(192);

    std::vector<uint8_t> hb3;
    h2::encode_prefixed_int(hb3, 0x20u, 5, 64);
    h2::encode_prefixed_int(hb3, 0x20u, 5, 192);
    auto req3 = h2::HpackEncoder::encode_literal_block(
        {
            {":method", "GET"},
            {":scheme", "https"},
            {":authority", "edge.internal"},
            {":path", "/v2/status"},
            {"host", "EDGE.INTERNAL"},
            {"content-length", "0"},
        },
        true,
        false);
    append_bytes(hb3, req3);
    auto f3 = h2::H2ServerConnection::serialize_frame(
        h2::FrameType::HEADERS,
        h2::FrameFlags::END_HEADERS | h2::FrameFlags::END_STREAM,
        3,
        hb3);
    check_cond(conn.receive_bytes(f3) == h2::ErrorCode::NO_ERROR, "Valid stream 3 after min+max table size update failed");
    check_cond(conn.completed_requests().size() == 2, "Expected 2 completed requests");
    check_cond(conn.completed_requests()[0].body == "hello", "Stream 1 body mismatch");
}

// 2. Defect 1: HPACK Dynamic-Table Self-Eviction Use-After-Free (non-SSO >32-byte header name!)
void test_group_hpack_self_eviction_uaf() {
    // Table max size = 128 bytes.
    // Insert entry with 40-char name (> SSO capacity, heap-allocated!) + 20-char value: cost = 32 + 40 + 20 = 92 bytes.
    h2::HpackDecoder dec(128);
    const std::string long_name = "x-federated- edge-telemetry-correlation-id";  // sanitize space -> valid tchar
    const std::string clean_long_name = "x-federated-edge-telemetry-correlation-id";  // 41 chars
    (void)long_name;

    std::vector<uint8_t> block1;
    block1.push_back(0x40u);  // incremental indexing, literal name
    push_hpack_str(block1, clean_long_name, false);
    push_hpack_str(block1, "first-val-0123456789", false);  // 20 chars -> cost = 32 + 41 + 20 = 93 <= 128

    std::vector<h2::HeaderField> out1;
    check_cond(dec.decode_block(block1.data(), block1.size(), out1) == h2::ErrorCode::NO_ERROR, "Initial dynamic insert failed");
    check_cond(dec.table().dynamic_count() == 1, "Expected 1 dynamic entry");

    // Second block: incremental indexing referencing dynamic index 62 (`clean_long_name`) with 30-char value!
    // New entry cost = 32 + 41 + 30 = 103 <= 128, so inserting it MUST evict entry 62 (93 + 103 > 128)
    // BEFORE pushing the new entry! Under unpatched code, `name_ref` dangles into freed heap memory (ASan UAF)!
    std::vector<uint8_t> block2;
    h2::encode_prefixed_int(block2, 0x40u, 6, 62);  // index 62 = first dynamic table slot
    push_hpack_str(block2, "second-longer-value-0123456789", false);

    std::vector<h2::HeaderField> out2;
    check_cond(dec.decode_block(block2.data(), block2.size(), out2) == h2::ErrorCode::NO_ERROR, "Self-evicting dynamic name reference failed");
    check_cond(out2.size() == 1 && out2[0].name == clean_long_name, "Decoded header name corrupted after self-eviction");
    check_cond(out2[0].value == "second-longer-value-0123456789", "Decoded header value mismatch");
    check_cond(dec.table().lookup(62) != nullptr && dec.table().lookup(62)->name == clean_long_name, "Dynamic slot 62 corrupted");

    // Also verify direct HpackTable::insert ownership safety when `name` aliases an entry evicted by `insert()`
    const auto* slot62 = dec.table().lookup(62);
    check_cond(slot62 != nullptr, "Missing dynamic slot 62 before direct HpackTable::insert check");
    dec.table().insert(slot62->name, "third-direct-evicting-value-012345");
    check_cond(
        dec.table().lookup(62) != nullptr && dec.table().lookup(62)->name == clean_long_name,
        "Direct HpackTable::insert corrupted name string_view upon self-eviction");
}

// 3. Defect 2: HPACK Varint Shift UB & SETTINGS_HEADER_TABLE_SIZE Protocol Ceiling Enforcement
void test_group_hpack_varint_and_table_size_cap() {
    // A: 12-byte continuation varint (`shift` reaches >= 64 if unchecked -> UBSan shift UB!)
    std::vector<uint8_t> bad_varint = {
        0x7fu, 0x81u, 0x81u, 0x81u, 0x81u, 0x81u, 0x81u, 0x81u, 0x81u, 0x81u, 0x81u, 0x01u
    };
    size_t off = 0;
    uint64_t val = 0;
    check_cond(!h2::decode_prefixed_int(bad_varint.data(), bad_varint.size(), off, 7, val), "Overflowing 80-bit HPACK varint was accepted!");

    // Also via HpackDecoder::decode_block -> must return COMPRESSION_ERROR cleanly without UBSan trap
    h2::HpackDecoder dec(256);
    std::vector<h2::HeaderField> out;
    check_cond(
        dec.decode_block(bad_varint.data(), bad_varint.size(), out) == h2::ErrorCode::COMPRESSION_ERROR,
        "Malformed varint in header block did not return COMPRESSION_ERROR");

    // B: Server lowers protocol_max_size to 128; peer first acknowledges 128 validly on stream 1,
    //    then on stream 3 attempts Dynamic Table Size Update = 512 (<= 4096 default, but > 128 protocol_max_size!)
    h2::H2ServerConnection conn1;
    conn1.set_local_header_table_limit(128);
    std::vector<uint8_t> wire1 = client_preface_with_settings();
    std::vector<uint8_t> ack_128;
    h2::encode_prefixed_int(ack_128, 0x20u, 5, 128);
    auto valid_req1 = h2::HpackEncoder::encode_literal_block(
        {{":method", "GET"}, {":scheme", "https"}, {":authority", "edge.internal"}, {":path", "/init"}},
        false,
        false);
    append_bytes(ack_128, valid_req1);
    append_bytes(
        wire1,
        h2::H2ServerConnection::serialize_frame(
            h2::FrameType::HEADERS,
            h2::FrameFlags::END_HEADERS | h2::FrameFlags::END_STREAM,
            1,
            ack_128));
    check_cond(conn1.receive_bytes(wire1) == h2::ErrorCode::NO_ERROR, "Initial 128 size-update stream 1 failed");

    std::vector<uint8_t> oversize_upd;
    h2::encode_prefixed_int(oversize_upd, 0x20u, 5, 512);
    append_bytes(oversize_upd, valid_req1);
    auto f_oversize = h2::H2ServerConnection::serialize_frame(
        h2::FrameType::HEADERS,
        h2::FrameFlags::END_HEADERS | h2::FrameFlags::END_STREAM,
        3,
        oversize_upd);
    check_cond(
        conn1.receive_bytes(f_oversize) == h2::ErrorCode::COMPRESSION_ERROR,
        "Encoder table size update exceeding server protocol_max_size (512 > 128) was accepted!");

    // C: Server lowers protocol_max_size from 4096 -> 64, and peer sends a header block WITHOUT the required <=64 size update!
    h2::H2ServerConnection conn2;
    std::vector<uint8_t> wire2 = client_preface_with_settings();
    check_cond(conn2.receive_bytes(wire2) == h2::ErrorCode::NO_ERROR, "Preface failed");
    conn2.set_local_header_table_limit(64);
    auto no_upd_block = h2::HpackEncoder::encode_literal_block(
        {{":method", "GET"}, {":scheme", "https"}, {":authority", "edge.internal"}, {":path", "/"}},
        true,
        false);
    auto f_no_upd = h2::H2ServerConnection::serialize_frame(
        h2::FrameType::HEADERS,
        h2::FrameFlags::END_HEADERS | h2::FrameFlags::END_STREAM,
        1,
        no_upd_block);
    check_cond(
        conn2.receive_bytes(f_no_upd) == h2::ErrorCode::COMPRESSION_ERROR,
        "Header block omitting mandatory RFC 7541 §4.2 table-size reduction update was accepted!");
}

// 4. Defect 3: CONTINUATION Interleaving, Trailer Pseudo-Header Smuggling, Content-Length Mismatch, & CRLF/NUL Injection
void test_group_continuation_trailers_and_smuggling() {
    // A: PING interleaved between HEADERS (without END_HEADERS) and CONTINUATION must fail with PROTOCOL_ERROR!
    {
        h2::H2ServerConnection conn;
        std::vector<uint8_t> wire = client_preface_with_settings();
        auto hb = h2::HpackEncoder::encode_literal_block(
            {{":method", "GET"}, {":scheme", "https"}, {":authority", "edge.internal"}, {":path", "/ok"}},
            false,
            false);
        std::vector<uint8_t> p1(hb.begin(), hb.begin() + 5);
        std::vector<uint8_t> p2(hb.begin() + 5, hb.end());
        append_bytes(wire, h2::H2ServerConnection::serialize_frame(h2::FrameType::HEADERS, h2::FrameFlags::END_STREAM, 1, p1));
        append_bytes(wire, h2::H2ServerConnection::serialize_frame(h2::FrameType::PING, 0, 0, {1, 2, 3, 4, 5, 6, 7, 8}));
        append_bytes(wire, h2::H2ServerConnection::serialize_frame(h2::FrameType::CONTINUATION, h2::FrameFlags::END_HEADERS, 1, p2));
        check_cond(
            conn.receive_bytes(wire) == h2::ErrorCode::PROTOCOL_ERROR,
            "PING interleaved during open CONTINUATION header block was accepted!");
    }

    // B: Trailing HEADERS containing `:path` pseudo-header must fail with PROTOCOL_ERROR!
    {
        h2::H2ServerConnection conn;
        std::vector<uint8_t> wire = client_preface_with_settings();
        auto init_h = h2::HpackEncoder::encode_literal_block(
            {{":method", "POST"}, {":scheme", "https"}, {":authority", "edge.internal"}, {":path", "/public/echo"}, {"te", "trailers"}},
            false,
            false);
        append_bytes(wire, h2::H2ServerConnection::serialize_frame(h2::FrameType::HEADERS, h2::FrameFlags::END_HEADERS, 1, init_h));
        append_bytes(wire, h2::H2ServerConnection::serialize_frame(h2::FrameType::DATA, 0, 1, {'a', 'b'}));
        auto smuggled_tr = h2::HpackEncoder::encode_literal_block({{":path", "/internal/admin"}}, false, false);
        append_bytes(
            wire,
            h2::H2ServerConnection::serialize_frame(
                h2::FrameType::HEADERS,
                h2::FrameFlags::END_HEADERS | h2::FrameFlags::END_STREAM,
                1,
                smuggled_tr));
        check_cond(
            conn.receive_bytes(wire) == h2::ErrorCode::PROTOCOL_ERROR,
            "Trailing HEADERS containing ':path' pseudo-header was accepted!");
    }

    // C: Declared `content-length: 10` but stream closes after only 4 DATA bytes -> PROTOCOL_ERROR!
    {
        h2::H2ServerConnection conn;
        std::vector<uint8_t> wire = client_preface_with_settings();
        auto init_h = h2::HpackEncoder::encode_literal_block(
            {{":method", "POST"}, {":scheme", "https"}, {":authority", "edge.internal"}, {":path", "/upload"}, {"content-length", "10"}},
            false,
            false);
        append_bytes(wire, h2::H2ServerConnection::serialize_frame(h2::FrameType::HEADERS, h2::FrameFlags::END_HEADERS, 1, init_h));
        append_bytes(
            wire,
            h2::H2ServerConnection::serialize_frame(h2::FrameType::DATA, h2::FrameFlags::END_STREAM, 1, {'a', 'b', 'c', 'd'}));
        check_cond(
            conn.receive_bytes(wire) == h2::ErrorCode::PROTOCOL_ERROR,
            "DATA payload length mismatching content-length header was accepted!");
    }

    // D: Huffman-encoded CR/LF or NUL byte inside header value -> PROTOCOL_ERROR!
    {
        h2::H2ServerConnection conn;
        std::vector<uint8_t> wire = client_preface_with_settings();
        auto crlf_h = h2::HpackEncoder::encode_literal_block(
            {
                {":method", "GET"},
                {":scheme", "https"},
                {":authority", "edge.internal"},
                {":path", "/test"},
                {"x-forwarded-user", std::string("alice\r\nx-admin: true")},
            },
            false,
            true);
        append_bytes(
            wire,
            h2::H2ServerConnection::serialize_frame(
                h2::FrameType::HEADERS,
                h2::FrameFlags::END_HEADERS | h2::FrameFlags::END_STREAM,
                1,
                crlf_h));
        check_cond(
            conn.receive_bytes(wire) == h2::ErrorCode::PROTOCOL_ERROR,
            "Header value containing CRLF injection was accepted!");
    }
}

// 5. Defect 4: SETTINGS_INITIAL_WINDOW_SIZE Signed 32-Bit Window Overflow & Non-EOS Huffman Padding
void test_group_flow_control_window_and_huffman_padding() {
    // A: Open stream 1 (initial send_window = 65535), send WINDOW_UPDATE(+0x7fff0000) so send_window = 0x7fffffff - 0,
    //    then send SETTINGS(INITIAL_WINDOW_SIZE = 0x7f000000) -> delta = +2130640897 -> stream send_window exceeds 0x7fffffff!
    //    Must return FLOW_CONTROL_ERROR without signed 32-bit integer overflow UB!
    {
        h2::H2ServerConnection conn;
        std::vector<uint8_t> wire = client_preface_with_settings();
        auto req = h2::HpackEncoder::encode_literal_block(
            {{":method", "POST"}, {":scheme", "https"}, {":authority", "edge.internal"}, {":path", "/stream"}},
            false,
            false);
        append_bytes(wire, h2::H2ServerConnection::serialize_frame(h2::FrameType::HEADERS, h2::FrameFlags::END_HEADERS, 1, req));
        // WINDOW_UPDATE on stream 1 by 0x7f000000
        append_bytes(
            wire,
            h2::H2ServerConnection::serialize_frame(h2::FrameType::WINDOW_UPDATE, 0, 1, {0x7f, 0x00, 0x00, 0x00}));
        // SETTINGS INITIAL_WINDOW_SIZE (0x0004) = 0x7f000000 -> delta = 0x7f000000 - 65535 -> stream 1 overflows 0x7fffffff!
        append_bytes(
            wire,
            h2::H2ServerConnection::serialize_frame(
                h2::FrameType::SETTINGS,
                0,
                0,
                {0x00, 0x04, 0x7f, 0x00, 0x00, 0x00}));
        check_cond(
            conn.receive_bytes(wire) == h2::ErrorCode::FLOW_CONTROL_ERROR,
            "SETTINGS_INITIAL_WINDOW_SIZE overflowing active stream window (> 0x7fffffff) did not return FLOW_CONTROL_ERROR!");
    }

    // B: Non-1s trailing bits in Huffman string ("0" = 5-bit `00000`; valid 1-byte encoding is `00000 111` = 0x07;
    //    `00000 110` = 0x06 has a trailing `0` bit in padding -> RFC 7541 §5.2 COMPRESSION_ERROR!)
    {
        std::string out;
        uint8_t valid_huff = 0x07u;
        uint8_t bad_pad_huff = 0x06u;
        check_cond(h2::huffman_decode(&valid_huff, 1, out) && out == "0", "Valid Huffman '0' (0x07) failed");
        check_cond(!h2::huffman_decode(&bad_pad_huff, 1, out), "Huffman byte 0x06 with non-1s padding was accepted!");
    }
}

}  // namespace

int main() {
    try {
        test_group_functional();
        test_group_hpack_self_eviction_uaf();
        test_group_hpack_varint_and_table_size_cap();
        test_group_continuation_trailers_and_smuggling();
        test_group_flow_control_window_and_huffman_padding();
    } catch (const std::exception& ex) {
        std::cerr << "VERIFY_FAIL: " << ex.what() << "\n";
        return 1;
    }
    std::cout << "ALL_H2_CHECKS_PASSED\n";
    return 0;
}
"""


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
        for tok in re.findall(r"[\w./-]+\.(?:cpp|hpp|cc|h)", blob)
    }
    matched_core = mentioned & CORE_FILES
    if len(matched_core) < 3:
        return False, f"Expected report.json to reference at least 3 core files from {sorted(CORE_FILES)}, got {sorted(mentioned)}"

    if not isinstance(findings, list) or len(findings) < 3:
        return False, "Expected at least 3 findings in report.json"
    for item in findings:
        txt = json.dumps(item) if isinstance(item, dict) else str(item)
        if len(txt.strip()) < 20 or "placeholder" in txt.lower():
            return False, f"Finding entry too brief or invalid: {txt!r}"

    summary = data.get("summary")
    if not isinstance(summary, str) or len(summary.strip()) < 15:
        return False, "Expected a non-empty 'summary' string in report.json"

    return True, f"Report validated (covered {sorted(matched_core)})"


def run_cmd(cmd: list[str], cwd: Path, timeout: int = 90) -> tuple[int, str]:
    try:
        proc = subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, timeout=timeout)
        return proc.returncode, (proc.stdout + "\n" + proc.stderr).strip()
    except subprocess.TimeoutExpired:
        return 124, f"Command timed out after {timeout}s: {' '.join(cmd)}"


def detect_cxx_and_san() -> tuple[str, list[str], bool]:
    for cxx in ("g++", "clang++"):
        probe = subprocess.run(
            [cxx, "-std=c++20", "-fsanitize=address,undefined", "-x", "c++", "-", "-o", "/dev/null"],
            input="int main(){return 0;}\n",
            capture_output=True,
            text=True,
        )
        if probe.returncode == 0:
            return cxx, ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"], True
    return "g++", ["-fno-omit-frame-pointer"], False


def verify(app_dir: Path, orig_dir: Path) -> tuple[bool, dict]:
    details: dict = {}

    ok_rep, msg_rep = check_report(app_dir)
    details["report"] = {"passed": ok_rep, "message": msg_rep}
    if not ok_rep:
        return False, details

    cxx_bin, san_flags, env_has_asan = detect_cxx_and_san()

    with tempfile.TemporaryDirectory() as tmp_str:
        tmp = Path(tmp_str)
        patched_copy = tmp / "patched_app"
        shutil.copytree(app_dir, patched_copy, ignore=shutil.ignore_patterns("build"))

        # 1. Build & run agent's test suite with ASan/UBSan (when supported by toolchain)
        rc_build, out_build = run_cmd(["make", "clean", "all", "test"], patched_copy)
        if rc_build != 0:
            details["agent_tests"] = {
                "passed": False,
                "message": f"make clean all test failed on /app:\n{out_build[-1500:]}",
            }
            return False, details

        smoke_bin = patched_copy / "build" / "smoke_test"
        if env_has_asan:
            nm_rc, nm_out = run_cmd(["nm", str(smoke_bin)], patched_copy, timeout=15)
            if nm_rc != 0 or "__asan_init" not in nm_out:
                details["asan_enabled"] = {"passed": False, "message": "AddressSanitizer (-fsanitize=address) was stripped from Makefile build"}
                return False, details
        details["asan_enabled"] = {"passed": True, "toolchain": cxx_bin, "sanitizers": env_has_asan}

        # 2. Verify agent's updated tests/smoke_test.cpp fails against original unpatched src/
        orig_check = tmp / "orig_check"
        shutil.copytree(orig_dir, orig_check, ignore=shutil.ignore_patterns("build"))
        if (patched_copy / "tests").is_dir():
            shutil.rmtree(orig_check / "tests", ignore_errors=True)
            shutil.copytree(patched_copy / "tests", orig_check / "tests")
        rc_orig, _ = run_cmd(["make", "clean", "all", "test"], orig_check)
        if rc_orig == 0:
            details["agent_tests"] = {
                "passed": False,
                "message": "Updated tests/smoke_test.cpp unexpectedly passed against unmodified original src/",
            }
            return False, details
        details["agent_tests"] = {
            "passed": True,
            "message": "Regression tests pass on hardened code and fail on original code",
        }

        # 3. Compile & execute hidden verifier C++ harness against libh2framer.a
        harness_cpp = tmp / "vh_hidden_harness.cpp"
        harness_bin = tmp / "vh_hidden_harness"
        harness_cpp.write_text(HIDDEN_CPP_HARNESS, encoding="utf-8")

        rc_hc, out_hc = run_cmd(
            [
                cxx_bin,
                "-std=c++20",
                "-O1",
                "-g",
                *san_flags,
                f"-I{patched_copy / 'include'}",
                str(harness_cpp),
                str(patched_copy / "build" / "libh2framer.a"),
                "-o",
                str(harness_bin),
            ],
            tmp,
        )
        if rc_hc != 0:
            details["hidden_suite"] = {
                "passed": False,
                "message": f"Failed compiling hidden C++ harness against /app:\n{out_hc[-1500:]}",
            }
            return False, details

        rc_hr, out_hr = run_cmd([str(harness_bin)], tmp)
        if rc_hr != 0 or "ALL_H2_CHECKS_PASSED" not in out_hr:
            details["hidden_suite"] = {
                "passed": False,
                "message": f"Hidden HTTP/2 + HPACK conformance suite failed (rc={rc_hr}):\n{out_hr[-1800:]}",
            }
            return False, details

        details["hidden_suite"] = {
            "passed": True,
            "message": "All 5 functional, HPACK self-eviction, varint/table-cap, CONTINUATION/trailer/CRLF, and window/Huffman checks passed",
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
