#!/usr/bin/env python3
"""Deterministic ASan/UBSan verifier for task: cpp-frame-compositor."""

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

STREAM_MAGIC = 0x43454446
ACCEPTED_FILES = {"compositor.cpp", "converter.cpp", "compositor.hpp"}
ACCEPTED_FUNCS = {
    "on_tile_received",
    "convert_yuv420_to_rgba",
    "is_valid",
    "crop_width",
    "crop_height",
    "init",
}


def fnv1a_64(data: bytes) -> int:
    h = 14695981039346656037
    for b in data:
        h ^= b
        h = (h * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return h


def clamp_u8(v: int) -> int:
    return 0 if v < 0 else (255 if v > 255 else v)


def pack_tile(
    w: int,
    h: int,
    stride: int,
    slice_h: int,
    has_crop: bool,
    cl: int,
    ct: int,
    cr: int,
    cb: int,
    payload: bytes,
) -> bytes:
    return (
        struct.pack(
            "<iiiiIiiiiI",
            w,
            h,
            stride,
            slice_h,
            1 if has_crop else 0,
            cl,
            ct,
            cr,
            cb,
            len(payload),
        )
        + payload
    )


def build_yuv420_solid(stride: int, plane_h: int, y_val: int, u_val: int, v_val: int) -> bytes:
    y_bytes = bytes([y_val]) * (stride * plane_h)
    uv_len = (stride // 2) * ((plane_h + 1) // 2)
    return y_bytes + bytes([u_val]) * uv_len + bytes([v_val]) * uv_len


def expected_solid_rgba(y_val: int, u_val: int, v_val: int) -> bytes:
    c = 298 * max(0, y_val - 16)
    u = u_val - 128
    v = v_val - 128
    r = clamp_u8((c + 409 * v + 128) >> 8)
    g = clamp_u8((c - 100 * u - 208 * v + 128) >> 8)
    b = clamp_u8((c + 516 * u + 128) >> 8)
    return bytes([r, g, b, 0xFF])


def supports_asan() -> bool:
    with tempfile.TemporaryDirectory() as tmp:
        cpp = Path(tmp) / "probe.cpp"
        out = Path(tmp) / "probe"
        cpp.write_text("int main(){return 0;}\n", encoding="utf-8")
        res = subprocess.run(["g++", "-fsanitize=address", str(cpp), "-o", str(out)], capture_output=True)
        return res.returncode == 0


def compile_cli(src_dir: Path, include_dir: Path, out_bin: Path, use_asan: bool) -> None:
    cmd = ["g++", "-std=c++17", "-Wall", "-Wextra", "-O1", "-g", f"-I{include_dir}"]
    if use_asan:
        cmd += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
    cmd += [
        str(src_dir / "converter.cpp"),
        str(src_dir / "compositor.cpp"),
        str(src_dir / "cli.cpp"),
        "-o",
        str(out_bin),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"Compilation failed for {src_dir}:\n{res.stderr}")


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
    err = proc.stderr
    return (
        "AddressSanitizer" in err
        or "runtime error:" in err
        or "Segmentation fault" in err
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
    if len(summary) < 12:
        return False, "Report summary is empty or too brief"
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

    if not (app_dir / "build" / "frame_cli").is_file():
        results["build"] = {"passed": False, "message": "Missing rebuilt /app/build/frame_cli"}
        return False, results

    use_asan = supports_asan()
    results["asan_enabled"] = use_asan
    orig_app = tests_dir / "orig_app"

    with tempfile.TemporaryDirectory() as tmp_str:
        tmp = Path(tmp_str)
        orig_bin = tmp / "orig_frame_cli"
        patched_bin = tmp / "patched_frame_cli"

        compile_cli(orig_app / "src", orig_app / "include", orig_bin, use_asan=use_asan)

        # 1. sample.bin must trigger ASan/UBSan crash on original compositor
        orig_run = run_cli(orig_bin, sample_path)
        if not did_crash(orig_run):
            results["sample"] = {
                "passed": False,
                "message": f"sample.bin did not trigger memory safety failure on original binary (rc={orig_run.returncode})",
            }
            return False, results
        results["sample"] = {
            "passed": True,
            "message": f"sample.bin triggered failure on original binary (rc={orig_run.returncode})",
        }

        # 2. Compile patched sources with original header to verify API compatibility
        try:
            compile_cli(app_dir / "src", orig_app / "include", patched_bin, use_asan=use_asan)
        except RuntimeError as exc:
            results["patch_build"] = {"passed": False, "message": str(exc)}
            return False, results

        # 3. Patched binary must cleanly handle sample.bin without ASan/UBSan crash
        patched_sample = run_cli(patched_bin, sample_path)
        if did_crash(patched_sample) or patched_sample.returncode != 1:
            results["patch_sample"] = {
                "passed": False,
                "message": f"Updated binary failed clean rejection on sample.bin (rc={patched_sample.returncode}): {patched_sample.stderr[:300]}",
            }
            return False, results
        results["patch_sample"] = {"passed": True, "message": "Updated binary cleanly rejected sample.bin without sanitizer errors"}

        # 4. Valid functional tests (exact FNV-1a canvas digest check)
        # Case A: Single 4x4 tile solid color
        px_a = expected_solid_rgba(120, 90, 180)
        stream_a = struct.pack("<IiiiiiiI", STREAM_MAGIC, 4, 4, 1, 1, 4, 4, 1) + pack_tile(
            4, 4, 4, 0, False, 0, 0, 0, 0, build_yuv420_solid(4, 4, 120, 90, 180)
        )
        canvas_a = px_a * 16

        # Case B: 2x2 tile grid (canvas 6x6, tile 4x4 -> edge-clipped right & bottom tiles)
        colors_b = [(80, 100, 150), (160, 140, 110), (200, 80, 200), (60, 170, 90)]
        tiles_b = b"".join(
            pack_tile(4, 4, 4, 0, False, 0, 0, 0, 0, build_yuv420_solid(4, 4, y, u, v))
            for y, u, v in colors_b
        )
        stream_b = struct.pack("<IiiiiiiI", STREAM_MAGIC, 6, 6, 2, 2, 4, 4, 4) + tiles_b
        canvas_b = bytearray(6 * 6 * 4)
        for ty in range(2):
            for tx in range(2):
                px = expected_solid_rgba(*colors_b[ty * 2 + tx])
                for r in range(ty * 4, min(6, (ty + 1) * 4)):
                    for c in range(tx * 4, min(6, (tx + 1) * 4)):
                        off = (r * 6 + c) * 4
                        canvas_b[off : off + 4] = px

        # Case C: Single cropped tile with stride > width and slice_height > height
        px_c = expected_solid_rgba(180, 128, 128)
        stream_c = struct.pack("<IiiiiiiI", STREAM_MAGIC, 4, 4, 1, 1, 4, 4, 1) + pack_tile(
            8, 6, 8, 8, True, 2, 1, 5, 4, build_yuv420_solid(8, 8, 180, 128, 128)
        )
        canvas_c = px_c * 16

        for label, blob, expected_canvas in [
            ("single_4x4", stream_a, canvas_a),
            ("grid_2x2_clipped_6x6", stream_b, bytes(canvas_b)),
            ("cropped_strided_4x4", stream_c, canvas_c),
        ]:
            f_in = tmp / f"{label}.bin"
            f_in.write_bytes(blob)
            proc = run_cli(patched_bin, f_in)
            exp_hash = f"{fnv1a_64(expected_canvas):016x}"
            if proc.returncode != 0 or did_crash(proc) or f"fnv1a={exp_hash}" not in proc.stdout:
                results["functional"] = {
                    "passed": False,
                    "message": f"Valid case '{label}' failed (rc={proc.returncode}, expected fnv1a={exp_hash}): out={proc.stdout!r} err={proc.stderr[:200]!r}",
                }
                return False, results
        results["functional"] = {"passed": True, "message": "All valid single-tile, 2x2 clipped grid, and cropped/strided tests matched exact digests"}

        # 5. Adversarial malformed stream matrix (must exit 1 cleanly, zero sanitizer errors)
        adversarial = [
            (
                "dst_top_past_canvas",
                struct.pack("<IiiiiiiI", STREAM_MAGIC, 4, 4, 2, 1, 4, 2, 2)
                + pack_tile(4, 4, 4, 0, False, 0, 0, 0, 0, build_yuv420_solid(4, 4, 80, 128, 128))
                + pack_tile(4, 6, 4, 0, False, 0, 0, 0, 0, build_yuv420_solid(4, 6, 90, 128, 128)),
            ),
            (
                "dst_left_past_canvas",
                struct.pack("<IiiiiiiI", STREAM_MAGIC, 4, 4, 1, 2, 2, 4, 2)
                + pack_tile(4, 4, 4, 0, False, 0, 0, 0, 0, build_yuv420_solid(4, 4, 80, 128, 128))
                + pack_tile(6, 4, 6, 0, False, 0, 0, 0, 0, build_yuv420_solid(6, 4, 90, 128, 128)),
            ),
            (
                "inverted_crop_vertical",
                struct.pack("<IiiiiiiI", STREAM_MAGIC, 4, 4, 1, 1, 4, 4, 1)
                + pack_tile(4, 4, 4, 0, True, 0, 3, 3, 1, build_yuv420_solid(4, 4, 80, 128, 128)),
            ),
            (
                "inverted_crop_horizontal",
                struct.pack("<IiiiiiiI", STREAM_MAGIC, 4, 4, 1, 1, 4, 4, 1)
                + pack_tile(4, 4, 4, 0, True, 2, 0, 0, 3, build_yuv420_solid(4, 4, 80, 128, 128)),
            ),
            (
                "crop_outside_src",
                struct.pack("<IiiiiiiI", STREAM_MAGIC, 4, 4, 1, 1, 4, 4, 1)
                + pack_tile(4, 4, 4, 0, True, 0, 0, 7, 3, build_yuv420_solid(4, 4, 80, 128, 128)),
            ),
            (
                "negative_crop",
                struct.pack("<IiiiiiiI", STREAM_MAGIC, 4, 4, 1, 1, 4, 4, 1)
                + pack_tile(4, 4, 4, 0, True, -2, 0, 1, 3, build_yuv420_solid(4, 4, 80, 128, 128)),
            ),
            (
                "truncated_payload",
                struct.pack("<IiiiiiiI", STREAM_MAGIC, 4, 4, 1, 1, 4, 4, 1)
                + pack_tile(4, 4, 4, 0, False, 0, 0, 0, 0, b"\x00" * 8),
            ),
        ]
        for label, blob in adversarial:
            f_bad = tmp / f"bad_{label}.bin"
            f_bad.write_bytes(blob)
            proc = run_cli(patched_bin, f_bad)
            if did_crash(proc) or proc.returncode != 1:
                results["adversarial"] = {
                    "passed": False,
                    "message": f"Malformed case '{label}' was not cleanly rejected (rc={proc.returncode}): {proc.stderr[:250]}",
                }
                return False, results
        results["adversarial"] = {"passed": True, "message": "All adversarial crop/offset/grid cases cleanly rejected without sanitizer errors"}

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
