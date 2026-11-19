#!/usr/bin/env python3
"""Deterministic verifier for task: java-base64-decoder (AVX-512 VBMI JNI)."""

from __future__ import annotations

import argparse
import json
import os
import resource
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ACCEPTED_FILES = {"base64_avx512.cpp", "Base64Codec.java"}
ACCEPTED_FUNCS = {
    "decode_block_avx512_vbmi",
    "Java_codec_Base64Codec_decodeBlockAvx512",
    "decodeBlockAvx512",
    "decodeBlock",
    "decodedOutLength",
    "decode0",
}


def _disable_core_dumps() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


def find_java_home() -> Path:
    javac = shutil.which("javac")
    if not javac:
        raise RuntimeError("javac not found in PATH")
    return Path(javac).resolve().parent.parent


def cpu_supports_avx512vbmi() -> bool:
    try:
        cpuinfo = Path("/proc/cpuinfo").read_text(encoding="utf-8", errors="ignore")
        return "avx512vbmi" in cpuinfo.split()
    except OSError:
        return False


def qemu_supports_avx512vbmi_jvm() -> bool:
    qemu = shutil.which("qemu-x86_64")
    java = shutil.which("java")
    if not qemu or not java:
        return False
    try:
        probe = subprocess.run(
            [qemu, "-cpu", "max", str(Path(java).resolve()), "-XX:TieredStopAtLevel=1", "-version"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        combined = f"{probe.stdout}\n{probe.stderr}"
        if probe.returncode != 0 or "doesn't support requested feature" in combined and "avx512vbmi" in combined:
            return False
        return True
    except Exception:
        return False


def check_report(app_dir: Path) -> tuple[bool, str]:
    report_path = app_dir / "report.json"
    if not report_path.is_file():
        return False, "Missing /app/report.json"
    try:
        data = json.loads(report_path.read_text(encoding="utf-8"))
    except Exception as exc:
        return False, f"Invalid JSON in report.json: {exc}"

    rel_file = Path(str(data.get("file", "")).strip()).name
    func = str(data.get("function", "")).strip().split("(")[0].split("::")[-1].split(".")[-1]
    summary = str(data.get("summary", "")).strip()

    if rel_file not in ACCEPTED_FILES:
        return False, f"Unexpected file '{rel_file}', expected one of {sorted(ACCEPTED_FILES)}"
    if func not in ACCEPTED_FUNCS:
        return False, f"Unexpected function '{func}', expected one of {sorted(ACCEPTED_FUNCS)}"
    if len(summary) < 10:
        return False, "Report summary is empty or too brief"
    return True, "Report accurately identifies target file and function"


def build_variant(
    codec_java_dir: Path,
    native_cpp: Path,
    harness_java: Path,
    shim_header: Path,
    out_dir: Path,
    verify_real_avx512_codegen: bool = True,
) -> tuple[Path, Path, str]:
    """Compile JNI library + Java classes and select execution mode."""
    out_dir.mkdir(parents=True, exist_ok=True)
    classes_dir = out_dir / "classes"
    classes_dir.mkdir(parents=True, exist_ok=True)

    java_home = find_java_home()
    jni_inc = [f"-I{java_home / 'include'}", f"-I{java_home / 'include' / 'linux'}"]

    # Always compile real x86-64 AVX-512 VBMI machine code first and verify SIMD instructions exist
    avx512_so = out_dir / "libb64avx512.so"
    cmd_avx = [
        "g++", "-O2", "-Wall", "-Wextra", "-shared", "-fPIC",
        "-mavx512f", "-mavx512bw", "-mavx512vbmi", "-mbmi2",
        *jni_inc, str(native_cpp), "-o", str(avx512_so),
    ]
    res_avx = subprocess.run(cmd_avx, capture_output=True, text=True)
    if res_avx.returncode != 0:
        raise RuntimeError(f"AVX-512 VBMI g++ build failed:\n{res_avx.stderr}")

    if verify_real_avx512_codegen:
        disasm = subprocess.run(["objdump", "-d", "-M", "intel", str(avx512_so)], capture_output=True, text=True)
        if "vmovdqu8" not in disasm.stdout or "vpermb" not in disasm.stdout:
            raise RuntimeError("Compiled libb64avx512.so no longer emits AVX-512 VBMI instructions (vpermb/vmovdqu8)")

    has_hw = cpu_supports_avx512vbmi()

    if has_hw:
        exec_mode = "native-avx512vbmi"
        runtime_lib_dir = out_dir
    elif qemu_supports_avx512vbmi_jvm():
        exec_mode = "qemu-avx512vbmi"
        runtime_lib_dir = out_dir
    else:
        # Host-only offline check when neither AVX-512 silicon nor qemu-x86_64 is installed
        exec_mode = "bmi2-portable-shim"
        shim_dir = out_dir / "portable_lib"
        shim_dir.mkdir(parents=True, exist_ok=True)
        cmd_shim = [
            "g++", "-O2", "-shared", "-fPIC", "-mbmi2",
            "-include", str(shim_header),
            *jni_inc, str(native_cpp), "-o", str(shim_dir / "libb64avx512.so"),
        ]
        res_shim = subprocess.run(cmd_shim, capture_output=True, text=True)
        if res_shim.returncode != 0:
            raise RuntimeError(f"Portable BMI2 verification build failed:\n{res_shim.stderr}")
        runtime_lib_dir = shim_dir

    java_files = sorted(str(p) for p in codec_java_dir.glob("*.java")) + [str(harness_java)]
    res_javac = subprocess.run(["javac", "-d", str(classes_dir), *java_files], capture_output=True, text=True)
    if res_javac.returncode != 0:
        raise RuntimeError(f"javac failed:\n{res_javac.stderr}")

    return classes_dir, runtime_lib_dir, exec_mode


def run_harness(
    classes_dir: Path,
    lib_dir: Path,
    exec_mode: str,
    mode: str,
    sample_file: Path,
    check_jni: bool = True,
) -> subprocess.CompletedProcess[str]:
    java_bin = str(Path(shutil.which("java") or "java").resolve())
    jvm_cmd = [java_bin, "--enable-native-access=ALL-UNNAMED"]
    if check_jni:
        jvm_cmd.append("-Xcheck:jni")
    jvm_cmd += [f"-Djava.library.path={lib_dir}", "-cp", str(classes_dir), "codec.VerifierHarness", mode, str(sample_file)]

    if exec_mode == "qemu-avx512vbmi":
        cmd = ["qemu-x86_64", "-cpu", "max", jvm_cmd[0], "-XX:TieredStopAtLevel=1", *jvm_cmd[1:]]
    else:
        cmd = jvm_cmd

    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        cwd=str(lib_dir),
        preexec_fn=_disable_core_dumps,
        timeout=45,
    )


def verify(app_dir: Path, tests_dir: Path) -> tuple[bool, dict[str, object]]:
    results: dict[str, object] = {}

    ok_report, msg_report = check_report(app_dir)
    results["report"] = {"passed": ok_report, "message": msg_report}
    if not ok_report:
        return False, results

    sample_path = app_dir / "sample.txt"
    if not sample_path.is_file():
        results["sample"] = {"passed": False, "message": "Missing /app/sample.txt"}
        return False, results
    sz = sample_path.stat().st_size
    if sz == 0 or sz > 64 * 1024:
        results["sample"] = {"passed": False, "message": f"sample.txt size {sz} out of bounds (1..65536)"}
        return False, results

    if not (app_dir / "build" / "b64_cli").is_file() or not (app_dir / "build" / "libb64avx512.so").is_file():
        results["build"] = {"passed": False, "message": "Missing rebuilt /app/build/b64_cli or libb64avx512.so"}
        return False, results

    harness_java = tests_dir / "VerifierHarness.java"
    shim_header = tests_dir / "avx512_portable_shim.h"
    orig_dir = tests_dir / "orig_app"

    with tempfile.TemporaryDirectory() as tmp_str:
        tmp = Path(tmp_str)

        # 1. Verify sample.txt triggers native JNI bounds corruption on original unmodified code
        orig_classes, orig_lib, exec_mode = build_variant(
            orig_dir / "src" / "codec",
            orig_dir / "native" / "base64_avx512.cpp",
            harness_java,
            shim_header,
            tmp / "orig",
        )
        results["execution_mode"] = exec_mode

        jni_probe = run_harness(orig_classes, orig_lib, exec_mode, "unpatched_jni", sample_path, check_jni=True)
        jni_aborted = (
            jni_probe.returncode != 0
            and ("failed bounds check" in jni_probe.stdout or "failed bounds check" in jni_probe.stderr or jni_probe.returncode < 0 or jni_probe.returncode >= 128)
        )

        canary_probe = run_harness(orig_classes, orig_lib, exec_mode, "unpatched_canary", sample_path, check_jni=False)
        canary_hit = canary_probe.returncode == 0 and "TRIGGERED_CANARY_OOB" in canary_probe.stdout

        if not (jni_aborted or canary_hit):
            results["sample"] = {
                "passed": False,
                "message": "sample.txt did not trigger AVX-512 native heap out-of-bounds write on original decoder",
            }
            return False, results

        results["sample"] = {
            "passed": True,
            "jni_bounds_abort": jni_aborted,
            "shared_canary_overwritten": canary_hit,
            "message": "sample.txt triggered native 64-lane out-of-bounds write on original AVX-512 decoder",
        }

        # 2. Compile updated /app code, verify real AVX-512 VBMI instructions remain, and run full test suite
        try:
            patched_classes, patched_lib, _ = build_variant(
                app_dir / "src" / "codec",
                app_dir / "native" / "base64_avx512.cpp",
                harness_java,
                shim_header,
                tmp / "patched",
                verify_real_avx512_codegen=True,
            )
        except RuntimeError as exc:
            results["patch_build"] = {"passed": False, "message": str(exc)}
            return False, results

        patched_run = run_harness(patched_classes, patched_lib, exec_mode, "patched_suite", sample_path, check_jni=True)
        if patched_run.returncode != 0 or "ALL_JAVA_CHECKS_PASSED" not in patched_run.stdout:
            results["patch_suite"] = {
                "passed": False,
                "message": f"Updated codec failed verification (rc={patched_run.returncode}):\n{patched_run.stdout}\n{patched_run.stderr}",
            }
            return False, results

        results["patch_suite"] = {
            "passed": True,
            "message": "AVX-512 VBMI fast path verified active; all short-tail JNI bounds checks and java.util.Base64 differential tests (0..220B) passed",
        }

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
