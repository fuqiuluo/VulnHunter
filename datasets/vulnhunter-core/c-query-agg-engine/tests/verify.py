#!/usr/bin/env python3
"""Deterministic verifier for task: c-query-agg-engine."""

from __future__ import annotations

import argparse
import json
import os
import re
import resource
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

CORE_FILES = {"planner.c", "hash_group.c", "exec.c"}
ALL_ENGINE_FILES = {
    "engine.h",
    "lexer.c",
    "parser.c",
    "table.c",
    "planner.c",
    "hash_group.c",
    "exec.c",
    "cli.c",
}


def _disable_core_dumps() -> None:
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))


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


def compile_verified_binary(app_dir: Path, out_bin: Path, cc: str, use_san: bool) -> None:
    src_dir = app_dir / "src"
    inc_dir = app_dir / "include"
    srcs = sorted(str(p) for p in src_dir.glob("*.c"))
    if not srcs:
        raise RuntimeError("No C source files found under /app/src")

    cmd = [cc, "-std=c11", "-Wall", "-Wextra", "-O1", "-g", f"-I{inc_dir}"]
    if use_san:
        cmd += ["-fsanitize=address,undefined", "-fno-omit-frame-pointer"]
    cmd += srcs + ["-o", str(out_bin)]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"Verifier compilation failed:\n{res.stderr}")


def run_sql(bin_path: Path, sql_script: str, tmp_dir: Path, label: str) -> subprocess.CompletedProcess[str]:
    sql_file = tmp_dir / f"{label}.sql"
    sql_file.write_text(sql_script, encoding="utf-8")
    env = os.environ.copy()
    env["ASAN_OPTIONS"] = "detect_leaks=1:exitcode=99:abort_on_error=0"
    env["UBSAN_OPTIONS"] = "print_stacktrace=1:exitcode=98:halt_on_error=1"
    return subprocess.run(
        [str(bin_path), str(sql_file)],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(tmp_dir),
        preexec_fn=_disable_core_dumps,
        timeout=20,
    )


def did_sanitizer_or_crash(proc: subprocess.CompletedProcess[str]) -> bool:
    if proc.returncode < 0 or proc.returncode in (98, 99) or proc.returncode >= 128:
        return True
    err_low = proc.stderr
    for marker in ("AddressSanitizer", "LeakSanitizer", "UndefinedBehaviorSanitizer", "runtime error:", "Segmentation fault"):
        if marker in err_low:
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

    mentioned_files: set[str] = set()
    raw_files = data.get("files")
    if isinstance(raw_files, list):
        for item in raw_files:
            mentioned_files |= _extract_basenames(str(item))
    elif isinstance(raw_files, str):
        mentioned_files |= _extract_basenames(raw_files)

    raw_file = data.get("file")
    if isinstance(raw_file, str):
        mentioned_files |= _extract_basenames(raw_file)

    findings_raw = data.get("findings")
    valid_findings = 0
    if isinstance(findings_raw, list):
        for entry in findings_raw:
            if isinstance(entry, dict):
                f_str = str(entry.get("file", ""))
                mentioned_files |= _extract_basenames(f_str)
                desc = " ".join(
                    str(entry.get(k, "")).strip()
                    for k in ("issue", "description", "summary", "detail", "root_cause", "fix", "remediation")
                ).strip()
                mentioned_files |= _extract_basenames(desc)
                if len(desc) >= 10 or str(entry.get("function", "")).strip():
                    valid_findings += 1
            elif isinstance(entry, str) and len(entry.strip()) >= 10:
                mentioned_files |= _extract_basenames(entry)
                valid_findings += 1

    summary = str(data.get("summary", "")).strip()
    mentioned_files |= _extract_basenames(summary)

    if valid_findings == 0 and len(summary) < 15:
        return False, "Report must contain substantive findings or a technical summary"
    if "placeholder" in summary.lower():
        return False, "Report summary still contains placeholder text"

    core_hits = mentioned_files & CORE_FILES
    if len(core_hits) >= 2 or (len(core_hits) >= 1 and valid_findings >= 2):
        return True, f"Report accepted (core files identified: {sorted(core_hits)}, findings={valid_findings})"

    return (
        False,
        f"Report did not sufficiently identify affected engine components (got {sorted(mentioned_files & ALL_ENGINE_FILES)})",
    )


def check_makefile_and_build(app_dir: Path, expect_san: bool) -> tuple[bool, str]:
    makefile = app_dir / "Makefile"
    if not makefile.is_file():
        return False, "Missing /app/Makefile"
    mk_text = makefile.read_text(encoding="utf-8")
    if "-fsanitize=address,undefined" not in mk_text:
        return False, "Makefile sanitizer flags (-fsanitize=address,undefined) were removed or altered"

    res = subprocess.run(["make", "-C", str(app_dir), "clean", "all"], capture_output=True, text=True, timeout=60)
    if res.returncode != 0:
        return False, f"make -C /app clean all failed:\n{res.stderr}"

    built_bin = app_dir / "build" / "agg_cli"
    if not built_bin.is_file() or not os.access(built_bin, os.X_OK):
        return False, "Rebuild did not produce executable /app/build/agg_cli"

    combined_out = f"{res.stdout}\n{res.stderr}"
    if expect_san and "-fsanitize=address,undefined" not in combined_out:
        return False, "Makefile build did not compile with -fsanitize=address,undefined"

    return True, "Makefile intact and /app/build/agg_cli rebuilt cleanly with sanitizers"


def verify(app_dir: Path) -> tuple[bool, dict[str, object]]:
    results: dict[str, object] = {}

    ok_rep, msg_rep = check_report(app_dir)
    results["report"] = {"passed": ok_rep, "message": msg_rep}
    if not ok_rep:
        return False, results

    cc, use_san = detect_san_compiler()
    results["sanitizer_toolchain"] = {"compiler": cc, "enabled": use_san}

    ok_mk, msg_mk = check_makefile_and_build(app_dir, expect_san=use_san)
    results["makefile_build"] = {"passed": ok_mk, "message": msg_mk}
    if not ok_mk:
        return False, results

    with tempfile.TemporaryDirectory() as tmp_str:
        tmp = Path(tmp_str)
        verified_bin = tmp / "verified_agg_cli"
        try:
            compile_verified_binary(app_dir, verified_bin, cc=cc, use_san=use_san)
        except RuntimeError as exc:
            results["verifier_compile"] = {"passed": False, "message": str(exc)}
            return False, results

        # Spot-check that /app/build/agg_cli itself also works (not a stale/broken binary)
        app_bin = app_dir / "build" / "agg_cli"
        smoke = run_sql(
            app_bin,
            "CREATE TABLE t (x INT); INSERT INTO t VALUES (7), (8); SELECT SUM(x) FROM t;",
            tmp,
            "smoke_app_bin",
        )
        if did_sanitizer_or_crash(smoke) or smoke.returncode != 0 or smoke.stdout.strip() != "15":
            results["app_binary_smoke"] = {
                "passed": False,
                "message": f"/app/build/agg_cli failed smoke check (rc={smoke.returncode}, out={smoke.stdout!r})",
            }
            return False, results

        # 1. Comprehensive functional analytical SQL suite
        functional_cases: list[tuple[str, str, str]] = [
            (
                "scan_where_arith_order_limit",
                """
                CREATE TABLE orders (id INT, customer TEXT, qty INT, unit_price INT, discount INT);
                INSERT INTO orders VALUES
                    (1, 'acme', 4, 25, 10),
                    (2, 'globex', 2, 60, 0),
                    (3, 'acme', 1, 40, 5),
                    (4, 'initech', 5, 30, 20),
                    (5, 'umbrella', 3, 15, 0);
                SELECT id, customer, qty * unit_price - discount AS net
                FROM orders
                WHERE (qty >= 2 AND unit_price >= 20) OR customer = 'acme'
                ORDER BY net DESC, id ASC
                LIMIT 3 OFFSET 1;
                """,
                "2|globex|120\n1|acme|90\n3|acme|35\n",
            ),
            (
                "multi_col_group_nulls_and_distinct",
                """
                CREATE TABLE telemetry (region TEXT, tier INT, host TEXT, latency FLOAT);
                INSERT INTO telemetry VALUES
                    ('us-east', 1, 'h1', 12.5),
                    ('us-east', 1, 'h2', 17.5),
                    ('us-east', 1, 'h1', NULL),
                    ('eu-west', NULL, 'h3', 20.0),
                    ('eu-west', NULL, 'h4', 30.0),
                    ('ap-south', 2, NULL, NULL);
                SELECT region, tier, COUNT(*), COUNT(host), COUNT(DISTINCT host), SUM(latency), AVG(latency), MIN(latency), MAX(latency)
                FROM telemetry
                GROUP BY region, tier
                ORDER BY region ASC;
                """,
                "ap-south|2|1|0|0|NULL|NULL|NULL|NULL\n"
                "eu-west|NULL|2|2|2|50.00|25.00|20.00|30.00\n"
                "us-east|1|3|3|2|30.00|15.00|12.50|17.50\n",
            ),
            (
                "empty_table_agg_vs_grouped",
                """
                CREATE TABLE empty_metrics (grp TEXT, val INT);
                SELECT COUNT(*), COUNT(val), SUM(val), AVG(val), MIN(val), MAX(val) FROM empty_metrics;
                SELECT COUNT(*) FROM empty_metrics HAVING COUNT(*) > 0;
                SELECT grp, COUNT(*) FROM empty_metrics GROUP BY grp;
                """,
                "0|0|NULL|NULL|NULL|NULL\n",
            ),
            (
                "three_valued_null_predicates",
                """
                CREATE TABLE flags (id INT, v INT);
                INSERT INTO flags VALUES (1, 10), (2, NULL), (3, 20);
                SELECT id FROM flags WHERE NOT (v = 10) ORDER BY id;
                SELECT id FROM flags WHERE v IS NULL OR (v > 15 AND 1 = 1) ORDER BY id;
                """,
                "3\n2\n3\n",
            ),
            (
                "distinct_set_growth_and_post_agg_arith",
                "CREATE TABLE clicks (campaign TEXT, uid TEXT, rev INT);\n"
                "INSERT INTO clicks VALUES "
                + ", ".join(
                    [f"('alpha', 'u{i % 75}', 10)" for i in range(150)]
                    + [f"('beta', 'u{i % 20}', 25)" for i in range(40)]
                )
                + ";\n"
                "SELECT campaign, COUNT(*), COUNT(DISTINCT uid), SUM(rev) - SUM(DISTINCT rev) AS repeat_rev "
                "FROM clicks GROUP BY campaign ORDER BY campaign ASC;\n",
                "alpha|150|75|1490\nbeta|40|20|975\n",
            ),
        ]

        for label, sql, expected in functional_cases:
            proc = run_sql(verified_bin, sql, tmp, f"func_{label}")
            if did_sanitizer_or_crash(proc) or proc.returncode != 0 or proc.stdout != expected:
                results["functional"] = {
                    "passed": False,
                    "case": label,
                    "rc": proc.returncode,
                    "expected": expected,
                    "stdout": proc.stdout,
                    "stderr": proc.stderr[:400],
                }
                return False, results
        results["functional"] = {"passed": True, "message": "All analytical SQL functional tests passed"}

        # 2. Defect A: Implicit aggregate slots appended by HAVING and ORDER BY exceeding SELECT/table width
        implicit_agg_cases: list[tuple[str, str, str]] = [
            (
                "having_and_orderby_unlisted_aggs_3col",
                """
                CREATE TABLE sales (dept TEXT, region TEXT, amount INT);
                INSERT INTO sales VALUES
                    ('eng', 'us', 100),
                    ('eng', 'eu', 200),
                    ('eng', 'apac', 300),
                    ('ops', 'us', 400),
                    ('ops', 'us', 500),
                    ('fin', 'us', 150),
                    ('fin', 'eu', 250),
                    ('hr', 'eu', 5);
                SELECT dept, SUM(amount)
                FROM sales
                GROUP BY dept
                HAVING COUNT(DISTINCT region) >= 2 AND MIN(amount) >= 50 AND COUNT(*) >= 2
                ORDER BY MAX(amount) DESC, AVG(amount) DESC, dept ASC;
                """,
                "eng|600\nfin|400\n",
            ),
            (
                "zero_select_aggs_with_multi_having_orderby",
                """
                CREATE TABLE events (service TEXT, ms INT);
                INSERT INTO events VALUES
                    ('auth', 20), ('auth', 80), ('auth', 50),
                    ('cache', 5), ('cache', 15),
                    ('billing', 40), ('billing', 90),
                    ('search', 100);
                SELECT service
                FROM events
                GROUP BY service
                HAVING COUNT(*) >= 2 AND MIN(ms) >= 10 AND SUM(ms) >= 100
                ORDER BY MAX(ms) DESC, AVG(ms) DESC;
                """,
                "billing\nauth\n",
            ),
            (
                "1col_table_unlisted_having_aggs",
                """
                CREATE TABLE samples (v INT);
                INSERT INTO samples VALUES (10), (20), (30), (40), (20);
                SELECT MAX(v) - MIN(v)
                FROM samples
                HAVING COUNT(*) = 5 AND COUNT(DISTINCT v) = 4 AND SUM(v) = 120 AND AVG(v) > 20;
                """,
                "30\n",
            ),
        ]

        for label, sql, expected in implicit_agg_cases:
            proc = run_sql(verified_bin, sql, tmp, f"imp_{label}")
            if did_sanitizer_or_crash(proc) or proc.returncode != 0 or proc.stdout != expected:
                results["implicit_agg_slots"] = {
                    "passed": False,
                    "case": label,
                    "rc": proc.returncode,
                    "expected": expected,
                    "stdout": proc.stdout,
                    "stderr": proc.stderr[:400],
                }
                return False, results
        results["implicit_agg_slots"] = {
            "passed": True,
            "message": "Implicit HAVING/ORDER BY aggregate accumulator allocation passed",
        }

        # 3. Defect B: High-cardinality GROUP BY rehash (300 groups -> 64 -> 128 -> 256 -> 512)
        group_tuples = []
        expected_unord = []
        for g in range(300):
            v1 = g * 3 + 1
            v2 = g * 3 + 5
            group_tuples.append(f"('grp_{g:03d}', 'c1', {v1}), ('grp_{g:03d}', 'c2', {v2})")
            expected_unord.append(f"grp_{g:03d}|2|2|{v1 + v2}")

        sql_rehash = (
            "CREATE TABLE high_card (grp TEXT, chan TEXT, val INT);\n"
            f"INSERT INTO high_card VALUES {', '.join(group_tuples)};\n"
            "SELECT grp, COUNT(*), COUNT(DISTINCT chan), SUM(val) FROM high_card GROUP BY grp;\n"
        )
        proc_rehash = run_sql(verified_bin, sql_rehash, tmp, "rehash_300_groups")
        got_lines = [ln for ln in proc_rehash.stdout.splitlines() if ln.strip()]
        if (
            did_sanitizer_or_crash(proc_rehash)
            or proc_rehash.returncode != 0
            or sorted(got_lines) != sorted(expected_unord)
        ):
            results["group_rehash"] = {
                "passed": False,
                "rc": proc_rehash.returncode,
                "rows_returned": len(got_lines),
                "stderr": proc_rehash.stderr[:400],
            }
            return False, results
        results["group_rehash"] = {
            "passed": True,
            "message": "300-group hash aggregation rehash preserved all group states without UAF",
        }

        # 4. Defect C: 64-bit pagination & arithmetic boundary safety
        proc_lim = run_sql(
            verified_bin,
            """
            CREATE TABLE seq (id INT, name TEXT);
            INSERT INTO seq VALUES (1, 'a'), (2, 'b'), (3, 'c'), (4, 'd'), (5, 'e');
            SELECT id, name FROM seq ORDER BY id ASC LIMIT 9223372036854775807 OFFSET 2;
            SELECT id, name FROM seq ORDER BY id ASC LIMIT 5000000000000000000 OFFSET 5000000000000000000;
            """,
            tmp,
            "pagination_int64_max",
        )
        if (
            did_sanitizer_or_crash(proc_lim)
            or proc_lim.returncode != 0
            or proc_lim.stdout != "3|c\n4|d\n5|e\n"
        ):
            results["pagination_bounds"] = {
                "passed": False,
                "rc": proc_lim.returncode,
                "stdout": proc_lim.stdout,
                "stderr": proc_lim.stderr[:400],
            }
            return False, results

        for neg_label, neg_sql in [
            ("neg_limit", "CREATE TABLE s (x INT); INSERT INTO s VALUES (1),(2); SELECT x FROM s LIMIT -1;"),
            ("neg_offset", "CREATE TABLE s (x INT); INSERT INTO s VALUES (1),(2); SELECT x FROM s LIMIT 2 OFFSET -1;"),
        ]:
            proc_neg_p = run_sql(verified_bin, neg_sql, tmp, neg_label)
            if did_sanitizer_or_crash(proc_neg_p) or proc_neg_p.returncode != 1:
                results["pagination_bounds"] = {
                    "passed": False,
                    "case": neg_label,
                    "rc": proc_neg_p.returncode,
                    "stderr": proc_neg_p.stderr[:400],
                }
                return False, results

        # Large SUM / arithmetic overflow checks (must never trigger UBSan or wrap negative)
        arith_edge_cases = [
            (
                "sum_int64_overflow",
                "CREATE TABLE big (v INT); INSERT INTO big VALUES (6000000000000000000), (6000000000000000000); SELECT SUM(v) FROM big;",
            ),
            (
                "avg_int64_large",
                "CREATE TABLE biga (v INT); INSERT INTO biga VALUES (6000000000000000000), (4000000000000000000); SELECT AVG(v) FROM biga;",
            ),
            (
                "add_int64_overflow",
                "CREATE TABLE bigx (v INT); INSERT INTO bigx VALUES (6000000000000000000); SELECT v + 5000000000000000000 FROM bigx;",
            ),
            (
                "mul_int64_overflow",
                "CREATE TABLE bigm (v INT); INSERT INTO bigm VALUES (4000000000); SELECT v * 4000000000 FROM bigm;",
            ),
            (
                "div_int64_min_neg1",
                "CREATE TABLE bigd (v INT); INSERT INTO bigd VALUES (1); SELECT (-9223372036854775807 - 1) / -1 FROM bigd;",
            ),
        ]
        for label, sql in arith_edge_cases:
            proc_ar = run_sql(verified_bin, sql, tmp, label)
            out_s = proc_ar.stdout.strip()
            wrapped_neg = proc_ar.returncode == 0 and out_s.startswith("-")
            if did_sanitizer_or_crash(proc_ar) or proc_ar.returncode not in (0, 1) or wrapped_neg or (
                proc_ar.returncode == 0 and not out_s
            ):
                results["int64_arithmetic"] = {
                    "passed": False,
                    "case": label,
                    "rc": proc_ar.returncode,
                    "stdout": out_s,
                    "stderr": proc_ar.stderr[:400],
                }
                return False, results
        results["int64_arithmetic"] = {
            "passed": True,
            "message": "64-bit pagination and integer overflow boundaries cleanly handled without UB",
        }

        # 5. Combined multi-defect analytical query (300 groups + unlisted HAVING/ORDER BY aggs + INT64_MAX LIMIT with OFFSET)
        comb_sql = (
            "CREATE TABLE regional_sales (dept TEXT, channel TEXT, revenue INT);\n"
            f"INSERT INTO regional_sales VALUES {', '.join(group_tuples)};\n"
            "SELECT dept, SUM(revenue) "
            "FROM regional_sales "
            "GROUP BY dept "
            "HAVING COUNT(DISTINCT channel) >= 2 AND MIN(revenue) > 0 "
            "ORDER BY MAX(revenue) ASC, AVG(revenue) ASC, dept ASC "
            "LIMIT 9223372036854775807 OFFSET 297;\n"
        )
        exp_comb = "\n".join(
            f"grp_{g:03d}|{(g * 3 + 1) + (g * 3 + 5)}" for g in (297, 298, 299)
        ) + "\n"
        proc_comb = run_sql(verified_bin, comb_sql, tmp, "combined_abc")
        if did_sanitizer_or_crash(proc_comb) or proc_comb.returncode != 0 or proc_comb.stdout != exp_comb:
            results["combined_analytical"] = {
                "passed": False,
                "rc": proc_comb.returncode,
                "expected": exp_comb,
                "stdout": proc_comb.stdout,
                "stderr": proc_comb.stderr[:400],
            }
            return False, results
        results["combined_analytical"] = {"passed": True, "message": "Combined stress query passed"}

        # 6. Negative SQL validation tests (must cleanly return exit code 1 with zero sanitizer/leak issues)
        invalid_sql_cases = [
            ("unknown_table", "SELECT x FROM missing_tbl;"),
            ("unknown_col", "CREATE TABLE t (x INT); SELECT y FROM t;"),
            ("agg_in_where", "CREATE TABLE t (x INT); INSERT INTO t VALUES (1); SELECT x FROM t WHERE COUNT(*) > 0;"),
            ("nested_agg", "CREATE TABLE t (x INT); INSERT INTO t VALUES (1); SELECT SUM(MAX(x)) FROM t;"),
            ("ungrouped_col", "CREATE TABLE t (k TEXT, x INT); INSERT INTO t VALUES ('a', 1); SELECT k, x, SUM(x) FROM t GROUP BY k;"),
            ("div_by_zero", "CREATE TABLE t (x INT); INSERT INTO t VALUES (10); SELECT x / 0 FROM t;"),
            ("unclosed_str", "CREATE TABLE t (s TEXT); INSERT INTO t VALUES ('unterminated);"),
        ]
        for label, bad_sql in invalid_sql_cases:
            proc_bad = run_sql(verified_bin, bad_sql, tmp, f"invalid_{label}")
            if did_sanitizer_or_crash(proc_bad) or proc_bad.returncode != 1:
                results["negative_sql"] = {
                    "passed": False,
                    "case": label,
                    "rc": proc_bad.returncode,
                    "stderr": proc_bad.stderr[:400],
                }
                return False, results
        results["negative_sql"] = {"passed": True, "message": "All invalid SQL and runtime error checks exited cleanly with code 1"}

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
