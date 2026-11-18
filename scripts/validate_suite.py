#!/usr/bin/env python3
"""Static linter (including Zero-Hint prompt check) and local Oracle simulator."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

from network_policy import resolve_allowed_hosts

ROOT = Path(__file__).resolve().parent.parent
REQUIRED_SECTIONS = ("metadata", "verifier", "agent", "environment")
FORBIDDEN_ENV_NAMES = {".git", "solve.sh", "reward.txt"}

# Giveaway terms forbidden in instruction.md and task directory names so models must analyze blindly
FORBIDDEN_HINT_PATTERNS = [
    r"漏洞",
    r"缺陷",
    r"\bvuln\w*\b",
    r"\bbugs?\b",
    r"\bexploits?\b",
    r"\bpocs?\b",
    r"\bcwe-\d+\b",
    r"\bcve-\d{4}-\d+\b",
    r"\bssrf\b",
    r"\bsqli\b",
    r"\bxss\b",
    r"\buaf\b",
    r"\boverflow\w*\b",
    r"\bunderflow\w*\b",
    r"\bcrash\w*\b",
    r"\bsegfault\w*\b",
    r"\brce\b",
    r"\bbypass\w*\b",
]


def check_zero_hint(text: str, label: str) -> list[str]:
    hits: list[str] = []
    for pat in FORBIDDEN_HINT_PATTERNS:
        match = re.search(pat, text, flags=re.IGNORECASE)
        if match:
            hits.append(f"Zero-hint violation in {label}: found giveaway term '{match.group(0)}'")
    return hits


def validate_task_static(task_dir: Path, allowed_hosts: set[str] | None = None) -> list[str]:
    permitted_hosts = allowed_hosts if allowed_hosts is not None else set(resolve_allowed_hosts())
    errors: list[str] = []
    toml_file = task_dir / "task.toml"
    instr_file = task_dir / "instruction.md"
    dockerfile = task_dir / "environment" / "Dockerfile"
    solve_sh = task_dir / "solution" / "solve.sh"
    test_sh = task_dir / "tests" / "test.sh"

    for req in (toml_file, instr_file, dockerfile, solve_sh, test_sh):
        if not req.is_file():
            errors.append(f"Missing required file: {req.relative_to(task_dir)}")

    if errors:
        return errors

    try:
        cfg = tomllib.loads(toml_file.read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"Invalid TOML in task.toml: {exc}")
        return errors

    for sec in REQUIRED_SECTIONS:
        if sec not in cfg:
            errors.append(f"task.toml missing [{sec}] section")

    if not errors:
        agent_cfg = cfg.get("agent", {})
        agent_net = agent_cfg.get("network_mode")
        if agent_net not in ("allowlist", "no-network"):
            errors.append(
                "task.toml [agent] must set network_mode = 'allowlist' or 'no-network' "
                "(internet access during evaluation is forbidden; see templates/task-skeleton/task.toml)"
            )
        elif agent_net == "allowlist":
            hosts = agent_cfg.get("allowed_hosts")
            if not isinstance(hosts, list) or not hosts:
                errors.append("task.toml [agent] with network_mode = 'allowlist' must declare non-empty allowed_hosts")
            else:
                unauthorized = [h for h in hosts if h not in permitted_hosts]
                if unauthorized:
                    errors.append(
                        f"task.toml [agent].allowed_hosts contains unauthorized internet host(s): {unauthorized} "
                        "(add extra URLs/hosts via VULNHUNTER_EXTRA_ALLOWED_HOSTS or *_BASE_URL in .env)"
                    )

        verifier_cfg = cfg.get("verifier", {})
        if verifier_cfg.get("network_mode") != "no-network":
            errors.append(
                "task.toml [verifier] must set network_mode = 'no-network' "
                "(see templates/task-skeleton/task.toml)"
            )

    instr_text = instr_file.read_text(encoding="utf-8")
    if len(instr_text.strip()) < 20:
        errors.append("instruction.md is too short or empty")

    # Enforce blind proactive analysis: no vulnerability/bug hints in task ID or instruction.md
    errors.extend(check_zero_hint(task_dir.name, f"task directory name '{task_dir.name}'"))
    errors.extend(check_zero_hint(instr_text, "instruction.md"))

    for script in (solve_sh, test_sh):
        if not os.access(script, os.X_OK):
            errors.append(f"Script is not executable (chmod +x needed): {script.relative_to(task_dir)}")

    # Anti-contamination / anti-leak check inside environment/
    env_dir = task_dir / "environment"
    for path in env_dir.rglob("*"):
        if path.name in FORBIDDEN_ENV_NAMES:
            errors.append(
                f"Security leak inside environment/: '{path.relative_to(task_dir)}' must not be exposed to agents"
            )

    return errors


def run_local_oracle(task_dir: Path) -> list[str]:
    errors: list[str] = []
    app_src = task_dir / "environment" / "app"
    if not app_src.is_dir():
        return ["Missing environment/app directory for local oracle simulation"]

    solve_sh = task_dir / "solution" / "solve.sh"
    test_sh = task_dir / "tests" / "test.sh"

    with tempfile.TemporaryDirectory() as tmp_str:
        tmp = Path(tmp_str)
        work_app = tmp / "app"
        logs_before = tmp / "logs_before"
        logs_after = tmp / "logs_after"
        shutil.copytree(app_src, work_app)
        logs_before.mkdir()
        logs_after.mkdir()

        if (work_app / "Makefile").is_file():
            build_res = subprocess.run(["make", "-C", str(work_app), "clean", "all"], capture_output=True, text=True)
            if build_res.returncode != 0:
                return [f"Initial Makefile build failed:\n{build_res.stderr}"]

        # 1. Unsolved state MUST score 0.0
        env_before = os.environ.copy()
        env_before["APP_DIR"] = str(work_app)
        env_before["REWARD_DIR"] = str(logs_before)
        subprocess.run([str(test_sh)], env=env_before, capture_output=True, text=True)
        reward_before = (
            (logs_before / "reward.txt").read_text(encoding="utf-8").strip()
            if (logs_before / "reward.txt").is_file()
            else ""
        )
        if float(reward_before or "1.0") != 0.0:
            errors.append(f"Unsolved workspace scored {reward_before!r} (expected 0.0)")
            return errors

        # 2. Run Oracle solve.sh
        env_solve = os.environ.copy()
        env_solve["APP_DIR"] = str(work_app)
        solve_res = subprocess.run([str(solve_sh)], env=env_solve, capture_output=True, text=True)
        if solve_res.returncode != 0:
            errors.append(f"Oracle solve.sh exited with {solve_res.returncode}:\n{solve_res.stderr}")
            return errors

        # 3. Solved state MUST score 1.0
        env_after = os.environ.copy()
        env_after["APP_DIR"] = str(work_app)
        env_after["REWARD_DIR"] = str(logs_after)
        subprocess.run([str(test_sh)], env=env_after, capture_output=True, text=True)
        reward_after = (
            (logs_after / "reward.txt").read_text(encoding="utf-8").strip()
            if (logs_after / "reward.txt").is_file()
            else ""
        )
        if float(reward_after or "0.0") != 1.0:
            details_file = logs_after / "details.json"
            extra = details_file.read_text(encoding="utf-8") if details_file.is_file() else ""
            errors.append(f"Solved workspace scored {reward_after!r} (expected 1.0). Details:\n{extra}")

    return errors


def discover_tasks(datasets_root: Path) -> list[Path]:
    return sorted(p.parent for p in datasets_root.rglob("task.toml"))


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate VulnHunter benchmark tasks.")
    parser.add_argument("--datasets-dir", default=str(ROOT / "datasets"))
    parser.add_argument("--env-file", default=str(ROOT / ".env"), help="Path to .env file for extra allowed URLs")
    parser.add_argument(
        "--local-oracle",
        action="store_true",
        help="Also run pre-solve (expect 0.0) and post-solve (expect 1.0) verification locally",
    )
    args = parser.parse_args()

    permitted_hosts = set(resolve_allowed_hosts(Path(args.env_file)))
    tasks = discover_tasks(Path(args.datasets_dir))
    if not tasks:
        print("No tasks found.", file=sys.stderr)
        return 1

    failed = 0
    for task_dir in tasks:
        rel = task_dir.relative_to(ROOT)
        errs = validate_task_static(task_dir, allowed_hosts=permitted_hosts)
        if not errs and args.local_oracle:
            errs = run_local_oracle(task_dir)

        if errs:
            failed += 1
            print(f"[FAIL] {rel}")
            for e in errs:
                print(f"       - {e}")
        else:
            mode = "static + zero-hint + local-oracle (0.0 -> 1.0)" if args.local_oracle else "static + zero-hint"
            print(f"[PASS] {rel} ({mode})")

    print(f"\nSummary: {len(tasks) - failed}/{len(tasks)} tasks passed.")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
