#!/usr/bin/env python3
"""Scaffold a new Harbor-compatible VulnHunter benchmark task."""

from __future__ import annotations

import argparse
import re
import shutil
import stat
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKELETON = ROOT / "templates" / "task-skeleton"


def make_executable(path: Path) -> None:
    mode = path.stat().st_mode
    path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


def main() -> int:
    parser = argparse.ArgumentParser(description="Create a new VulnHunter benchmark task.")
    parser.add_argument("task_id", help="Neutral module slug for the task (e.g. c-session-cache)")
    parser.add_argument("--dataset", default="vulnhunter-core", help="Dataset directory under datasets/")
    parser.add_argument("--difficulty", choices=["easy", "medium", "hard"], default="medium")
    parser.add_argument("--category", default="security", help="Capability category (e.g. memory-safety, web-security)")
    parser.add_argument("--tags", default="security", help="Comma-separated tags")
    args = parser.parse_args()

    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]*", args.task_id):
        print(f"Error: task_id '{args.task_id}' must use lowercase letters, digits, '-' or '_'.", file=sys.stderr)
        return 1

    dest = ROOT / "datasets" / args.dataset / args.task_id
    if dest.exists():
        print(f"Error: Task directory already exists: {dest}", file=sys.stderr)
        return 1

    shutil.copytree(SKELETON, dest)

    tags_list = [t.strip() for t in args.tags.split(",") if t.strip()]
    tags_toml = ", ".join(f'"{t}"' for t in tags_list)

    toml_path = dest / "task.toml"
    toml_text = toml_path.read_text(encoding="utf-8")
    toml_text = toml_text.replace('difficulty = "medium"', f'difficulty = "{args.difficulty}"')
    toml_text = toml_text.replace('category = "security"', f'category = "{args.category}"')
    toml_text = toml_text.replace('tags = ["security"]', f"tags = [{tags_toml}]")
    toml_path.write_text(toml_text, encoding="utf-8")

    make_executable(dest / "solution" / "solve.sh")
    make_executable(dest / "tests" / "test.sh")

    print(f"Created new task at: {dest}")
    print("Next steps:")
    print(f"  1. Add target source files in {dest / 'environment' / 'app'}")
    print(f"  2. Write agent prompt in       {dest / 'instruction.md'}")
    print(f"  3. Write gold solution in      {dest / 'solution' / 'solve.sh'}")
    print(f"  4. Write verifier script in    {dest / 'tests' / 'test.sh'}")
    print(f"  5. Validate via: python3 scripts/validate_suite.py --local-oracle")
    return 0


if __name__ == "__main__":
    sys.exit(main())
