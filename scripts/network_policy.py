#!/usr/bin/env python3
"""Resolve and sync Harbor [agent].allowed_hosts from environment variables and .env."""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import sys
import tomllib
import urllib.parse
from collections.abc import Mapping
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

DEFAULT_ALLOWED_HOSTS: tuple[str, ...] = (
    "api.anthropic.com",
    "api.openai.com",
    "generativelanguage.googleapis.com",
)

# Hosts required when running Antigravity CLI (`agy`) via local Google OAuth subscription
AGY_OAUTH_ALLOWED_HOSTS: tuple[str, ...] = (
    "daily-cloudcode-pa.googleapis.com",
    "cloudcode-pa.googleapis.com",
    "oauth2.googleapis.com",
    "www.googleapis.com",
    "*.googleapis.com",
)

# Environment variables whose URLs/hosts are automatically added to [agent].allowed_hosts
EXTRA_HOST_ENV_KEYS: tuple[str, ...] = (
    "VULNHUNTER_EXTRA_ALLOWED_HOSTS",
    "EXTRA_ALLOWED_HOSTS",
    "ANTHROPIC_BASE_URL",
    "OPENAI_BASE_URL",
    "GEMINI_BASE_URL",
    "GOOGLE_GEMINI_BASE_URL",
    "AGY_LLM_GATEWAY_URL",
)


def parse_dotenv(env_file: Path) -> dict[str, str]:
    """Parse a standard .env file without external dependencies."""
    values: dict[str, str] = {}
    if not env_file.is_file():
        return values

    for raw_line in env_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue

        key, val = line.split("=", 1)
        key = key.strip()
        val = val.strip()
        if not key:
            continue

        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]
        else:
            # Strip trailing inline comment on unquoted values
            val = re.sub(r"\s+#.*$", "", val).strip()

        values[key] = val
    return values


def extract_host_entry(raw_token: str) -> str:
    """Normalize a URL, host:port, wildcard domain, IP, or CIDR into a Harbor allowed_hosts entry."""
    token = raw_token.strip().strip("'\"")
    if not token:
        return ""

    if "://" in token:
        parsed = urllib.parse.urlsplit(token)
        return (parsed.hostname or "").strip().lower()

    # Preserve valid IPv4/IPv6 CIDR blocks (e.g. 10.0.0.0/8)
    if "/" in token:
        left, right = token.split("/", 1)
        if right.isdigit():
            try:
                net = ipaddress.ip_network(token, strict=False)
                return str(net)
            except ValueError:
                pass
        token = left

    # Bracketed IPv6 with optional :port, e.g. [2001:db8::1]:8443
    if token.startswith("[") and "]" in token:
        return token[1 : token.index("]")].strip().lower()

    # host:port or ipv4:port (single colon with numeric port)
    if token.count(":") == 1:
        host_part, port_part = token.rsplit(":", 1)
        if port_part.isdigit():
            token = host_part

    return token.strip().lower()


def parse_yaml_base_urls(yaml_file: Path) -> list[str]:
    """Extract *_BASE_URL or *EXTRA_ALLOWED_HOSTS values from a local Harbor YAML config without PyYAML."""
    if not yaml_file.is_file():
        return []
    found: list[str] = []
    key_group = "|".join(re.escape(k) for k in EXTRA_HOST_ENV_KEYS)
    pat = re.compile(rf"^\s*(?:{key_group})\s*:\s*(.+?)\s*$")
    for raw_line in yaml_file.read_text(encoding="utf-8").splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        m = pat.match(raw_line)
        if not m:
            continue
        val = m.group(1).strip()
        if len(val) >= 2 and val[0] == val[-1] and val[0] in ("'", '"'):
            val = val[1:-1]
        else:
            val = re.sub(r"\s+#.*$", "", val).strip()
        if val and not val.startswith("$"):
            found.append(val)
    return found


def yaml_uses_agy_oauth(yaml_file: Path) -> bool:
    """Return True if the Harbor YAML config enables CustomAntigravityCli (local OAuth subscription)."""
    if not yaml_file.is_file():
        return False
    for raw_line in yaml_file.read_text(encoding="utf-8").splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "custom_antigravity:CustomAntigravityCli" in stripped:
            return True
    return False


def resolve_allowed_hosts(
    env_file: Path | None = None,
    environ: Mapping[str, str] | None = None,
    harnesses_yaml: Path | None = None,
) -> list[str]:
    """Return DEFAULT_ALLOWED_HOSTS plus any extra hosts configured in .env, YAML, and process env."""
    merged_env: dict[str, str] = {}
    dotenv_path = env_file if env_file is not None else (ROOT / ".env")
    yaml_path = harnesses_yaml if harnesses_yaml is not None else (ROOT / "configs" / "official_harnesses.yaml")
    merged_env.update(parse_dotenv(dotenv_path))
    merged_env.update(environ if environ is not None else os.environ)

    hosts: list[str] = list(DEFAULT_ALLOWED_HOSTS)
    seen: set[str] = set(hosts)

    agy_oauth_env = merged_env.get("VULNHUNTER_AGY_OAUTH", "").strip().lower()
    if agy_oauth_env in ("1", "true", "yes", "on") or yaml_uses_agy_oauth(yaml_path):
        for host in AGY_OAUTH_ALLOWED_HOSTS:
            if host not in seen:
                seen.add(host)
                hosts.append(host)

    raw_sources: list[str] = [merged_env.get(key, "").strip() for key in EXTRA_HOST_ENV_KEYS]
    raw_sources.extend(parse_yaml_base_urls(yaml_path))

    for raw_val in raw_sources:
        if not raw_val:
            continue
        for part in re.split(r"[,;\s]+", raw_val):
            host = extract_host_entry(part)
            if host and host not in seen:
                seen.add(host)
                hosts.append(host)

    return hosts


def format_allowed_hosts_toml(hosts: list[str]) -> str:
    items = "".join(f'    "{h}",\n' for h in hosts)
    return f"allowed_hosts = [\n{items}]"


def sync_task_toml(toml_path: Path, allowed_hosts: list[str]) -> bool:
    """Update [agent].allowed_hosts in task.toml if network_mode == 'allowlist'. Returns True if modified."""
    original = toml_path.read_text(encoding="utf-8")
    cfg = tomllib.loads(original)
    agent_cfg = cfg.get("agent", {})
    if agent_cfg.get("network_mode") != "allowlist":
        return False
    if agent_cfg.get("allowed_hosts") == allowed_hosts:
        return False

    replacement = format_allowed_hosts_toml(allowed_hosts)

    # Match [agent] section body up to the next [section] header or EOF
    section_pat = re.compile(r"(^\[agent\]\s*\n)(.*?)(?=^\[|\Z)", flags=re.MULTILINE | re.DOTALL)
    match = section_pat.search(original)
    if not match:
        return False

    header, body = match.group(1), match.group(2)
    list_pat = re.compile(r"^allowed_hosts\s*=\s*\[[^\]]*\]", flags=re.MULTILINE | re.DOTALL)
    if list_pat.search(body):
        new_body = list_pat.sub(replacement, body, count=1)
    else:
        suffix = "" if body.endswith("\n") else "\n"
        new_body = f"{body}{suffix}{replacement}\n"

    updated = original[: match.start()] + header + new_body + original[match.end() :]
    if updated != original:
        toml_path.write_text(updated, encoding="utf-8")
        return True
    return False


def main() -> int:
    parser = argparse.ArgumentParser(description="Resolve and sync allowed_hosts from .env and environment.")
    parser.add_argument("--env-file", default=str(ROOT / ".env"), help="Path to .env file")
    parser.add_argument("--datasets-dir", default=str(ROOT / "datasets"), help="Datasets directory to sync")
    parser.add_argument("--include-template", action="store_true", help="Also sync templates/task-skeleton/task.toml")
    parser.add_argument("--print-only", action="store_true", help="Only print resolved allowed_hosts without writing")
    args = parser.parse_args()

    hosts = resolve_allowed_hosts(Path(args.env_file))
    if args.print_only:
        for h in hosts:
            print(h)
        return 0

    targets = sorted(Path(args.datasets_dir).rglob("task.toml"))
    if args.include_template:
        tpl_toml = ROOT / "templates" / "task-skeleton" / "task.toml"
        if tpl_toml.is_file():
            targets.append(tpl_toml)

    changed = 0
    for toml_path in targets:
        if sync_task_toml(toml_path, hosts):
            changed += 1
            rel = toml_path.relative_to(ROOT) if toml_path.is_relative_to(ROOT) else toml_path
            print(f"[UPDATED] {rel}")

    print(f"Resolved allowed_hosts ({len(hosts)}): {', '.join(hosts)} ({changed} file(s) updated)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
