#!/usr/bin/env python3
"""Export sanitized VulnHunter benchmark results into docs/data/leaderboard.{json,js}.

Reads task metadata from datasets/vulnhunter-core/*/task.toml and merges completed
Harbor job runs under jobs/ (excluding oracle jobs and transient ApiRateLimitError
retries that did not execute). Produces zero-secret static datasets consumed by the
GitHub Pages dashboard in docs/.
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import tomllib
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

TIER1_TASKS: tuple[str, ...] = (
    "c-cmdstream-sequencer",
    "c-session-broker",
    "c-telemetry-parser",
    "c-vm-mmu",
    "cpp-frame-compositor",
    "java-base64-decoder",
    "py-flow-studio",
    "py-webhook-preview",
)
TIER2_TASKS: tuple[str, ...] = (
    "c-ike-key-schedule",
    "c-query-agg-engine",
    "cpp-quic-stream-mux",
    "py-wal-kv-store",
    "rs-chunked-deque",
    "ts-edge-gateway-auth",
)
TIER3_TASKS: tuple[str, ...] = (
    "c-ebpf-verifier-sandbox",
    "cpp-http2-hpack-framer",
    "java-jwk-federation-guard",
    "py-wasm-aot-validator",
    "rs-mvcc-ssi-engine",
    "ts-graphql-federation-planner",
)
ALL_TASKS: tuple[str, ...] = TIER1_TASKS + TIER2_TASKS + TIER3_TASKS

DEFAULT_JOB_DIRS: tuple[str, ...] = (
    "jobs/vulnhunter-v3",
    "jobs/vulnhunter-v3-rerun",
    "jobs/vulnhunter-tier2-6tasks",
    "jobs/vulnhunter-tier2-rerun",
    "jobs/vulnhunter-20tasks-expansion",
    "jobs/vulnhunter-20tasks-rerun",
    "jobs/vulnhunter-5400s-recall",
)

LANG_MAP: dict[str, str] = {
    "c": "C",
    "cpp": "C++",
    "java": "Java",
    "py": "Python",
    "rs": "Rust",
    "ts": "TypeScript",
}

PROVIDER_LABEL: dict[str, str] = {
    "anthropic": "Anthropic",
    "openai": "OpenAI",
    "google": "Google",
    "deepseek": "DeepSeek",
    "zai": "Zhipu AI",
}

CODE_EXTS: frozenset[str] = frozenset(
    {".c", ".h", ".cpp", ".hpp", ".cc", ".java", ".py", ".rs", ".ts", ".js"}
)

TASK_TITLES: dict[str, tuple[str, str]] = {
    "c-cmdstream-sequencer": ("命令流微码定序器", "Command-Stream Microcode Sequencer"),
    "c-session-broker": ("会话协商代理", "Session Negotiation Broker"),
    "c-telemetry-parser": ("二进制遥测帧解析器", "Binary Telemetry Frame Parser"),
    "c-vm-mmu": ("虚拟内存写时复制 MMU", "Copy-on-Write Virtual MMU"),
    "cpp-frame-compositor": ("图形帧合成器", "Graphics Frame Compositor"),
    "java-base64-decoder": ("向量化 Base64 解码器", "Vectorized Base64 Decoder"),
    "py-flow-studio": ("工作流表达式沙箱", "Workflow Expression Sandbox"),
    "py-webhook-preview": ("Webhook 预览客户端", "Webhook Preview Client"),
    "c-ike-key-schedule": ("IKEv2 多轮混合密钥调度器", "IKEv2 Hybrid Key Schedule"),
    "c-query-agg-engine": ("分析型 SQL 聚合引擎", "Analytical SQL Aggregation Engine"),
    "cpp-quic-stream-mux": ("QUIC 流多路复用器", "QUIC Stream Multiplexer"),
    "py-wal-kv-store": ("WAL 崩溃恢复键值存储", "WAL Crash-Recovery KV Store"),
    "rs-chunked-deque": ("Rust Unsafe 分块双端队列", "Rust Unsafe Chunked Deque"),
    "ts-edge-gateway-auth": ("多租户边缘鉴权网关", "Multi-Tenant Edge Auth Gateway"),
    "c-ebpf-verifier-sandbox": ("eBPF 抽象解释验证与沙箱", "eBPF Abstract Verifier & Sandbox"),
    "cpp-http2-hpack-framer": ("HTTP/2 与 HPACK 协议帧器", "HTTP/2 & HPACK Protocol Framer"),
    "java-jwk-federation-guard": ("联邦 OIDC JWS / DPoP 守卫", "Federated OIDC JWS & DPoP Guard"),
    "py-wasm-aot-validator": ("WebAssembly 字节码验证器", "WebAssembly Bytecode Validator"),
    "rs-mvcc-ssi-engine": ("MVCC 可串行化快照隔离引擎", "MVCC Serializable Snapshot Engine"),
    "ts-graphql-federation-planner": ("GraphQL 联邦查询规划器", "GraphQL Federation Query Planner"),
}


def count_task_loc(task_dir: Path) -> int:
    app_dir = task_dir / "environment" / "app"
    if not app_dir.is_dir():
        return 0
    total = 0
    for f in app_dir.rglob("*"):
        if f.is_file() and f.suffix.lower() in CODE_EXTS:
            if any(part in ("build", "target", "node_modules", "__pycache__") for part in f.parts):
                continue
            try:
                total += sum(1 for ln in f.read_text(encoding="utf-8", errors="ignore").splitlines() if ln.strip())
            except OSError:
                pass
    return total


def is_safety_refusal(trial_dir: Path, exc_type: str | None) -> bool:
    if exc_type == "AgentSafetyRefusalError":
        return True
    traj = trial_dir / "agent" / "trajectory.json"
    if traj.is_file():
        txt = traj.read_text(encoding="utf-8", errors="replace")
        if "blocked by Gemini's filters" in txt:
            return True
    return False


def format_harness_name(agent_cfg: dict) -> str:
    raw = str(agent_cfg.get("name") or agent_cfg.get("import_path") or "")
    if "custom_claude" in raw:
        return "Claude Code"
    if "custom_antigravity" in raw:
        return "Antigravity CLI"
    if raw == "claude-code":
        return "Claude Code"
    if raw == "codex":
        return "Codex CLI"
    return raw


def infer_effort(model_name: str, latest_effort: str) -> str:
    if latest_effort:
        return latest_effort
    lower = model_name.lower()
    for suffix in ("xhigh", "high", "max", "medium", "low"):
        if lower.endswith(f"-{suffix}"):
            return suffix
    return "default"


def load_tasks() -> list[dict]:
    tasks: list[dict] = []
    for task_id in ALL_TASKS:
        tdir = ROOT / "datasets" / "vulnhunter-core" / task_id
        toml_path = tdir / "task.toml"
        cfg = tomllib.loads(toml_path.read_text(encoding="utf-8")) if toml_path.is_file() else {}
        meta = cfg.get("metadata", {})
        tier = 1 if task_id in TIER1_TASKS else (2 if task_id in TIER2_TASKS else 3)
        lang_prefix = task_id.split("-", 1)[0]
        title_zh, title_en = TASK_TITLES.get(task_id, (task_id, task_id))
        tasks.append(
            {
                "id": task_id,
                "tier": tier,
                "language": LANG_MAP.get(lang_prefix, lang_prefix.upper()),
                "category": str(meta.get("category", "security")),
                "difficulty": str(meta.get("difficulty", "hard")),
                "tags": list(meta.get("tags", [])),
                "timeout_sec": float((cfg.get("agent") or {}).get("timeout_sec", 5400.0)),
                "loc": count_task_loc(tdir),
                "title_zh": title_zh,
                "title_en": title_en,
            }
        )
    return tasks


def load_merged_trials(job_dirs: tuple[str, ...]) -> tuple[dict[tuple[str, str], dict], dict[str, dict]]:
    merged: dict[tuple[str, str], dict] = {}
    model_meta: dict[str, dict] = {}

    for rel_jdir in job_dirs:
        jdir = ROOT / rel_jdir
        if not jdir.is_dir():
            continue
        for rpath_str in sorted(glob.glob(str(jdir / "*" / "result.json"))):
            rpath = Path(rpath_str)
            try:
                data = json.loads(rpath.read_text(encoding="utf-8"))
            except Exception:
                continue
            task_id = str(data.get("task_name") or "")
            agent_cfg = (data.get("config") or {}).get("agent") or {}
            model_id = str(agent_cfg.get("model_name") or "")
            if task_id not in ALL_TASKS or not model_id:
                continue

            exc_info = data.get("exception_info") or {}
            exc_type = exc_info.get("exception_type")
            if exc_type == "ApiRateLimitError":
                # Do not let a quota-blocked retry overwrite an executed attempt
                continue

            rew = ((data.get("verifier_result") or {}).get("rewards") or {}).get("reward")
            passed = rew == 1.0
            started = data.get("started_at")
            finished = data.get("finished_at")
            dur = (
                int(round((datetime.fromisoformat(finished) - datetime.fromisoformat(started)).total_seconds()))
                if (started and finished)
                else 0
            )
            safety = is_safety_refusal(rpath.parent, exc_type)
            if passed:
                status = "pass"
            elif safety:
                status = "safety_refusal"
            elif exc_type == "AgentTimeoutError":
                status = "timeout"
            else:
                status = "fail"

            key = (model_id, task_id)
            prev = merged.get(key)
            if prev is None or (finished or "") > (prev.get("finished_at") or ""):
                merged[key] = {
                    "passed": passed,
                    "status": status,
                    "duration_sec": dur,
                    "finished_at": finished or "",
                }

            effort = str((agent_cfg.get("kwargs") or {}).get("reasoning_effort") or "")
            prev_m = model_meta.get(model_id)
            if prev_m is None or (finished or "") > (prev_m.get("finished_at") or ""):
                prov_key = model_id.split("/", 1)[0] if "/" in model_id else "other"
                short = model_id.split("/", 1)[1] if "/" in model_id else model_id
                short = short.replace("[1m]", "").replace("-latest", "")
                model_meta[model_id] = {
                    "id": model_id,
                    "short": short,
                    "provider_key": prov_key,
                    "provider": PROVIDER_LABEL.get(prov_key, prov_key),
                    "harness": format_harness_name(agent_cfg),
                    "effort": infer_effort(model_id, effort),
                    "finished_at": finished or "",
                }

    return merged, model_meta


def main() -> int:
    parser = argparse.ArgumentParser(description="Export VulnHunter benchmark leaderboard JSON/JS for GitHub Pages.")
    parser.add_argument("--out-dir", default=str(ROOT / "docs" / "data"))
    args = parser.parse_args()

    tasks = load_tasks()
    merged, model_meta = load_merged_trials(DEFAULT_JOB_DIRS)
    model_ids = sorted(model_meta.keys())

    # Enrich each task with empirical pass counts
    for t in tasks:
        tid = t["id"]
        t["passes"] = sum(1 for m in model_ids if merged.get((m, tid), {}).get("passed"))
        t["total_models"] = len(model_ids)

    models_out: list[dict] = []
    for mid in model_ids:
        meta = dict(model_meta[mid])
        meta.pop("finished_at", None)
        results = []
        for t in tasks:
            cell = merged.get((mid, t["id"]))
            if cell is None:
                results.append({"passed": False, "status": "missing", "duration_sec": 0})
            else:
                results.append(
                    {
                        "passed": cell["passed"],
                        "status": cell["status"],
                        "duration_sec": cell["duration_sec"],
                    }
                )
        meta["results"] = results
        models_out.append(meta)

    total_cells = len(model_ids) * len(tasks)
    total_passed = sum(
        1 for m in models_out for r in m["results"] if r["passed"]
    )

    payload = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "benchmark": {
            "name": "VulnHunter Core",
            "repo": "https://github.com/fuqiuluo/VulnHunter",
            "timeout_sec": 5400,
            "total_tasks": len(tasks),
            "total_models": len(models_out),
            "total_trials": total_cells,
            "total_passed": total_passed,
            "tiers": [
                {"tier": 1, "label_zh": "一期基础", "label_en": "Tier 1 · Foundational", "count": len(TIER1_TASKS)},
                {"tier": 2, "label_zh": "二期多缺陷", "label_en": "Tier 2 · Multi-Defect", "count": len(TIER2_TASKS)},
                {"tier": 3, "label_zh": "三期深水区", "label_en": "Tier 3 · Deep-Water", "count": len(TIER3_TASKS)},
            ],
        },
        "tasks": tasks,
        "models": models_out,
    }

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    json_str = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    (out_dir / "leaderboard.json").write_text(json_str, encoding="utf-8")
    (out_dir / "leaderboard.js").write_text(
        "// Auto-generated by scripts/export_leaderboard.py — do not edit manually\n"
        f"window.__VULNHUNTER_DATA__ = {json_str.strip()};\n",
        encoding="utf-8",
    )
    print(
        f"Exported {len(models_out)} models x {len(tasks)} tasks = {total_cells} trials "
        f"({total_passed}/{total_cells} = {total_passed / max(1, total_cells) * 100:.1f}%) to {out_dir}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
