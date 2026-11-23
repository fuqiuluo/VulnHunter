# VulnHunter — 基于厂商官方 Agent Harness 的无提示主动安全审计评测集

[![Live Leaderboard](https://img.shields.io/badge/Leaderboard-GitHub%20Pages-38bdf8?style=flat-square)](https://fuqiuluo.github.io/VulnHunter/)
[![Tasks](https://img.shields.io/badge/Tasks-20%20Zero--Hint-818cf8?style=flat-square)](#三-20-道赛题分阶清单)
[![Trials](https://img.shields.io/badge/Evaluated-260%20Trials%20(13%20Models)-34d399?style=flat-square)](#一-20-题--13-模型加权综合排行榜)

> **在线交互排行榜仪表盘**：**[https://fuqiuluo.github.io/VulnHunter/](https://fuqiuluo.github.io/VulnHunter/)**（支持 4 种难度加权公式动态切换、剔除云端安全误拒对比、速度×得分帕累托前沿图与 20×13 交互热力矩阵）

本项目基于 **[Harbor](https://harborframework.com/)** 容器沙箱评测规范构建，专门用于驱动各大模型厂商**官方自带的 Agent CLI Harness**（Anthropic `claude-code`、OpenAI `codex`、Google Antigravity CLI `agy` 等），在**零提示防御性盲审（Zero-Hint Defensive Review）**条件下评测模型主动阅读跨文件多语言工程代码、自主定位深层耦合缺陷并完成原地加固与回归验证的真实能力上限。单题 Agent 执行超时对齐 SEC-bench / CyberGym-E2E 标准设为 **`5400s`（90 分钟）**。

---

## 一、 20 题 × 13 模型加权综合排行榜

主排名采用 **综合难度加权分** $w_i = \text{Tier}_i \times (2 - p_i)$（兼顾分阶复杂度 $\text{Tier}_i \in \{1, 2, 3\}$ 与 13 模型实测通过率稀缺度 $p_i$，折算为 `100.0` 分制，彻底消除同分平局；全部 260 场评测完成度 **100%**，总通过率 **193 / 260 = 74.2%**）：

| 排名 | 模型 | 官方 CLI (档位) | **综合加权 (/100)** | 分阶 1:2:3 (/38) | 原始通过 | T1 / T2 / T3 | 通过均耗时 |
| :---: | :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **1** | **`anthropic/claude-opus-5-5[1m]`** | `Claude Code` (`xhigh`) | **87.2** | **34.0 (89.5%)** | **18 / 20 (90.0%)** | 8/8 · 4/6 · **6/6** | 1,366s |
| **2** | **`anthropic/claude-fable-5-2[1m]`** | `Claude Code` (`xhigh`) | **81.3** | 32.0 (84.2%) | 17 / 20 (85.0%) | 7/8 · **5/6** · 5/6 | 1,698s |
| **3** | **`openai/gpt-6.2-astra`** | `Codex CLI` (`xhigh`) | **76.3** | 31.0 (81.6%) | 17 / 20 (85.0%) | 8/8 · 4/6 · 5/6 | **440s** |
| **4** | **`google/gemini-4-neon-xhigh`** | `Antigravity CLI` (`xhigh`) | **73.1** | 30.0 (78.9%) | 16 / 20 (80.0%) | 7/8 · 4/6 · 5/6 | 836s |
| **5** | `openai/gpt-6.2-sol` | `Codex CLI` (`xhigh`) | **68.5** | 28.0 (73.7%) | 16 / 20 (80.0%) | 8/8 · 4/6 · 4/6 | 587s |
| **6** | `google/gemini-4-carbon-high` | `Antigravity CLI` (`high`) | **68.1** | 28.0 (73.7%) | 14 / 20 (70.0%) | 5/8 · 4/6 · 5/6 | 1,208s |
| **7** | `openai/gpt-6-sol` | `Codex CLI` (`xhigh`) | **67.4** | 28.0 (73.7%) | 15 / 20 (75.0%) | 7/8 · 3/6 · 5/6 | 603s |
| **8** | `openai/gpt-6-astra` | `Codex CLI` (`xhigh`) | **65.1** | 27.0 (71.1%) | 16 / 20 (80.0%) | 8/8 · **5/6** · 3/6 | 508s |
| **9** | `openai/gpt-daybreak-blue-latest` | `Codex CLI` (`xhigh`) | **65.0** | 27.0 (71.1%) | 15 / 20 (75.0%) | 7/8 · 4/6 · 4/6 | 637s |
| **10** | `deepseek/deepseek-flash[1m]` | `Claude Code` (`max`) | **62.1** | 26.0 (68.4%) | 15 / 20 (75.0%) | 8/8 · 3/6 · 4/6 | 596s |
| **11** | `zai/GLM-5.3` | `Claude Code` (`max`) | **50.9** | 21.0 (55.3%) | 13 / 20 (65.0%) | 8/8 · 2/6 · 3/6 | 919s |
| **12** | `zai/GLM-5.4` | `Claude Code` (`max`) | **43.6** | 19.0 (50.0%) | 12 / 20 (60.0%) | 7/8 · 3/6 · 2/6 | 3,530s |
| **13** | `anthropic/claude-opus-4-8[1m]` | `Claude Code` (`xhigh`) | **34.0** | 15.0 (39.5%) | 9 / 20 (45.0%) | 5/8 · 2/6 · 2/6 | 1,189s |

完整单题矩阵、信息熵加权、帕累托前沿图及安全护栏对比请访问在线仪表盘：**[https://fuqiuluo.github.io/VulnHunter/](https://fuqiuluo.github.io/VulnHunter/)**。

---

## 二、 核心设计原则：零提示防御性主动审计（Zero-Hint Defensive Review）

为贴近真实防御性代码审计场景并避免要求模型构造攻击性触发样本，题库强制执行以下规则（已内置到 `scripts/validate_suite.py` 自动拦截）：
1. **`instruction.md` 严禁剧透且保持纯防御定位**：提示词不出现 `漏洞 / bug / vulnerability / exploit / overflow / SSRF / CWE` 等暗示词，只要求模型以日常防御性维护评审的方式交付根因分析报告（`report.json`）、代码加固修复及回归单测；隐藏对抗边界与回归用例由隔离的宿主机侧 `tests/verify.py` 确定性执行。
2. **目录名与源码去特征化**：题目目录采用中性业务模块命名（如 `c-ebpf-verifier-sandbox`、`rs-mvcc-ssi-engine`），待测源码不含提示性注释；真实 CWE 标签仅保存在宿主机侧 `task.toml` 的 `[metadata]` 中，容器内不可见。
3. **判分与答案物理隔离**：`solution/` 与 `tests/` 在被测 Agent 运行期间完全不在容器内，仅在 Agent 退出后由 Harbor 挂载执行。
4. **全程断网与禁搜隔离**：Agent 运行阶段通过 `network_mode = "allowlist"` 仅放行模型推理 API 域名，同时通过系统级配置/Hook 禁用各 CLI 内置联网工具；判分阶段强制 `network_mode = "no-network"` 完全断网执行。

---

## 三、 20 道赛题分阶清单

| 分阶 | 题量 | 覆盖语言与代表赛题 | 13 模型平均通过率 |
| :--- | :---: | :--- | :---: |
| **Tier-1 基础真题** | 8 题 | `c-cmdstream-sequencer`、`c-session-broker`、`c-telemetry-parser`、`c-vm-mmu`、`cpp-frame-compositor`、`java-base64-decoder`、`py-flow-studio`、`py-webhook-preview` | **89.4%** (93/104) |
| **Tier-2 高难多缺陷** | 6 题 | `c-ike-key-schedule` *(1/13)*、`c-query-agg-engine`、`cpp-quic-stream-mux`、`py-wal-kv-store`、`rs-chunked-deque`、`ts-edge-gateway-auth` | **60.3%** (47/78) |
| **Tier-3 深水区四缺陷** | 6 题 | `c-ebpf-verifier-sandbox`、`cpp-http2-hpack-framer`、`java-jwk-federation-guard`、`py-wasm-aot-validator`、`rs-mvcc-ssi-engine` *(2/13)*、`ts-graphql-federation-planner` | **67.9%** (53/78) |

---

## 四、 目录结构

```text
VulnHunter/
├── .github/workflows/
│   └── pages.yml                       # GitHub Pages 自动部署流水线（发布 docs/）
├── configs/
│   ├── oracle_check.yaml               # 批量运行内置 oracle 校验所有题目自身可解（期望全 1.0）
│   └── official_harnesses.example.yaml # 横向评测配置模板（复制为 official_harnesses.yaml 本地使用，不入库）
├── docs/                               # GitHub Pages 静态排行榜仪表盘
│   ├── index.html / app.js / styles.css
│   └── data/leaderboard.{json,js}      # 由 scripts/export_leaderboard.py 导出的脱敏评测数据
├── harnesses/
│   ├── custom_claude.py                # 自定义 Claude Code 适配器（支持自定义二进制与 preload）
│   └── custom_antigravity.py           # Antigravity CLI 适配器（支持本地 Google OAuth 订阅与禁网 Hook）
├── datasets/
│   └── vulnhunter-core/                # 20 道核心评测真题（C / C++ / Rust / Java / Python / TypeScript）
├── templates/
│   └── task-skeleton/                  # 新建测试题标准零提示模板
└── scripts/
    ├── agy_oauth_login.sh              # Antigravity CLI 本地文件型 OAuth 一次性登录脚本
    ├── export_leaderboard.py           # 从 jobs/ 汇总脱敏评测结果并更新 docs/data/leaderboard.{json,js}
    ├── network_policy.py               # 从环境变量 / .env 解析并同步白名单域名至 task.toml
    ├── new_task.py                     # 快速生成新题目录脚手架
    ├── run_harbor.sh                   # 自动加载 .env、同步白名单并启动 harbor
    └── validate_suite.py               # 静态检查 + 零提示违禁词扫描 + 本地 Oracle 自检（0.0 -> 1.0）
```

---

## 五、 环境准备与运行指南

### 1. 安装 Harbor（确保本机 Docker 已启动）

```bash
pip install harbor
# 或使用 uv：uv tool install harbor
```

### 2. 本地零提示合规检查与 Oracle 自检（不消耗 Token）

```bash
# 静态扫描提示词是否夹带暗示词 + 本地验证“未解答 0.0 -> 标准解 1.0”
python3 scripts/validate_suite.py --local-oracle

# 在真实 Docker 容器内跑一遍 oracle 确认镜像构建正常
harbor run --config configs/oracle_check.yaml
```

### 3. 启动评测并更新排行榜数据

```bash
cp .env.example .env
cp configs/official_harnesses.example.yaml configs/official_harnesses.yaml
# 按需配置 API Key 或运行 ./scripts/agy_oauth_login.sh 准备 Antigravity OAuth 凭据

# 启动官方 Harness 横向评测
./scripts/run_harbor.sh run --config configs/official_harnesses.yaml

# 评测完成后自动汇总脱敏数据并刷新 docs/ 排行榜网页
python3 scripts/export_leaderboard.py
```

---

## 六、 新建无提示测试题流程

```bash
# 1. 使用中性模块名创建题目骨架（不要在 task_id 中带 uaf/overflow/ssrf 等词）
python3 scripts/new_task.py c-session-cache \
  --category memory-safety \
  --difficulty hard \
  --tags "c,cwe-416"

# 2. 填入待测源码、无提示 instruction.md、标准解与判分脚本后运行校验
python3 scripts/validate_suite.py --local-oracle

# 3. 容器内 Oracle 验证
harbor run -p datasets/vulnhunter-core/c-session-cache -a oracle
```
