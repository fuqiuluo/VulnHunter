# VulnHunter — 基于厂商官方 Agent Harness 的无提示主动审计评测集

本项目基于 **[Harbor](https://harborframework.com/)** 容器沙箱评测规范构建，专门用于驱动各大模型厂商**官方自带的 Agent CLI Harness**（如 Anthropic `claude-code`、OpenAI `codex`、Google `gemini-cli`），在**零提示（Zero-Hint / Blind Review）**条件下评测模型主动阅读代码、自主发现深层隐患、构造验证用例并完成修复的真实能力上限。

---

## 一、 核心设计原则：零提示主动分析（Zero-Hint）

为贴近真实的盲审场景，题库强制执行以下防剧透规则（已内置到 `scripts/validate_suite.py` 自动拦截）：
1. **`instruction.md` 严禁剧透**：提示词不出现 `漏洞 / bug / vulnerability / exploit / overflow / SSRF / CWE` 等任何暗示词，只要求模型对 `/app` 开展全面分析并按统一契约交付分析报告（`report.json`）、验证样本/单测与代码改进。
2. **目录名与源码去特征化**：题目目录采用中性业务模块命名（如 `c-telemetry-parser`、`py-webhook-preview`），待测源码不含提示性注释或显眼的异常类名；真实 CWE 标签仅保存在宿主机侧 `task.toml` 的 `[metadata]` 中，容器内不可见。
3. **判分与答案物理隔离**：`solution/` 与 `tests/` 在被测 Agent 运行期间完全不在容器内，仅在 Agent 退出后由 Harbor 挂载执行。
4. **全程断网与禁搜隔离**：Agent 运行阶段通过 `network_mode = "allowlist"` 仅放行模型推理 API 域名，拦截容器外网访问；同时在容器 `/etc/` 系统级配置中强制禁用 Claude Code（`WebSearch`/`WebFetch`）、Codex CLI（`web_search`）、Gemini CLI（`google_web_search`/`web_fetch`）内置联网工具；判分阶段（`[verifier]`）强制设为 `network_mode = "no-network"` 完全断网执行。

---

## 二、 目录结构

```text
VulnHunter/
├── configs/
│   ├── oracle_check.yaml               # 批量运行内置 oracle 校验所有题目自身可解（期望全 1.0）
│   └── official_harnesses.example.yaml # 横向评测配置模板（复制为 official_harnesses.yaml 本地使用，不入库）
├── harnesses/
│   └── custom_claude.py                # 自定义 Claude Code 适配器（支持自定义二进制名如 claude-2.1.322 及 preload 拷贝命令）
├── datasets/
│   └── vulnhunter-core/                # 核心能力测试集目录
│       ├── c-telemetry-parser/         # 示例题 1：C 遥测帧解析模块盲审
│       ├── java-base64-decoder/        # 示例题 2：Java Base64 向量块解码器盲审（节选自 OpenJDK Java4Shell）
│       └── py-webhook-preview/         # 示例题 3：Python Webhook 预览客户端盲审
├── templates/
│   └── task-skeleton/                  # 新建测试题标准零提示模板
└── scripts/
    ├── network_policy.py               # 从环境变量 / .env 解析并同步白名单域名至 task.toml
    ├── new_task.py                     # 快速生成新题目录脚手架
    ├── run_harbor.sh                   # 自动加载 .env、同步白名单并启动 harbor
    └── validate_suite.py               # 静态检查 + 零提示违禁词扫描 + 本地 Oracle 自检（0.0 -> 1.0）
```

---

## 三、 环境准备与开启测试

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

### 3. 使用各厂商官方 Agent Harness 开启评测

支持直接在 `.env`（参考 `.env.example`）或环境变量中配置 API Key，以及通过 `VULNHUNTER_EXTRA_ALLOWED_HOSTS` 或 `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` / `GOOGLE_GEMINI_BASE_URL` 额外放行自定义反代/网关 URL：

```bash
cp .env.example .env
cp configs/official_harnesses.example.yaml configs/official_harnesses.yaml
# 编辑 .env 与 configs/official_harnesses.yaml（两者均已在 .gitignore 忽略，不会提交本地密钥或企业定制配置）
# 支持通过 harnesses.custom_claude:CustomClaudeCode 自定义 binary_name（如 claude-2.1.322）与 preload（如 upload ~/.claude-2.1.322 /root/.claude-2.1.322）

# 方式 A：通过封装脚本启动（自动加载 .env、提取白名单域名同步至 task.toml 并执行 harbor）
./scripts/run_harbor.sh run --config configs/official_harnesses.yaml

# 方式 B：单独评测某一家官方 CLI（手动同步 .env 白名单后调用 harbor）
python3 scripts/network_policy.py
harbor run -p datasets/vulnhunter-core \
  --agent claude-code \
  --model anthropic/claude-sonnet-4-5 \
  --n-concurrent 2
```

---

## 四、 新建无提示测试题流程

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
