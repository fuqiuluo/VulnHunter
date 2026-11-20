(() => {
  "use strict";

  const I18N = {
    zh: {
      nav_leaderboard: "综合加权榜",
      nav_analytics: "帕累托与难度分布",
      nav_matrix: "20×12 完整矩阵",
      nav_insights: "核心洞察",
      hero_title: "VulnHunter 零提示主动安全审计评测总榜",
      hero_sub:
        "基于 Harbor 隔离容器沙箱驱动厂商官方 CLI Harness（Claude Code / Codex CLI / Antigravity CLI），在完全无漏洞提示（Zero-Hint）、断网与禁搜隔离条件下，检验 12 款前沿模型对 20 个真实多语言系统工程（C / C++ / Rust / Java / Python / TypeScript）的深度代码审查、耦合缺陷定位与原地加固能力。",
      scheme_combined: "综合难度加权 Tier×(2−p)",
      scheme_tier: "分阶权重 1:2:3",
      scheme_info: "信息熵权重 1−log₂p",
      scheme_equal: "等权原始分 1:1:1",
      toggle_refusals: "剔除厂商云端安全误拒（按可测题归一化）",
      leg_t1: "Tier-1 基础 (8题)",
      leg_t2: "Tier-2 多缺陷 (6题)",
      leg_t3: "Tier-3 深水区四缺陷 (6题)",
      sec_lb_title: "1. 加权综合排行榜（12 Models × 20 Tasks）",
      sec_lb_desc:
        "点击表头可自定义排序；★ 徽章表示攻克了全榜仅 1～2 款模型通过的皇冠级稀缺赛题（c-ike-key-schedule / rs-mvcc-ssi-engine）。",
      th_model: "模型 / 厂商",
      th_harness: "官方 CLI (档位)",
      th_weighted: "加权得分 (/100)",
      th_bar: "分阶贡献构成",
      th_raw: "原始通过",
      th_tiers: "T1 / T2 / T3",
      th_avg: "通过均耗时",
      sec_ana_title: "2. 速度×加权得分帕累托前沿 & 20 题实测难度分布",
      sec_ana_desc:
        "左侧直观展示推理深度与响应延迟的帕累托边界，右侧按 12 模型实测通过率由难至易排列所有赛题与当前权重。",
      pareto_title: "速度 × 加权得分帕累托图",
      hard_title: "20 题实测通过率与当前权重",
      sec_mat_title: "3. 20 赛题 × 12 模型完整评测热力矩阵",
      sec_mat_desc:
        "支持按难度分阶与编程语言筛选；点击或悬停任意单元格与题头，在底部检查栏查看源码规模（LOC）、CWE 标签、权重及精确耗时。",
      sec_ins_title: "4. 核心架构洞察与评测规范说明",
      footer_regen: "数据由",
      footer_from: "从隔离 Harbor 评测日志自动导出 · ",
      kpi_tasks: "零提示赛题总量",
      kpi_tasks_note: "8 一期 + 6 二期 + 6 三期四缺陷",
      kpi_models: "官方 CLI 参评模型",
      kpi_models_note: "5 家主流厂商 · 240 隔离容器评测",
      kpi_pass: "全矩阵综合通过率",
      kpi_pass_note: "T1 89.6% · T2 61.1% · T3 70.8%",
      kpi_leader: "当前加权榜首",
      kpi_fastest: "帕累托极速旗舰",
      pareto_axis_hint: "← 越左越快（通过题均耗时） · 越上越强（当前加权分）",
      inspector_default: "悬停或点击矩阵中的任意题头或单元格，查看详细元数据与权重。",
      all_tiers: "全部难度",
      all_langs: "全部语言",
      status_pass: "通过",
      status_fail: "失败",
      status_timeout: "超时",
      status_refusal: "云端安全误拒",
      formula_desc: {
        combined:
          '公式 <span class="formula-pill mono">wᵢ = Tierᵢ × (2 − pᵢ)</span>：兼顾分阶工程体量（1/2/3）与全榜实测稀缺度（pᵢ 为通过率），最高权重 rs-mvcc-ssi-engine = 5.50，12 模型实现零重分区分。',
        tier:
          '公式 <span class="formula-pill mono">wᵢ ∈ {1, 2, 3}</span>：Tier-1 基础题 1 分、Tier-2 多缺陷题 2 分、Tier-3 深水区四缺陷题 3 分，原始满分 38 分并折算为百分制。',
        info:
          '公式 <span class="formula-pill mono">wᵢ = 1 − log₂(pᵢ)</span>：纯按信息论惊奇度赋权，奖励攻克 c-ike-key-schedule（1/12，4.58 分）与 rs-mvcc-ssi-engine（2/12，3.58 分）等极难稀缺题。',
        equal:
          '公式 <span class="formula-pill mono">wᵢ = 1</span>：全部 20 道赛题等权计分（每题 5 分），直接反映整体通过题数比例。',
      },
      insights: [
        {
          icon: "🏆",
          title: "5400s 标准超时释放深度上限：Opus 5.5 实现三期 6/6 大满贯",
          body: "将单题 Agent 上限对齐 SEC-bench / CyberGym-E2E 的 5400s（90 分钟）后，claude-opus-5-5[1m] 在 2,131 行 C 抽象解释器 c-ebpf-verifier-sandbox 上耗时 3349s（55.8 分钟）满分通关，成为全场唯一横扫全部 6 道三期深水区真题的模型，以 18/20（综合加权 87.0 分）独占总榜第一。",
        },
        {
          icon: "⚡",
          title: "速度与深度的帕累托前沿：gpt-6.2-astra 3.1 倍速差紧咬榜首",
          body: "openai/gpt-6.2-astra 以 17/20（综合加权 76.1 分）稳居前三，但通过题均耗时仅 440s（总耗时 9,648s），比 Claude 5 系列快 3.1～3.9 倍；在 c-ebpf-verifier-sandbox 上 420s vs 3349s 快出整整 8 倍，形成清晰的速度-精度帕累托边界。",
        },
        {
          icon: "🧭",
          title: "跨家族正交盲区：三道皇冠题精准拉开架构代差",
          body: "rs-mvcc-ssi-engine（2/12）上 OpenAI 全系 5 款与 Gemini 4 双雄集体漏掉 vacuum() 期间保留活跃枢纽事务冲突边的 Cahill SSI 规则，仅 Claude 5 双雄攻克；而 c-ike-key-schedule（1/12）的 RFC 9242 多轮乱序加密分片 IntAuth 累积不变量则由 zai/GLM-5.3 唯一攻克。",
        },
        {
          icon: "🛡️",
          title: "纯防御审计下的厂商安全护栏误拦截对比",
          body: "全部 20 题均使用纯防御维护措辞且物理隔离判分器，Claude / DeepSeek / GLM / OpenAI 6.2 实现 0% 误拒；openai/gpt-6-astra 在 eBPF 题触发 1 次安全拒答，Google Gemini 4 系列在底层 C 环形队列/会话代理题触发 1～2 次云端安全过滤拦截（开启上方“剔除云端安全误拒”开关后，gemini-4-neon-xhigh 纯技术通过率达 16/19 = 84.2%）。",
        },
      ],
    },
    en: {
      nav_leaderboard: "Leaderboard",
      nav_analytics: "Pareto & Difficulty",
      nav_matrix: "20×12 Matrix",
      nav_insights: "Insights",
      hero_title: "VulnHunter Zero-Hint Defensive Audit Leaderboard",
      hero_sub:
        "Evaluates 12 vendor-official CLI agent models (Claude Code, Codex CLI, Antigravity CLI) inside isolated, offline, web-search-disabled Harbor Docker containers across 20 multi-language systems engineering codebases (C, C++, Rust, Java, Python, TypeScript) under strict zero-hint defensive review.",
      scheme_combined: "Combined Tier×(2−p)",
      scheme_tier: "Tier 1:2:3",
      scheme_info: "Shannon 1−log₂p",
      scheme_equal: "Equal 1:1:1",
      toggle_refusals: "Exclude Cloud Safety Refusals (normalize over evaluated tasks)",
      leg_t1: "Tier-1 Foundational (8)",
      leg_t2: "Tier-2 Multi-Defect (6)",
      leg_t3: "Tier-3 Deep-Water 4-Defect (6)",
      sec_lb_title: "1. Difficulty-Weighted Grand Leaderboard (12 Models × 20 Tasks)",
      sec_lb_desc:
        "Click any column header to sort; ★ marks solvers of crown-jewel rare tasks passed by ≤ 2/12 models (c-ike-key-schedule / rs-mvcc-ssi-engine).",
      th_model: "Model / Provider",
      th_harness: "Official CLI (Effort)",
      th_weighted: "Weighted (/100)",
      th_bar: "Tier Contribution",
      th_raw: "Raw Pass",
      th_tiers: "T1 / T2 / T3",
      th_avg: "Avg Pass Time",
      sec_ana_title: "2. Latency × Weighted Score Pareto Frontier & Task Hardness",
      sec_ana_desc:
        "Left: efficiency-vs-depth Pareto frontier across providers. Right: all 20 tasks ordered from hardest to easiest with active weights.",
      pareto_title: "Latency × Weighted Score Pareto Frontier",
      hard_title: "Empirical Pass Rate & Active Task Weight",
      sec_mat_title: "3. Interactive 20-Task × 12-Model Evaluation Matrix",
      sec_mat_desc:
        "Filter by tier or language; hover or click any task header or cell to inspect source LOC, CWE tags, active weight, and exact runtime.",
      sec_ins_title: "4. Key Architectural Findings & Benchmark Protocol",
      footer_regen: "Generated deterministically via",
      footer_from: "from isolated Harbor trial logs · ",
      kpi_tasks: "Zero-Hint Tasks",
      kpi_tasks_note: "8 Tier-1 · 6 Tier-2 · 6 Tier-3",
      kpi_models: "Official CLI Models",
      kpi_models_note: "5 Vendors · 240 Isolated Trials",
      kpi_pass: "Grand Pass Rate",
      kpi_pass_note: "T1 89.6% · T2 61.1% · T3 70.8%",
      kpi_leader: "Weighted Leader",
      kpi_fastest: "Pareto Speed Leader",
      pareto_axis_hint: "← Faster avg pass time · Higher weighted score ↑",
      inspector_default: "Hover or click any task header or matrix cell to inspect LOC, CWE tags, weight, and runtime.",
      all_tiers: "All Tiers",
      all_langs: "All Languages",
      status_pass: "PASS",
      status_fail: "FAIL",
      status_timeout: "TIMEOUT",
      status_refusal: "CLOUD REFUSAL",
      formula_desc: {
        combined:
          'Formula <span class="formula-pill mono">wᵢ = Tierᵢ × (2 − pᵢ)</span>: combines structural task tier (1/2/3) with empirical scarcity (pᵢ = pass rate across 12 models). Top weight: rs-mvcc-ssi-engine (5.50). Eliminates all ties across the 12 models.',
        tier:
          'Formula <span class="formula-pill mono">wᵢ ∈ {1, 2, 3}</span>: fixed 1 pt for Tier-1, 2 pts for Tier-2, 3 pts for Tier-3 (38 raw pts normalized to 100).',
        info:
          'Formula <span class="formula-pill mono">wᵢ = 1 − log₂(pᵢ)</span>: Shannon information surprisal weighting rewarding rare breakthroughs such as c-ike-key-schedule (1/12, 4.58) and rs-mvcc-ssi-engine (2/12, 3.58).',
        equal:
          'Formula <span class="formula-pill mono">wᵢ = 1</span>: uniform equal weighting across all 20 tasks (5 pts each).',
      },
      insights: [
        {
          icon: "🏆",
          title: "5400s Timeout Unlocks Clean Tier-3 Sweep for Opus 5.5",
          body: "Aligning the per-task budget to SEC-bench / CyberGym-E2E's 5400s (90m) standard allowed claude-opus-5-5[1m] to solve the 2,131-LOC C eBPF abstract interpreter in 3,349s (55.8m), achieving the benchmark's sole 6/6 Tier-3 sweep and undisputed #1 finish at 18/20 (87.0 weighted).",
        },
        {
          icon: "⚡",
          title: "Speed-Depth Pareto Frontier: gpt-6.2-astra Is 3.1× Faster",
          body: "openai/gpt-6.2-astra posts 17/20 (76.1 weighted) at just 440s average pass time (9,648s total)—over 3.1× faster than Opus 5.5 and 8× faster on c-ebpf-verifier-sandbox (420s vs 3,349s).",
        },
        {
          icon: "🧭",
          title: "Orthogonal Cross-Family Blind Spots Separate Top Models",
          body: "All 5 OpenAI models and both Gemini 4 models hit the exact same Cahill SSI vacuum() pivot-retention defect in rs-mvcc-ssi-engine (2/12, solved solely by Claude 5), whereas zai/GLM-5.3 was the sole solver (1/12) of the RFC 9242 out-of-order fragmented IKEv2 key schedule.",
        },
        {
          icon: "🛡️",
          title: "Defensive Audit Availability Under Vendor Safety Filters",
          body: "All 20 prompts are strictly defensive code-maintenance reviews. Claude, DeepSeek, GLM, and OpenAI 6.2 had 0% refusals, whereas gpt-6-astra refused c-ebpf-verifier-sandbox once and Gemini 4 triggered cloud filter blocks on 1–2 low-level C Tier-1 tasks (toggle above: gemini-4-neon-xhigh reaches 16/19 = 84.2% non-refusal).",
        },
      ],
    },
  };

  const PROV_COLORS = {
    anthropic: "var(--prov-anthropic)",
    openai: "var(--prov-openai)",
    google: "var(--prov-google)",
    deepseek: "var(--prov-deepseek)",
    zai: "var(--prov-zai)",
  };

  const state = {
    data: null,
    lang: "zh",
    theme: "dark",
    scheme: "combined",
    excludeRefusals: false,
    sortKey: "score",
    sortDir: "desc",
    tierFilter: "all",
    langFilter: "all",
  };

  function t(key) {
    return I18N[state.lang][key] || key;
  }

  function taskWeight(task, scheme) {
    const p = Math.max(1 / task.total_models, task.passes / task.total_models);
    if (scheme === "combined") return task.tier * (2.0 - task.passes / task.total_models);
    if (scheme === "tier") return task.tier;
    if (scheme === "info") return 1.0 - Math.log2(p);
    return 1.0;
  }

  function computeLeaderboard() {
    const { tasks, models } = state.data;
    const weights = tasks.map((task) => taskWeight(task, state.scheme));
    const fullMax = weights.reduce((a, b) => a + b, 0);

    const rows = models.map((m) => {
      let s1 = 0, s2 = 0, s3 = 0;
      let c1 = 0, c2 = 0, c3 = 0;
      let eligibleWeight = 0;
      let eligibleCount = 0;
      let passDurSum = 0;
      let refusals = 0;
      let timeouts = 0;
      const crowns = [];

      tasks.forEach((task, i) => {
        const res = m.results[i];
        const w = weights[i];
        if (res.status === "safety_refusal") refusals++;
        if (res.status === "timeout") timeouts++;

        const excluded = state.excludeRefusals && res.status === "safety_refusal";
        if (!excluded) {
          eligibleWeight += w;
          eligibleCount += 1;
        }
        if (res.passed) {
          if (task.tier === 1) { s1 += w; c1++; }
          else if (task.tier === 2) { s2 += w; c2++; }
          else { s3 += w; c3++; }
          passDurSum += res.duration_sec;
          if (task.passes <= 2) crowns.push(task.id);
        }
      });

      const denom = state.excludeRefusals ? Math.max(1e-9, eligibleWeight) : fullMax;
      const rawCount = c1 + c2 + c3;
      const avgSec = rawCount > 0 ? Math.round(passDurSum / rawCount) : 0;
      return {
        ...m,
        p1: (s1 / denom) * 100,
        p2: (s2 / denom) * 100,
        p3: (s3 / denom) * 100,
        score: ((s1 + s2 + s3) / denom) * 100,
        rawCount,
        eligibleCount,
        c1, c2, c3,
        avgSec,
        refusals,
        timeouts,
        crowns,
      };
    });

    // Assign canonical rank first by default score order
    const canonical = [...rows].sort(
      (a, b) => b.score - a.score || b.c3 - a.c3 || a.avgSec - b.avgSec
    );
    canonical.forEach((r, idx) => {
      r.rank = idx + 1;
    });

    // Apply user column sort
    rows.sort((a, b) => {
      const k = state.sortKey;
      let diff = 0;
      if (k === "short" || k === "harness") {
        diff = String(a[k]).localeCompare(String(b[k]));
      } else {
        diff = a[k] - b[k];
      }
      if (diff === 0) return a.rank - b.rank;
      return state.sortDir === "asc" ? diff : -diff;
    });

    return { rows, canonical, weights, fullMax };
  }

  function applyI18n() {
    document.documentElement.lang = state.lang === "zh" ? "zh-CN" : "en";
    document.querySelectorAll("[data-i18n]").forEach((el) => {
      const k = el.dataset.i18n;
      if (I18N[state.lang][k]) el.textContent = I18N[state.lang][k];
    });
    document.getElementById("lang-toggle").textContent = state.lang === "zh" ? "English" : "中文";
    document.getElementById("theme-toggle").textContent =
      state.theme === "dark" ? "☀️ Light" : "🌙 Dark";
  }

  function renderKPIs(canonical) {
    const b = state.data.benchmark;
    const leader = canonical[0];
    const fastest = [...canonical]
      .filter((r) => r.rawCount >= 16)
      .sort((a, b) => a.avgSec - b.avgSec)[0] || canonical[0];

    const passPct = ((b.total_passed / b.total_trials) * 100).toFixed(1);
    const cards = [
      { label: t("kpi_tasks"), val: `${b.total_tasks}`, note: t("kpi_tasks_note") },
      { label: t("kpi_models"), val: `${b.total_models}`, note: t("kpi_models_note") },
      { label: t("kpi_pass"), val: `${b.total_passed}/${b.total_trials} (${passPct}%)`, note: t("kpi_pass_note") },
      {
        label: t("kpi_leader"),
        val: leader.short,
        note: `${leader.score.toFixed(1)}/100 · ${leader.rawCount}/${leader.eligibleCount} · T3 ${leader.c3}/6`,
      },
      {
        label: t("kpi_fastest"),
        val: `${fastest.short}`,
        note: `${fastest.avgSec}s avg · ${fastest.score.toFixed(1)}/100`,
      },
    ];

    document.getElementById("kpi-grid").innerHTML = cards
      .map(
        (c) => `
      <div class="kpi-card">
        <div class="kpi-label">${c.label}</div>
        <div class="kpi-value mono">${c.val}</div>
        <div class="kpi-note">${c.note}</div>
      </div>`
      )
      .join("");
  }

  function renderLeaderboard(rows) {
    const tbody = document.getElementById("lb-tbody");
    tbody.innerHTML = rows
      .map((r) => {
        const rankCls = r.rank <= 3 ? `rank-badge rank-${r.rank}` : "rank-badge";
        const provCol = PROV_COLORS[r.provider_key] || "var(--accent)";
        const crownHtml = r.crowns.length
          ? `<span class="crown-badge" title="${r.crowns.join(", ")}">★ ${r.crowns.length}</span>`
          : "";
        const refTag =
          r.refusals > 0
            ? `<span class="tag-chip" style="color:var(--refusal-fg);border-color:var(--refusal-bd)" title="Cloud safety filter blocks">🛡️ ${r.refusals}</span>`
            : "";
        const t1Cls = r.c1 === 8 ? "perfect" : "";
        const t2Cls = r.c2 === 6 ? "perfect" : "";
        const t3Cls = r.c3 === 6 ? "perfect" : "";

        return `
          <tr>
            <td class="mono"><span class="${rankCls}">#${r.rank}</span></td>
            <td>
              <div class="model-cell">
                <span class="prov-dot" style="background:${provCol}"></span>
                <div>
                  <div class="model-name">${r.short} ${crownHtml} ${refTag}</div>
                  <div style="font-size:11px;color:var(--text-faint)">${r.provider}</div>
                </div>
              </div>
            </td>
            <td>
              <span class="tag-chip">${r.harness}</span>
              <span class="tag-chip mono">${r.effort}</span>
            </td>
            <td class="mono score-main">${r.score.toFixed(1)}</td>
            <td>
              <div class="bar-track" title="T1: ${r.p1.toFixed(1)} | T2: ${r.p2.toFixed(1)} | T3: ${r.p3.toFixed(1)}">
                <div class="bar-seg" style="width:${r.p1.toFixed(2)}%;background:var(--t1)"></div>
                <div class="bar-seg" style="width:${r.p2.toFixed(2)}%;background:var(--t2)"></div>
                <div class="bar-seg" style="width:${r.p3.toFixed(2)}%;background:var(--t3)"></div>
              </div>
            </td>
            <td class="mono">
              <strong>${r.rawCount}/${r.eligibleCount}</strong>
              <span style="color:var(--text-faint);font-size:11px">(${((r.rawCount / r.eligibleCount) * 100).toFixed(1)}%)</span>
            </td>
            <td class="mono">
              <div class="tier-mini">
                <span class="${t1Cls}">${r.c1}/8</span>
                <span class="${t2Cls}">${r.c2}/6</span>
                <span class="${t3Cls}">${r.c3}/6</span>
              </div>
            </td>
            <td class="mono">${r.avgSec}s</td>
          </tr>`;
      })
      .join("");
  }

  function renderPareto(canonical) {
    const provs = [
      ["anthropic", "Anthropic"],
      ["openai", "OpenAI"],
      ["google", "Google"],
      ["deepseek", "DeepSeek"],
      ["zai", "Zhipu AI"],
    ];
    document.getElementById("prov-legend").innerHTML = provs
      .map(
        ([k, lbl]) =>
          `<span class="legend-item"><span class="legend-swatch" style="background:${PROV_COLORS[k]};border-radius:99px"></span>${lbl}</span>`
      )
      .join("");

    const W = 620, H = 355, padL = 46, padR = 26, padT = 26, padB = 34;
    const minX = 350, maxX = 1820;
    const minY = Math.max(20, Math.floor(Math.min(...canonical.map((r) => r.score)) - 6));
    const maxY = Math.min(100, Math.ceil(Math.max(...canonical.map((r) => r.score)) + 6));

    const xOf = (s) => padL + ((s - minX) / (maxX - minX)) * (W - padL - padR);
    const yOf = (sc) => H - padB - ((sc - minY) / (maxY - minY)) * (H - padT - padB);

    const byFast = [...canonical].sort((a, b) => a.avgSec - b.avgSec);
    const frontier = [];
    let best = -1;
    byFast.forEach((r) => {
      if (r.score > best) {
        frontier.push(r);
        best = r.score;
      }
    });
    const frontierPts = frontier
      .map((r) => `${xOf(r.avgSec).toFixed(1)},${yOf(r.score).toFixed(1)}`)
      .join(" ");

    let grid = "";
    const yTicks = 5;
    for (let i = 0; i <= yTicks; i++) {
      const val = minY + ((maxY - minY) * i) / yTicks;
      const y = yOf(val).toFixed(1);
      grid += `<line x1="${padL}" y1="${y}" x2="${W - padR}" y2="${y}" stroke="var(--border)" stroke-dasharray="3,3"/>`;
      grid += `<text x="${padL - 8}" y="${Number(y) + 4}" text-anchor="end" fill="var(--text-faint)" font-size="11">${val.toFixed(0)}</text>`;
    }
    [450, 750, 1050, 1350, 1650].forEach((xv) => {
      const x = xOf(xv).toFixed(1);
      grid += `<line x1="${x}" y1="${padT}" x2="${x}" y2="${H - padB}" stroke="var(--border)" stroke-dasharray="3,3"/>`;
      grid += `<text x="${x}" y="${H - 10}" text-anchor="middle" fill="var(--text-faint)" font-size="11">${xv}s</text>`;
    });

    const labelOffsets = {
      "gpt-6-sol": [0, 16],
      "gpt-daybreak-blue": [14, 15],
      "deepseek-flash": [-12, 16],
      "gpt-6-astra": [-10, -10],
    };

    const points = canonical
      .map((r, idx) => {
        const cx = xOf(r.avgSec).toFixed(1);
        const cy = yOf(r.score).toFixed(1);
        const col = PROV_COLORS[r.provider_key] || "var(--accent)";
        const onFront = frontier.some((f) => f.id === r.id);
        const [dx, dy] = labelOffsets[r.short] || [0, -10];
        return `
          <g class="pareto-node" data-idx="${idx}" style="cursor:pointer">
            ${onFront ? `<circle cx="${cx}" cy="${cy}" r="9.5" fill="none" stroke="${col}" stroke-opacity="0.45" stroke-width="1.6"/>` : ""}
            <circle cx="${cx}" cy="${cy}" r="5.5" fill="${col}" />
            <text x="${(Number(cx) + dx).toFixed(1)}" y="${(Number(cy) + dy).toFixed(1)}" text-anchor="middle" fill="var(--text)" font-size="11" font-weight="${onFront ? "600" : "400"}">${r.short}</text>
          </g>`;
      })
      .join("");

    const wrap = document.getElementById("pareto-chart");
    wrap.innerHTML = `
      <svg viewBox="0 0 ${W} ${H}" style="width:100%;height:auto;display:block">
        ${grid}
        <text x="${padL + 6}" y="${padT - 8}" fill="var(--text-muted)" font-size="11">${t("pareto_axis_hint")}</text>
        <polyline points="${frontierPts}" fill="none" stroke="var(--accent)" stroke-width="1.8" stroke-dasharray="5,4"/>
        ${points}
      </svg>`;

    const tip = document.getElementById("svg-tooltip");
    wrap.querySelectorAll(".pareto-node").forEach((node) => {
      node.addEventListener("mousemove", (ev) => {
        const r = canonical[Number(node.dataset.idx)];
        tip.innerHTML = `
          <div style="font-weight:700;margin-bottom:3px">#${r.rank} ${r.short} (${r.provider})</div>
          <div class="mono" style="font-size:11px;color:var(--text-muted)">
            Weighted: <strong style="color:var(--text)">${r.score.toFixed(1)}/100</strong><br/>
            Raw: ${r.rawCount}/${r.eligibleCount} [T1 ${r.c1}/8 · T2 ${r.c2}/6 · T3 ${r.c3}/6]<br/>
            Avg Pass: ${r.avgSec}s · CLI: ${r.harness} (${r.effort})
          </div>`;
        tip.style.left = `${Math.min(window.innerWidth - 290, ev.clientX + 14)}px`;
        tip.style.top = `${Math.max(12, ev.clientY - 12)}px`;
        tip.style.opacity = "1";
      });
      node.addEventListener("mouseleave", () => {
        tip.style.opacity = "0";
      });
    });
  }

  function renderHardness(weights) {
    const tasks = state.data.tasks.map((task, idx) => ({
      ...task,
      weight: weights[idx],
      passRate: (task.passes / task.total_models) * 100,
    }));
    tasks.sort((a, b) => a.passes - b.passes || b.tier - a.tier || a.id.localeCompare(b.id));

    document.getElementById("hard-weight-tag").textContent =
      `w_max = ${Math.max(...weights).toFixed(2)}`;

    document.getElementById("hardness-list").innerHTML = tasks
      .map((tk) => {
        const col = tk.tier === 1 ? "var(--t1)" : tk.tier === 2 ? "var(--t2)" : "var(--t3)";
        return `
          <div class="hard-row">
            <span class="mono" style="color:${col};font-weight:700">T${tk.tier}</span>
            <span class="mono" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${tk.id} (${tk.title_zh})">${tk.id}</span>
            <div class="hard-bar-bg">
              <div class="hard-bar-fill" style="width:${tk.passRate.toFixed(1)}%;background:${col}"></div>
            </div>
            <span class="mono" style="text-align:right;color:var(--text-muted)">${tk.passes}/12 · <strong style="color:var(--text)">${tk.weight.toFixed(1)}</strong></span>
          </div>`;
      })
      .join("");
  }

  function renderMatrixFilters() {
    const tiers = [
      ["all", t("all_tiers")],
      ["1", "Tier 1 (8)"],
      ["2", "Tier 2 (6)"],
      ["3", "Tier 3 (6)"],
    ];
    document.getElementById("tier-filters").innerHTML = tiers
      .map(
        ([v, lbl]) =>
          `<button class="filter-pill ${state.tierFilter === v ? "active" : ""}" data-tier="${v}" type="button">${lbl}</button>`
      )
      .join("");

    const langs = ["all", "C", "C++", "Rust", "Java", "Python", "TypeScript"];
    document.getElementById("lang-filters").innerHTML = langs
      .map(
        (lg) =>
          `<button class="filter-pill ${state.langFilter === lg ? "active" : ""}" data-lang="${lg}" type="button">${lg === "all" ? t("all_langs") : lg}</button>`
      )
      .join("");

    document.querySelectorAll("#tier-filters button").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.tierFilter = btn.dataset.tier;
        renderAll();
      });
    });
    document.querySelectorAll("#lang-filters button").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.langFilter = btn.dataset.lang;
        renderAll();
      });
    });
  }

  function renderMatrix(canonical, weights) {
    const { tasks } = state.data;
    const visibleIdx = tasks
      .map((tk, i) => ({ tk, i, w: weights[i] }))
      .filter(({ tk }) => {
        const tierOk = state.tierFilter === "all" || String(tk.tier) === state.tierFilter;
        const langOk = state.langFilter === "all" || tk.language === state.langFilter;
        return tierOk && langOk;
      });

    const table = document.getElementById("matrix-table");
    const headCols = visibleIdx
      .map(({ tk, i, w }) => {
        const col = tk.tier === 1 ? "var(--t1)" : tk.tier === 2 ? "var(--t2)" : "var(--t3)";
        const shortTask = tk.id.replace(/^(c|cpp|java|py|rs|ts)-/, "");
        return `<th data-task-idx="${i}" title="${tk.id} — ${state.lang === "zh" ? tk.title_zh : tk.title_en}">
          <div style="color:${col};font-weight:700">T${tk.tier} · ${tk.language}</div>
          <div class="mono" style="color:var(--text)">${shortTask}</div>
          <div class="mono" style="font-size:10px;color:var(--text-faint)">${tk.passes}/12 · w=${w.toFixed(2)}</div>
        </th>`;
      })
      .join("");

    const bodyRows = canonical
      .map((m, mIdx) => {
        const cells = visibleIdx
          .map(({ i }) => {
            const res = m.results[i];
            let cls = "cell-fail";
            let lbl = `✗ ${res.duration_sec}s`;
            if (res.status === "pass") {
              cls = "cell-pass";
              lbl = `✓ ${res.duration_sec}s`;
            } else if (res.status === "timeout") {
              cls = "cell-timeout";
              lbl = `⏱ ${res.duration_sec}s`;
            } else if (res.status === "safety_refusal") {
              cls = "cell-refusal";
              lbl = `🛡 ${res.duration_sec}s`;
            }
            return `<td><span class="cell-badge mono ${cls}" data-m-idx="${mIdx}" data-t-idx="${i}">${lbl}</span></td>`;
          })
          .join("");
        return `<tr><td>#${m.rank} ${m.short}</td>${cells}</tr>`;
      })
      .join("");

    table.innerHTML = `<thead><tr><th>${t("th_model")}</th>${headCols}</tr></thead><tbody>${bodyRows}</tbody>`;

    const insp = document.getElementById("inspector-bar");
    insp.innerHTML = `<span style="color:var(--text-muted)">${t("inspector_default")}</span>`;

    const showTaskInfo = (tIdx, mIdx = null) => {
      const tk = tasks[tIdx];
      const w = weights[tIdx];
      const title = state.lang === "zh" ? tk.title_zh : tk.title_en;
      const tags = tk.tags.slice(0, 6).map((tg) => `<span class="tag-chip mono">${tg}</span>`).join(" ");
      let extra = "";
      if (mIdx !== null) {
        const m = canonical[mIdx];
        const res = m.results[tIdx];
        const statusText = t(`status_${res.status === "safety_refusal" ? "refusal" : res.status}`);
        extra = `<span class="formula-pill mono">${m.short}: ${statusText} (${res.duration_sec}s)</span>`;
      }
      insp.innerHTML = `
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
          <strong class="mono">${tk.id}</strong>
          <span>${title}</span>
          <span class="tag-chip mono">Tier ${tk.tier} · ${tk.language} · ${tk.loc} LOC</span>
          <span class="tag-chip mono">Pass ${tk.passes}/12 · w=${w.toFixed(2)}</span>
          ${extra}
        </div>
        <div style="display:flex;gap:5px;flex-wrap:wrap">${tags}</div>`;
    };

    table.querySelectorAll("th[data-task-idx]").forEach((th) => {
      const idx = Number(th.dataset.taskIdx);
      th.addEventListener("mouseenter", () => showTaskInfo(idx));
      th.addEventListener("click", () => showTaskInfo(idx));
    });
    table.querySelectorAll(".cell-badge").forEach((cell) => {
      const mIdx = Number(cell.dataset.mIdx);
      const tIdx = Number(cell.dataset.tIdx);
      cell.addEventListener("mouseenter", () => showTaskInfo(tIdx, mIdx));
      cell.addEventListener("click", () => showTaskInfo(tIdx, mIdx));
    });
  }

  function renderInsights() {
    document.getElementById("insights-grid").innerHTML = I18N[state.lang].insights
      .map(
        (card) => `
      <article class="insight-card">
        <h3><span>${card.icon}</span><span>${card.title}</span></h3>
        <p>${card.body}</p>
      </article>`
      )
      .join("");
  }

  function renderAll() {
    applyI18n();
    document.querySelectorAll("#scheme-buttons button").forEach((b) => {
      b.classList.toggle("active", b.dataset.scheme === state.scheme);
    });
    document.getElementById("formula-desc").innerHTML =
      I18N[state.lang].formula_desc[state.scheme];

    const { rows, canonical, weights } = computeLeaderboard();
    renderKPIs(canonical);
    renderLeaderboard(rows);
    renderPareto(canonical);
    renderHardness(weights);
    renderMatrixFilters();
    renderMatrix(canonical, weights);
    renderInsights();

    document.getElementById("footer-meta").textContent =
      `VulnHunter Core · Timeout ${state.data.benchmark.timeout_sec}s · Updated ${state.data.generated_at}`;
  }

  function bindEvents() {
    document.querySelectorAll("#scheme-buttons button").forEach((btn) => {
      btn.addEventListener("click", () => {
        state.scheme = btn.dataset.scheme;
        state.sortKey = "score";
        state.sortDir = "desc";
        renderAll();
      });
    });

    document.getElementById("exclude-refusals").addEventListener("change", (ev) => {
      state.excludeRefusals = ev.target.checked;
      renderAll();
    });

    document.querySelectorAll("#lb-table th[data-sort]").forEach((th) => {
      th.addEventListener("click", () => {
        const key = th.dataset.sort;
        if (state.sortKey === key) {
          state.sortDir = state.sortDir === "desc" ? "asc" : "desc";
        } else {
          state.sortKey = key;
          state.sortDir = key === "avgSec" || key === "rank" || key === "short" ? "asc" : "desc";
        }
        renderAll();
      });
    });

    document.getElementById("lang-toggle").addEventListener("click", () => {
      state.lang = state.lang === "zh" ? "en" : "zh";
      renderAll();
    });

    document.getElementById("theme-toggle").addEventListener("click", () => {
      state.theme = state.theme === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", state.theme);
      applyI18n();
    });
  }

  async function init() {
    if (window.__VULNHUNTER_DATA__) {
      state.data = window.__VULNHUNTER_DATA__;
    } else {
      const resp = await fetch("./data/leaderboard.json");
      state.data = await resp.json();
    }
    bindEvents();
    renderAll();
  }

  init().catch((err) => {
    document.body.innerHTML = `<pre style="padding:24px;color:#fb7185">Failed to load leaderboard data: ${err}</pre>`;
  });
})();
