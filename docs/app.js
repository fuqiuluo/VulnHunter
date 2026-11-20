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
        "行为赛题（按难度分阶分组），列为模型（按当前加权排名）；可按分阶与语言筛选，悬停任意单元格查看精确耗时、源码规模（LOC）、CWE 标签与当前权重。",
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
      all_tiers: "全部难度",
      all_langs: "全部语言",
      status_pass: "通过",
      status_fail: "失败",
      status_timeout: "超时",
      status_refusal: "云端安全误拒",
      ctl_weighting: "加权方式",
      pareto_x: "通过题均耗时（分钟）",
      pareto_y: "加权得分",
      leg_frontier: "帕累托前沿",
      leg_dominated: "被支配",
      col_task: "赛题",
      col_lang: "语言",
      col_pass: "通过",
      col_passrate: "通过率",
      col_weight: "权重",
      cell_timeout: "超时",
      cell_refusal: "拒答",
      legend_minutes: "格内数字为该次评测耗时（分钟）",
      max_weight: "最高权重",
      lbl_score: "加权得分",
      lbl_avg: "通过均耗时",
      theme_light: "浅色",
      theme_dark: "深色",
      refusals: (n) => `误拒 ${n}`,
      tasks_n: (n) => `${n} 题`,
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
          title: "5400s 标准超时释放深度上限：Opus 5.5 实现三期 6/6 大满贯",
          body: "将单题 Agent 上限对齐 SEC-bench / CyberGym-E2E 的 5400s（90 分钟）后，claude-opus-5-5[1m] 在 2,131 行 C 抽象解释器 c-ebpf-verifier-sandbox 上耗时 3349s（55.8 分钟）满分通关，成为全场唯一横扫全部 6 道三期深水区真题的模型，以 18/20（综合加权 87.0 分）独占总榜第一。",
        },
        {
          title: "速度与深度的帕累托前沿：gpt-6.2-astra 3.1 倍速差紧咬榜首",
          body: "openai/gpt-6.2-astra 以 17/20（综合加权 76.1 分）稳居前三，但通过题均耗时仅 440s（总耗时 9,648s），比 Claude 5 系列快 3.1～3.9 倍；在 c-ebpf-verifier-sandbox 上 420s vs 3349s 快出整整 8 倍，形成清晰的速度-精度帕累托边界。",
        },
        {
          title: "跨家族正交盲区：三道皇冠题精准拉开架构代差",
          body: "rs-mvcc-ssi-engine（2/12）上 OpenAI 全系 5 款与 Gemini 4 双雄集体漏掉 vacuum() 期间保留活跃枢纽事务冲突边的 Cahill SSI 规则，仅 Claude 5 双雄攻克；而 c-ike-key-schedule（1/12）的 RFC 9242 多轮乱序加密分片 IntAuth 累积不变量则由 zai/GLM-5.3 唯一攻克。",
        },
        {
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
        "Rows are tasks grouped by tier; columns are models in current rank order. Filter by tier or language, and hover any cell for exact runtime, source LOC, CWE tags, and active weight.",
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
      all_tiers: "All Tiers",
      all_langs: "All Languages",
      status_pass: "Pass",
      status_fail: "Fail",
      status_timeout: "Timeout",
      status_refusal: "Cloud safety refusal",
      ctl_weighting: "Weighting",
      pareto_x: "Average time per passed task (minutes)",
      pareto_y: "Weighted score",
      leg_frontier: "Pareto frontier",
      leg_dominated: "Dominated",
      col_task: "Task",
      col_lang: "Language",
      col_pass: "Passed",
      col_passrate: "Pass rate",
      col_weight: "Weight",
      cell_timeout: "T/O",
      cell_refusal: "REF",
      legend_minutes: "Numbers are that trial's runtime in minutes",
      max_weight: "Max weight",
      lbl_score: "Weighted score",
      lbl_avg: "Avg pass time",
      theme_light: "Light",
      theme_dark: "Dark",
      refusals: (n) => `${n} ${n === 1 ? "refusal" : "refusals"}`,
      tasks_n: (n) => `${n} ${n === 1 ? "task" : "tasks"}`,
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
          title: "5400s Timeout Unlocks Clean Tier-3 Sweep for Opus 5.5",
          body: "Aligning the per-task budget to SEC-bench / CyberGym-E2E's 5400s (90m) standard allowed claude-opus-5-5[1m] to solve the 2,131-LOC C eBPF abstract interpreter in 3,349s (55.8m), achieving the benchmark's sole 6/6 Tier-3 sweep and undisputed #1 finish at 18/20 (87.0 weighted).",
        },
        {
          title: "Speed-Depth Pareto Frontier: gpt-6.2-astra Is 3.1× Faster",
          body: "openai/gpt-6.2-astra posts 17/20 (76.1 weighted) at just 440s average pass time (9,648s total)—over 3.1× faster than Opus 5.5 and 8× faster on c-ebpf-verifier-sandbox (420s vs 3,349s).",
        },
        {
          title: "Orthogonal Cross-Family Blind Spots Separate Top Models",
          body: "All 5 OpenAI models and both Gemini 4 models hit the exact same Cahill SSI vacuum() pivot-retention defect in rs-mvcc-ssi-engine (2/12, solved solely by Claude 5), whereas zai/GLM-5.3 was the sole solver (1/12) of the RFC 9242 out-of-order fragmented IKEv2 key schedule.",
        },
        {
          title: "Defensive Audit Availability Under Vendor Safety Filters",
          body: "All 20 prompts are strictly defensive code-maintenance reviews. Claude, DeepSeek, GLM, and OpenAI 6.2 had 0% refusals, whereas gpt-6-astra refused c-ebpf-verifier-sandbox once and Gemini 4 triggered cloud filter blocks on 1–2 low-level C Tier-1 tasks (toggle above: gemini-4-neon-xhigh reaches 16/19 = 84.2% non-refusal).",
        },
      ],
    },
  };

  const LANG_ORDER = ["C", "C++", "Rust", "Java", "Python", "TypeScript"];

  const state = {
    data: null,
    tierTotals: { 1: 0, 2: 0, 3: 0 },
    lang: "zh",
    theme: "dark",
    scheme: "combined",
    excludeRefusals: false,
    sortKey: "score",
    sortDir: "desc",
    tierFilter: "all",
    langFilter: "all",
  };

  // The latest computed leaderboard, read by the delegated hover handlers.
  let view = { canonical: [], weights: [] };

  function t(key) {
    return I18N[state.lang][key] || key;
  }

  function esc(value) {
    return String(value).replace(
      /[&<>"']/g,
      (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]
    );
  }

  // 1366 -> "22m 46s". Exact seconds stay available in tooltips.
  function fmtDur(sec) {
    const s = Math.round(sec);
    if (s < 60) return `${s}s`;
    return `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, "0")}s`;
  }

  // Whole minutes for dense cells; anything under a minute still reads as 1.
  function fmtMin(sec) {
    return String(Math.max(1, Math.round(sec / 60)));
  }

  function statusText(status) {
    return t(`status_${status === "safety_refusal" ? "refusal" : status}`);
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

  // ── Tooltip ───────────────────────────────────────────────────────────────

  let tipKey = null;

  // `key` identifies what is being described, so the HTML is rebuilt only when
  // the pointer moves onto something new, not on every mousemove.
  function showTip(key, buildHtml, x, y) {
    const tip = document.getElementById("svg-tooltip");
    if (key !== tipKey) {
      tip.innerHTML = buildHtml();
      tipKey = key;
    }
    const w = tip.offsetWidth;
    const h = tip.offsetHeight;
    let left = x + 14;
    let top = y + 16;
    if (left + w > window.innerWidth - 8) left = Math.max(8, x - w - 14);
    if (top + h > window.innerHeight - 8) top = Math.max(8, y - h - 12);
    tip.style.left = `${left}px`;
    tip.style.top = `${top}px`;
    tip.style.opacity = "1";
  }

  function hideTip() {
    tipKey = null;
    document.getElementById("svg-tooltip").style.opacity = "0";
  }

  function modelTip(r) {
    const tt = state.tierTotals;
    return `
      <div class="tip-title">#${r.rank} ${esc(r.short)}</div>
      <div>${esc(r.provider)} · ${esc(r.harness)} · ${esc(r.effort)}</div>
      <div>${t("lbl_score")} <strong class="num">${r.score.toFixed(1)}</strong> · ${t("col_pass")} <strong class="num">${r.rawCount}/${r.eligibleCount}</strong></div>
      <div class="num">T1 ${r.c1}/${tt[1]} · T2 ${r.c2}/${tt[2]} · T3 ${r.c3}/${tt[3]}</div>
      <div>${t("lbl_avg")} <strong class="num">${fmtDur(r.avgSec)}</strong></div>`;
  }

  function taskTip(tIdx, mIdx) {
    const tk = state.data.tasks[tIdx];
    const title = state.lang === "zh" ? tk.title_zh : tk.title_en;
    const meta =
      `Tier ${tk.tier} · ${tk.language} · ${Number(tk.loc).toLocaleString("en-US")} LOC · ` +
      `${t("col_pass")} ${tk.passes}/${tk.total_models} · ${t("col_weight")} ${view.weights[tIdx].toFixed(2)}`;

    if (mIdx === null) {
      return `
        <div class="tip-title mono">${esc(tk.id)}</div>
        <div>${esc(title)}</div>
        <div class="num">${esc(meta)}</div>
        <div class="mono">${esc(tk.tags.slice(0, 6).join(" · "))}</div>`;
    }

    const m = view.canonical[mIdx];
    const res = m.results[tIdx];
    return `
      <div class="tip-title">${esc(m.short)} · <span class="mono">${esc(tk.id)}</span></div>
      <div><strong>${esc(statusText(res.status))}</strong> · <span class="num">${fmtDur(res.duration_sec)} (${res.duration_sec}s)</span></div>
      <div>${esc(title)}</div>
      <div class="num">${esc(meta)}</div>`;
  }

  // ── Rendering ─────────────────────────────────────────────────────────────

  function applyI18n() {
    document.documentElement.lang = state.lang === "zh" ? "zh-CN" : "en";
    document.querySelectorAll("[data-i18n]").forEach((el) => {
      const k = el.dataset.i18n;
      if (I18N[state.lang][k]) el.textContent = I18N[state.lang][k];
    });
    // Both toggles are labelled with what they switch to.
    document.getElementById("lang-toggle").textContent = state.lang === "zh" ? "English" : "中文";
    document.getElementById("theme-toggle").textContent =
      state.theme === "dark" ? t("theme_light") : t("theme_dark");
  }

  function renderSortState() {
    document.querySelectorAll("#lb-table th[data-sort]").forEach((th) => {
      if (th.dataset.sort === state.sortKey) {
        th.setAttribute("aria-sort", state.sortDir === "asc" ? "ascending" : "descending");
      } else {
        th.removeAttribute("aria-sort");
      }
    });
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
      {
        label: t("kpi_pass"),
        val: `${passPct}%`,
        unit: `${b.total_passed}/${b.total_trials}`,
        note: t("kpi_pass_note"),
      },
      {
        label: t("kpi_leader"),
        val: leader.short,
        note: `${leader.score.toFixed(1)}/100 · ${leader.rawCount}/${leader.eligibleCount} · T3 ${leader.c3}/${state.tierTotals[3]}`,
      },
      {
        label: t("kpi_fastest"),
        val: fastest.short,
        note: `${fmtDur(fastest.avgSec)} · ${fastest.score.toFixed(1)}/100`,
      },
    ];

    document.getElementById("kpi-grid").innerHTML = cards
      .map(
        (c) => `
      <div class="stat">
        <div class="stat-label">${esc(c.label)}</div>
        <div class="stat-value" title="${esc(c.val)}">${esc(c.val)}${c.unit ? ` <span class="stat-unit">${esc(c.unit)}</span>` : ""}</div>
        <div class="stat-note">${esc(c.note)}</div>
      </div>`
      )
      .join("");
  }

  function renderLeaderboard(rows) {
    const tt = state.tierTotals;
    const seg = (pct, tier) =>
      pct > 0.05
        ? `<div class="bar-seg" style="width:${pct.toFixed(2)}%;background:var(--tier-${tier})"></div>`
        : "";
    const tierCell = (count, total) =>
      `<td class="num r tier-count${count === total ? " full" : ""}">${count}/${total}</td>`;

    document.getElementById("lb-tbody").innerHTML = rows
      .map((r) => {
        const flags = [];
        if (r.crowns.length) {
          flags.push(`<span class="flag" title="${esc(r.crowns.join(", "))}">★ ${r.crowns.length}</span>`);
        }
        if (r.refusals > 0) {
          flags.push(`<span class="flag" title="${esc(t("status_refusal"))}">${esc(t("refusals")(r.refusals))}</span>`);
        }
        const passPct = ((r.rawCount / r.eligibleCount) * 100).toFixed(0);

        return `
          <tr>
            <td class="num rank">${r.rank}</td>
            <td>
              <div class="model-name">${esc(r.short)}${flags.join("")}</div>
              <div class="model-sub">${esc(r.provider)}</div>
            </td>
            <td class="harness">${esc(r.harness)} · ${esc(r.effort)}</td>
            <td class="num r score">${r.score.toFixed(1)}</td>
            <td class="bar-cell">
              <div class="bar-track" title="T1 ${r.p1.toFixed(1)} · T2 ${r.p2.toFixed(1)} · T3 ${r.p3.toFixed(1)}">
                ${seg(r.p1, 1)}${seg(r.p2, 2)}${seg(r.p3, 3)}
              </div>
            </td>
            <td class="num r">${r.rawCount}/${r.eligibleCount} <span class="sub">${passPct}%</span></td>
            ${tierCell(r.c1, tt[1])}${tierCell(r.c2, tt[2])}${tierCell(r.c3, tt[3])}
            <td class="num r">${fmtDur(r.avgSec)}</td>
          </tr>`;
      })
      .join("");
  }

  let measureCtx = null;

  function textWidth(text, font) {
    if (!measureCtx) measureCtx = document.createElement("canvas").getContext("2d");
    if (!measureCtx) return text.length * 6.4;
    measureCtx.font = font;
    return measureCtx.measureText(text).width;
  }

  const overlapArea = (a, b) =>
    Math.max(0, Math.min(a.x1, b.x1) - Math.max(a.x0, b.x0)) *
    Math.max(0, Math.min(a.y1, b.y1) - Math.max(a.y0, b.y0));

  // Give every point a name label that does not sit on another label, another
  // point, or the frontier line. Each label tries eight directions at three
  // distances and takes the cheapest; a label that had to move away from its
  // point gets a leader line (`far`).
  function placeLabels(nodes, obstacles, bounds) {
    const LABEL_H = 14;
    const placed = [];
    const dots = nodes.map((n) => ({ x0: n.x - 7, y0: n.y - 7, x1: n.x + 7, y1: n.y + 7 }));
    const order = nodes
      .map((n, i) => i)
      .sort((a, b) => Number(nodes[b].onFront) - Number(nodes[a].onFront) || nodes[b].score - nodes[a].score);

    order.forEach((i) => {
      const n = nodes[i];
      const w = n.labelW;
      let best = null;

      [9, 21, 35].forEach((d, ring) => {
        const diag = d * 0.72;
        const candidates = [
          [n.x - w / 2, n.y - d - LABEL_H + 3],
          [n.x + d, n.y - LABEL_H / 2],
          [n.x - d - w, n.y - LABEL_H / 2],
          [n.x - w / 2, n.y + d - 2],
          [n.x + diag, n.y - diag - LABEL_H + 3],
          [n.x - diag - w, n.y - diag - LABEL_H + 3],
          [n.x + diag, n.y + diag - 2],
          [n.x - diag - w, n.y + diag - 2],
        ];
        candidates.forEach(([x, y], direction) => {
          const box = { x0: x, y0: y, x1: x + w, y1: y + LABEL_H };
          let cost = ring * 30 + direction;
          if (box.x0 < bounds.x0 || box.x1 > bounds.x1 || box.y0 < bounds.y0 || box.y1 > bounds.y1) cost += 5000;
          placed.forEach((p) => { const a = overlapArea(box, p); if (a > 0) cost += 1000 + a; });
          dots.forEach((dot, j) => { if (j !== i && overlapArea(box, dot) > 0) cost += 400; });
          obstacles.forEach((o) => { if (overlapArea(box, o) > 0) cost += 120; });
          if (!best || cost < best.cost) best = { cost, box, far: ring > 0 };
        });
      });

      placed.push(best.box);
      n.label = best;
    });
  }

  function renderPareto(canonical) {
    document.getElementById("pareto-legend").innerHTML = `
      <span class="legend-item"><span class="legend-swatch dot" style="background:var(--accent)"></span>${t("leg_frontier")}</span>
      <span class="legend-item"><span class="legend-swatch dot" style="background:var(--dim-mark)"></span>${t("leg_dominated")}</span>`;

    const W = 680, H = 540, padL = 40, padR = 16, padT = 30, padB = 46;
    const X_STEP = 300; // seconds; ticks every 5 minutes
    const Y_STEP = 10;
    const times = canonical.map((r) => r.avgSec);
    const scores = canonical.map((r) => r.score);
    const minX = Math.max(0, Math.floor((Math.min(...times) - 60) / X_STEP) * X_STEP);
    const maxX = Math.ceil((Math.max(...times) + 60) / X_STEP) * X_STEP;
    const minY = Math.max(0, Math.floor((Math.min(...scores) - 2) / Y_STEP) * Y_STEP);
    const maxY = Math.min(100, Math.ceil(Math.max(...scores) / Y_STEP) * Y_STEP);

    const plotR = W - padR;
    const plotB = H - padB;
    const xOf = (s) => padL + ((s - minX) / (maxX - minX)) * (plotR - padL);
    const yOf = (sc) => plotB - ((sc - minY) / (maxY - minY)) * (plotB - padT);

    // Frontier: no other model is both faster and higher-scoring.
    const frontierIds = new Set();
    let bestScore = -Infinity;
    [...canonical]
      .sort((a, b) => a.avgSec - b.avgSec || b.score - a.score)
      .forEach((r) => {
        if (r.score > bestScore) {
          frontierIds.add(r.id);
          bestScore = r.score;
        }
      });

    const fontFamily = getComputedStyle(document.body).fontFamily;
    const nodes = canonical.map((r) => {
      const onFront = frontierIds.has(r.id);
      return {
        r,
        onFront,
        score: r.score,
        x: xOf(r.avgSec),
        y: yOf(r.score),
        labelW: textWidth(r.short, `${onFront ? 600 : 400} 11.5px ${fontFamily}`) + 2,
      };
    });

    // Drawn as steps: the best score reachable within a given time budget.
    const front = nodes.filter((n) => n.onFront).sort((a, b) => a.x - b.x);
    const lineBoxes = [];
    let path = "";
    front.forEach((n, i) => {
      if (i === 0) {
        path = `M${n.x.toFixed(1)},${n.y.toFixed(1)}`;
        return;
      }
      const prev = front[i - 1];
      path += ` H${n.x.toFixed(1)} V${n.y.toFixed(1)}`;
      lineBoxes.push({ x0: prev.x, y0: prev.y - 2, x1: n.x, y1: prev.y + 2 });
      lineBoxes.push({ x0: n.x - 2, y0: n.y, x1: n.x + 2, y1: prev.y });
    });
    if (front.length) {
      const last = front[front.length - 1];
      path += ` H${plotR}`;
      lineBoxes.push({ x0: last.x, y0: last.y - 2, x1: plotR, y1: last.y + 2 });
    }

    placeLabels(nodes, lineBoxes, { x0: padL + 2, y0: 2, x1: W - 2, y1: plotB - 2 });

    let axes = "";
    for (let v = minY; v <= maxY + 1e-9; v += Y_STEP) {
      const y = yOf(v).toFixed(1);
      axes += `<line class="${v === minY ? "pc-axis" : "pc-grid"}" x1="${padL}" y1="${y}" x2="${plotR}" y2="${y}"/>`;
      axes += `<text class="pc-tick" x="${padL - 8}" y="${Number(y) + 4}" text-anchor="end">${v}</text>`;
    }
    for (let v = minX; v <= maxX + 1e-9; v += X_STEP) {
      const x = xOf(v).toFixed(1);
      axes += `<line class="pc-axis" x1="${x}" y1="${plotB}" x2="${x}" y2="${plotB + 4}"/>`;
      axes += `<text class="pc-tick" x="${x}" y="${plotB + 18}" text-anchor="middle">${v / 60}</text>`;
    }
    axes += `<text class="pc-title" x="0" y="12">${esc(t("pareto_y"))}</text>`;
    axes += `<text class="pc-title" x="${(padL + plotR) / 2}" y="${H - 6}" text-anchor="middle">${esc(t("pareto_x"))}</text>`;

    const leaders = nodes
      .filter((n) => n.label.far)
      .map((n) => {
        const b = n.label.box;
        const tx = Math.min(Math.max(n.x, b.x0), b.x1);
        const ty = Math.min(Math.max(n.y, b.y0 + 3), b.y1 - 3);
        return `<line class="pc-leader" x1="${n.x.toFixed(1)}" y1="${n.y.toFixed(1)}" x2="${tx.toFixed(1)}" y2="${ty.toFixed(1)}"/>`;
      })
      .join("");

    const points = nodes
      .map((n, idx) => {
        const b = n.label.box;
        const cls = n.onFront ? "is-front" : "is-dim";
        return `
          <g class="pareto-node ${cls}" data-idx="${idx}" tabindex="0" role="img"
             aria-label="${esc(`#${n.r.rank} ${n.r.short}: ${n.r.score.toFixed(1)}, ${fmtDur(n.r.avgSec)}`)}">
            <circle class="halo" cx="${n.x.toFixed(1)}" cy="${n.y.toFixed(1)}" r="9"/>
            <circle class="pc-dot" cx="${n.x.toFixed(1)}" cy="${n.y.toFixed(1)}" r="6"/>
            <text class="pc-label" x="${b.x0.toFixed(1)}" y="${(b.y0 + 11).toFixed(1)}">${esc(n.r.short)}</text>
          </g>`;
      })
      .join("");

    const wrap = document.getElementById("pareto-chart");
    wrap.innerHTML = `
      <svg viewBox="0 0 ${W} ${H}" role="group" aria-label="${esc(t("pareto_title"))}">
        ${axes}
        <path class="pc-frontier" d="${path}"/>
        ${leaders}
        ${points}
      </svg>`;

    // Hover picks the nearest point, so a 12px dot does not need a dead-centre hit.
    const svg = wrap.querySelector("svg");
    const nodeEls = [...svg.querySelectorAll(".pareto-node")];
    let active = -1;
    const setActive = (idx) => {
      if (idx === active) return;
      if (active >= 0) nodeEls[active].classList.remove("is-active");
      if (idx >= 0) nodeEls[idx].classList.add("is-active");
      active = idx;
    };

    svg.addEventListener("mousemove", (ev) => {
      const rect = svg.getBoundingClientRect();
      const px = (ev.clientX - rect.left) * (W / rect.width);
      const py = (ev.clientY - rect.top) * (H / rect.height);
      let nearest = -1;
      let nearestDist = 32 * 32;
      nodes.forEach((n, i) => {
        const d = (n.x - px) ** 2 + (n.y - py) ** 2;
        if (d < nearestDist) {
          nearestDist = d;
          nearest = i;
        }
      });
      setActive(nearest);
      if (nearest < 0) {
        hideTip();
        return;
      }
      showTip(`pareto:${nearest}`, () => modelTip(nodes[nearest].r), ev.clientX, ev.clientY);
    });
    svg.addEventListener("mouseleave", () => {
      setActive(-1);
      hideTip();
    });
    nodeEls.forEach((el, i) => {
      el.addEventListener("focus", () => {
        const rect = el.querySelector(".pc-dot").getBoundingClientRect();
        showTip(`pareto:${i}`, () => modelTip(nodes[i].r), rect.right, rect.top);
      });
      el.addEventListener("blur", hideTip);
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
      `${t("max_weight")} ${Math.max(...weights).toFixed(2)}`;

    const head = `
      <div class="hard-row hard-head">
        <span></span>
        <span>${t("col_task")}</span>
        <span>${t("col_passrate")}</span>
        <span class="r">${t("col_pass")}</span>
        <span class="r">${t("col_weight")}</span>
      </div>`;

    document.getElementById("hardness-list").innerHTML =
      head +
      tasks
        .map((tk) => {
          const title = state.lang === "zh" ? tk.title_zh : tk.title_en;
          return `
          <div class="hard-row" title="${esc(`${tk.id} — ${title}`)}">
            <span class="hard-tier num">T${tk.tier}</span>
            <span class="hard-id mono">${esc(tk.id)}</span>
            <div class="hard-bar"><div style="width:${tk.passRate.toFixed(1)}%"></div></div>
            <span class="hard-pass num r">${tk.passes}/${tk.total_models}</span>
            <span class="hard-weight num r">${tk.weight.toFixed(2)}</span>
          </div>`;
        })
        .join("");
  }

  function renderMatrixFilters() {
    const button = (attr, value, label, isActive) =>
      `<button class="seg-btn${isActive ? " active" : ""}" data-${attr}="${esc(value)}" aria-pressed="${isActive}" type="button">${esc(label)}</button>`;

    const tiers = [["all", t("all_tiers")], ["1", "Tier 1"], ["2", "Tier 2"], ["3", "Tier 3"]];
    document.getElementById("tier-filters").innerHTML = tiers
      .map(([v, lbl]) => button("tier", v, lbl, state.tierFilter === v))
      .join("");

    const present = new Set(state.data.tasks.map((tk) => tk.language));
    const langs = [
      ...LANG_ORDER.filter((lg) => present.has(lg)),
      ...[...present].filter((lg) => !LANG_ORDER.includes(lg)),
    ];
    document.getElementById("lang-filters").innerHTML =
      button("lang", "all", t("all_langs"), state.langFilter === "all") +
      langs.map((lg) => button("lang", lg, lg, state.langFilter === lg)).join("");
  }

  // Rows are tasks, columns are models: task names read horizontally, all 12
  // model columns fit without scrolling, and filtering removes rows instead of
  // reflowing column widths.
  function renderMatrix(canonical) {
    const { tasks, benchmark } = state.data;
    const visible = tasks
      .map((tk, i) => ({ tk, i }))
      .filter(({ tk }) => {
        const tierOk = state.tierFilter === "all" || String(tk.tier) === state.tierFilter;
        const langOk = state.langFilter === "all" || tk.language === state.langFilter;
        return tierOk && langOk;
      });

    const colgroup = `
      <colgroup>
        <col class="mx-col-task"><col class="mx-col-lang"><col class="mx-col-pass">
        ${canonical.map(() => "<col>").join("")}
      </colgroup>`;

    const head = `
      <thead><tr>
        <th class="mx-task mx-meta" scope="col">${t("col_task")}</th>
        <th class="mx-lang mx-meta" scope="col">${t("col_lang")}</th>
        <th class="mx-pass mx-meta" scope="col">${t("col_pass")}</th>
        ${canonical
          .map(
            (m, mIdx) =>
              `<th class="mx-model" scope="col" data-m-idx="${mIdx}"><span class="mx-rank num">#${m.rank}</span><span class="mx-name">${esc(m.short)}</span></th>`
          )
          .join("")}
      </tr></thead>`;

    const cell = (m, mIdx, tk, i) => {
      const res = m.results[i];
      let cls = "is-fail";
      let text = "×";
      if (res.status === "pass") {
        cls = "is-pass";
        text = fmtMin(res.duration_sec);
      } else if (res.status === "timeout") {
        cls = "is-timeout";
        text = t("cell_timeout");
      } else if (res.status === "safety_refusal") {
        cls = "is-refusal";
        text = t("cell_refusal");
      }
      const label = `${m.short}, ${tk.id}: ${statusText(res.status)}, ${fmtDur(res.duration_sec)}`;
      return `<td class="mx-cell ${cls}" data-m-idx="${mIdx}" data-t-idx="${i}" aria-label="${esc(label)}">${esc(text)}</td>`;
    };

    let body = "";
    [...new Set(visible.map(({ tk }) => tk.tier))]
      .sort((a, b) => a - b)
      .forEach((tier) => {
        const group = visible.filter(({ tk }) => tk.tier === tier);
        const meta = (benchmark.tiers || []).find((x) => x.tier === tier);
        const name = !meta ? `Tier ${tier}` : state.lang === "zh" ? `Tier ${tier} · ${meta.label_zh}` : meta.label_en;
        body += `<tr class="mx-group"><th scope="rowgroup"><strong>${esc(name)}</strong> · ${esc(t("tasks_n")(group.length))}</th></tr>`;
        group.forEach(({ tk, i }) => {
          body += `
            <tr>
              <th class="mx-task mono" scope="row" data-t-idx="${i}">${esc(tk.id)}</th>
              <td class="mx-lang">${esc(tk.language)}</td>
              <td class="mx-pass num">${tk.passes}/${tk.total_models}</td>
              ${canonical.map((m, mIdx) => cell(m, mIdx, tk, i)).join("")}
            </tr>`;
        });
      });

    document.getElementById("matrix-table").innerHTML = `${colgroup}${head}<tbody>${body}</tbody>`;

    // Each swatch is a miniature of the cell it explains; the name is dropped
    // where the cell text already says it (zh "超时").
    const item = (tint, cellText, name) =>
      `<span class="legend-item"><span class="legend-swatch glyph num" style="background:var(--${tint}-tint)">${esc(cellText)}</span>${cellText === name ? "" : esc(name)}</span>`;
    document.getElementById("matrix-legend").innerHTML =
      item("pass", "12", t("status_pass")) +
      item("fail", "×", t("status_fail")) +
      item("timeout", t("cell_timeout"), t("status_timeout")) +
      item("refusal", t("cell_refusal"), t("status_refusal")) +
      `<span class="legend-note">${esc(t("legend_minutes"))}</span>`;
  }

  function renderInsights() {
    document.getElementById("insights-grid").innerHTML = I18N[state.lang].insights
      .map(
        (card, i) => `
      <article class="insight-card">
        <span class="insight-num num">${String(i + 1).padStart(2, "0")}</span>
        <div>
          <h3>${card.title}</h3>
          <p>${card.body}</p>
        </div>
      </article>`
      )
      .join("");
  }

  function renderAll() {
    hideTip();
    applyI18n();
    document.querySelectorAll("#scheme-buttons button").forEach((b) => {
      const isActive = b.dataset.scheme === state.scheme;
      b.classList.toggle("active", isActive);
      b.setAttribute("aria-pressed", String(isActive));
    });
    document.getElementById("formula-desc").innerHTML =
      I18N[state.lang].formula_desc[state.scheme];

    const { rows, canonical, weights } = computeLeaderboard();
    view = { canonical, weights };
    renderSortState();
    renderKPIs(canonical);
    renderLeaderboard(rows);
    renderPareto(canonical);
    renderHardness(weights);
    renderMatrixFilters();
    renderMatrix(canonical);
    renderInsights();

    const b = state.data.benchmark;
    const updated = String(state.data.generated_at).replace("T", " ").replace(/:\d\d(\.\d+)?Z$/, " UTC");
    document.getElementById("footer-meta").textContent =
      `${b.name} · Timeout ${b.timeout_sec}s · Updated ${updated}`;
  }

  // ── Events ────────────────────────────────────────────────────────────────

  function bindMatrixHover() {
    const table = document.getElementById("matrix-table");
    let activeHead = null;

    const clear = () => {
      if (activeHead) activeHead.classList.remove("is-active");
      activeHead = null;
      hideTip();
    };

    table.addEventListener("mousemove", (ev) => {
      const el = ev.target.closest("[data-t-idx], [data-m-idx]");
      if (!el || !table.contains(el)) {
        clear();
        return;
      }
      const mIdx = el.dataset.mIdx !== undefined ? Number(el.dataset.mIdx) : null;
      const tIdx = el.dataset.tIdx !== undefined ? Number(el.dataset.tIdx) : null;

      // Mark the hovered cell's column header; the row label is handled in CSS.
      const headEl = mIdx !== null ? table.querySelector(`thead th[data-m-idx="${mIdx}"]`) : null;
      if (headEl !== activeHead) {
        if (activeHead) activeHead.classList.remove("is-active");
        if (headEl) headEl.classList.add("is-active");
        activeHead = headEl;
      }

      showTip(
        `matrix:${mIdx}:${tIdx}`,
        () => (tIdx === null ? modelTip(view.canonical[mIdx]) : taskTip(tIdx, mIdx)),
        ev.clientX,
        ev.clientY
      );
    });
    table.addEventListener("mouseleave", clear);
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
      const sort = () => {
        const key = th.dataset.sort;
        if (state.sortKey === key) {
          state.sortDir = state.sortDir === "desc" ? "asc" : "desc";
        } else {
          state.sortKey = key;
          state.sortDir = key === "avgSec" || key === "rank" || key === "short" ? "asc" : "desc";
        }
        renderAll();
      };
      th.tabIndex = 0;
      th.addEventListener("click", sort);
      th.addEventListener("keydown", (ev) => {
        if (ev.key === "Enter" || ev.key === " ") {
          ev.preventDefault();
          sort();
        }
      });
    });

    document.getElementById("tier-filters").addEventListener("click", (ev) => {
      const btn = ev.target.closest("button[data-tier]");
      if (!btn) return;
      state.tierFilter = btn.dataset.tier;
      renderAll();
    });
    document.getElementById("lang-filters").addEventListener("click", (ev) => {
      const btn = ev.target.closest("button[data-lang]");
      if (!btn) return;
      state.langFilter = btn.dataset.lang;
      renderAll();
    });

    document.getElementById("lang-toggle").addEventListener("click", () => {
      state.lang = state.lang === "zh" ? "en" : "zh";
      renderAll();
    });

    document.getElementById("theme-toggle").addEventListener("click", () => {
      state.theme = state.theme === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", state.theme);
      try {
        localStorage.setItem("vh-theme", state.theme);
      } catch (e) {
        // Storage can be unavailable (private mode); the choice then lasts for this page view.
      }
      applyI18n();
    });

    // Until the reader picks a theme, keep following the OS setting.
    const osDark = window.matchMedia("(prefers-color-scheme: dark)");
    osDark.addEventListener("change", () => {
      if (document.documentElement.hasAttribute("data-theme")) return;
      state.theme = osDark.matches ? "dark" : "light";
      applyI18n();
    });

    bindMatrixHover();
    window.addEventListener("scroll", hideTip, { passive: true });
  }

  async function init() {
    if (window.__VULNHUNTER_DATA__) {
      state.data = window.__VULNHUNTER_DATA__;
    } else {
      const resp = await fetch("./data/leaderboard.json");
      state.data = await resp.json();
    }
    state.data.tasks.forEach((task) => {
      state.tierTotals[task.tier] = (state.tierTotals[task.tier] || 0) + 1;
    });
    state.theme =
      document.documentElement.getAttribute("data-theme") ||
      (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
    bindEvents();
    renderAll();
  }

  init().catch((err) => {
    document.body.innerHTML = `<pre style="padding:24px;color:#d03b3b">Failed to load leaderboard data: ${err}</pre>`;
  });
})();
