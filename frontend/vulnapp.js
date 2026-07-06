const POLL_INTERVAL_MS = 12000;

const state = {
  currentView: "overview",
  assets: [],
  runs: [],
  currentRun: null,
  findings: [],
  findingDetail: null,
  findingEvidence: [],
  agents: [],
  interventions: [],
  timeline: [],
  fileTree: null,
  selectedArtifactPath: null,
  artifactFileMeta: null,
  relatedFindingTimeline: [],
  launchState: {
    running: false,
    target: "",
    scope: "",
    started_at: 0,
    run_id: "",
    last_result: null,
    last_error: "",
  },
  selectedAssetId: null,
  selectedRunId: null,
  selectedFindingId: null,
  selectedAgentId: null,
  refreshing: false,
  pollHandle: null,
};

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  }[char]));
}

function severityClass(severity) {
  const value = String(severity || "").toLowerCase();
  if (value === "critical" || value === "high") return "danger";
  if (value === "medium") return "warn";
  return "success";
}

function excerpt(value, fallback = "暂无。") {
  const text = String(value || "").trim();
  return text || fallback;
}

function formatTime(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric <= 0) return "未记录";
  const millis = numeric > 1e12 ? numeric : numeric * 1000;
  return new Date(millis).toLocaleString("zh-CN", { hour12: false });
}

function selectedAsset() {
  return state.assets.find((asset) => asset.asset_id === state.selectedAssetId) || null;
}

function selectedFinding() {
  return state.findings.find((finding) => finding.finding_id === state.selectedFindingId) || state.findingDetail || null;
}

function selectedAgent() {
  return state.agents.find((agent) => agent.agent_id === state.selectedAgentId) || null;
}

function selectedAgentName() {
  return selectedAgent()?.agent_name || "";
}

function selectedFindingEvidenceArtifactPath() {
  const directMatch = state.findingEvidence.find((item) => String(item.artifact_path || "").trim());
  return String(directMatch?.artifact_path || state.selectedArtifactPath || "").trim();
}

function filteredTimeline() {
  const agentName = selectedAgentName();
  if (!agentName) return state.timeline;
  const matches = state.timeline.filter((event) => String(event.agent_name || "") === agentName);
  return matches.length ? matches : state.timeline;
}

function trackedRunId() {
  const activeRunId = String(state.launchState.run_id || "").trim();
  if (activeRunId) return activeRunId;
  return String(state.launchState.last_result?.run_id || "").trim();
}

async function fetchJson(path, options = undefined) {
  const response = await fetch(path, options);
  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`);
  }
  return response.json();
}

function createQuery(params) {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    const normalized = String(value ?? "").trim();
    if (normalized) {
      query.set(key, normalized);
    }
  });
  const queryString = query.toString();
  return queryString ? `?${queryString}` : "";
}

async function loadFileTree(runId) {
  if (!runId) {
    state.fileTree = null;
    return;
  }
  const payload = await fetchJson(`/api/runs/${runId}/file-tree`);
  state.fileTree = payload.tree || null;
}

async function loadArtifactContent(runId, relativePath) {
  if (!runId || !relativePath) {
    state.selectedArtifactPath = null;
    state.artifactFileMeta = null;
    return;
  }
  const payload = await fetchJson(`/api/runs/${runId}/files/content${createQuery({ path: relativePath })}`);
  state.selectedArtifactPath = relativePath;
  state.artifactFileMeta = payload.data || null;
}

async function loadRelatedFindingTimeline(runId) {
  if (!runId || !state.selectedFindingId) {
    state.relatedFindingTimeline = [];
    return;
  }
  const artifactPath = selectedFindingEvidenceArtifactPath();
  const payload = await fetchJson(
    `/api/runs/${runId}/timeline${createQuery({ limit: 100, finding_id: state.selectedFindingId, artifact_path: artifactPath })}`,
  );
  state.relatedFindingTimeline = payload.data || [];
}

function formatFileSize(value) {
  const size = Number(value || 0);
  if (!Number.isFinite(size) || size <= 0) return "0 B";
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  return `${(size / (1024 * 1024)).toFixed(1)} MB`;
}

function collectArtifactPaths(node) {
  if (!node) return [];
  if (node.kind === "file") {
    return node.relative_path ? [node.relative_path] : [];
  }
  return (node.children || []).flatMap((child) => collectArtifactPaths(child));
}

async function refreshData() {
  if (state.refreshing) return;
  state.refreshing = true;

  try {
    const [launchPayload, assetPayload] = await Promise.all([
      fetchJson("/api/vuln/run-state"),
      fetchJson("/api/assets"),
    ]);
    state.launchState = launchPayload.data || state.launchState;
    state.assets = assetPayload.data || [];
    const activeRunId = trackedRunId();
    let activeRun = null;

    if (activeRunId) {
      try {
        const activeRunPayload = await fetchJson(`/api/runs/${activeRunId}`);
        activeRun = activeRunPayload.data || null;
      } catch (_error) {
        activeRun = null;
      }
    }

    if (activeRun?.asset_id) {
      state.selectedAssetId = activeRun.asset_id;
      state.selectedRunId = activeRun.run_id || activeRunId;
    }

    if (!state.assets.some((asset) => asset.asset_id === state.selectedAssetId)) {
      state.selectedAssetId = state.assets[0]?.asset_id || null;
    }

    state.runs = [];
    state.currentRun = null;
    state.findings = [];
    state.findingDetail = null;
    state.findingEvidence = [];
    state.agents = [];
    state.interventions = [];
    state.timeline = [];
    state.fileTree = null;
    state.selectedArtifactPath = null;
    state.artifactFileMeta = null;
    state.relatedFindingTimeline = [];

    if (state.selectedAssetId) {
      const runPayload = await fetchJson(`/api/assets/${state.selectedAssetId}/runs`);
      state.runs = runPayload.data || [];
      if (activeRunId && state.runs.some((run) => run.run_id === activeRunId)) {
        state.selectedRunId = state.launchState.run_id;
      } else if (!state.runs.some((run) => run.run_id === state.selectedRunId)) {
        state.selectedRunId = state.runs[0]?.run_id || null;
      }
    } else {
      state.selectedRunId = null;
    }

    if (state.selectedRunId) {
      const runRequest = activeRun && activeRun.run_id === state.selectedRunId
        ? Promise.resolve({ data: activeRun })
        : fetchJson(`/api/runs/${state.selectedRunId}`);
      const [runPayload, findingsPayload, agentsPayload, interventionsPayload, timelinePayload] = await Promise.all([
        runRequest,
        fetchJson(`/api/runs/${state.selectedRunId}/findings`),
        fetchJson(`/api/runs/${state.selectedRunId}/agents`),
        fetchJson(`/api/runs/${state.selectedRunId}/interventions`),
        fetchJson(`/api/runs/${state.selectedRunId}/timeline?limit=100`),
      ]);
      state.currentRun = runPayload.data || null;
      state.findings = findingsPayload.data || [];
      state.agents = agentsPayload.data || [];
      state.interventions = interventionsPayload.data || [];
      state.timeline = timelinePayload.data || [];

      if (!state.findings.some((finding) => finding.finding_id === state.selectedFindingId)) {
        state.selectedFindingId = state.findings[0]?.finding_id || null;
      }
      if (!state.agents.some((agent) => agent.agent_id === state.selectedAgentId)) {
        state.selectedAgentId = state.agents[0]?.agent_id || null;
      }

      if (state.selectedFindingId) {
        const [detailPayload, evidencePayload] = await Promise.all([
          fetchJson(`/api/findings/${state.selectedFindingId}`),
          fetchJson(`/api/findings/${state.selectedFindingId}/evidence`),
        ]);
        state.findingDetail = detailPayload.data || null;
        state.findingEvidence = evidencePayload.data || [];
      }

      await loadFileTree(state.selectedRunId);

      const availableArtifactPaths = collectArtifactPaths(state.fileTree);
      const preferredArtifactPath = selectedFindingEvidenceArtifactPath();
      const nextArtifactPath = availableArtifactPaths.includes(state.selectedArtifactPath)
        ? state.selectedArtifactPath
        : (preferredArtifactPath && availableArtifactPaths.includes(preferredArtifactPath) ? preferredArtifactPath : availableArtifactPaths[0] || null);

      if (nextArtifactPath) {
        await loadArtifactContent(state.selectedRunId, nextArtifactPath);
      }

      await loadRelatedFindingTimeline(state.selectedRunId);
    } else {
      state.selectedFindingId = null;
      state.selectedAgentId = null;
    }

    render();
  } catch (error) {
    renderError(error);
  } finally {
    state.refreshing = false;
  }
}

function renderError(error) {
  const summary = document.getElementById("globalSummary");
  if (summary) {
    summary.textContent = `载入失败：${error}`;
  }
}

function syncViewButtons() {
  document.querySelectorAll(".view-switch button").forEach((button) => {
    button.classList.toggle("active", button.dataset.view === state.currentView);
  });
}

function toggleViews() {
  document.querySelector(".overview-grid")?.classList.toggle("hidden", state.currentView !== "overview");
  document.getElementById("assetShell")?.classList.toggle("hidden", state.currentView !== "asset");
  document.getElementById("supervisionShell")?.classList.toggle("hidden", state.currentView !== "supervision");
  document.getElementById("reportShell")?.classList.toggle("hidden", state.currentView !== "report");
}

function updateSummary() {
  const summary = document.getElementById("globalSummary");
  if (!summary) return;

  if (state.launchState.running) {
    summary.textContent = `正在分析 ${state.launchState.target}，范围 ${state.launchState.scope || "unspecified"}，开始于 ${formatTime(state.launchState.started_at)}。`;
    return;
  }

  if (!state.assets.length) {
    summary.textContent = "当前还没有运行记录。先跑一次固件分析，就能在这里看到结构化结果。";
    return;
  }

  const asset = selectedAsset();
  summary.textContent = `已记录 ${state.assets.length} 个资产，当前资产 ${asset?.name || state.selectedAssetId}，run 状态 ${state.currentRun?.status || "idle"}，可疑点 ${state.findings.length}，活跃 Agent ${state.agents.length}，介入记录 ${state.interventions.length}。`;
}

function renderLaunchState() {
  const button = document.getElementById("launchButton");
  const status = document.getElementById("launchStatus");
  if (!button || !status) return;

  button.disabled = Boolean(state.launchState.running);
  if (state.launchState.running) {
    const runId = trackedRunId();
    status.textContent = runId
      ? `正在分析：${state.launchState.target} / ${runId}`
      : `正在分析：${state.launchState.target}`;
    return;
  }

  const lastResult = state.launchState.last_result;
  if (lastResult?.run_id) {
    status.textContent = lastResult.success
      ? `最近完成：${lastResult.run_id}`
      : `最近失败：${lastResult.error || lastResult.target || "unknown"}`;
    return;
  }

  status.textContent = "支持本地固件路径、目录或授权目标 URL。";
}

function findingButtonMarkup(finding, { compact = false, switchView = false } = {}) {
  const active = finding.finding_id === state.selectedFindingId;
  return `
    <button
      type="button"
      class="item-button ${active ? "active" : ""}"
      data-finding-id="${escapeHtml(finding.finding_id)}"
      ${switchView ? 'data-switch-view="asset"' : ""}
    >
      <div class="severity-row">
        <span class="pill ${severityClass(finding.severity)}">${escapeHtml(finding.severity || "unknown")}</span>
        <span class="pill">${escapeHtml(finding.state || "suspect")}</span>
      </div>
      <h3>${escapeHtml(finding.title || finding.finding_id)}</h3>
      <div class="meta">${escapeHtml(finding.category || "uncategorized")}</div>
      <div class="summary-line">${escapeHtml(excerpt(finding.why_suspicious, "暂无可疑点说明。"))}</div>
      ${compact ? "" : `<div class="meta">置信度：${escapeHtml(String(finding.confidence ?? "0"))}</div>`}
    </button>
  `;
}

function renderAssetList() {
  const target = document.getElementById("assetList");
  if (!target) return;

  if (!state.assets.length) {
    target.innerHTML = '<div class="empty-state">当前还没有资产记录。</div>';
    return;
  }

  target.innerHTML = state.assets.map((asset) => `
    <button
      type="button"
      class="item-button ${asset.asset_id === state.selectedAssetId ? "active" : ""}"
      data-asset-id="${escapeHtml(asset.asset_id)}"
    >
      <h3>${escapeHtml(asset.name || asset.asset_id)}</h3>
      <div class="meta">${escapeHtml(asset.kind || "unknown")} · ${escapeHtml(asset.source_path || "")}</div>
      <div class="summary-line">首次记录：${escapeHtml(formatTime(asset.created_at))}</div>
    </button>
  `).join("");
}

function renderRunList() {
  const target = document.getElementById("runList");
  if (!target) return;

  if (!state.selectedAssetId) {
    target.innerHTML = '<div class="empty-state">先选择一个资产。</div>';
    return;
  }

  if (!state.runs.length) {
    target.innerHTML = '<div class="empty-state">这个资产还没有 run 记录。</div>';
    return;
  }

  target.innerHTML = state.runs.map((run) => `
    <button
      type="button"
      class="item-button ${run.run_id === state.selectedRunId ? "active" : ""}"
      data-run-id="${escapeHtml(run.run_id)}"
    >
      <div class="severity-row">
        <span class="pill ${run.status === "failed" ? "danger" : "success"}">${escapeHtml(run.status || "unknown")}</span>
        <span class="pill mono">${escapeHtml(run.run_id)}</span>
      </div>
      <div class="meta">开始：${escapeHtml(formatTime(run.started_at))}</div>
      <div class="meta">结束：${escapeHtml(formatTime(run.ended_at))}</div>
      <div class="summary-line">${escapeHtml(excerpt(run.summary, "等待 run 摘要。"))}</div>
    </button>
  `).join("");
}

function renderFindingLists() {
  const listTarget = document.getElementById("findingList");
  const overviewTarget = document.getElementById("overviewFindings");

  if (!state.selectedRunId) {
    const empty = '<div class="empty-state">当前资产还没有 run 记录。</div>';
    if (listTarget) listTarget.innerHTML = empty;
    if (overviewTarget) overviewTarget.innerHTML = empty;
    return;
  }

  if (!state.findings.length) {
    const empty = '<div class="empty-state">当前 run 还没有结构化 finding。</div>';
    if (listTarget) listTarget.innerHTML = empty;
    if (overviewTarget) overviewTarget.innerHTML = empty;
    return;
  }

  if (listTarget) {
    listTarget.innerHTML = state.findings.map((finding) => findingButtonMarkup(finding)).join("");
  }

  if (overviewTarget) {
    overviewTarget.innerHTML = state.findings
      .slice(0, 4)
      .map((finding) => findingButtonMarkup(finding, { compact: true, switchView: true }))
      .join("");
  }
}

function renderFindingDetail() {
  const detail = state.findingDetail || selectedFinding();
  const reportText = String(state.launchState.last_result?.report || "").trim();
  const enriched = reportText ? enrichFindingWithReport([detail || {}], reportText)[0] : (detail || {});
  const header = document.getElementById("findingHeader");
  const why = document.getElementById("findingWhy");
  const hypothesis = document.getElementById("findingHypothesis");
  const nextStep = document.getElementById("findingNextStep");
  const evidence = document.getElementById("findingEvidence");
  const findingTimeline = document.getElementById("findingTimeline");

  if (!header || !why || !hypothesis || !nextStep || !evidence || !findingTimeline) return;

  if (!detail) {
    header.textContent = "选中一个 finding 后，这里会展示它为什么可疑、如何利用、现在卡在哪里。";
    why.textContent = "等待 finding 详情。";
    hypothesis.textContent = "等待当前假设。";
    nextStep.textContent = "等待下一步验证动作。";
    evidence.innerHTML = '<div class="empty-state">等待 evidence。</div>';
    findingTimeline.innerHTML = '<div class="empty-state">等待和当前可疑点相关的事件流。</div>';
    return;
  }

  const cvssVector = enriched._cvss_vector || "";
  const cvssScore = enriched._cvss_score || "";
  const cvssSev = enriched._cvss_severity || "";
  const cwe = enriched._cwe || "";
  const pocPath = enriched._poc_path || "";
  const pocUsage = enriched._poc_usage || "";

  const cvssBadge = cvssVector
    ? `<span class="cvss-badge ${cvssSev.toLowerCase() || cvssSeverityLevel(cvssScore) || "medium"}">CVSS ${escapeHtml(cvssVector.slice(0, 6))}${cvssScore ? " " + escapeHtml(cvssScore) : ""}${cvssSev ? " " + escapeHtml(cvssSev) : ""}</span>`
    : "";
  const cweTag = cwe ? `<span class="cwe-tag">${escapeHtml(cwe)}</span>` : "";
  const pocTag = pocPath ? `<span class="pill success">PoC: ${escapeHtml(pocPath.split("/").pop())}</span>` : "";

  header.innerHTML = `
    <div class="severity-row">
      <span class="pill ${severityClass(detail.severity)}">${escapeHtml(detail.severity || "unknown")}</span>
      <span class="pill">${escapeHtml(detail.state || "suspect")}</span>
      <span class="pill mono">${escapeHtml(detail.finding_id || "")}</span>
    </div>
    <h3>${escapeHtml(detail.title || "未命名 finding")}</h3>
    <div class="meta">${escapeHtml(detail.category || "uncategorized")} · 更新时间 ${escapeHtml(formatTime(detail.updated_at))}</div>
    ${(cvssBadge || cweTag || pocTag) ? `<div class="finding-meta-row">${cvssBadge}${cweTag}${pocTag}</div>` : ""}
    <div class="finding-impact">${escapeHtml(excerpt(detail.impact_statement, "等待影响评估。"))}</div>
    ${pocUsage ? `<div class="meta" style="margin-top:6px">${escapeHtml(pocUsage)}</div>` : ""}
  `;
  why.innerHTML = `<p>${escapeHtml(excerpt(detail.why_suspicious, "暂无可疑点说明。"))}</p>`;
  hypothesis.innerHTML = `<p>${escapeHtml(excerpt(detail.current_hypothesis, "当前还没有形成明确假设，更多时候说明 agent 还停留在枚举和收集阶段。"))}</p>`;
  nextStep.innerHTML = `<p>${escapeHtml(excerpt(detail.next_best_action, "继续补充验证动作。"))}</p>`;

  evidence.innerHTML = state.findingEvidence.length
    ? state.findingEvidence.map((item) => `
      <article class="surface">
        <h3>${escapeHtml(item.title || item.kind || "evidence")}</h3>
        <div class="meta-grid">
          <div class="meta-block">
            <span class="meta-label">来源</span>
            <div class="meta-value mono">${escapeHtml(item.source_ref || item.artifact_path || "unknown")}</div>
          </div>
          <div class="meta-block">
            <span class="meta-label">采集者</span>
            <div class="meta-value">${escapeHtml(item.collector || "unknown")}</div>
          </div>
        </div>
        <div class="evidence-snippet">${escapeHtml(excerpt(item.snippet, "暂无片段。"))}</div>
      </article>
    `).join("")
    : '<div class="empty-state">这个 finding 还没有挂接 evidence。</div>';

  findingTimeline.innerHTML = renderTimelineMarkup(
    relatedFindingTimeline().slice(-8).reverse(),
    "当前 finding 还没有足够多的相关时间线。",
  );
}

function renderOverview() {
  const hypothesis = document.getElementById("overviewHypothesis");
  const nextStep = document.getElementById("overviewNextStep");
  const evidence = document.getElementById("overviewEvidence");
  const runtime = document.getElementById("overviewRuntime");
  const timeline = document.getElementById("overviewTimeline");
  const detail = state.findingDetail || selectedFinding();

  if (hypothesis) {
    hypothesis.innerHTML = detail
      ? `
        <div class="surface">
          <h3>${escapeHtml(detail.title || "当前聚焦 finding")}</h3>
          <div class="summary-line">${escapeHtml(excerpt(detail.current_hypothesis, "当前还没有形成明确假设。"))}</div>
          <div class="meta">可疑点：${escapeHtml(excerpt(detail.why_suspicious, "暂无。"))}</div>
        </div>
      `
      : '<div class="empty-state">还没有聚焦到具体 finding。</div>';
  }

  if (nextStep) {
    const steps = [
      detail?.next_best_action ? `finding：${detail.next_best_action}` : "",
      state.agents[0]?.next_step ? `agent：${state.agents[0].next_step}` : "",
      state.currentRun?.summary ? `run：${state.currentRun.summary}` : "",
    ].filter(Boolean);
    nextStep.innerHTML = steps.length
      ? steps.slice(0, 3).map((item) => `<div class="surface">${escapeHtml(item)}</div>`).join("")
      : '<div class="empty-state">当前还没有明确的下一步。</div>';
  }

  if (evidence) {
    evidence.innerHTML = state.findingEvidence.length
      ? state.findingEvidence.slice(0, 3).map((item) => `
        <div class="surface">
          <h3>${escapeHtml(item.title || item.kind || "evidence")}</h3>
          <div class="meta mono">${escapeHtml(item.source_ref || item.artifact_path || "unknown")}</div>
          <div class="summary-line">${escapeHtml(excerpt(item.snippet, "暂无片段。"))}</div>
        </div>
      `).join("")
      : '<div class="empty-state">当前 finding 还没有关联证据。</div>';
  }

  if (runtime) {
    runtime.innerHTML = state.currentRun
      ? `
        <div class="runtime-stats">
          <div class="stat-chip">
            <span class="meta">findings</span>
            <strong>${escapeHtml(String(state.findings.length))}</strong>
          </div>
          <div class="stat-chip">
            <span class="meta">agents</span>
            <strong>${escapeHtml(String(state.agents.length))}</strong>
          </div>
          <div class="stat-chip">
            <span class="meta">events</span>
            <strong>${escapeHtml(String(state.timeline.length))}</strong>
          </div>
          <div class="stat-chip">
            <span class="meta">interventions</span>
            <strong>${escapeHtml(String(state.interventions.length))}</strong>
          </div>
        </div>
        <div class="meta-grid">
          <div class="meta-block">
            <span class="meta-label">run_id</span>
            <div class="meta-value mono">${escapeHtml(state.currentRun.run_id || state.selectedRunId || "")}</div>
          </div>
          <div class="meta-block">
            <span class="meta-label">scope</span>
            <div class="meta-value">${escapeHtml(state.currentRun.scope || "unspecified")}</div>
          </div>
          <div class="meta-block">
            <span class="meta-label">开始时间</span>
            <div class="meta-value">${escapeHtml(formatTime(state.currentRun.started_at))}</div>
          </div>
          <div class="meta-block">
            <span class="meta-label">结束时间</span>
            <div class="meta-value">${escapeHtml(formatTime(state.currentRun.ended_at))}</div>
          </div>
        </div>
      `
      : '<div class="empty-state">等待运行态摘要。</div>';
  }

  if (timeline) {
    timeline.innerHTML = renderTimelineMarkup(state.timeline.slice(-5).reverse(), "当前还没有事件流。");
  }
}

function renderAgentList() {
  const target = document.getElementById("agentList");
  if (!target) return;

  if (!state.agents.length) {
    target.innerHTML = '<div class="empty-state">当前 run 还没有投影出 agent 状态。</div>';
    return;
  }

  target.innerHTML = state.agents.map((agent) => `
    <button
      type="button"
      class="item-button ${agent.agent_id === state.selectedAgentId ? "active" : ""}"
      data-agent-id="${escapeHtml(agent.agent_id)}"
    >
      <div class="severity-row">
        <span class="pill ${agent.status === "running" ? "success" : "warn"}">${escapeHtml(agent.status || "unknown")}</span>
      </div>
      <h3>${escapeHtml(agent.agent_name || agent.agent_id)}</h3>
      <div class="meta">目标：${escapeHtml(excerpt(agent.current_target, "等待目标。"))}</div>
      <div class="summary-line">${escapeHtml(excerpt(agent.current_hypothesis, "尚未写入当前假设。"))}</div>
    </button>
  `).join("");
}

function renderAgentDetail() {
  const target = document.getElementById("agentDetail");
  if (!target) return;

  const agent = selectedAgent();
  if (!agent) {
    target.innerHTML = '<div class="empty-state">当前 run 还没有 agent 细节。</div>';
    updateInterventionHint();
    return;
  }

  target.innerHTML = `
    <div class="meta-grid">
      <div class="meta-block">
        <span class="meta-label">Agent</span>
        <div class="meta-value">${escapeHtml(agent.agent_name || "unknown")}</div>
      </div>
      <div class="meta-block">
        <span class="meta-label">状态</span>
        <div class="meta-value">${escapeHtml(agent.status || "unknown")}</div>
      </div>
      <div class="meta-block">
        <span class="meta-label">当前目标</span>
        <div class="meta-value mono">${escapeHtml(excerpt(agent.current_target, "暂无。"))}</div>
      </div>
      <div class="meta-block">
        <span class="meta-label">最近更新时间</span>
        <div class="meta-value">${escapeHtml(formatTime(agent.updated_at))}</div>
      </div>
    </div>
    <section class="detail-group">
      <h3>当前假设</h3>
      <div class="detail-copy">${escapeHtml(excerpt(agent.current_hypothesis, "这个 Agent 还没有明确写下当前假设。"))}</div>
    </section>
    <section class="detail-group">
      <h3>难点 / 阻塞</h3>
      <div class="detail-copy">${escapeHtml(excerpt(agent.current_blocker, "暂未记录阻塞点。"))}</div>
    </section>
    <section class="detail-group">
      <h3>下一步</h3>
      <div class="detail-copy">${escapeHtml(excerpt(agent.next_step, "等待下一步动作。"))}</div>
    </section>
  `;
  updateInterventionHint();
}

function describeTimelineEvent(event) {
  const type = String(event.type || "");
  const data = event.data || {};
  const node = String(data.node || event.message || "").trim();
  const toolName = String(data.tool_name || event.message || "").trim();

  switch (type) {
    case "node.enter":
      return { title: `进入节点 ${node || "unknown"}`, note: "开始执行一个新的阶段。", body: "" };
    case "node.exit":
      return { title: `离开节点 ${node || "unknown"}`, note: "该阶段执行结束。", body: "" };
    case "reasoning.started":
      return { title: "开始推理", note: `迭代 ${event.iteration || 0}`, body: "" };
    case "reasoning.completed":
      return { title: "阶段性判断产出", note: "生成了本轮思考摘要。", body: String(event.message || "").trim() };
    case "reasoning.tool_call":
      return { title: `计划调用工具 ${toolName || "unknown"}`, note: "这是 agent 在推理阶段给出的下一步动作。", body: JSON.stringify(data.tool_args || {}, null, 2) };
    case "tool.called":
      return { title: `调用工具 ${toolName || "unknown"}`, note: "开始执行工具验证。", body: JSON.stringify(data.arguments || {}, null, 2) };
    case "tool.result":
      return { title: `工具结果 ${toolName || "unknown"}`, note: "收到了工具输出摘要。", body: String(event.message || "").trim() };
    case "tool.error":
      return { title: `工具报错 ${toolName || "unknown"}`, note: "这个环节是重点排障位置。", body: String(data.error || event.message || "").trim() };
    case "verify.completed":
      return { title: `验证${data.success ? "成功" : "失败"}`, note: "验证结果会直接影响 finding 是否升级。", body: String(event.message || "").trim() };
    case "intervention.received":
      return { title: "收到人工介入", note: `scope=${data.scope_type || "run"}`, body: String(data.instruction || event.message || "").trim() };
    case "intervention.applied":
      return { title: "介入已注入当前阶段", note: `scope=${data.scope_type || "run"}`, body: String(data.response_summary || data.instruction || event.message || "").trim() };
    case "token.budget":
      return { title: "Token 使用进度", note: "用于判断是否进入压缩与收敛阶段。", body: `${event.tokens_used || 0} / ${event.tokens_total || 0}` };
    case "agent.error":
      return { title: "Agent 异常", note: "这里通常意味着需要介入或修正路径。", body: String(data.error || event.message || "").trim() };
    default:
      return {
        title: type || "未知事件",
        note: "原始事件流。",
        body: String(event.message || "").trim() || JSON.stringify(data || {}, null, 2),
      };
  }
}

function renderTimelineMarkup(events, emptyText) {
  if (!events.length) {
    return `<div class="empty-state">${escapeHtml(emptyText)}</div>`;
  }

  return events.map((event) => {
    const description = describeTimelineEvent(event);
    const body = String(description.body || "").trim();
    return `
      <article class="timeline-row">
        <div class="timeline-header">
          <div>
            <div class="timeline-title">${escapeHtml(description.title)}</div>
            <div class="timeline-note">${escapeHtml(description.note)}</div>
          </div>
          <div class="meta">${escapeHtml(event.agent_name || "run")} · ${escapeHtml(formatTime(event.timestamp || event.created_at))}</div>
        </div>
        ${body ? `<div class="timeline-body">${escapeHtml(body)}</div>` : ""}
      </article>
    `;
  }).join("");
}

function renderInterventions() {
  const target = document.getElementById("interventionList");
  if (!target) return;

  if (!state.interventions.length) {
    target.innerHTML = '<div class="empty-state">等待第一条介入记录。</div>';
    return;
  }

  target.innerHTML = state.interventions.map((item) => `
    <article class="surface">
      <div class="severity-row">
        <span class="pill ${item.status === "applied" ? "success" : "warn"}">${escapeHtml(item.status || "unknown")}</span>
        <span class="pill">${escapeHtml(item.scope_type || "run")}</span>
      </div>
      <div class="meta">scope_id：${escapeHtml(item.scope_id || "")}</div>
      <div class="meta">时间：${escapeHtml(formatTime(item.created_at))}</div>
      <div class="summary-line">${escapeHtml(excerpt(item.instruction, "暂无指令。"))}</div>
      ${item.response_summary ? `<div class="timeline-body">${escapeHtml(item.response_summary)}</div>` : ""}
    </article>
  `).join("");
}

function renderTimelinePanels() {
  const target = document.getElementById("agentTimeline");
  if (target) {
    target.innerHTML = renderTimelineMarkup(filteredTimeline().slice(-12).reverse(), "当前还没有 agent 事件流。");
  }
}

function updateInterventionHint() {
  const status = document.getElementById("interventionStatus");
  if (!status) return;
  const agent = selectedAgent();
  status.textContent = agent
    ? `当前会投递给 ${agent.agent_name}；scope_id=${agent.agent_id}`
    : "默认发给整个 run。";
}

function bindSelectionButtons() {
  document.querySelectorAll("[data-asset-id]").forEach((button) => {
    button.onclick = async () => {
      state.selectedAssetId = button.dataset.assetId || null;
      state.selectedRunId = null;
      state.selectedFindingId = null;
      state.selectedAgentId = null;
      await refreshData();
    };
  });

  document.querySelectorAll("[data-run-id]").forEach((button) => {
    button.onclick = async () => {
      state.selectedRunId = button.dataset.runId || null;
      state.selectedFindingId = null;
      state.selectedAgentId = null;
      await refreshData();
    };
  });

  document.querySelectorAll("[data-finding-id]").forEach((button) => {
    button.onclick = async () => {
      state.selectedFindingId = button.dataset.findingId || null;
      if (button.dataset.switchView) {
        state.currentView = button.dataset.switchView;
      }
      await refreshData();
    };
  });

  document.querySelectorAll("[data-artifact-path]").forEach((button) => {
    button.onclick = async () => {
      const artifactPath = button.dataset.artifactPath || null;
      if (!state.selectedRunId || !artifactPath) return;
      await loadArtifactContent(state.selectedRunId, artifactPath);
      await loadRelatedFindingTimeline(state.selectedRunId);
      renderArtifactPanels();
      renderFindingDetail();
    };
  });

  document.querySelectorAll("[data-agent-id]").forEach((button) => {
    button.onclick = () => {
      state.selectedAgentId = button.dataset.agentId || null;
      renderAgentDetail();
      renderInterventions();
      renderTimelinePanels();
      if (state.currentView !== "supervision") {
        state.currentView = "supervision";
        syncViewButtons();
        toggleViews();
      }
    };
  });
}

function readNumberInput(id, fallback) {
  const input = document.getElementById(id);
  if (!input) return fallback;
  const value = Number(input.value);
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

async function submitLaunch(event) {
  event.preventDefault();
  const target = document.getElementById("launchTarget");
  const scope = document.getElementById("launchScope");
  const button = document.getElementById("launchButton");
  const status = document.getElementById("launchStatus");
  if (!target || !scope || !button || !status) return;

  const targetValue = target.value.trim();
  if (!targetValue) {
    status.textContent = "请先输入目标路径或 URL。";
    return;
  }

  button.disabled = true;
  status.textContent = "正在提交分析任务...";
  try {
    await fetchJson("/api/vuln/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target: targetValue,
        scope: scope.value.trim(),
        max_iterations: readNumberInput("launchIterations", 5),
        token_limit: readNumberInput("launchBudget", 100000),
      }),
    });
    state.currentView = "supervision";
    syncViewButtons();
    toggleViews();
    status.textContent = `已启动分析：${targetValue}`;
    await refreshData();
  } catch (error) {
    status.textContent = `启动失败：${error}`;
  } finally {
    button.disabled = Boolean(state.launchState.running);
  }
}

async function submitIntervention(event) {
  event.preventDefault();
  const input = document.getElementById("interventionInput");
  const button = document.getElementById("interventionButton");
  const status = document.getElementById("interventionStatus");
  if (!input || !button || !status) return;

  const instruction = input.value.trim();
  if (!instruction) {
    status.textContent = "请输入要给 agent 的介入指令。";
    return;
  }
  if (!state.selectedRunId) {
    status.textContent = "当前没有 run，无法投递介入。";
    return;
  }

  const agent = selectedAgent();
  button.disabled = true;
  status.textContent = "正在投递介入指令...";
  try {
    const payload = await fetchJson("/api/interventions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        run_id: state.selectedRunId,
        scope_type: agent ? "agent" : "run",
        scope_id: agent ? agent.agent_id : state.selectedRunId,
        instruction,
      }),
    });
    input.value = "";
    status.textContent = `已接收介入：${payload.data.intervention_id}`;
    await refreshData();
  } catch (error) {
    status.textContent = `介入失败：${error}`;
  } finally {
    button.disabled = false;
  }
}

function parseCvssFromText(text) {
  const vectorMatch = text.match(/CVSS:3\.\d\/[A-Z]{1,2}:[A-Z]\/[A-Z]{1,2}:[A-Z]\/[A-Z]{1,2}:[A-Z]\/[A-Z]{1,2}:[A-Z]\/[A-Z]{1,2}:[A-Z]\/[A-Z]{1,2}:[A-Z]/i);
  const scoreMatch = text.match(/CVSS (?:Score|score)[:\s]*(\d+\.?\d*)/i) || text.match(/CVSS[:\s]+(\d+\.?\d*)/i) || text.match(/Score[:\s]*(\d+\.?\d*)/i);
  const severityMatch = text.match(/(?:Severity|severity)[:\s]*(CRITICAL|HIGH|MEDIUM|LOW|NONE)/i);
  return {
    vector: vectorMatch ? vectorMatch[0].replace(/^CVSS:?[\d.]*\s*/i, "").trim() : "",
    score: scoreMatch ? scoreMatch[1] : "",
    severity: severityMatch ? severityMatch[1].toUpperCase() : "",
  };
}

function parseCweFromText(text) {
  const match = text.match(/CWE-(\d+)(?:\s*[—–-]\s*([^\n,]+))?/i);
  if (!match) return "";
  const cweId = `CWE-${match[1]}`;
  const cweName = (match[2] || "").trim();
  return cweName ? `${cweId} — ${cweName}` : cweId;
}

function cvssSeverityLevel(score) {
  const numeric = parseFloat(score);
  if (Number.isNaN(numeric)) return "";
  if (numeric >= 9.0) return "critical";
  if (numeric >= 7.0) return "high";
  if (numeric >= 4.0) return "medium";
  if (numeric >= 0.1) return "low";
  return "";
}

function renderMarkdownCodeBlocks(text) {
  const escaped = text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

  return escaped.replace(
    /```(\w*)\n([\s\S]*?)```/g,
    (_full, lang, code) => {
      const langLabel = lang ? escapeHtml(lang) : "code";
      const lines = code.split("\n");
      const coloredLines = lines.map((line) => {
        if (/\/\*\s*BEFORE/i.test(line) || /\/\*\s*AFTER/i.test(line)) return `<span class="vuln-after"><strong>${line}</strong></span>`;
        if (/\/\/\s*←/.test(line) || /#\s*←/.test(line)) return `<span class="vuln-before">${line}</span>`;
        return line;
      }).join("\n");
      return `<div class="code-block"><div class="code-lang">${langLabel}</div><pre>${coloredLines}</pre></div>`;
    },
  );
}

function enrichFindingWithReport(findings, reportText) {
  if (!reportText || !findings.length) return findings;
  return findings.map((finding) => {
    const title = (finding.title || "").toLowerCase();
    const enriched = { ...finding };
    let bestSection = "";

    const sectionPattern = /## Confirmed Findings\n([\s\S]*?)(?=## \w|\n## |$)/i;
    const cfMatch = reportText.match(sectionPattern);
    if (cfMatch) bestSection = cfMatch[1];

    if (bestSection) {
      const keywords = title.split(/\s+/).filter((w) => w.length > 4);
      if (keywords.some((kw) => bestSection.toLowerCase().includes(kw))) {
        const cvss = parseCvssFromText(bestSection);
        const cwe = parseCweFromText(bestSection);
        if (cvss.vector && !enriched._cvss_vector) enriched._cvss_vector = cvss.vector;
        if (cvss.score && !enriched._cvss_score) enriched._cvss_score = cvss.score;
        if (cvss.severity && !enriched._cvss_severity) enriched._cvss_severity = cvss.severity;
        if (cwe && !enriched._cwe) enriched._cwe = cwe;
      }
    }

    const pocSection = (reportText.match(/## Proof of Concept\n([\s\S]*?)(?=## \w|\n## |$)/i) || [])[1] || "";
    if (pocSection) {
      const pocPathMatch = pocSection.match(/`([^`]+\.py)`/);
      if (pocPathMatch && !enriched._poc_path) enriched._poc_path = pocPathMatch[1];
      const pocUsageMatch = pocSection.match(/Usage:\s*`([^`]+)`/i);
      if (pocUsageMatch && !enriched._poc_usage) enriched._poc_usage = pocUsageMatch[1];
    }

    return enriched;
  });
}

function buildReportHtml(reportText) {
  if (!reportText) {
    return '<div class="no-report">??????<strong>??????</strong>????????????????????????????? CVSS ?????????????PoC ?????????????</div>';
  }

  let html = renderMarkdownCodeBlocks(reportText);

  html = html.split("\n").map((line) => {
    if (/^## (.+)/.test(line)) {
      return line.replace(/^## (.+)/, '<h2 id="$1">$1</h2>');
    }
    if (/^### (.+)/.test(line)) {
      return line.replace(/^### (.+)/, '<h3>$1</h3>');
    }
    if (line.startsWith("- ")) {
      return `<li>${line.slice(2)}</li>`;
    }
    const numberedMatch = line.match(/^(\d+)\.\s+(.+)/);
    if (numberedMatch) {
      return `<li value="${numberedMatch[1]}">${numberedMatch[2]}</li>`;
    }
    if (/^\*\*([^*]+)\*\*/.test(line)) {
      return `<p>${line.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>")}</p>`;
    }
    if (line.trim()) {
      return `<p>${line}</p>`;
    }
    return "";
  }).join("\n");

  html = html.replace(/<li>([\s\S]*?)<\/li>/g, (match) => `<ul style="list-style: disc; padding-left: 22px; margin: 4px 0;">${match}</ul>`);
  html = html.replace(/<li value="(\d+)">/g, '<ol style="list-style: decimal; padding-left: 22px; margin: 4px 0;"><li>');
  html = html.replace(/<li>/g, (offset, full) => {
    const before = full.slice(Math.max(0, offset - 200), offset);
    return before.includes("<ol ") ? "<li>" : "&bull; ";
  });

  html = html.replace(
    /(CVSS:3\.\d\/[A-Z]{1,2}:[A-Z]\/[A-Z]{1,2}:[A-Z]\/[A-Z]{1,2}:[A-Z]\/[A-Z]{1,2}:[A-Z]\/[A-Z]{1,2}:[A-Z]\/[A-Z]{1,2}:[A-Z]\s*\(?([\d.]+)\)?\s*\(?(CRITICAL|HIGH|MEDIUM|LOW|NONE)?\)?)/gi,
    (_full, vector, score, severity) => {
      const level = (severity || cvssSeverityLevel(score) || "medium").toLowerCase();
      const scoreText = score ? ` ${score}` : "";
      const sevText = severity ? ` ${severity}` : "";
      return `<span class="cvss-badge ${level}">CVSS ${vector.slice(0, 8)}${scoreText}${sevText}</span>`;
    },
  );

  html = html.replace(
    /(CWE-\d+(?:\s*[—–-]\s*[A-Za-z][^\n,<]{3,40})?)/gi,
    '<span class="cwe-tag">$1</span>',
  );

  const pocSectionMatch = reportText.match(/## Proof of Concept\n([\s\S]*?)(?=## \w|\n## |\Z)/i);
  if (pocSectionMatch) {
    const pocContent = renderMarkdownCodeBlocks(pocSectionMatch[1]);
    const wrappedPoc = `<div class="poc-block"><h4>?? PoC ??</h4>${pocContent}</div>`;
    html = html.replace(/<h2[^>]*>Proof of Concept<\/h2>[\s\S]*?(?=<h2[^>]*>|$)/i, (match) => {
      return match.replace(pocSectionMatch[1], wrappedPoc);
    });
  }

  const remSectionMatch = reportText.match(/## Remediation\n([\s\S]*?)(?=## \w|\n## |\Z)/i);
  if (remSectionMatch) {
    const remContent = renderMarkdownCodeBlocks(remSectionMatch[1]);
    const wrappedRem = `<div class="remediation-block"><h4>?? ????</h4>${remContent}</div>`;
    html = html.replace(/<h2[^>]*>Remediation<\/h2>[\s\S]*?(?=<h2[^>]*>|$)/i, (match) => {
      return match.replace(remSectionMatch[1], wrappedRem);
    });
  }

  return `<div class="report-body">${html}</div>`;
}

function renderReport() {
  const target = document.getElementById("reportContent");
  if (!target) return;

  const reportText = String(state.launchState.last_result?.report || "").trim();
  if (!reportText && !state.launchState.last_result) {
    target.innerHTML = '<div class="no-report">??????<strong>??????</strong>????????????????? CVSS ?????????????PoC ???????????</div>';
    return;
  }
  if (!reportText) {
    target.innerHTML = '<div class="no-report">?????????<strong>??????</strong>?????????? PoC ????????????????????</div>';
    return;
  }

  target.innerHTML = buildReportHtml(reportText);
}

function bindGlobalEvents() {
  document.querySelectorAll(".view-switch button").forEach((button) => {
    button.addEventListener("click", () => {
      state.currentView = button.dataset.view || "overview";
      syncViewButtons();
      toggleViews();
    });
  });

  document.getElementById("launchForm")?.addEventListener("submit", submitLaunch);
  document.getElementById("interventionForm")?.addEventListener("submit", submitIntervention);
}

function render() {
  syncViewButtons();
  toggleViews();
  updateSummary();
  renderLaunchState();
  renderAssetList();
  renderRunList();
  renderFindingLists();
  renderFindingDetail();
  renderOverview();
  renderAgentList();
  renderAgentDetail();
  renderInterventions();
  renderTimelinePanels();
  renderArtifactPanels();
  renderReport();
  bindSelectionButtons();
}

function startPolling() {
  if (state.pollHandle) {
    window.clearInterval(state.pollHandle);
  }
  state.pollHandle = window.setInterval(() => {
    refreshData().catch(() => {});
  }, POLL_INTERVAL_MS);
}

bindGlobalEvents();
updateInterventionHint();
startPolling();
refreshData().catch((error) => {
  renderError(error);
});
