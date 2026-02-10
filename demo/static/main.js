/* ============================================================
   AEGIS-Claw v0.2 Security Demo — Main Script
   ============================================================ */

const API = "";
let currentMode = "input";
let testCount = 0,
  blockedCount = 0,
  escalatedCount = 0,
  modifiedCount = 0,
  approvedCount = 0;
let presets = [];
let activeFilter = "all";
let currentLang = localStorage.getItem("aegis-lang") || "en";

// ---------------------------------------------------------------
// i18n Translations
// ---------------------------------------------------------------

const i18n = {
  en: {
    subtitle: "Security Guard Demo — Before vs After",
    tests: "tests",
    blocked: "blocked",
    escalated: "escalated",
    modified: "modified",
    approved: "approved",
    mode_input: "User Input",
    mode_command: "Shell Command",
    mode_external: "External Content",
    mode_output: "AI Response",
    input_placeholder:
      "Enter text to test or click a preset below...",
    analyze: "Analyze",
    preset_title: "Preset Attack Scenarios",
    run_all: "Run All",
    analysis_result: "Analysis Result",
    no_protection: "No Protection",
    current_state: "Current default state",
    protected: "Protected",
    after_aegis: "After AEGIS-Claw v0.2",
    sanitized_preview: "Security Wrapping Preview",
    batch_results: "Batch Results",
    test_history: "Test History",
    th_input: "Input",
    th_mode: "Mode",
    th_no_protection: "No Protection",
    th_aegis_decision: "AEGIS Decision",
    th_risk: "Risk",
    th_latency: "Latency",
    filter_all: "All",
    running: "Running...",
    run_all_btn: "▶ Run All",
    protection_confidence: "Protection confidence",
    confidence: "Confidence",
    risk_label: "Risk",
    known_vulns: "Known Vulnerabilities",
    defense_attempts: "Defense Attempts",
    detection_evidence: "Detection Evidence",
    sanitizer_patterns: "Content Sanitizer Patterns",
    pipeline_stages: "Pipeline Stages",
    modified_output: "Modified Output",
    batch_total: "Total",
    batch_total_ms: "Total",
  },
  ko: {
    subtitle: "보안 가드 데모 — Before vs After",
    tests: "테스트",
    blocked: "차단",
    escalated: "경고",
    modified: "수정",
    approved: "승인",
    mode_input: "사용자 입력",
    mode_command: "셸 명령",
    mode_external: "외부 콘텐츠",
    mode_output: "AI 응답",
    input_placeholder:
      "테스트할 텍스트를 입력하거나 아래 프리셋을 클릭하세요...",
    analyze: "분석",
    preset_title: "프리셋 공격 시나리오",
    run_all: "전체 실행",
    analysis_result: "분석 결과",
    no_protection: "보호 없음",
    current_state: "현재 기본 상태",
    protected: "보호 적용",
    after_aegis: "AEGIS-Claw v0.2 적용 후",
    sanitized_preview: "보안 래핑 미리보기",
    batch_results: "전체 실행 결과",
    test_history: "테스트 기록",
    th_input: "입력",
    th_mode: "모드",
    th_no_protection: "보호 없음",
    th_aegis_decision: "AEGIS 결정",
    th_risk: "위험도",
    th_latency: "지연시간",
    filter_all: "전체",
    running: "실행 중...",
    run_all_btn: "▶ 전체 실행",
    protection_confidence: "보호 신뢰도",
    confidence: "신뢰도",
    risk_label: "위험",
    known_vulns: "알려진 취약점",
    defense_attempts: "방어 시도",
    detection_evidence: "탐지 증거",
    sanitizer_patterns: "Content Sanitizer 패턴",
    pipeline_stages: "파이프라인 단계",
    modified_output: "수정된 출력",
    batch_total: "총",
    batch_total_ms: "총",
  },
};

function t(key) {
  return (i18n[currentLang] && i18n[currentLang][key]) || i18n.en[key] || key;
}

function applyI18n() {
  // Text content
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const key = el.getAttribute("data-i18n");
    el.textContent = t(key);
  });
  // Placeholders
  document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
    const key = el.getAttribute("data-i18n-placeholder");
    el.placeholder = t(key);
  });
  // Language toggle label
  document.getElementById("langLabel").textContent =
    currentLang === "en" ? "KR" : "EN";
  // HTML lang attribute
  document.documentElement.lang = currentLang === "ko" ? "ko" : "en";
}

function toggleLang() {
  currentLang = currentLang === "en" ? "ko" : "en";
  localStorage.setItem("aegis-lang", currentLang);
  applyI18n();
  // Re-render filters with new language
  renderFilters(presets);
}

// ---------------------------------------------------------------
// Init
// ---------------------------------------------------------------

document.addEventListener("DOMContentLoaded", async () => {
  applyI18n();
  await loadPresets();
  bindEvents();
});

async function loadPresets() {
  const res = await fetch(`${API}/api/presets`);
  presets = await res.json();
  renderPresets(presets);
  renderFilters(presets);
}

// ---------------------------------------------------------------
// Events
// ---------------------------------------------------------------

function bindEvents() {
  document.querySelectorAll(".mode-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document
        .querySelectorAll(".mode-btn")
        .forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      currentMode = btn.dataset.mode;
    });
  });

  document.getElementById("analyzeBtn").addEventListener("click", analyze);
  document.getElementById("runAllBtn").addEventListener("click", runAll);
  document.getElementById("langToggle").addEventListener("click", toggleLang);

  document.getElementById("inputText").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      analyze();
    }
  });
}

// ---------------------------------------------------------------
// Presets
// ---------------------------------------------------------------

function renderPresets(items) {
  const grid = document.getElementById("presetsGrid");
  grid.innerHTML = "";
  const filtered =
    activeFilter === "all"
      ? items
      : items.filter((p) => p.category === activeFilter);
  filtered.forEach((p) => {
    const card = document.createElement("div");
    card.className = "preset-card";
    card.innerHTML = `
      <div class="label">${escapeHtml(p.label)}</div>
      <div class="preview">${escapeHtml(p.text)}</div>
      <span class="cat-badge">${escapeHtml(p.category)}</span>
    `;
    card.addEventListener("click", () => {
      document.getElementById("inputText").value = p.text;
      setMode(p.mode || "input");
      analyze();
    });
    grid.appendChild(card);
  });
}

function renderFilters(items) {
  const container = document.getElementById("presetFilters");
  const categories = ["all", ...new Set(items.map((p) => p.category))];
  container.innerHTML = "";
  categories.forEach((cat) => {
    const btn = document.createElement("button");
    btn.className = `filter-btn${cat === "all" ? " active" : ""}`;
    btn.textContent = cat === "all" ? t("filter_all") : cat;
    btn.addEventListener("click", () => {
      activeFilter = cat;
      container
        .querySelectorAll(".filter-btn")
        .forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      renderPresets(presets);
    });
    container.appendChild(btn);
  });
}

function setMode(mode) {
  currentMode = mode;
  document.querySelectorAll(".mode-btn").forEach((b) => {
    b.classList.toggle("active", b.dataset.mode === mode);
  });
}

// ---------------------------------------------------------------
// Decision helpers
// ---------------------------------------------------------------

function decisionInfo(decision) {
  const map = {
    BLOCK: { icon: "🛡️", label: "BLOCK", cls: "block", color: "#ef4444" },
    APPROVE: {
      icon: "✅",
      label: "APPROVE",
      cls: "approve",
      color: "#10b981",
    },
    ESCALATE: {
      icon: "⚠️",
      label: "ESCALATE",
      cls: "escalate",
      color: "#f59e0b",
    },
    MODIFY: {
      icon: "✏️",
      label: "MODIFY",
      cls: "modify",
      color: "#8b5cf6",
    },
    REASK: { icon: "❓", label: "REASK", cls: "reask", color: "#6366f1" },
  };
  return map[decision] || map["BLOCK"];
}

// ---------------------------------------------------------------
// Single Analysis
// ---------------------------------------------------------------

async function analyze() {
  const text = document.getElementById("inputText").value.trim();
  if (!text) return;

  const btn = document.getElementById("analyzeBtn");
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>';

  try {
    const res = await fetch(`${API}/api/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text, mode: currentMode }),
    });
    const data = await res.json();
    renderResults(data);
    addHistory(data);
    updateStats(data);
  } catch (err) {
    console.error(err);
  } finally {
    btn.disabled = false;
    btn.innerHTML = `<span class="btn-text">${t("analyze")}</span><span class="btn-icon">→</span>`;
  }
}

// ---------------------------------------------------------------
// Run All Presets
// ---------------------------------------------------------------

async function runAll() {
  const btn = document.getElementById("runAllBtn");
  btn.disabled = true;
  btn.textContent = t("running");

  try {
    const res = await fetch(`${API}/api/run-all`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });
    const data = await res.json();
    renderBatchResults(data);

    // Add each result to history & stats
    data.results.forEach((r) => {
      addHistory(r);
      updateStats(r);
    });
  } catch (err) {
    console.error(err);
  } finally {
    btn.disabled = false;
    btn.innerHTML = `▶ <span data-i18n="run_all">${t("run_all")}</span>`;
  }
}

function renderBatchResults(data) {
  const section = document.getElementById("batchSection");
  section.style.display = "block";

  // Summary counts
  const counts = { BLOCK: 0, APPROVE: 0, ESCALATE: 0, MODIFY: 0, REASK: 0 };
  let totalMs = 0;
  data.results.forEach((r) => {
    const d = r.protected.decision;
    counts[d] = (counts[d] || 0) + 1;
    totalMs += r.protected.total_latency_ms;
  });

  document.getElementById("batchSummary").innerHTML = `
    <span class="batch-stat">${t("batch_total")} ${data.total}</span>
    <span class="batch-stat block-stat">BLOCK ${counts.BLOCK}</span>
    <span class="batch-stat escalate-stat">ESCALATE ${counts.ESCALATE}</span>
    <span class="batch-stat modify-stat">MODIFY ${counts.MODIFY}</span>
    <span class="batch-stat approve-stat">APPROVE ${counts.APPROVE}</span>
    <span class="batch-stat">${t("batch_total_ms")} ${totalMs.toFixed(1)}ms</span>
  `;

  // Grid cards
  const grid = document.getElementById("batchGrid");
  grid.innerHTML = "";
  data.results.forEach((r) => {
    const info = decisionInfo(r.protected.decision);
    const card = document.createElement("div");
    card.className = `batch-card ${info.cls}`;
    card.innerHTML = `
      <div class="batch-card-header">
        <span class="batch-decision ${info.cls}">${info.icon} ${info.label}</span>
        <span class="batch-latency">${r.protected.total_latency_ms}ms</span>
      </div>
      <div class="batch-label">${escapeHtml(r.preset.label)}</div>
      <div class="batch-text">${escapeHtml(r.input)}</div>
      <div class="batch-meta">
        <span class="tag">${r.mode}</span>
        ${r.protected.risk ? `<span class="tag ${info.cls}">${r.protected.risk.severity}</span>` : ""}
        <span class="batch-confidence">${Math.round(r.protected.confidence * 100)}%</span>
      </div>
    `;
    card.addEventListener("click", () => {
      document.getElementById("inputText").value = r.input;
      setMode(r.mode);
      analyze();
      section.scrollIntoView({ behavior: "smooth" });
    });
    grid.appendChild(card);
  });

  section.scrollIntoView({ behavior: "smooth", block: "start" });
}

// ---------------------------------------------------------------
// Render Single Results
// ---------------------------------------------------------------

function renderResults(data) {
  const section = document.getElementById("resultsSection");
  section.style.display = "block";
  section.scrollIntoView({ behavior: "smooth", block: "start" });

  document.getElementById("inputEcho").textContent = `[${data.mode.toUpperCase()}] ${data.input}`;
  renderUnprotected(data.unprotected);
  renderProtected(data.protected);

  // Sanitized preview for external mode
  const sanitizedSection = document.getElementById("sanitizedSection");
  if (data.sanitized_preview) {
    sanitizedSection.style.display = "block";
    document.getElementById("sanitizedPreview").textContent =
      data.sanitized_preview;
  } else {
    sanitizedSection.style.display = "none";
  }
}

function renderUnprotected(u) {
  const body = document.getElementById("unprotectedBody");
  body.innerHTML = `
    <div class="decision-row">
      <div class="decision-badge pass">⚠️ ${u.decision}</div>
    </div>
    <div class="confidence-bar">
      <div class="confidence-fill danger" style="width: ${(1 - u.confidence) * 100}%"></div>
    </div>
    <div class="conf-label">${t("protection_confidence")}: ${Math.round(u.confidence * 100)}%</div>
    <div class="message-box">${escapeHtml(u.message)}</div>
    ${
      u.vulnerabilities.length > 0
        ? `<div class="section-label">${t("known_vulns")}</div>
           <ul class="vuln-list">
             ${u.vulnerabilities.map((v) => `<li>${escapeHtml(v)}</li>`).join("")}
           </ul>`
        : ""
    }
    ${
      u.defenses.length > 0
        ? `<div class="section-label">${t("defense_attempts")}</div>
           <ul class="evidence-list dim">
             ${u.defenses.map((d) => `<li>${escapeHtml(d)}</li>`).join("")}
           </ul>`
        : ""
    }
  `;
}

function renderProtected(p) {
  const body = document.getElementById("protectedBody");
  const info = decisionInfo(p.decision);

  body.innerHTML = `
    <div class="decision-row">
      <div class="decision-badge ${info.cls}">${info.icon} ${p.decision}</div>
    </div>
    <div class="confidence-bar">
      <div class="confidence-fill ${info.cls}" style="width: ${p.confidence * 100}%"></div>
    </div>
    <div class="conf-label">
      ${t("confidence")}: ${Math.round(p.confidence * 100)}%
      ${p.risk ? ` · ${t("risk_label")}: ${p.risk.label} (${p.risk.severity})` : ""}
    </div>
    <div class="message-box">${escapeHtml(p.message)}</div>
    ${
      p.evidence.length > 0
        ? `<div class="section-label">${t("detection_evidence")}</div>
           <ul class="evidence-list">
             ${p.evidence
               .map(
                 (e) =>
                   `<li><strong>${escapeHtml(e.rule_id)}</strong>: ${escapeHtml(e.reason || "")}${e.matched_text ? ` <code>${escapeHtml(e.matched_text)}</code>` : ""}</li>`,
               )
               .join("")}
           </ul>`
        : ""
    }
    ${
      p.injection_patterns && p.injection_patterns.length > 0
        ? `<div class="section-label">${t("sanitizer_patterns")}</div>
           <div class="injection-patterns">
             ${p.injection_patterns.map((pat) => `<span class="injection-tag">${escapeHtml(pat)}</span>`).join("")}
           </div>`
        : ""
    }
    ${
      p.pipeline_stages.length > 0
        ? `<div class="section-label pipeline-stages">${t("pipeline_stages")}</div>
           ${p.pipeline_stages
             .map(
               (s, i) => `
             <div class="stage-row" style="animation-delay: ${i * 0.1}s">
               <div class="stage-icon ${s.passed ? "pass" : "fail"}">${s.passed ? "✓" : "✗"}</div>
               <span class="stage-name">${escapeHtml(s.name)}</span>
               <span class="stage-detail" title="${escapeHtml(s.detail || "")}">${escapeHtml(s.detail || "--")}</span>
               <span class="stage-latency">${s.latency_ms}ms</span>
             </div>`,
             )
             .join("")}
           <div class="total-latency">Total: ${p.total_latency_ms}ms</div>`
        : ""
    }
    ${
      p.rewrite
        ? `<div class="section-label">${t("modified_output")}</div>
           <div class="message-box rewrite">${escapeHtml(p.rewrite)}</div>`
        : ""
    }
  `;
}

// ---------------------------------------------------------------
// History
// ---------------------------------------------------------------

function addHistory(data) {
  const section = document.getElementById("historySection");
  section.style.display = "block";
  const tbody = document.getElementById("historyBody");

  testCount++;
  const info = decisionInfo(data.protected.decision);
  const severity = data.protected.risk
    ? data.protected.risk.severity
    : "-";

  const row = document.createElement("tr");
  row.innerHTML = `
    <td class="mono">${testCount}</td>
    <td class="text-cell" title="${escapeHtml(data.input)}">${escapeHtml(data.input)}</td>
    <td><span class="tag">${data.mode}</span></td>
    <td><span class="tag danger">PASSED</span></td>
    <td><span class="tag ${info.cls}">${data.protected.decision}</span></td>
    <td><span class="tag ${severity === "critical" ? "danger" : severity === "high" ? "warning" : ""}">${severity}</span></td>
    <td class="mono">${data.protected.total_latency_ms}ms</td>
  `;
  tbody.prepend(row);
}

// ---------------------------------------------------------------
// Stats
// ---------------------------------------------------------------

function updateStats(data) {
  const d = data.protected.decision;
  if (d === "BLOCK") blockedCount++;
  else if (d === "ESCALATE") escalatedCount++;
  else if (d === "MODIFY") modifiedCount++;
  else if (d === "APPROVE") approvedCount++;

  document.querySelector("#totalTests .stat-num").textContent = testCount;
  document.querySelector("#totalBlocked .stat-num").textContent = blockedCount;
  document.querySelector("#totalEscalated .stat-num").textContent =
    escalatedCount;
  document.querySelector("#totalModified .stat-num").textContent =
    modifiedCount;
  document.querySelector("#totalApproved .stat-num").textContent =
    approvedCount;
}

// ---------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------

function escapeHtml(str) {
  if (!str) return "";
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
