/**
 * PhishGuard – Popup Script
 */

const DASHBOARD_URL = "http://localhost:5173";

// ── State ──────────────────────────────────────────────────────────────────────
let lastResult = null;
let stats = { total: 0, phishing: 0, suspicious: 0, benign: 0 };
let history = [];

// ── Init ───────────────────────────────────────────────────────────────────────
document.addEventListener("DOMContentLoaded", async () => {
  const { enabled = true, history: h = [] } =
    await chrome.storage.local.get(["enabled", "history"]);
  history = h;

  // Build stats from history
  stats.total = history.length;
  stats.phishing   = history.filter(x => x.label === "phishing").length;
  stats.suspicious = history.filter(x => x.label === "suspicious").length;
  stats.benign     = history.filter(x => x.label === "benign").length;

  document.getElementById("enabledToggle").checked = enabled;
  document.getElementById("enabledLabel").textContent = enabled ? "ON" : "OFF";

  document.getElementById("enabledToggle").addEventListener("change", e => {
    const v = e.target.checked;
    document.getElementById("enabledLabel").textContent = v ? "ON" : "OFF";
    chrome.runtime.sendMessage({ type: "SET_SETTINGS", settings: { enabled: v } });
  });

  if (!enabled) {
    renderDisabled();
  } else {
    await loadCurrentTab();
  }
});

// ── Load current tab ───────────────────────────────────────────────────────────
async function loadCurrentTab() {
  renderScanning();

  chrome.runtime.sendMessage({ type: "SCAN_CURRENT_TAB" }, result => {
    lastResult = result;
    render(result);
  });
}

// ── Render ─────────────────────────────────────────────────────────────────────
function render(result) {
  const content = document.getElementById("content");
  if (!result) {
    renderError();
    return;
  }

  const label = result.threat.label;
  const score = Math.round(result.threat.score * 100);
  const barColor = label === "phishing" ? "#ef4444" : label === "suspicious" ? "#f59e0b" : "#22c55e";

  const risksHTML = result.risk_factors.slice(0, 3).map(r =>
    `<div class="risk-item">• ${escHtml(r)}</div>`).join("");

  const historyHTML = history.slice(0, 5).map(h => `
    <div class="history-item">
      <span class="history-url" title="${escHtml(h.url)}">${escHtml(trimUrl(h.url))}</span>
      <span class="history-badge badge-${h.label}">${h.label}</span>
    </div>
  `).join("");

  content.innerHTML = `
    <div class="verdict-card ${label}">
      <div class="verdict-header">
        <span class="verdict-label">${labelIcon(label)} ${label}</span>
        <span class="verdict-score">${score}%</span>
      </div>
      <div class="verdict-url">${escHtml(result.url)}</div>
      ${result.decoded_url !== result.url
        ? `<div class="verdict-url" style="color:#4b5563;margin-top:3px">→ ${escHtml(result.decoded_url)}</div>`
        : ""}
      ${risksHTML ? `<div class="risk-list">${risksHTML}</div>` : ""}
    </div>

    <div class="score-bar-wrap">
      <div class="score-bar-bg">
        <div class="score-bar-fill" style="width:${score}%;background:${barColor}"></div>
      </div>
    </div>

    <div class="stats-row">
      <div class="stat-pill">
        <div class="stat-num cyan">${stats.total}</div>
        <div class="stat-lbl">Total</div>
      </div>
      <div class="stat-pill">
        <div class="stat-num red">${stats.phishing}</div>
        <div class="stat-lbl">Phishing</div>
      </div>
      <div class="stat-pill">
        <div class="stat-num yellow">${stats.suspicious}</div>
        <div class="stat-lbl">Suspicious</div>
      </div>
      <div class="stat-pill">
        <div class="stat-num green">${stats.benign}</div>
        <div class="stat-lbl">Benign</div>
      </div>
    </div>

    <div class="actions">
      <button class="btn btn-scan" id="btnRescan">↺ Rescan</button>
      <button class="btn btn-dash" id="btnDash">Dashboard ↗</button>
    </div>

    ${history.length > 0 ? `
      <div class="section-title">Recent Scans</div>
      <div class="history-list">${historyHTML}</div>
    ` : ""}
  `;

  document.getElementById("btnRescan").addEventListener("click", loadCurrentTab);
  document.getElementById("btnDash").addEventListener("click", () => {
    chrome.tabs.create({ url: DASHBOARD_URL });
  });
}

function renderScanning() {
  document.getElementById("content").innerHTML = `
    <div class="scanning-spinner"><span class="spin">⊛</span><br/><br/>Scanning URL…</div>`;
}

function renderError() {
  document.getElementById("content").innerHTML = `
    <div class="disabled-msg">
      ⚠ Could not reach PhishGuard API.<br/><br/>
      Make sure the backend is running on<br/>
      <span style="color:#06b6d4">localhost:8000</span>
      <br/><br/>
      <button class="btn btn-scan" style="width:120px;margin:0 auto;display:block"
        id="btnRetry">Retry</button>
    </div>`;
  document.getElementById("btnRetry").addEventListener("click", loadCurrentTab);
}

function renderDisabled() {
  document.getElementById("content").innerHTML = `
    <div class="disabled-msg">
      PhishGuard is disabled.<br/><br/>
      Toggle the switch above to enable<br/>real-time protection.
    </div>`;
}

// ── Utils ──────────────────────────────────────────────────────────────────────
function escHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

function trimUrl(url) {
  try {
    const u = new URL(url);
    return u.hostname + (u.pathname.length > 1 ? u.pathname.slice(0, 20) + "…" : "");
  } catch { return url.slice(0, 35) + "…"; }
}

function labelIcon(label) {
  return label === "phishing" ? "⚠" : label === "suspicious" ? "?" : "✓";
}
