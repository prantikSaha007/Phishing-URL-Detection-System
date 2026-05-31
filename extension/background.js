/**
 * PhishGuard – Background Service Worker
 * Intercepts navigation events and triggers URL scans.
 */

const API_BASE = "http://localhost:8000";
const CACHE_TTL_MS = 10 * 60 * 1000; // 10 minutes
const scanCache = new Map(); // url → { result, ts }

// ── Badge helpers ─────────────────────────────────────────────────────────────
function setBadge(tabId, label) {
  const cfg = {
    phishing:   { text: "⚠",  color: "#ef4444" },
    suspicious: { text: "?",  color: "#f59e0b" },
    benign:     { text: "✓",  color: "#22c55e" },
    scanning:   { text: "…",  color: "#06b6d4" },
    error:      { text: "!",  color: "#6b7280" },
  };
  const c = cfg[label] || cfg.error;
  chrome.action.setBadgeText({ tabId, text: c.text });
  chrome.action.setBadgeBackgroundColor({ tabId, color: c.color });
}

// ── Scan a URL ────────────────────────────────────────────────────────────────
async function scanURL(url, tabId) {
  // Cache hit
  const cached = scanCache.get(url);
  if (cached && Date.now() - cached.ts < CACHE_TTL_MS) {
    updateTab(tabId, cached.result);
    return cached.result;
  }

  setBadge(tabId, "scanning");

  try {
    const res = await fetch(`${API_BASE}/scan`, {
      method:  "POST",
      headers: { "Content-Type": "application/json" },
      body:    JSON.stringify({ url, source: "extension" }),
      signal:  AbortSignal.timeout(8000),
    });

    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const result = await res.json();

    scanCache.set(url, { result, ts: Date.now() });
    updateTab(tabId, result);

    // Persist to extension storage (last 200 scans)
    const { history = [] } = await chrome.storage.local.get("history");
    history.unshift({
      scan_id:   result.scan_id,
      url:       result.url,
      label:     result.threat.label,
      score:     result.threat.score,
      timestamp: result.timestamp,
    });
    await chrome.storage.local.set({ history: history.slice(0, 200) });

    return result;
  } catch (err) {
    setBadge(tabId, "error");
    console.warn("[PhishGuard] Scan failed:", err.message);
    return null;
  }
}

function updateTab(tabId, result) {
  setBadge(tabId, result.threat.label);

  // Alert on high-confidence phishing
  if (result.threat.label === "phishing" && result.threat.score >= 0.8) {
    chrome.notifications.create(`phish-${result.scan_id}`, {
      type:    "basic",
      iconUrl: "icons/icon48.png",
      title:   "⚠ Phishing Site Detected",
      message: `PhishGuard blocked a high-risk URL (${Math.round(result.threat.score * 100)}%):\n${result.url.slice(0, 80)}`,
      priority: 2,
    });

    // Send to content script to show overlay
    chrome.tabs.sendMessage(tabId, {
      type:  "PHISHGUARD_ALERT",
      result,
    }).catch(() => {}); // Tab may not have content script injected yet
  }
}

// ── Navigation listener ───────────────────────────────────────────────────────
chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return; // main frame only
  const url = details.url;
  if (!url.startsWith("http")) return; // skip chrome:// etc.
  await scanURL(url, details.tabId);
});

// ── Message handler (from popup) ──────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "SCAN_CURRENT_TAB") {
    (async () => {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab?.url) return sendResponse(null);
      const result = await scanURL(tab.url, tab.id);
      sendResponse(result);
    })();
    return true; // keep channel open for async
  }

  if (msg.type === "GET_SETTINGS") {
    chrome.storage.local.get(["enabled", "history"], sendResponse);
    return true;
  }

  if (msg.type === "SET_SETTINGS") {
    chrome.storage.local.set(msg.settings, () => sendResponse({ ok: true }));
    return true;
  }

  if (msg.type === "CLEAR_HISTORY") {
    chrome.storage.local.set({ history: [] }, () => sendResponse({ ok: true }));
    return true;
  }
});
