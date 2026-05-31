/**
 * PhishGuard – Content Script
 * Injects a warning overlay on confirmed phishing pages.
 */

let overlayInjected = false;

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "PHISHGUARD_ALERT" && !overlayInjected) {
    injectOverlay(msg.result);
  }
});

function injectOverlay(result) {
  overlayInjected = true;
  const score = Math.round(result.threat.score * 100);

  const overlay = document.createElement("div");
  overlay.id = "__phishguard_overlay__";
  overlay.style.cssText = `
    position: fixed; inset: 0; z-index: 2147483647;
    background: rgba(0,0,0,0.92);
    display: flex; align-items: center; justify-content: center;
    font-family: 'Courier New', monospace;
  `;

  overlay.innerHTML = `
    <div style="
      max-width: 480px; width: 90%; padding: 32px;
      background: #0a0000; border: 2px solid #ef4444;
      border-radius: 12px; text-align: center; color: #e5e7eb;
    ">
      <div style="font-size: 48px; margin-bottom: 12px;">⚠</div>
      <h1 style="color: #ef4444; font-size: 18px; letter-spacing: 3px; margin-bottom: 8px; font-weight: bold;">
        PHISHING SITE DETECTED
      </h1>
      <p style="color: #9ca3af; font-size: 12px; margin-bottom: 16px;">
        PhishGuard has identified this URL as a high-risk phishing attempt.<br/>
        Threat score: <strong style="color:#ef4444">${score}%</strong>
      </p>

      <div style="background:#0f0000;border:1px solid #450a0a;border-radius:6px;padding:10px;margin-bottom:16px;text-align:left;">
        <p style="font-size:10px;color:#6b7280;margin-bottom:6px;text-transform:uppercase;letter-spacing:1px;">Risk Factors</p>
        ${(result.risk_factors || []).map(f =>
          `<p style="font-size:11px;color:#fca5a5;margin:3px 0;">• ${escHtml(f)}</p>`
        ).join("")}
      </div>

      <p style="font-size:10px;color:#6b7280;word-break:break-all;margin-bottom:20px;">
        ${escHtml(result.url.slice(0, 100))}${result.url.length > 100 ? "…" : ""}
      </p>

      <div style="display:flex;gap:10px;justify-content:center;">
        <button id="__pg_back__" style="
          padding: 10px 20px; border-radius: 6px; border: none; cursor: pointer;
          background: #ef4444; color: white; font-family: inherit;
          font-weight: bold; font-size: 12px; letter-spacing: 1px;
        ">← GO BACK (SAFE)</button>
        <button id="__pg_proceed__" style="
          padding: 10px 20px; border-radius: 6px; cursor: pointer;
          background: transparent; color: #6b7280;
          border: 1px solid #374151; font-family: inherit;
          font-size: 11px;
        ">Proceed anyway (unsafe)</button>
      </div>
    </div>
  `;

  document.documentElement.appendChild(overlay);

  document.getElementById("__pg_back__").addEventListener("click", () => {
    window.history.back();
    setTimeout(() => overlay.remove(), 300);
  });

  document.getElementById("__pg_proceed__").addEventListener("click", () => {
    overlay.remove();
    overlayInjected = false;
  });
}

function escHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
