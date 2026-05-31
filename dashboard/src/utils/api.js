export const API_BASE = import.meta.env.VITE_API_BASE || "http://localhost:8000";

export async function scanUrl(url) {
  const res = await fetch(`${API_BASE}/scan`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, source: "dashboard" }),
  });
  if (!res.ok) throw new Error(`Scan failed: ${res.status}`);
  return res.json();
}

export async function getScans(verdict = null, limit = 100) {
  const params = new URLSearchParams({ limit });
  if (verdict) params.set("verdict", verdict);
  const res = await fetch(`${API_BASE}/scans?${params}`);
  return res.json();
}

export async function getScan(id) {
  const res = await fetch(`${API_BASE}/scans/${id}`);
  return res.json();
}

export async function getStats() {
  const res = await fetch(`${API_BASE}/stats`);
  return res.json();
}

export function verdictColor(label) {
  return label === "phishing"   ? "#ef4444"
       : label === "suspicious" ? "#f59e0b"
       : "#22c55e";
}

export function verdictBg(label) {
  return label === "phishing"   ? "bg-red-900/30 border-red-700 text-red-400"
       : label === "suspicious" ? "bg-yellow-900/30 border-yellow-700 text-yellow-400"
       : "bg-green-900/30 border-green-700 text-green-400";
}
