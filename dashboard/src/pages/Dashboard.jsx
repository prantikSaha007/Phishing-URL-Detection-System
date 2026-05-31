import { useState, useEffect, useCallback } from "react";
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid,
  AreaChart, Area,
} from "recharts";
import { Search, AlertTriangle, CheckCircle, Clock, Zap, Globe, Shield } from "lucide-react";
import { scanUrl, getScans, getStats, verdictBg, verdictColor } from "../utils/api";

const COLORS = { phishing: "#ef4444", suspicious: "#f59e0b", benign: "#22c55e" };

export default function Dashboard({ navigate }) {
  const [url, setUrl]         = useState("");
  const [scanning, setScanning] = useState(false);
  const [result, setResult]   = useState(null);
  const [error, setError]     = useState("");
  const [scans, setScans]     = useState([]);
  const [stats, setStats]     = useState(null);

  const refresh = useCallback(async () => {
    const [s, sc] = await Promise.all([getStats(), getScans(null, 10)]);
    setStats(s);
    setScans(sc);
  }, []);

  useEffect(() => { refresh(); }, []);

  const handleScan = async () => {
    if (!url.trim()) return;
    setScanning(true);
    setError("");
    setResult(null);
    try {
      const r = await scanUrl(url.trim());
      setResult(r);
      refresh();
    } catch (e) {
      setError(e.message);
    } finally {
      setScanning(false);
    }
  };

  const pieData = stats ? [
    { name: "Phishing",   value: stats.phishing   || 0 },
    { name: "Suspicious", value: stats.suspicious  || 0 },
    { name: "Benign",     value: stats.benign      || 0 },
  ] : [];

  // Build simple timeline from last 10 scans reversed
  const timelineData = [...scans].reverse().map((s, i) => ({
    i: i + 1,
    score: Math.round(s.threat.score * 100),
    label: s.threat.label,
  }));

  return (
    <div className="space-y-6">
      {/* ── Scan input ─────────────────────────────────────────────── */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg p-6">
        <h2 className="text-sm text-gray-400 uppercase tracking-widest mb-4 flex items-center gap-2">
          <Search size={14} /> URL Scanner
        </h2>
        <div className="flex gap-2">
          <input
            value={url}
            onChange={e => setUrl(e.target.value)}
            onKeyDown={e => e.key === "Enter" && handleScan()}
            placeholder="https://suspicious-domain.example/login?redirect=..."
            className="flex-1 bg-gray-950 border border-gray-700 rounded px-4 py-2.5 text-sm
                       text-gray-200 placeholder-gray-600 focus:outline-none focus:border-cyan-600
                       font-mono"
          />
          <button onClick={handleScan} disabled={scanning}
            className="bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed
                       text-white text-sm px-5 py-2.5 rounded font-bold tracking-wider transition
                       flex items-center gap-2">
            {scanning ? (
              <><span className="animate-spin inline-block">⊛</span> Scanning…</>
            ) : (
              <><Zap size={14} /> SCAN</>
            )}
          </button>
        </div>
        {error && (
          <p className="mt-2 text-xs text-red-400">{error}</p>
        )}

        {/* ── Scan result ─────────────────────────────────────────── */}
        {result && (
          <div className={`mt-4 border rounded-lg p-4 ${verdictBg(result.threat.label)}`}>
            <div className="flex items-start justify-between gap-4">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  {result.threat.label === "phishing" ? (
                    <AlertTriangle size={16} className="text-red-400 shrink-0" />
                  ) : result.threat.label === "suspicious" ? (
                    <AlertTriangle size={16} className="text-yellow-400 shrink-0" />
                  ) : (
                    <CheckCircle size={16} className="text-green-400 shrink-0" />
                  )}
                  <span className="font-bold uppercase tracking-widest text-sm">
                    {result.threat.label}
                  </span>
                  <span className="text-xs opacity-70">
                    Score: {Math.round(result.threat.score * 100)}% | {result.duration_ms.toFixed(0)}ms
                  </span>
                </div>
                <p className="text-xs font-mono truncate opacity-60">{result.url}</p>
                {result.decoded_url !== result.url && (
                  <p className="text-xs font-mono truncate opacity-50 mt-0.5">
                    → Decoded: {result.decoded_url}
                  </p>
                )}
                {result.risk_factors.length > 0 && (
                  <ul className="mt-2 space-y-0.5">
                    {result.risk_factors.map((f, i) => (
                      <li key={i} className="text-xs opacity-80">• {f}</li>
                    ))}
                  </ul>
                )}
              </div>
              <button
                onClick={() => navigate("detail", result.scan_id)}
                className="shrink-0 text-xs border border-current/30 rounded px-3 py-1.5
                           hover:bg-white/5 transition">
                Full Report →
              </button>
            </div>
          </div>
        )}
      </div>

      {/* ── Stats cards ──────────────────────────────────────────────── */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {[
            { label: "Total Scans",  value: stats.total,      icon: Globe,         color: "text-cyan-400" },
            { label: "Phishing",     value: stats.phishing,   icon: AlertTriangle, color: "text-red-400" },
            { label: "Suspicious",   value: stats.suspicious, icon: Clock,         color: "text-yellow-400" },
            { label: "Benign",       value: stats.benign,     icon: CheckCircle,   color: "text-green-400" },
          ].map(({ label, value, icon: Icon, color }) => (
            <div key={label} className="bg-gray-900 border border-gray-800 rounded-lg p-4">
              <div className="flex items-center gap-2 mb-1">
                <Icon size={13} className={color} />
                <span className="text-xs text-gray-500 uppercase tracking-widest">{label}</span>
              </div>
              <p className={`text-2xl font-bold ${color}`}>{value ?? 0}</p>
            </div>
          ))}
        </div>
      )}

      {/* ── Charts ───────────────────────────────────────────────────── */}
      {stats && stats.total > 0 && (
        <div className="grid md:grid-cols-2 gap-4">
          {/* Pie */}
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
            <h3 className="text-xs text-gray-500 uppercase tracking-widest mb-4">Risk Distribution</h3>
            <ResponsiveContainer width="100%" height={200}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" innerRadius={55} outerRadius={80}
                     paddingAngle={3} dataKey="value" nameKey="name">
                  {pieData.map((entry) => (
                    <Cell key={entry.name} fill={COLORS[entry.name.toLowerCase()]} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{ background: "#111827", border: "1px solid #374151", borderRadius: 6 }}
                  labelStyle={{ color: "#9ca3af" }}
                  itemStyle={{ color: "#f3f4f6" }}
                />
              </PieChart>
            </ResponsiveContainer>
            <div className="flex justify-center gap-4 mt-2">
              {pieData.map(d => (
                <span key={d.name} className="flex items-center gap-1 text-xs text-gray-400">
                  <span className="w-2 h-2 rounded-full inline-block"
                        style={{ background: COLORS[d.name.toLowerCase()] }} />
                  {d.name} ({d.value})
                </span>
              ))}
            </div>
          </div>

          {/* Timeline */}
          <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
            <h3 className="text-xs text-gray-500 uppercase tracking-widest mb-4">Recent Threat Scores</h3>
            <ResponsiveContainer width="100%" height={200}>
              <AreaChart data={timelineData}>
                <defs>
                  <linearGradient id="scoreGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor="#06b6d4" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#06b6d4" stopOpacity={0}   />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                <XAxis dataKey="i" tick={{ fill: "#6b7280", fontSize: 10 }} />
                <YAxis domain={[0, 100]} tick={{ fill: "#6b7280", fontSize: 10 }} />
                <Tooltip
                  contentStyle={{ background: "#111827", border: "1px solid #374151", borderRadius: 6 }}
                  formatter={(v) => [`${v}%`, "Threat Score"]}
                />
                <Area type="monotone" dataKey="score" stroke="#06b6d4"
                      fill="url(#scoreGrad)" strokeWidth={2} dot={{ fill: "#06b6d4", r: 3 }} />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* ── Recent scans table ──────────────────────────────────────── */}
      {scans.length > 0 && (
        <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
          <div className="px-4 py-3 border-b border-gray-800 flex items-center justify-between">
            <h3 className="text-xs text-gray-500 uppercase tracking-widest">Recent Scans</h3>
            <button onClick={() => navigate("history")} className="text-xs text-cyan-500 hover:text-cyan-400">
              View all →
            </button>
          </div>
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-gray-800 text-gray-600">
                {["URL", "Verdict", "Score", "Time", ""].map(h => (
                  <th key={h} className="text-left px-4 py-2 font-normal uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {scans.map(s => (
                <tr key={s.scan_id} className="border-b border-gray-800/50 hover:bg-gray-800/30 transition">
                  <td className="px-4 py-2.5 font-mono text-gray-300 max-w-xs truncate">
                    {s.url}
                  </td>
                  <td className="px-4 py-2.5">
                    <span className={`px-2 py-0.5 rounded border text-xs font-bold uppercase ${verdictBg(s.threat.label)}`}>
                      {s.threat.label}
                    </span>
                  </td>
                  <td className="px-4 py-2.5"
                      style={{ color: verdictColor(s.threat.label) }}>
                    {Math.round(s.threat.score * 100)}%
                  </td>
                  <td className="px-4 py-2.5 text-gray-600">
                    {new Date(s.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="px-4 py-2.5">
                    <button onClick={() => navigate("detail", s.scan_id)}
                      className="text-cyan-600 hover:text-cyan-400 transition">→</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {scans.length === 0 && !scanning && (
        <div className="text-center py-20 text-gray-700">
          <Shield size={40} className="mx-auto mb-3 opacity-30" />
          <p className="text-sm">No scans yet. Enter a URL above to begin.</p>
        </div>
      )}
    </div>
  );
}
