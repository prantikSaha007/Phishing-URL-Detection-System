import { useState, useEffect } from "react";
import { Download, Filter, RefreshCw } from "lucide-react";
import { getScans, verdictBg, verdictColor } from "../utils/api";

export default function ScanHistory({ navigate }) {
  const [scans, setScans]       = useState([]);
  const [filter, setFilter]     = useState("all");
  const [loading, setLoading]   = useState(true);
  const [search, setSearch]     = useState("");

  const load = async () => {
    setLoading(true);
    const data = await getScans(filter === "all" ? null : filter, 500);
    setScans(data);
    setLoading(false);
  };

  useEffect(() => { load(); }, [filter]);

  const filtered = scans.filter(s =>
    s.url.toLowerCase().includes(search.toLowerCase())
  );

  const exportCSV = () => {
    const rows = [
      ["scan_id","url","verdict","score","timestamp","duration_ms"].join(","),
      ...filtered.map(s => [
        s.scan_id, `"${s.url}"`, s.threat.label,
        s.threat.score, s.timestamp, s.duration_ms,
      ].join(",")),
    ];
    const blob = new Blob([rows.join("\n")], { type: "text/csv" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `phishguard_scans_${Date.now()}.csv`;
    a.click();
  };

  const exportIOC = () => {
    const iocs = filtered
      .filter(s => s.threat.label !== "benign")
      .map(s => ({
        url:     s.url,
        verdict: s.threat.label,
        score:   s.threat.score,
        risks:   s.risk_factors,
        ts:      s.timestamp,
        ioc:     s.ioc_report?.ioc,
      }));
    const blob = new Blob([JSON.stringify(iocs, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `phishguard_ioc_${Date.now()}.json`;
    a.click();
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-sm font-bold text-gray-300 uppercase tracking-widest">
          Scan History ({filtered.length})
        </h1>
        <div className="flex items-center gap-2">
          <button onClick={load} className="flex items-center gap-1.5 text-xs text-gray-400
            hover:text-gray-200 border border-gray-700 rounded px-3 py-1.5 hover:bg-gray-800 transition">
            <RefreshCw size={11} /> Refresh
          </button>
          <button onClick={exportCSV} className="flex items-center gap-1.5 text-xs text-cyan-500
            hover:text-cyan-400 border border-cyan-900 rounded px-3 py-1.5 hover:bg-cyan-900/20 transition">
            <Download size={11} /> Export CSV
          </button>
          <button onClick={exportIOC} className="flex items-center gap-1.5 text-xs text-orange-500
            hover:text-orange-400 border border-orange-900 rounded px-3 py-1.5 hover:bg-orange-900/20 transition">
            <Download size={11} /> Export IoC JSON
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-2 items-center">
        <div className="flex items-center gap-1 text-xs text-gray-500">
          <Filter size={11} /> Filter:
        </div>
        {["all","phishing","suspicious","benign"].map(v => (
          <button key={v} onClick={() => setFilter(v)}
            className={`text-xs px-3 py-1 rounded border transition uppercase tracking-wider
              ${filter === v
                ? "bg-cyan-900/40 border-cyan-700 text-cyan-400"
                : "border-gray-700 text-gray-500 hover:border-gray-600 hover:text-gray-300"}`}>
            {v}
          </button>
        ))}
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search URL…"
          className="ml-2 bg-gray-900 border border-gray-700 rounded px-3 py-1 text-xs
                     text-gray-300 placeholder-gray-600 focus:outline-none focus:border-cyan-700 w-64"
        />
      </div>

      {/* Table */}
      <div className="bg-gray-900 border border-gray-800 rounded-lg overflow-hidden">
        {loading ? (
          <div className="p-12 text-center text-gray-600 text-sm animate-pulse">Loading…</div>
        ) : filtered.length === 0 ? (
          <div className="p-12 text-center text-gray-600 text-sm">No scans match your filter.</div>
        ) : (
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-gray-800 text-gray-600">
                {["Timestamp","URL","Decoded","Verdict","Score","Duration","Risks",""].map(h => (
                  <th key={h} className="text-left px-3 py-2 font-normal uppercase tracking-wider">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map(s => (
                <tr key={s.scan_id} className="border-b border-gray-800/40 hover:bg-gray-800/20 transition">
                  <td className="px-3 py-2 text-gray-600 whitespace-nowrap">
                    {new Date(s.timestamp).toLocaleString()}
                  </td>
                  <td className="px-3 py-2 font-mono text-gray-300 max-w-[200px] truncate">
                    {s.url}
                  </td>
                  <td className="px-3 py-2 font-mono text-gray-600 max-w-[150px] truncate">
                    {s.decoded_url !== s.url ? s.decoded_url : "—"}
                  </td>
                  <td className="px-3 py-2">
                    <span className={`px-2 py-0.5 rounded border font-bold uppercase ${verdictBg(s.threat.label)}`}>
                      {s.threat.label}
                    </span>
                  </td>
                  <td className="px-3 py-2 font-bold" style={{ color: verdictColor(s.threat.label) }}>
                    {Math.round(s.threat.score * 100)}%
                  </td>
                  <td className="px-3 py-2 text-gray-600">{s.duration_ms.toFixed(0)}ms</td>
                  <td className="px-3 py-2 text-gray-600">{s.risk_factors?.length ?? 0}</td>
                  <td className="px-3 py-2">
                    <button onClick={() => navigate("detail", s.scan_id)}
                      className="text-cyan-600 hover:text-cyan-400 transition">→</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
