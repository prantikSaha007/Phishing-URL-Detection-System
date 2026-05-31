import { useState, useEffect } from "react";
import { RadarChart, Radar, PolarGrid, PolarAngleAxis, ResponsiveContainer } from "recharts";
import { Download, ArrowLeft, AlertTriangle, CheckCircle, Shield } from "lucide-react";
import { getScan, verdictBg, verdictColor } from "../utils/api";

const Section = ({ title, children }) => (
  <div className="bg-gray-900 border border-gray-800 rounded-lg p-4">
    <h3 className="text-xs text-gray-500 uppercase tracking-widest mb-3">{title}</h3>
    {children}
  </div>
);

const KV = ({ k, v, mono = false }) => (
  <div className="flex justify-between gap-4 py-1 border-b border-gray-800/50 last:border-0">
    <span className="text-xs text-gray-500 shrink-0">{k}</span>
    <span className={`text-xs text-gray-300 text-right truncate ${mono ? "font-mono" : ""}`}>{v || "—"}</span>
  </div>
);

export default function ScanDetail({ scanId, navigate }) {
  const [scan, setScan] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!scanId) return;
    getScan(scanId).then(d => { setScan(d); setLoading(false); });
  }, [scanId]);

  if (loading) return (
    <div className="p-20 text-center text-gray-600 animate-pulse text-sm">Loading report…</div>
  );
  if (!scan) return (
    <div className="p-20 text-center text-gray-600 text-sm">Scan not found.</div>
  );

  const { threat, forensics, cti, ml_features, risk_factors, ioc_report } = scan;

  // Build radar data from selected features (normalized 0-1)
  const radarData = [
    { subject: "Entropy",    value: Math.min(ml_features.entropy_url / 5, 1) },
    { subject: "Length",     value: Math.min(scan.url.length / 200, 1) },
    { subject: "Dots",       value: Math.min(ml_features.num_dots / 10, 1) },
    { subject: "Keywords",   value: Math.min(ml_features.suspicious_keyword_count / 5, 1) },
    { subject: "Digit %",    value: ml_features.digit_ratio_domain },
    { subject: "Hyphens",    value: Math.min(ml_features.num_hyphens / 5, 1) },
  ];

  const downloadReport = () => {
    const blob = new Blob([JSON.stringify(ioc_report, null, 2)], { type: "application/json" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = `ioc_${scan.scan_id.slice(0, 8)}.json`;
    a.click();
  };

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between gap-4">
        <button onClick={() => navigate("history")}
          className="flex items-center gap-2 text-xs text-gray-500 hover:text-gray-300 transition">
          <ArrowLeft size={13} /> Back to history
        </button>
        <button onClick={downloadReport}
          className="flex items-center gap-2 text-xs text-orange-500 border border-orange-900
                     rounded px-3 py-1.5 hover:bg-orange-900/20 transition">
          <Download size={12} /> Download IoC Report
        </button>
      </div>

      {/* Verdict banner */}
      <div className={`border rounded-lg p-5 ${verdictBg(threat.label)}`}>
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-3">
            {threat.label !== "benign"
              ? <AlertTriangle size={28} />
              : <CheckCircle    size={28} />}
            <div>
              <p className="font-bold uppercase tracking-widest text-lg">{threat.label}</p>
              <p className="text-xs opacity-60 font-mono truncate max-w-lg">{scan.url}</p>
            </div>
          </div>
          <div className="text-right">
            <p className="text-3xl font-bold" style={{ color: verdictColor(threat.label) }}>
              {Math.round(threat.score * 100)}%
            </p>
            <p className="text-xs opacity-60">threat score</p>
          </div>
        </div>
        {risk_factors.length > 0 && (
          <div className="mt-3 pt-3 border-t border-current/20">
            <p className="text-xs opacity-60 uppercase tracking-wider mb-1">Risk Factors</p>
            <ul className="space-y-0.5">
              {risk_factors.map((f, i) => (
                <li key={i} className="text-xs">• {f}</li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {/* Grid */}
      <div className="grid md:grid-cols-2 gap-4">
        {/* URL info */}
        <Section title="URL Analysis">
          <KV k="Original URL"  v={scan.url}         mono />
          <KV k="Decoded URL"   v={scan.decoded_url}  mono />
          <KV k="Scan Time"     v={new Date(scan.timestamp).toLocaleString()} />
          <KV k="Duration"      v={`${scan.duration_ms.toFixed(1)}ms`} />
          <KV k="Confidence"    v={`${Math.round(threat.confidence * 100)}%`} />
          {ioc_report?.ioc?.sha256 && (
            <KV k="SHA-256" v={ioc_report.ioc.sha256} mono />
          )}
        </Section>

        {/* Forensics */}
        <Section title="DNS / WHOIS Forensics">
          <KV k="Domain"       v={forensics.domain} mono />
          <KV k="Registrar"    v={forensics.registrar} />
          <KV k="Created"      v={forensics.creation_date} />
          <KV k="Domain Age"   v={forensics.domain_age_days != null
            ? `${forensics.domain_age_days} days` : null} />
          <KV k="Country"      v={forensics.country} />
          <KV k="DNS Resolves" v={forensics.dns_resolves ? "Yes" : "No"} />
          <KV k="IPs"          v={forensics.ip_addresses?.join(", ")} mono />
          <KV k="Typosquat →"  v={forensics.typosquat_target} />
        </Section>

        {/* CTI */}
        <Section title="Threat Intelligence">
          {cti.virustotal?.available ? (
            <>
              <KV k="VT Malicious"  v={cti.virustotal.malicious} />
              <KV k="VT Suspicious" v={cti.virustotal.suspicious} />
              <KV k="VT Harmless"   v={cti.virustotal.harmless} />
              {cti.virustotal.permalink && (
                <div className="pt-1">
                  <a href={cti.virustotal.permalink} target="_blank" rel="noopener noreferrer"
                     className="text-xs text-cyan-500 hover:underline">View on VirusTotal →</a>
                </div>
              )}
            </>
          ) : (
            <p className="text-xs text-gray-600">VirusTotal: {cti.virustotal?.reason || "Not available"}</p>
          )}
          <div className="mt-3 pt-2 border-t border-gray-800">
            <KV k="URLhaus" v={
              cti.urlhaus?.found
                ? `FOUND – ${cti.urlhaus.threat || "malicious"}`
                : cti.urlhaus?.available ? "Not found" : "Unavailable"
            } />
            {cti.urlhaus?.tags?.length > 0 && (
              <KV k="Tags" v={cti.urlhaus.tags.join(", ")} />
            )}
          </div>
        </Section>

        {/* Feature radar */}
        <Section title="ML Feature Profile">
          <ResponsiveContainer width="100%" height={180}>
            <RadarChart data={radarData}>
              <PolarGrid stroke="#374151" />
              <PolarAngleAxis dataKey="subject"
                tick={{ fill: "#6b7280", fontSize: 10 }} />
              <Radar dataKey="value" stroke="#06b6d4" fill="#06b6d4" fillOpacity={0.2}
                     strokeWidth={1.5} dot={{ r: 3, fill: "#06b6d4" }} />
            </RadarChart>
          </ResponsiveContainer>
        </Section>
      </div>

      {/* Raw features */}
      <Section title="ML Feature Vector">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-x-6 max-h-64 overflow-y-auto">
          {Object.entries(ml_features)
            .sort((a, b) => b[1] - a[1])
            .map(([k, v]) => (
              <div key={k} className="flex justify-between py-0.5 border-b border-gray-800/40">
                <span className="text-xs text-gray-600 font-mono">{k}</span>
                <span className="text-xs text-gray-400 font-mono ml-2">
                  {typeof v === "number" ? v.toFixed(3) : v}
                </span>
              </div>
            ))}
        </div>
      </Section>
    </div>
  );
}
