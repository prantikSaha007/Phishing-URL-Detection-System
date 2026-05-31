import { Shield, LayoutDashboard, List, Activity } from "lucide-react";

export default function Navbar({ page, navigate, stats }) {
  const links = [
    { id: "dashboard", label: "Dashboard", icon: LayoutDashboard },
    { id: "history",   label: "Scan History", icon: List },
  ];

  return (
    <header className="border-b border-gray-800 bg-gray-900/80 backdrop-blur sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 flex items-center justify-between h-14">
        {/* Logo */}
        <button onClick={() => navigate("dashboard")}
          className="flex items-center gap-2 text-cyan-400 font-bold tracking-widest hover:text-cyan-300 transition">
          <Shield size={22} className="text-cyan-400" />
          <span className="text-sm">PHISHGUARD</span>
          <span className="text-xs text-gray-500 font-normal tracking-normal">SOC Dashboard</span>
        </button>

        {/* Nav links */}
        <nav className="flex items-center gap-1">
          {links.map(({ id, label, icon: Icon }) => (
            <button key={id} onClick={() => navigate(id)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded text-xs transition
                ${page === id
                  ? "bg-cyan-900/40 text-cyan-400 border border-cyan-800"
                  : "text-gray-400 hover:text-gray-200 hover:bg-gray-800"}`}>
              <Icon size={13} />
              {label}
            </button>
          ))}
        </nav>

        {/* Live stats pill */}
        {stats && stats.total > 0 && (
          <div className="flex items-center gap-3 text-xs text-gray-500">
            <span className="flex items-center gap-1">
              <Activity size={11} className="text-cyan-500" />
              {stats.total} scans
            </span>
            <span className="text-red-400">{stats.phishing} phishing</span>
            <span className="text-yellow-400">{stats.suspicious} suspicious</span>
          </div>
        )}
      </div>
    </header>
  );
}
