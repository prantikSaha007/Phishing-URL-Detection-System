import { useState, useEffect } from "react";
import Dashboard from "./pages/Dashboard";
import ScanHistory from "./pages/ScanHistory";
import ScanDetail from "./pages/ScanDetail";
import Navbar from "./components/Navbar";
import { API_BASE } from "./utils/api";

export default function App() {
  const [page, setPage] = useState("dashboard");
  const [selectedScanId, setSelectedScanId] = useState(null);
  const [stats, setStats] = useState(null);

  const navigate = (p, id = null) => {
    setPage(p);
    if (id) setSelectedScanId(id);
  };

  useEffect(() => {
    fetch(`${API_BASE}/stats`)
      .then(r => r.json())
      .then(setStats)
      .catch(() => {});
  }, []);

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100 font-mono">
      <Navbar page={page} navigate={navigate} stats={stats} />
      <main className="max-w-7xl mx-auto px-4 py-8">
        {page === "dashboard"  && <Dashboard navigate={navigate} />}
        {page === "history"    && <ScanHistory navigate={navigate} />}
        {page === "detail"     && <ScanDetail scanId={selectedScanId} navigate={navigate} />}
      </main>
    </div>
  );
}
