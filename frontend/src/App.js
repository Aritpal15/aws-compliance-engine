import React, { useState } from "react";
import { jsPDF } from "jspdf";

function App() {
  // --- Core Application States (UNCHANGED) ---
  const [accountId, setAccountId] = useState("");
  const [scanData, setScanData] = useState(null);
  const [historyData, setHistoryData] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  // --- NEW: layout-only state for the dark/light toggle ---
  const [darkMode, setDarkMode] = useState(false);

  // --- 1. Fetch Live & Simulated Scan Action (UNCHANGED) ---
  const handleScan = async (e) => {
    e.preventDefault();
    if (!/^\d{12}$/.test(accountId)) {
      setError("Please enter a valid 12-digit AWS Account ID.");
      return;
    }

    setLoading(true);
    setError("");

    try {
      const response = await fetch("http://localhost:8000/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ account_id: accountId }),
      });

      if (!response.ok)
        throw new Error("Compliance engine scan pipeline failed.");

      const data = await response.json();
      setScanData(data);

      await fetchHistoryTrend(accountId);
    } catch (err) {
      setError(err.message || "Failed connecting to backend API services.");
    } finally {
      setLoading(false);
    }
  };

  // --- 2. Query DynamoDB Scan Trends History (UNCHANGED) ---
  const fetchHistoryTrend = async (id) => {
    try {
      const res = await fetch(`http://localhost:8000/api/history/${id}`);
      if (res.ok) {
        const historyLogs = await res.json();
        setHistoryData(historyLogs);
      }
    } catch (err) {
      console.error("Failed fetching historical database sequences:", err);
    }
  };

  // --- 3. Client-Side PDF Report Generation Engine (UNCHANGED) ---
  const exportToPDF = () => {
    if (!scanData || !scanData.logs) return;

    const doc = new jsPDF();
    let yPosition = 20;

    doc.setFont("helvetica", "bold");
    doc.setFontSize(22);
    doc.text("AWS Cloud Compliance Audit Report", 14, yPosition);
    yPosition += 10;

    doc.setFontSize(10);
    doc.setFont("helvetica", "normal");
    doc.text(`Tenant Target ID: ${scanData.tenant_id}`, 14, yPosition);
    doc.text(`Generated On: ${new Date().toLocaleString()}`, 130, yPosition);
    yPosition += 15;

    doc.setFontSize(14);
    doc.setFont("helvetica", "bold");
    doc.text("Executive Summary Matrix", 14, yPosition);
    yPosition += 8;

    doc.setFontSize(11);
    doc.setFont("helvetica", "normal");
    doc.text(
      `Global Compliance Score: ${scanData.compliance_score}%`,
      16,
      yPosition,
    );
    yPosition += 6;
    doc.text(
      `Critical Breaches Flagged: ${scanData.critical_alerts}`,
      16,
      yPosition,
    );
    yPosition += 6;
    doc.text(
      `Warning Findings Flagged: ${scanData.warning_alerts}`,
      16,
      yPosition,
    );
    yPosition += 15;

    doc.setFontSize(14);
    doc.setFont("helvetica", "bold");
    doc.text("Real-Time Compliance Rule Evaluation Stream", 14, yPosition);
    yPosition += 10;

    doc.setFontSize(9);
    scanData.logs.forEach((log) => {
      if (yPosition > 270) {
        doc.addPage();
        yPosition = 20;
      }

      if (log.status === "CRITICAL") doc.setTextColor(220, 38, 38);
      else if (log.status === "WARNING") doc.setTextColor(217, 119, 6);
      else if (log.status === "COMPLIANT") doc.setTextColor(5, 150, 105);
      else doc.setTextColor(100, 116, 139);

      doc.setFont("helvetica", "bold");
      doc.text(`[${log.status}] (${log.pillar})`, 14, yPosition);

      doc.setFont("helvetica", "normal");
      doc.setTextColor(30, 41, 59);

      const wrappedMessage = doc.splitTextToSize(log.message, 125);
      doc.text(wrappedMessage, 75, yPosition);

      yPosition += wrappedMessage.length * 5 + 4;
    });

    doc.save(`AWS-Compliance-Report-${scanData.tenant_id}.pdf`);
  };

  const resetDashboard = () => {
    setScanData(null);
    setHistoryData([]);
    setAccountId("");
    setError("");
  };

  // --- Layout-only helper: builds an SVG sparkline path from historyData ---
  const buildSparklinePoints = () => {
    if (!historyData || historyData.length < 2) return null;
    const scores = historyData.map((r) => r.compliance_score);
    const max = Math.max(...scores, 100);
    const min = Math.min(...scores, 0);
    const range = max - min || 1;
    const stepX = 600 / (scores.length - 1);

    return scores
      .map((s, i) => {
        const x = i * stepX;
        const y = 80 - ((s - min) / range) * 70;
        return `${x},${y}`;
      })
      .join(" ");
  };
  const sparklinePoints = buildSparklinePoints();

  // --- Theme tokens (layout-only) ---
  const pageBg = darkMode
    ? "bg-black"
    : "bg-gradient-to-br from-slate-100 via-white to-slate-100";
  const cardBg = darkMode
    ? "bg-zinc-950 border-zinc-800"
    : "bg-white border-slate-100";
  const textPrimary = darkMode ? "text-zinc-50" : "text-slate-900";
  const textMuted = darkMode ? "text-zinc-500" : "text-slate-400";

  return (
    <div
      className={`min-h-screen ${pageBg} p-4 md:p-8 font-sans transition-colors duration-300`}
    >
      <div className="max-w-7xl mx-auto">
        {/* ============ HEADER ============ */}
        <div
          className={`flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-6 ${cardBg} border p-6 rounded-2xl shadow-sm`}
        >
          <div>
            <h1 className={`text-2xl font-black tracking-tight ${textPrimary}`}>
              AWS Compliance Engine
            </h1>
            <p className={`text-sm ${textMuted}`}>
              Multi-Tenant Real-Time Security & Governance Audit Layer
            </p>
          </div>

          <div className="flex items-center gap-3">
            {/* Sliding capsule dark/light toggle */}
            <button
              onClick={() => setDarkMode(!darkMode)}
              className={`relative w-28 h-9 rounded-full transition-colors duration-300 px-1 ${
                darkMode ? "bg-black border border-zinc-700" : "bg-slate-200"
              }`}
              aria-label="Toggle dark mode"
            >
              {/* Label sits on the side OPPOSITE the knob, so the knob never covers it */}
              <span
                className={`absolute inset-y-0 flex items-center text-[10px] font-bold tracking-wider transition-opacity duration-200 ${
                  darkMode ? "left-3 text-zinc-400" : "right-3 text-slate-500"
                }`}
              >
                {darkMode ? "NIGHT" : "DAY"}
              </span>
              <span
                className={`absolute top-1 h-7 w-7 rounded-full bg-white shadow-md transform transition-transform duration-300 flex items-center justify-center text-xs ${
                  darkMode ? "translate-x-[76px]" : "translate-x-0"
                }`}
              >
                {darkMode ? "🌙" : "☀️"}
              </span>
            </button>

            <button
              onClick={resetDashboard}
              className={`px-4 py-2 text-xs font-bold rounded-lg transition ${
                darkMode
                  ? "text-zinc-300 bg-zinc-900 hover:bg-zinc-800 border border-zinc-800"
                  : "text-slate-500 bg-slate-100 hover:bg-slate-200"
              }`}
            >
              RESET DASHBOARD
            </button>
          </div>
        </div>

        {/* ============ TOP ROW: 3 COLORFUL KPI TILES ============ */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-5 mb-5">
          {/* TILE 1: Compliance Score */}
          <div className="relative overflow-hidden rounded-2xl shadow-sm p-6 bg-gradient-to-br from-indigo-500 via-violet-600 to-violet-700 text-white flex flex-col justify-between min-h-[180px]">
            <div>
              <h3 className="text-[11px] font-bold uppercase tracking-wider text-indigo-100">
                Overall Compliance
              </h3>
            </div>
            <div className="flex items-center justify-between">
              <div className="relative flex items-center justify-center h-24 w-24">
                <div className="absolute text-2xl font-black">
                  {scanData ? `${scanData.compliance_score}%` : "0%"}
                </div>
                <svg
                  className="w-full h-full transform -rotate-90"
                  viewBox="0 0 100 100"
                >
                  <circle
                    cx="50"
                    cy="50"
                    r="40"
                    stroke="rgba(255,255,255,0.25)"
                    strokeWidth="10"
                    fill="transparent"
                  />
                  <circle
                    cx="50"
                    cy="50"
                    r="40"
                    stroke="#ffffff"
                    strokeWidth="10"
                    fill="transparent"
                    strokeDasharray="251.2"
                    strokeDashoffset={
                      251.2 -
                      (251.2 * (scanData ? scanData.compliance_score : 0)) / 100
                    }
                    strokeLinecap="round"
                    className="transition-all duration-1000 ease-out"
                  />
                </svg>
              </div>
              <p className="text-xs font-semibold text-indigo-100 text-right max-w-[100px]">
                {scanData
                  ? scanData.compliance_score === 100
                    ? "Fully Secure Baseline"
                    : "Breaches Found"
                  : "Awaiting Ingress Handshake"}
              </p>
            </div>
          </div>

          {/* TILE 2: Critical Findings */}
          <div className="relative overflow-hidden rounded-2xl shadow-sm p-6 bg-gradient-to-br from-rose-500 via-red-500 to-red-600 text-white flex flex-col justify-between min-h-[180px]">
            <h4 className="text-[11px] font-bold uppercase tracking-wider text-rose-100">
              Critical Findings
            </h4>
            <div>
              <div className="text-5xl font-black leading-none">
                {scanData ? scanData.critical_alerts : 0}
              </div>
              <p className="text-xs text-rose-100 mt-3 font-medium">
                Immediate remediation action required.
              </p>
            </div>
          </div>

          {/* TILE 3: Warning Findings */}
          <div className="relative overflow-hidden rounded-2xl shadow-sm p-6 bg-gradient-to-br from-amber-400 via-orange-500 to-orange-500 text-white flex flex-col justify-between min-h-[180px]">
            <h4 className="text-[11px] font-bold uppercase tracking-wider text-amber-50">
              Warning Findings
            </h4>
            <div>
              <div className="text-5xl font-black leading-none">
                {scanData ? scanData.warning_alerts : 0}
              </div>
              <p className="text-xs text-amber-50 mt-3 font-medium">
                Review configuration parameters shortly.
              </p>
            </div>
          </div>
        </div>

        {/* ============ ACTION CONTROL PANEL (full width) ============ */}
        <div className={`${cardBg} border p-6 rounded-2xl shadow-sm mb-5`}>
          <h3
            className={`text-xs font-bold uppercase tracking-wider ${textMuted} mb-3`}
          >
            Engine Orchestration
          </h3>
          <form
            onSubmit={handleScan}
            className="flex flex-col sm:flex-row gap-3"
          >
            <input
              type="text"
              placeholder="Enter 12-Digit AWS Account ID"
              value={accountId}
              onChange={(e) => setAccountId(e.target.value)}
              className={`flex-1 px-4 py-2.5 rounded-xl font-mono text-center focus:outline-none focus:ring-2 transition text-sm border ${
                darkMode
                  ? "bg-zinc-900 border-zinc-800 text-zinc-100 focus:ring-zinc-500"
                  : "border-slate-200 focus:ring-slate-900"
              }`}
            />
            <button
              type="submit"
              disabled={loading}
              className={`sm:w-64 font-semibold py-2.5 px-4 rounded-xl transition duration-200 text-sm ${
                darkMode
                  ? "bg-white text-black hover:bg-zinc-200 disabled:bg-zinc-700 disabled:text-zinc-400"
                  : "bg-slate-950 text-white hover:bg-slate-800 disabled:bg-slate-300"
              }`}
            >
              {loading ? "Evaluating..." : "Trigger Account Scan"}
            </button>
            {scanData && (
              <button
                type="button"
                onClick={exportToPDF}
                className="sm:w-64 bg-emerald-600 hover:bg-emerald-700 text-white font-semibold py-2.5 px-4 rounded-xl transition duration-200 text-sm"
              >
                Download Audit PDF
              </button>
            )}
          </form>
          {error && (
            <p className="mt-3 text-xs font-medium text-rose-500 text-center">
              {error}
            </p>
          )}
        </div>

        {/* ============ SCAN ACTIVITY TREND (sparkline) ============ */}
        <div className={`${cardBg} border p-6 rounded-2xl shadow-sm mb-5`}>
          <h3
            className={`text-xs font-bold uppercase tracking-wider ${textMuted} mb-4`}
          >
            Scan Activity Trend
          </h3>
          {sparklinePoints ? (
            <svg viewBox="0 0 600 90" className="w-full h-24">
              <polyline
                points={sparklinePoints}
                fill="none"
                stroke={darkMode ? "#f87171" : "#ef4444"}
                strokeWidth="2.5"
                strokeLinecap="round"
                strokeLinejoin="round"
              />
            </svg>
          ) : (
            <p className={`text-xs ${textMuted} py-8 text-center`}>
              Run at least two scans to plot a compliance trend line.
            </p>
          )}
        </div>

        {/* ============ REAL-TIME RULE EVALUATION STREAM ============ */}
        <div className={`${cardBg} border p-6 rounded-2xl shadow-sm mb-5`}>
          <h3
            className={`text-sm font-bold uppercase tracking-wider ${textMuted} mb-4`}
          >
            Real-Time Rule Evaluation Stream
          </h3>
          <div className="bg-black text-slate-100 font-mono text-xs rounded-xl p-4 h-60 overflow-y-auto space-y-2 shadow-inner border border-zinc-900">
            {!scanData && (
              <div className="text-zinc-600">
                Awaiting first scan trigger...
              </div>
            )}
            {scanData &&
              scanData.logs.map((log, idx) => (
                <div key={idx} className="leading-relaxed">
                  <span
                    className={`font-bold ${
                      log.status === "CRITICAL"
                        ? "text-rose-400"
                        : log.status === "WARNING"
                          ? "text-amber-400"
                          : log.status === "COMPLIANT"
                            ? "text-emerald-400"
                            : "text-sky-400"
                    }`}
                  >
                    {log.status === "INFO" ? "✓" : `[${log.status}]`}
                  </span>{" "}
                  <span className="text-zinc-500">({log.pillar})</span>{" "}
                  {log.message}
                </div>
              ))}
          </div>
        </div>

        {/* ============ HISTORICAL GOVERNANCE TREND REGISTRY ============ */}
        {historyData && historyData.length > 0 && (
          <div className={`${cardBg} border p-6 rounded-2xl shadow-sm`}>
            <h3
              className={`text-sm font-bold uppercase tracking-wider ${textMuted} mb-4`}
            >
              Historical Governance Trend Registry (DynamoDB Time-Series)
            </h3>
            <div
              className={`overflow-x-auto rounded-xl border ${
                darkMode ? "border-zinc-800" : "border-slate-100"
              }`}
            >
              <table
                className={`w-full text-left text-sm ${
                  darkMode ? "text-zinc-300" : "text-slate-600"
                }`}
              >
                <thead
                  className={`text-xs uppercase font-semibold border-b ${
                    darkMode
                      ? "bg-zinc-900 text-zinc-500 border-zinc-800"
                      : "bg-slate-50 text-slate-500 border-slate-100"
                  }`}
                >
                  <tr>
                    <th className="px-6 py-3.5">Timestamp Baseline</th>
                    <th className="px-6 py-3.5">Compliance Score</th>
                    <th className="px-6 py-3.5">Critical Breaches</th>
                    <th className="px-6 py-3.5">Warning Flags</th>
                  </tr>
                </thead>
                <tbody
                  className={`divide-y ${
                    darkMode ? "divide-zinc-800" : "divide-slate-100"
                  }`}
                >
                  {historyData.map((record, index) => (
                    <tr
                      key={index}
                      className={`transition ${
                        darkMode
                          ? "hover:bg-zinc-900/60"
                          : "hover:bg-slate-50/80"
                      }`}
                    >
                      <td className="px-6 py-3.5 font-mono text-xs opacity-70">
                        {new Date(record.timestamp).toLocaleString()}
                      </td>
                      <td className="px-6 py-3.5">
                        <span
                          className={`font-bold px-2 py-1 rounded text-xs ${
                            record.compliance_score >= 80
                              ? "bg-emerald-500/10 text-emerald-500"
                              : record.compliance_score >= 50
                                ? "bg-amber-500/10 text-amber-500"
                                : "bg-rose-500/10 text-rose-500"
                          }`}
                        >
                          {record.compliance_score}%
                        </span>
                      </td>
                      <td className="px-6 py-3.5 text-rose-500 font-semibold">
                        {record.critical_alerts}
                      </td>
                      <td className="px-6 py-3.5 text-amber-500 font-semibold">
                        {record.warning_alerts}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;
