const { useState, useEffect, useRef } = React;

function App() {
  const [events, setEvents] = useState([]);
  const [overview, setOverview] = useState({
    total_events: 0,
    unique_ips: 0,
    ssh_events: 0,
    http_events: 0,
    critical_threats: 0,
    high_threats: 0,
    medium_threats: 0,
    low_threats: 0,
    top_threat_vector: "None"
  });
  const [services, setServices] = useState([]);
  const [riskMatrix, setRiskMatrix] = useState([]);
  const [credentials, setCredentials] = useState([]);
  const [geoDist, setGeoDist] = useState([]);
  const [wsConnected, setWsConnected] = useState(false);
  const [activeFilter, setActiveFilter] = useState("ALL");
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedPayload, setSelectedPayload] = useState(null);
  const [isSimulating, setIsSimulating] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);

  const terminalEndRef = useRef(null);
  const chartRef = useRef(null);
  const chartInstance = useRef(null);
  const wsRef = useRef(null);

  // Initialize Lucide icons on DOM updates
  useEffect(() => {
    if (window.lucide) {
      window.lucide.createIcons();
    }
  });

  // Fetch initial REST data
  const fetchData = async () => {
    try {
      const [ovRes, evRes, srvRes, matRes, credRes, geoRes] = await Promise.all([
        fetch("/api/analytics/overview"),
        fetch("/api/events?limit=100"),
        fetch("/api/services/status"),
        fetch("/api/analytics/risk-matrix"),
        fetch("/api/analytics/credentials"),
        fetch("/api/analytics/geo")
      ]);

      if (ovRes.ok) setOverview(await ovRes.json());
      if (evRes.ok) setEvents(await evRes.json());
      if (srvRes.ok) setServices(await srvRes.json());
      if (matRes.ok) setRiskMatrix(await matRes.json());
      if (credRes.ok) setCredentials(await credRes.json());
      if (geoRes.ok) setGeoDist(await geoRes.json());

      updateChart();
    } catch (err) {
      console.error("Error fetching analytics:", err);
    }
  };

  // WebSocket Connection
  const connectWebSocket = () => {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const host = window.location.host || "127.0.0.1:8000";
    const wsUrl = `${protocol}//${host}/ws/live`;

    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      console.log("[WS] Connected to Honeypot live stream");
      setWsConnected(true);
    };

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);
        if (msg.type === "NEW_EVENT" && msg.data) {
          const newEv = msg.data;
          setEvents((prev) => [newEv, ...prev.slice(0, 199)]);
          
          // Increment overview counters locally
          setOverview((prev) => ({
            ...prev,
            total_events: prev.total_events + 1,
            ssh_events: newEv.service === "SSH" ? prev.ssh_events + 1 : prev.ssh_events,
            http_events: newEv.service === "HTTP" ? prev.http_events + 1 : prev.http_events,
            critical_threats: newEv.risk_level === "CRITICAL" ? prev.critical_threats + 1 : prev.critical_threats,
            high_threats: newEv.risk_level === "HIGH" ? prev.high_threats + 1 : prev.high_threats,
          }));

          // Trigger throttled refresh of analytics tables
          refreshAnalyticsDebounced();
        }
      } catch (err) {
        console.error("WS parse error:", err);
      }
    };

    ws.onclose = () => {
      console.log("[WS] Disconnected. Retrying in 3s...");
      setWsConnected(false);
      setTimeout(connectWebSocket, 3000);
    };

    ws.onerror = (err) => {
      console.error("[WS] Error:", err);
      ws.close();
    };
  };

  let debounceTimer = null;
  const refreshAnalyticsDebounced = () => {
    if (debounceTimer) clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      fetch("/api/analytics/risk-matrix").then(r => r.json()).then(setRiskMatrix).catch(() => {});
      fetch("/api/analytics/credentials").then(r => r.json()).then(setCredentials).catch(() => {});
      fetch("/api/analytics/geo").then(r => r.json()).then(setGeoDist).catch(() => {});
      fetch("/api/services/status").then(r => r.json()).then(setServices).catch(() => {});
      updateChart();
    }, 1500);
  };

  // Update Activity Chart
  const updateChart = async () => {
    try {
      const res = await fetch("/api/analytics/frequency?minutes=30");
      if (!res.ok) return;
      const data = await res.json();

      const labels = data.map((d) => d.time_bucket);
      const sshData = data.map((d) => d.ssh_count);
      const httpData = data.map((d) => d.http_count);

      if (chartRef.current) {
        if (chartInstance.current) {
          chartInstance.current.destroy();
        }

        const ctx = chartRef.current.getContext("2d");
        chartInstance.current = new Chart(ctx, {
          type: "line",
          data: {
            labels: labels,
            datasets: [
              {
                label: "SSH Decoy Probes",
                data: sshData,
                borderColor: "#06b6d4",
                backgroundColor: "rgba(6, 182, 212, 0.15)",
                fill: true,
                tension: 0.35,
                borderWidth: 2,
                pointRadius: 3,
                pointBackgroundColor: "#06b6d4",
              },
              {
                label: "HTTP Decoy Traps",
                data: httpData,
                borderColor: "#10b981",
                backgroundColor: "rgba(16, 185, 129, 0.15)",
                fill: true,
                tension: 0.35,
                borderWidth: 2,
                pointRadius: 3,
                pointBackgroundColor: "#10b981",
              },
            ],
          },
          options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
              legend: {
                labels: { color: "#94a3b8", font: { family: "Inter", size: 12 } },
              },
            },
            scales: {
              x: {
                grid: { color: "#1e293b" },
                ticks: { color: "#64748b", font: { family: "JetBrains Mono", size: 10 } },
              },
              y: {
                beginAtZero: true,
                grid: { color: "#1e293b" },
                ticks: { color: "#64748b", font: { family: "JetBrains Mono", size: 10 }, stepSize: 1 },
              },
            },
          },
        });
      }
    } catch (e) {
      console.error("Chart error:", e);
    }
  };

  useEffect(() => {
    fetchData();
    connectWebSocket();
    const interval = setInterval(fetchData, 15000);
    return () => {
      clearInterval(interval);
      if (wsRef.current) wsRef.current.close();
    };
  }, []);

  useEffect(() => {
    if (autoScroll && terminalEndRef.current) {
      terminalEndRef.current.scrollIntoView({ behavior: "smooth" });
    }
  }, [events, autoScroll]);

  // Trigger attack simulation
  const handleTriggerSim = async (scenario = "all") => {
    setIsSimulating(true);
    try {
      await fetch(`/api/simulator/trigger?scenario=${scenario}`, { method: "POST" });
      setTimeout(() => {
        fetchData();
        setIsSimulating(false);
      }, 800);
    } catch (e) {
      console.error("Simulator error:", e);
      setIsSimulating(false);
    }
  };

  // Clear all events
  const handleClear = async () => {
    if (window.confirm("Reset all captured honeypot logs and threat intelligence records?")) {
      await fetch("/api/events", { method: "DELETE" });
      fetchData();
    }
  };

  // Filtered Events
  const filteredEvents = events.filter((ev) => {
    const matchesFilter =
      activeFilter === "ALL" ||
      (activeFilter === "SSH" && ev.service === "SSH") ||
      (activeFilter === "HTTP" && ev.service === "HTTP") ||
      (activeFilter === "CRITICAL" && (ev.risk_level === "CRITICAL" || ev.risk_level === "HIGH"));

    const matchesSearch =
      searchQuery === "" ||
      (ev.source_ip && ev.source_ip.includes(searchQuery)) ||
      (ev.payload && ev.payload.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (ev.username && ev.username.toLowerCase().includes(searchQuery.toLowerCase())) ||
      (ev.classification && ev.classification.toLowerCase().includes(searchQuery.toLowerCase()));

    return matchesFilter && matchesSearch;
  });

  const getRiskBadgeClass = (level) => {
    switch (level) {
      case "CRITICAL": return "badge-critical";
      case "HIGH": return "badge-high";
      case "MEDIUM": return "badge-medium";
      case "LOW": return "badge-low";
      default: return "badge-info";
    }
  };

  return (
    <div className="flex flex-col min-h-screen">
      {/* Top SOC Navbar */}
      <header className="border-b border-cyber-800 bg-cyber-900/90 backdrop-blur-md sticky top-0 z-50 px-6 py-3">
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div className="flex items-center space-x-3">
            <div className="w-9 h-9 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400 font-mono font-bold text-lg">
              Ψ
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-extrabold tracking-wider text-base text-slate-100 uppercase">
                  CYBER-SOC HONEYPOT
                </span>
                <span className="text-xs px-2 py-0.5 rounded bg-cyan-500/20 text-cyan-300 font-mono border border-cyan-500/30">
                  DECEPTION DEFENSE v1.0
                </span>
              </div>
              <p className="text-xs text-slate-400">Intelligent Threat Pattern Analysis & Decoy Network</p>
            </div>
          </div>

          {/* Service Status Badges */}
          <div className="flex items-center space-x-3 text-xs">
            {services.map((s, idx) => (
              <div key={idx} className="flex items-center space-x-2 bg-cyber-850 px-3 py-1.5 rounded-md border border-cyber-700">
                <span className={`w-2 h-2 rounded-full ${s.status === "ONLINE" ? "bg-emerald-400 animate-pulse" : "bg-amber-400"}`}></span>
                <span className="text-slate-300 font-medium">{s.type} Decoy</span>
                <span className="text-slate-500 font-mono">:{s.port}</span>
              </div>
            ))}

            {/* Live WS Pulse */}
            <div className={`flex items-center space-x-2 px-3 py-1.5 rounded-md border ${wsConnected ? 'bg-emerald-950/40 border-emerald-500/40 text-emerald-300' : 'bg-red-950/40 border-red-500/40 text-red-300'}`}>
              <span className={`w-2.5 h-2.5 rounded-full ${wsConnected ? 'bg-emerald-400 animate-ping' : 'bg-red-500'}`}></span>
              <span className="font-mono text-[11px] font-semibold">
                {wsConnected ? 'STREAM LIVE' : 'CONNECTING...'}
              </span>
            </div>
          </div>

          {/* Quick Actions */}
          <div className="flex items-center space-x-2">
            <button
              onClick={() => handleTriggerSim("all")}
              disabled={isSimulating}
              className="flex items-center space-x-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-bold px-3.5 py-1.5 rounded text-xs transition shadow-lg shadow-cyan-900/30"
            >
              <span>⚡</span>
              <span>{isSimulating ? "Injecting Attack..." : "Simulate Attacks"}</span>
            </button>
            <button
              onClick={handleClear}
              className="bg-cyber-800 hover:bg-red-950/50 hover:text-red-300 hover:border-red-500/40 text-slate-400 border border-cyber-700 px-3 py-1.5 rounded text-xs transition"
              title="Reset events database"
            >
              Clear Logs
            </button>
          </div>
        </div>
      </header>

      {/* Main Content Dashboard */}
      <main className="flex-1 p-6 space-y-6 max-w-[1600px] mx-auto w-full">
        {/* KPI Metrics Cards */}
        <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <div className="stat-card p-4 rounded-xl relative overflow-hidden">
            <div className="flex justify-between items-start">
              <div>
                <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">Total Captured Attacks</p>
                <h3 className="text-3xl font-extrabold text-slate-100 font-mono mt-1">{overview.total_events}</h3>
              </div>
              <div className="p-2.5 rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20 font-mono text-xs">
                100% MALICIOUS
              </div>
            </div>
            <div className="mt-3 flex items-center justify-between text-xs text-slate-500 border-t border-cyber-800 pt-2 font-mono">
              <span>SSH: <strong className="text-cyan-400">{overview.ssh_events}</strong></span>
              <span>HTTP: <strong className="text-emerald-400">{overview.http_events}</strong></span>
              <span className="text-slate-400">Zero False-Positives</span>
            </div>
          </div>

          <div className="stat-card p-4 rounded-xl relative overflow-hidden">
            <div className="flex justify-between items-start">
              <div>
                <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">Unique Adversary IPs</p>
                <h3 className="text-3xl font-extrabold text-cyan-400 font-mono mt-1">{overview.unique_ips}</h3>
              </div>
              <div className="p-2.5 rounded-lg bg-blue-500/10 text-blue-400 border border-blue-500/20 text-xs font-mono">
                GEO-ISOLATED
              </div>
            </div>
            <div className="mt-3 flex items-center justify-between text-xs text-slate-500 border-t border-cyber-800 pt-2 font-mono">
              <span>Global Threat Vectors</span>
              <span className="text-cyan-300">Auto-Enriched GeoIP</span>
            </div>
          </div>

          <div className="stat-card p-4 rounded-xl relative overflow-hidden border-red-500/30">
            <div className="flex justify-between items-start">
              <div>
                <p className="text-xs font-medium text-red-400 uppercase tracking-wider">Critical & High Threats</p>
                <h3 className="text-3xl font-extrabold text-red-400 font-mono mt-1">
                  {overview.critical_threats + overview.high_threats}
                </h3>
              </div>
              <div className="p-2.5 rounded-lg bg-red-500/20 text-red-400 border border-red-500/40 text-xs font-mono animate-pulse">
                ACTION REQUIRED
              </div>
            </div>
            <div className="mt-3 flex items-center justify-between text-xs text-slate-500 border-t border-cyber-800 pt-2 font-mono">
              <span className="text-red-400 font-semibold">Critical: {overview.critical_threats}</span>
              <span className="text-amber-400 font-semibold">High: {overview.high_threats}</span>
              <span className="text-slate-400">Med: {overview.medium_threats}</span>
            </div>
          </div>

          <div className="stat-card p-4 rounded-xl relative overflow-hidden">
            <div className="flex justify-between items-start">
              <div>
                <p className="text-xs font-medium text-slate-400 uppercase tracking-wider">Primary Attack Vector</p>
                <h3 className="text-lg font-bold text-emerald-400 font-mono mt-2 truncate max-w-[200px]" title={overview.top_threat_vector}>
                  {overview.top_threat_vector}
                </h3>
              </div>
              <div className="p-2.5 rounded-lg bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-xs font-mono">
                RULE-CLASSIFIED
              </div>
            </div>
            <div className="mt-3 flex items-center justify-between text-xs text-slate-500 border-t border-cyber-800 pt-2 font-mono">
              <span>Dynamic Severity Matrix</span>
              <span className="text-emerald-400">Active Scoring</span>
            </div>
          </div>
        </section>

        {/* Quick Simulation Scenario Launcher Bar */}
        <section className="bg-cyber-900 border border-cyber-800 rounded-xl p-3.5 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center space-x-2">
            <span className="text-xs font-mono text-cyan-400 font-semibold uppercase tracking-wider">🧪 Quick Lab Simulation Vectors:</span>
            <span className="text-xs text-slate-400">Trigger individual attack vectors to test detection rules:</span>
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              onClick={() => handleTriggerSim("ssh_bruteforce")}
              className="px-2.5 py-1 bg-cyber-800 hover:bg-cyan-950 border border-cyber-700 hover:border-cyan-500/50 rounded text-xs font-mono text-cyan-300 transition"
            >
              + SSH Brute Force
            </button>
            <button
              onClick={() => handleTriggerSim("command_injection")}
              className="px-2.5 py-1 bg-cyber-800 hover:bg-red-950 border border-cyber-700 hover:border-red-500/50 rounded text-xs font-mono text-red-300 transition"
            >
              + Command Injection / Dropper
            </button>
            <button
              onClick={() => handleTriggerSim("web_sqli")}
              className="px-2.5 py-1 bg-cyber-800 hover:bg-amber-950 border border-cyber-700 hover:border-amber-500/50 rounded text-xs font-mono text-amber-300 transition"
            >
              + Web SQL Injection
            </button>
            <button
              onClick={() => handleTriggerSim("botnet_recon")}
              className="px-2.5 py-1 bg-cyber-800 hover:bg-purple-950 border border-cyber-700 hover:border-purple-500/50 rounded text-xs font-mono text-purple-300 transition"
            >
              + Botnet Scanner Recon
            </button>
            <button
              onClick={() => handleTriggerSim("path_traversal")}
              className="px-2.5 py-1 bg-cyber-800 hover:bg-blue-950 border border-cyber-700 hover:border-blue-500/50 rounded text-xs font-mono text-blue-300 transition"
            >
              + Path Traversal
            </button>
          </div>
        </section>

        {/* Section 1: Live Terminal Stream & Attack Activity Timeline */}
        <section className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Live Terminal Telemetry Box (7 cols) */}
          <div className="lg:col-span-7 flex flex-col bg-cyber-900 border border-cyber-800 rounded-xl overflow-hidden shadow-2xl">
            <div className="bg-cyber-850 px-4 py-3 border-b border-cyber-800 flex flex-wrap items-center justify-between gap-3">
              <div className="flex items-center space-x-2">
                <span className="w-3 h-3 rounded-full bg-red-500/80 inline-block"></span>
                <span className="w-3 h-3 rounded-full bg-yellow-500/80 inline-block"></span>
                <span className="w-3 h-3 rounded-full bg-green-500/80 inline-block"></span>
                <span className="font-mono text-xs font-bold text-slate-200 ml-2">
                  LIVE INTERACTION TELEMETRY STREAM
                </span>
                <span className="text-[11px] font-mono text-slate-500">({filteredEvents.length} events)</span>
              </div>

              {/* Terminal Filters */}
              <div className="flex items-center space-x-2">
                <div className="flex rounded bg-cyber-950 p-0.5 border border-cyber-800 text-[11px] font-mono">
                  {["ALL", "SSH", "HTTP", "CRITICAL"].map((f) => (
                    <button
                      key={f}
                      onClick={() => setActiveFilter(f)}
                      className={`px-2 py-0.5 rounded transition ${
                        activeFilter === f ? "bg-cyan-600 text-slate-950 font-bold" : "text-slate-400 hover:text-slate-200"
                      }`}
                    >
                      {f}
                    </button>
                  ))}
                </div>
                <input
                  type="text"
                  placeholder="Filter IP/payload..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="bg-cyber-950 border border-cyber-800 rounded px-2.5 py-1 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500 w-32 md:w-40 font-mono"
                />
              </div>
            </div>

            {/* Terminal Feed Scroll Body */}
            <div className="terminal-box p-4 font-mono text-xs overflow-y-auto max-h-[460px] min-h-[380px] space-y-2.5 flex-1 select-text">
              {filteredEvents.length === 0 ? (
                <div className="text-center py-16 text-slate-600">
                  <p className="font-mono">-- [DEC-00] Honeypot standing by. No malicious events matching filter --</p>
                  <p className="text-xs text-slate-700 mt-2">Click "Simulate Attacks" above to test the ingestion stream</p>
                </div>
              ) : (
                filteredEvents.map((ev) => (
                  <div
                    key={ev.id}
                    onClick={() => setSelectedPayload(ev)}
                    className="p-2 rounded bg-cyber-950/80 border border-cyber-800/80 hover:border-cyan-500/40 transition cursor-pointer flex flex-col space-y-1 group"
                  >
                    <div className="flex flex-wrap items-center justify-between text-[11px] text-slate-400 gap-2">
                      <div className="flex items-center space-x-2">
                        <span className="text-slate-500">
                          {ev.timestamp ? ev.timestamp.substring(11, 19) : "00:00:00"}
                        </span>
                        <span className={`px-1.5 py-0.2 rounded font-bold ${ev.service === 'SSH' ? 'bg-cyan-950 text-cyan-300 border border-cyan-800' : 'bg-emerald-950 text-emerald-300 border border-emerald-800'}`}>
                          {ev.service}
                        </span>
                        <span className="text-slate-300 font-semibold">{ev.source_ip}</span>
                        {ev.geo && ev.geo.country_code !== "XX" && (
                          <span className="text-[10px] text-slate-500 font-sans">
                            📍 {ev.geo.city}, {ev.geo.country}
                          </span>
                        )}
                      </div>
                      <div className="flex items-center space-x-2">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${getRiskBadgeClass(ev.risk_level)}`}>
                          {ev.risk_level} ({ev.risk_score})
                        </span>
                        <span className="text-slate-400 font-mono text-[10px] bg-cyber-800 px-1.5 py-0.5 rounded">
                          {ev.classification}
                        </span>
                      </div>
                    </div>

                    <div className="text-slate-200 break-all pl-2 border-l-2 border-slate-700 group-hover:border-cyan-400">
                      {ev.username && (
                        <span className="text-amber-400 mr-2">
                          [auth: user="{ev.username}" {ev.password ? `pass="${ev.password}"` : ""}]
                        </span>
                      )}
                      <span className="text-slate-300">
                        {ev.payload || `${ev.request_method || 'GET'} ${ev.path || '/'}`}
                      </span>
                    </div>

                    {ev.matched_rule && (
                      <div className="text-[10px] text-slate-500 pl-2">
                        ⚡ Rule: <span className="text-slate-400">{ev.matched_rule}</span>
                      </div>
                    )}
                  </div>
                ))
              )}
              <div ref={terminalEndRef} />
            </div>

            <div className="bg-cyber-950 px-4 py-2 border-t border-cyber-800 flex justify-between items-center text-[11px] text-slate-500 font-mono">
              <div className="flex items-center space-x-2">
                <span className="inline-block w-2 h-2 rounded-full bg-cyan-400 animate-pulse"></span>
                <span>Click any log item to inspect full payload & raw metadata</span>
              </div>
              <label className="flex items-center space-x-1.5 cursor-pointer">
                <input
                  type="checkbox"
                  checked={autoScroll}
                  onChange={(e) => setAutoScroll(e.target.checked)}
                  className="rounded bg-cyber-900 border-cyber-700 text-cyan-500 focus:ring-0"
                />
                <span>Auto-scroll</span>
              </label>
            </div>
          </div>

          {/* Attack Frequency Chart & Overview (5 cols) */}
          <div className="lg:col-span-5 flex flex-col space-y-4">
            <div className="bg-cyber-900 border border-cyber-800 rounded-xl p-4 flex flex-col flex-1 shadow-2xl">
              <div className="flex items-center justify-between pb-3 border-b border-cyber-800">
                <div className="flex items-center space-x-2">
                  <span className="text-cyan-400">📈</span>
                  <h3 className="font-mono text-xs font-bold text-slate-200 uppercase">
                    Attack Probing Frequency
                  </h3>
                </div>
                <span className="text-[10px] font-mono text-slate-500">Timeline (Last 30 Min)</span>
              </div>
              <div className="flex-1 min-h-[260px] pt-4 relative">
                <canvas ref={chartRef}></canvas>
              </div>
            </div>

            {/* Honeypot System Safety Status */}
            <div className="bg-cyber-900 border border-cyber-800 rounded-xl p-4 space-y-3">
              <div className="flex items-center space-x-2">
                <span className="text-emerald-400">🛡️</span>
                <h3 className="font-mono text-xs font-bold text-slate-200 uppercase">
                  Safety & Lab Isolation Protocol
                </h3>
              </div>
              <div className="grid grid-cols-2 gap-2 text-[11px] font-mono">
                <div className="p-2 rounded bg-cyber-950 border border-cyber-800 flex items-center space-x-2">
                  <span className="text-emerald-400">✓</span>
                  <span className="text-slate-300">Payload Execution: <strong>DISABLED</strong></span>
                </div>
                <div className="p-2 rounded bg-cyber-950 border border-cyber-800 flex items-center space-x-2">
                  <span className="text-emerald-400">✓</span>
                  <span className="text-slate-300">Host Egress: <strong>RESTRICTED</strong></span>
                </div>
                <div className="p-2 rounded bg-cyber-950 border border-cyber-800 flex items-center space-x-2">
                  <span className="text-emerald-400">✓</span>
                  <span className="text-slate-300">Prod Credentials: <strong>NONE</strong></span>
                </div>
                <div className="p-2 rounded bg-cyber-950 border border-cyber-800 flex items-center space-x-2">
                  <span className="text-emerald-400">✓</span>
                  <span className="text-slate-300">False-Positive Rate: <strong>0.00%</strong></span>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* Section 2: Attack Pattern Matrix & Top Targeted Credentials */}
        <section className="grid grid-cols-1 lg:grid-cols-12 gap-6">
          {/* Classified Threat Pattern Matrix (7 cols) */}
          <div className="lg:col-span-7 bg-cyber-900 border border-cyber-800 rounded-xl p-4 shadow-2xl flex flex-col">
            <div className="flex items-center justify-between pb-3 border-b border-cyber-800">
              <div className="flex items-center space-x-2">
                <span className="text-amber-400">🎯</span>
                <h3 className="font-mono text-xs font-bold text-slate-200 uppercase">
                  Classified Attack Vectors & Risk Matrix
                </h3>
              </div>
              <span className="text-[10px] font-mono text-slate-500">Rule-Based Threat Intelligence</span>
            </div>

            <div className="overflow-x-auto mt-3">
              <table className="w-full text-left text-xs font-mono">
                <thead>
                  <tr className="border-b border-cyber-800 text-slate-400 text-[11px]">
                    <th className="pb-2 font-semibold">ATTACK VECTOR</th>
                    <th className="pb-2 font-semibold">SEVERITY</th>
                    <th className="pb-2 font-semibold">SCORE</th>
                    <th className="pb-2 font-semibold">COUNT</th>
                    <th className="pb-2 font-semibold">SAMPLE PAYLOAD</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-cyber-800/60">
                  {riskMatrix.length === 0 ? (
                    <tr>
                      <td colSpan="5" className="py-6 text-center text-slate-600">
                        No classified attack patterns recorded yet.
                      </td>
                    </tr>
                  ) : (
                    riskMatrix.map((item, idx) => (
                      <tr key={idx} className="hover:bg-cyber-850/50 transition">
                        <td className="py-2.5 font-bold text-slate-200">
                          {item.classification}
                          <div className="text-[10px] font-normal text-slate-500">{item.description}</div>
                        </td>
                        <td className="py-2.5">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${getRiskBadgeClass(item.risk_level)}`}>
                            {item.risk_level}
                          </span>
                        </td>
                        <td className="py-2.5">
                          <div className="flex items-center space-x-2">
                            <span className="text-slate-300 font-bold">{item.risk_score}</span>
                            <div className="w-16 bg-cyber-950 h-1.5 rounded-full overflow-hidden">
                              <div
                                className={`h-full ${
                                  item.risk_score >= 80 ? 'bg-red-500' : item.risk_score >= 50 ? 'bg-amber-500' : 'bg-cyan-500'
                                }`}
                                style={{ width: `${item.risk_score}%` }}
                              ></div>
                            </div>
                          </div>
                        </td>
                        <td className="py-2.5 text-cyan-400 font-bold">{item.count}</td>
                        <td className="py-2.5 max-w-[220px] truncate text-slate-400 text-[11px]" title={item.sample_payloads.join(" | ")}>
                          {item.sample_payloads[0] || "-"}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Top Targeted Credentials (5 cols) */}
          <div className="lg:col-span-5 bg-cyber-900 border border-cyber-800 rounded-xl p-4 shadow-2xl flex flex-col">
            <div className="flex items-center justify-between pb-3 border-b border-cyber-800">
              <div className="flex items-center space-x-2">
                <span className="text-cyan-400">🔑</span>
                <h3 className="font-mono text-xs font-bold text-slate-200 uppercase">
                  Top Targeted Credentials
                </h3>
              </div>
              <span className="text-[10px] font-mono text-slate-500">Trapped Auth Permutations</span>
            </div>

            <div className="space-y-4 mt-3 flex-1">
              {credentials.length === 0 ? (
                <div className="text-center py-10 text-slate-600 text-xs font-mono">
                  No login credentials trapped yet.
                </div>
              ) : (
                <div className="space-y-3">
                  {credentials.map((cred, idx) => (
                    <div key={idx} className="space-y-1">
                      <div className="flex justify-between text-xs font-mono">
                        <span className="text-slate-300">
                          <strong className={cred.type === 'username' ? 'text-amber-400' : 'text-cyan-400'}>
                            {cred.type.toUpperCase()}:
                          </strong>{" "}
                          <span className="bg-cyber-950 px-1.5 py-0.5 rounded border border-cyber-800">{cred.credential}</span>
                        </span>
                        <span className="text-slate-400">{cred.count} hits ({cred.percentage}%)</span>
                      </div>
                      <div className="w-full bg-cyber-950 h-2 rounded-full overflow-hidden border border-cyber-800">
                        <div
                          className={`h-full ${cred.type === 'username' ? 'bg-amber-500' : 'bg-cyan-500'}`}
                          style={{ width: `${Math.min(100, cred.percentage * 1.5)}%` }}
                        ></div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </section>

        {/* Section 3: Geographic Threat Distribution */}
        <section className="bg-cyber-900 border border-cyber-800 rounded-xl p-4 shadow-2xl">
          <div className="flex items-center justify-between pb-3 border-b border-cyber-800">
            <div className="flex items-center space-x-2">
              <span className="text-cyan-400">🌍</span>
              <h3 className="font-mono text-xs font-bold text-slate-200 uppercase">
                Adversary Geolocation & Infrastructure Origin
              </h3>
            </div>
            <span className="text-[10px] font-mono text-slate-500">IP-API & Lab Simulation Attribution</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3 mt-3">
            {geoDist.length === 0 ? (
              <div className="col-span-4 text-center py-6 text-slate-600 text-xs font-mono">
                No geolocation data available.
              </div>
            ) : (
              geoDist.map((g, idx) => (
                <div key={idx} className="p-3 bg-cyber-950 rounded-lg border border-cyber-800 space-y-1.5 font-mono">
                  <div className="flex justify-between items-center text-xs">
                    <span className="text-slate-200 font-bold">
                      📍 {g.city}, {g.country}
                    </span>
                    <span className="px-1.5 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-300 text-[10px] font-bold">
                      {g.count} Attacks
                    </span>
                  </div>
                  <div className="text-[11px] text-slate-400">
                    Coords: <span className="text-slate-500">{g.lat ? `${g.lat}, ${g.lon}` : 'N/A'}</span>
                  </div>
                  <div className="text-[10px] text-slate-500 truncate" title={g.ip_samples.join(", ")}>
                    IPs: {g.ip_samples.join(", ")}
                  </div>
                </div>
              ))
            )}
          </div>
        </section>
      </main>

      {/* Payload Inspection Modal */}
      {selectedPayload && (
        <div className="fixed inset-0 bg-black/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-cyber-900 border border-cyber-700 rounded-xl max-w-2xl w-full p-6 space-y-4 shadow-2xl">
            <div className="flex justify-between items-start border-b border-cyber-800 pb-3">
              <div>
                <h3 className="text-sm font-bold text-slate-100 font-mono">Captured Honeypot Interaction #{selectedPayload.id}</h3>
                <p className="text-xs text-slate-400 font-mono">Timestamp: {selectedPayload.timestamp}</p>
              </div>
              <button
                onClick={() => setSelectedPayload(null)}
                className="text-slate-400 hover:text-white text-lg font-mono px-2"
              >
                ✕
              </button>
            </div>

            <div className="space-y-3 font-mono text-xs">
              <div className="grid grid-cols-2 gap-2 bg-cyber-950 p-3 rounded border border-cyber-800">
                <div>Source IP: <strong className="text-cyan-400">{selectedPayload.source_ip}:{selectedPayload.source_port}</strong></div>
                <div>Service: <strong className="text-emerald-400">{selectedPayload.service}</strong></div>
                <div>Event Type: <span className="text-slate-300">{selectedPayload.event_type}</span></div>
                <div>Risk Severity: <span className={`px-1.5 py-0.5 rounded font-bold ${getRiskBadgeClass(selectedPayload.risk_level)}`}>{selectedPayload.risk_level} ({selectedPayload.risk_score})</span></div>
                <div>Classification: <span className="text-amber-400">{selectedPayload.classification}</span></div>
                <div>Origin: <span className="text-slate-300">{selectedPayload.geo?.city}, {selectedPayload.geo?.country}</span></div>
              </div>

              <div>
                <label className="block text-[11px] text-slate-400 mb-1">Captured Payload / Raw Command:</label>
                <pre className="bg-cyber-950 p-3 rounded border border-cyber-800 text-cyan-300 text-xs overflow-x-auto whitespace-pre-wrap">
                  {selectedPayload.payload || "No explicit body payload"}
                </pre>
              </div>

              {selectedPayload.matched_rule && (
                <div className="p-2 rounded bg-red-950/20 border border-red-500/30 text-red-300 text-[11px]">
                  ⚡ <strong>Rule Triggered:</strong> {selectedPayload.matched_rule}
                </div>
              )}
            </div>

            <div className="flex justify-end pt-2">
              <button
                onClick={() => setSelectedPayload(null)}
                className="bg-cyber-800 hover:bg-cyber-700 text-slate-200 px-4 py-1.5 rounded text-xs font-mono"
              >
                Close Inspector
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

ReactDOM.render(<App />, document.getElementById("root"));
