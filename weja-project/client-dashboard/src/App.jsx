import { useState, useEffect, useCallback } from "react";
import axios from "axios";
import {
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import "./App.css";

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:3000/api";

const COLORS = {
  SQL_INJECTION: "#ff4757",
  XSS: "#ffa502",
  PATH_TRAVERSAL: "#a55eea",
  COMMAND_INJECTION: "#ff6b81",
  BLACKLISTED: "#2f3640",
  SAFE: "#26de81",
  ERROR: "#6c6c80",
};

const FALLBACK_COLORS = [
  "#4f8eff",
  "#ff6b81",
  "#26de81",
  "#ffa502",
  "#a55eea",
  "#2f3640",
  "#6c6c80",
];

const normalizeAttackType = (type = "") =>
  String(type)
    .toUpperCase()
    .replace(/[^A-Z0-9]+/g, "_")
    .replace(/^_+|_+$/g, "");

const getChartColor = (type, index) => {
  const normalizedType = normalizeAttackType(type);
  return (
    COLORS[normalizedType] || FALLBACK_COLORS[index % FALLBACK_COLORS.length]
  );
};

function App() {
  const [logs, setLogs] = useState([]);
  const [stats, setStats] = useState(null);
  const [health, setHealth] = useState(null);
  const [topAttackers, setTopAttackers] = useState([]);
  const [topAttackedRoutes, setTopAttackedRoutes] = useState([]);
  const [blacklist, setBlacklist] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [activeTab, setActiveTab] = useState("live"); // 'live' | 'attackers' | 'routes' | 'blacklist'
  const [rateLimit, setRateLimit] = useState({
    windowMs: 60000,
    maxRequests: 50,
  });
  const [isEditingRateLimit, setIsEditingRateLimit] = useState(false);

  const fetchData = useCallback(async () => {
    try {
      setError(null);
      const [
        logsRes,
        statsRes,
        healthRes,
        attackersRes,
        blacklistRes,
        rateLimitRes,
        topAttackedRoutesRes,
      ] = await Promise.all([
        axios.get(`${API_URL}/logs?limit=50`),
        axios.get(`${API_URL}/stats`),
        axios.get(`${API_URL}/health`),
        axios.get(`${API_URL}/top-attackers?limit=10`),
        axios.get(`${API_URL}/blacklist`),
        axios.get(`${API_URL}/rate-limit`),
        axios.get(`${API_URL}/top-attacked-routes?limit=10`),
      ]);
      setLogs(logsRes.data.logs);
      setStats(statsRes.data);
      setHealth(healthRes.data);
      setTopAttackers(attackersRes.data.attackers || []);
      setBlacklist(blacklistRes.data.blacklist || []);
      setTopAttackedRoutes(topAttackedRoutesRes.data.routes || []);
      if (!isEditingRateLimit) {
        setRateLimit(rateLimitRes.data);
      }
    } catch (err) {
      setError("Unable to connect to WAF Gateway");
      console.error("Failed to fetch data:", err);
    } finally {
      setLoading(false);
    }
  }, [isEditingRateLimit]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000); // Refresh every 5s
    return () => clearInterval(interval);
  }, [fetchData]);

  const formatTime = (timestamp) => {
    const date = new Date(timestamp);
    return date.toLocaleTimeString("en-US", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  };

  const getFlagEmoji = (countryCode) => {
    if (!countryCode || countryCode === "XX") return "🌐";
    const codePoints = countryCode
      .toUpperCase()
      .split("")
      .map((char) => 127397 + char.charCodeAt(0));
    return String.fromCodePoint(...codePoints);
  };

  const removeFromBlacklist = async (ip) => {
    try {
      await axios.delete(`${API_URL}/blacklist/${encodeURIComponent(ip)}`);
      fetchData();
    } catch (err) {
      console.error("Failed to remove IP from blacklist:", err);
    }
  };

  const updateRateLimit = async () => {
    try {
      await axios.post(`${API_URL}/rate-limit`, {
        windowMs: rateLimit.windowMs,
        maxRequests: rateLimit.maxRequests,
      });

      setIsEditingRateLimit(false);
      fetchData();
      alert("Rate limit updated successfully");
    } catch (err) {
      console.error("Failed to update rate limit:", err);
    }
  };

  const isHealthy =
    health && health.waf === "healthy" && health.aiEngine === "healthy";

  return (
    <div className="app-container">
      {/* Header */}
      <header className="header">
        <h1>
          <span className="shield-icon">🛡️</span>
          WEJÀ Dashboard
        </h1>
        <div className="header-status">
          <div className={`status-indicator ${isHealthy ? "" : "error"}`}>
            <span className="status-dot"></span>
            {isHealthy ? "All Systems Operational" : "System Issue Detected"}
          </div>
          <button
            className="refresh-btn"
            onClick={fetchData}
            disabled={loading}
          >
            {loading ? "Refreshing..." : "↻ Refresh"}
          </button>
        </div>
      </header>

      {/* Main Content */}
      <main className="main-content">
        {error && (
          <div className="error-banner">
            ⚠️ {error} - Make sure WAF Gateway is running on port 3000
          </div>
        )}

        {/* Stats Row */}
        <div className="stats-row">
          <div className="stat-card">
            <span className="stat-label">Total Requests</span>
            <span className="stat-value total">
              {stats?.summary?.total || 0}
            </span>
          </div>
          <div className="stat-card blocked">
            <span className="stat-label">Blocked Attacks</span>
            <span className="stat-value blocked">
              {stats?.summary?.blocked || 0}
            </span>
          </div>
          <div className="stat-card allowed">
            <span className="stat-label">Allowed Requests</span>
            <span className="stat-value allowed">
              {stats?.summary?.allowed || 0}
            </span>
          </div>
          <div className="stat-card">
            <span className="stat-label">Block Rate</span>
            <span className="stat-value rate">
              {stats?.summary?.blockRate || 0}%
            </span>
          </div>
          <div className="stat-card blacklist">
            <span className="stat-label">Blacklisted IPs</span>
            <span className="stat-value blacklist">
              {health?.blacklistedIPs || blacklist.length || 0}
            </span>
          </div>
        </div>

        {/* Charts */}
        <div className="card">
          <div className="card-header">
            <h2 className="card-title">📊 Attack Type Distribution</h2>
          </div>
          <div className="card-body">
            {stats?.attackTypes?.length > 0 ? (
              <div className="chart-container">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={stats.attackTypes}
                      dataKey="count"
                      nameKey="type"
                      cx="50%"
                      cy="50%"
                      outerRadius={100}
                      label={({ type, count }) => `${type}: ${count}`}
                    >
                      {stats.attackTypes.map((entry, index) => (
                        <Cell
                          key={`cell-${index}`}
                          fill={getChartColor(entry.type, index)}
                        />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        background: "#1a1a2e",
                        border: "1px solid rgba(255,255,255,0.1)",
                        borderRadius: "8px",
                      }}
                    />
                    <Legend />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <div className="empty-state">
                <span className="empty-state-icon">📈</span>
                <p>No attack data yet</p>
              </div>
            )}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <h2 className="card-title">📉 Traffic Overview</h2>
          </div>
          <div className="card-body">
            {stats?.attackTypes?.length > 0 ? (
              <div className="chart-container">
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart data={stats.attackTypes}>
                    <CartesianGrid
                      strokeDasharray="3 3"
                      stroke="rgba(255,255,255,0.1)"
                    />
                    <XAxis
                      dataKey="type"
                      stroke="#a0a0b8"
                      tick={{ fontSize: 12 }}
                    />
                    <YAxis stroke="#a0a0b8" />
                    <Tooltip
                      contentStyle={{
                        background: "#1a1a2e",
                        border: "1px solid rgba(255,255,255,0.1)",
                        borderRadius: "8px",
                      }}
                    />
                    <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                      {stats.attackTypes.map((entry, index) => (
                        <Cell
                          key={`bar-cell-${index}`}
                          fill={getChartColor(entry.type, index)}
                        />
                      ))}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            ) : (
              <div className="empty-state">
                <span className="empty-state-icon">📊</span>
                <p>No traffic data yet</p>
              </div>
            )}
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="card" style={{ gridColumn: "1 / -1" }}>
          <div className="card-header">
            <div className="tab-nav">
              <button
                className={`tab-btn ${activeTab === "live" ? "active" : ""}`}
                onClick={() => setActiveTab("live")}
              >
                🔴 Live Feed
              </button>
              <button
                className={`tab-btn ${activeTab === "attackers" ? "active" : ""}`}
                onClick={() => setActiveTab("attackers")}
              >
                🌍 Top Attackers
              </button>
              <button
                className={`tab-btn ${activeTab === "routes" ? "active" : ""}`}
                onClick={() => setActiveTab("routes")}
              >
                🎯 Top Attacked Routes
              </button>
              <button
                className={`tab-btn ${activeTab === "blacklist" ? "active" : ""}`}
                onClick={() => setActiveTab("blacklist")}
              >
                🚫 Blacklist ({blacklist.length})
              </button>
            </div>
          </div>

          <div className="card-body">
            {/* Live Feed Tab */}
            {activeTab === "live" && (
              <div className="live-feed">
                <div className="feed-header">
                  <span className="log-count">{logs.length} entries</span>
                </div>
                {loading && logs.length === 0 ? (
                  <div className="loading">
                    <div className="spinner"></div>
                  </div>
                ) : logs.length > 0 ? (
                  logs.map((log) => (
                    <div
                      key={log._id}
                      className={`log-entry ${log.blocked ? "blocked" : "allowed"}`}
                    >
                      <span
                        className={`log-status ${log.blocked ? "blocked" : "allowed"}`}
                      >
                        {log.blocked ? "🚫 BLOCKED" : "✅ ALLOWED"}
                      </span>
                      <span className="log-method">{log.method}</span>
                      <span className="log-path">{log.path}</span>
                      <span className="log-ip">{log.sourceIp}</span>
                      <span
                        className="log-geo"
                        style={{ fontSize: "0.9em", color: "#a0a0b8" }}
                      >
                        {log.geo
                          ? `${getFlagEmoji(log.geo.countryCode)} ${log.geo.city || "Unknown"}`
                          : ""}
                      </span>
                      <span className="log-type">{log.attackType}</span>
                      <span className="log-time">
                        {formatTime(log.timestamp)}
                      </span>
                    </div>
                  ))
                ) : (
                  <div className="empty-state">
                    <span className="empty-state-icon">📭</span>
                    <p>No requests logged yet</p>
                    <p style={{ fontSize: "0.85rem" }}>
                      Send requests to http://localhost:3000/proxy/* to see them
                      here
                    </p>
                  </div>
                )}
              </div>
            )}

            {/* Top Attackers Tab */}
            {activeTab === "attackers" && (
              <div className="attackers-list">
                {topAttackers.length > 0 ? (
                  <table className="attackers-table">
                    <thead>
                      <tr>
                        <th>Rank</th>
                        <th>IP Address</th>
                        <th>Location</th>
                        <th>Attacks</th>
                        <th>Top Attack Type</th>
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {topAttackers.map((attacker, index) => (
                        <tr
                          key={attacker.ip}
                          className={
                            attacker.isBlacklisted ? "blacklisted-row" : ""
                          }
                        >
                          <td className="rank">#{index + 1}</td>
                          <td className="ip-cell">
                            <code>{attacker.ip}</code>
                          </td>
                          <td className="location-cell">
                            <span className="country-flag">
                              {getFlagEmoji(attacker.geo?.countryCode)}
                            </span>
                            {attacker.geo?.city}, {attacker.geo?.country}
                          </td>
                          <td className="attack-count">
                            <span className="count-badge">
                              {attacker.attackCount}
                            </span>
                          </td>
                          <td className="attack-type">
                            {attacker.attackTypes?.[0]?.type || "N/A"}
                          </td>
                          <td className="status-cell">
                            {attacker.isBlacklisted ? (
                              <span className="status-badge blacklisted">
                                🚫 Blacklisted
                              </span>
                            ) : (
                              <span className="status-badge active">
                                ⚠️ Active
                              </span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <div className="empty-state">
                    <span className="empty-state-icon">🌍</span>
                    <p>No attackers detected yet</p>
                  </div>
                )}
              </div>
            )}

            {/* Top Attacked Routes Tab */}
            {activeTab === "routes" && (
              <div className="routes-list">
                {topAttackedRoutes.length > 0 ? (
                  <table className="attackers-table">
                    <thead>
                      <tr>
                        <th>Rank</th>
                        <th>Route</th>
                        <th>Attacks</th>
                        <th>Unique Attackers</th>
                        <th>Top Attack Type</th>
                        <th>Top Attacker</th>
                      </tr>
                    </thead>
                    <tbody>
                      {topAttackedRoutes.map((route, index) => (
                        <tr key={route.route}>
                          <td className="rank">#{index + 1}</td>
                          <td className="route-cell">
                            <code>{route.route}</code>
                          </td>
                          <td className="attack-count">
                            <span className="count-badge">
                              {route.attackCount}
                            </span>
                          </td>
                          <td className="unique-attackers">
                            <span className="count-badge">
                              {route.uniqueAttackers}
                            </span>
                          </td>
                          <td className="attack-type">
                            {route.attackTypes?.[0]?.type || "N/A"} (
                            {route.attackTypes?.[0]?.count || 0})
                          </td>
                          <td className="top-attacker">
                            {route.topAttackers?.[0]?.ip ? (
                              <code>{route.topAttackers[0].ip}</code>
                            ) : (
                              "N/A"
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <div className="empty-state">
                    <span className="empty-state-icon">🎯</span>
                    <p>No attacked routes detected yet</p>
                  </div>
                )}
              </div>
            )}

            {/* Blacklist Tab */}
            {activeTab === "blacklist" && (
              <div className="blacklist-list">
                {blacklist.length > 0 ? (
                  <table className="attackers-table">
                    <thead>
                      <tr>
                        <th>IP Address</th>
                        <th>Location</th>
                        <th>Reason</th>
                        <th>Expires In</th>
                        <th>Type</th>
                        <th>Action</th>
                      </tr>
                    </thead>
                    <tbody>
                      {blacklist.map((entry) => (
                        <tr key={entry.ip}>
                          <td className="ip-cell">
                            <code>{entry.ip}</code>
                          </td>
                          <td className="location-cell">
                            <span className="country-flag">
                              {getFlagEmoji(entry.geo?.countryCode)}
                            </span>
                            {entry.geo?.city}, {entry.geo?.country}
                          </td>
                          <td className="reason-cell">{entry.reason}</td>
                          <td className="expires-cell">
                            {Math.floor(entry.remainingSeconds / 60)}m{" "}
                            {entry.remainingSeconds % 60}s
                          </td>
                          <td>
                            {entry.autoBlocked ? (
                              <span className="type-badge auto">Auto</span>
                            ) : (
                              <span className="type-badge manual">Manual</span>
                            )}
                          </td>
                          <td>
                            <button
                              className="remove-btn"
                              onClick={() => removeFromBlacklist(entry.ip)}
                            >
                              Remove
                            </button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                ) : (
                  <div className="empty-state">
                    <span className="empty-state-icon">✅</span>
                    <p>No IPs currently blacklisted</p>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
        {/* Rate Limit Settings */}
        <div className="rate-limit-card">
          <div className="rate-limit-header">
            <div className="rate-icon">⚙️</div>
            <div>
              <h2>Rate Limit Settings</h2>
              <p>
                Configure the global rate limiting rules for incoming requests.
              </p>
            </div>
          </div>

          <div className="rate-limit-divider"></div>

          <div className="rate-limit-grid">
            <div className="rate-box">
              <h3>🕒 Time Window</h3>
              <p>The time window in which requests are counted.</p>

              <input
                type="number"
                value={rateLimit.windowMs / 1000}
                onFocus={() => setIsEditingRateLimit(true)}
                onChange={(e) =>
                  setRateLimit((prev) => ({
                    ...prev,
                    windowMs: Number(e.target.value) * 1000,
                  }))
                }
              />

              <small>Minimum 1 second</small>
            </div>

            <div className="rate-box">
              <h3>📊 Max Requests</h3>
              <p>Maximum number of requests allowed.</p>

              <input
                type="number"
                value={rateLimit.maxRequests}
                onFocus={() => setIsEditingRateLimit(true)}
                onChange={(e) =>
                  setRateLimit((prev) => ({
                    ...prev,
                    maxRequests: Number(e.target.value),
                  }))
                }
              />

              <small>Minimum 1 request</small>
            </div>
          </div>

          <div className="rate-info">
            ℹ️ Changes take effect immediately after saving.
          </div>

          <button className="save-btn" onClick={updateRateLimit}>
            💾 Save
          </button>

          <p className="save-note">
            Click Save to update the rate limit configuration.
          </p>
        </div>
      </main>
    </div>
  );
}

export default App;
