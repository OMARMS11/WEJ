import { useState, useEffect, useCallback } from 'react'
import axios from 'axios'
import {
  BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend
} from 'recharts'
import './App.css'

const API_URL = 'http://localhost:3000/api'

const COLORS = {
  SQL_INJECTION: '#ff4757',
  XSS: '#ffa502',
  PATH_TRAVERSAL: '#a55eea',
  COMMAND_INJECTION: '#ff6b81',
  BLACKLISTED: '#2f3640',
  SAFE: '#26de81',
  ERROR: '#6c6c80'
}

function App() {
  const [logs, setLogs] = useState([])
  const [stats, setStats] = useState(null)
  const [health, setHealth] = useState(null)
  const [topAttackers, setTopAttackers] = useState([])
  const [blacklist, setBlacklist] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [activeTab, setActiveTab] = useState('live') // 'live' | 'attackers' | 'blacklist'

  const fetchData = useCallback(async () => {
    try {
      setError(null)
      const [logsRes, statsRes, healthRes, attackersRes, blacklistRes] = await Promise.all([
        axios.get(`${API_URL}/logs?limit=50`),
        axios.get(`${API_URL}/stats`),
        axios.get(`${API_URL}/health`),
        axios.get(`${API_URL}/top-attackers?limit=10`),
        axios.get(`${API_URL}/blacklist`)
      ])
      setLogs(logsRes.data.logs)
      setStats(statsRes.data)
      setHealth(healthRes.data)
      setTopAttackers(attackersRes.data.attackers || [])
      setBlacklist(blacklistRes.data.blacklist || [])
    } catch (err) {
      setError('Unable to connect to WAF Gateway')
      console.error('Failed to fetch data:', err)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 5000) // Refresh every 5s
    return () => clearInterval(interval)
  }, [fetchData])

  const formatTime = (timestamp) => {
    const date = new Date(timestamp)
    return date.toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit'
    })
  }

  const removeFromBlacklist = async (ip) => {
    try {
      await axios.delete(`${API_URL}/blacklist/${encodeURIComponent(ip)}`)
      fetchData()
    } catch (err) {
      console.error('Failed to remove IP from blacklist:', err)
    }
  }

  const isHealthy = health &&
    health.waf === 'healthy' &&
    health.aiEngine === 'healthy'

  return (
    <div className="app-container">
      {/* Header */}
      <header className="header">
        <h1>
          <span className="shield-icon">🛡️</span>
          WEJÀ Dashboard
        </h1>
        <div className="header-status">
          <div className={`status-indicator ${isHealthy ? '' : 'error'}`}>
            <span className="status-dot"></span>
            {isHealthy ? 'All Systems Operational' : 'System Issue Detected'}
          </div>
          <button
            className="refresh-btn"
            onClick={fetchData}
            disabled={loading}
          >
            {loading ? 'Refreshing...' : '↻ Refresh'}
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
                          fill={COLORS[entry.type] || '#4f8eff'}
                        />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{
                        background: '#1a1a2e',
                        border: '1px solid rgba(255,255,255,0.1)',
                        borderRadius: '8px'
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
                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.1)" />
                    <XAxis
                      dataKey="type"
                      stroke="#a0a0b8"
                      tick={{ fontSize: 12 }}
                    />
                    <YAxis stroke="#a0a0b8" />
                    <Tooltip
                      contentStyle={{
                        background: '#1a1a2e',
                        border: '1px solid rgba(255,255,255,0.1)',
                        borderRadius: '8px'
                      }}
                    />
                    <Bar
                      dataKey="count"
                      fill="#4f8eff"
                      radius={[4, 4, 0, 0]}
                    />
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
        <div className="card" style={{ gridColumn: '1 / -1' }}>
          <div className="card-header">
            <div className="tab-nav">
              <button
                className={`tab-btn ${activeTab === 'live' ? 'active' : ''}`}
                onClick={() => setActiveTab('live')}
              >
                🔴 Live Feed
              </button>
              <button
                className={`tab-btn ${activeTab === 'attackers' ? 'active' : ''}`}
                onClick={() => setActiveTab('attackers')}
              >
                🌍 Top Attackers
              </button>
              <button
                className={`tab-btn ${activeTab === 'blacklist' ? 'active' : ''}`}
                onClick={() => setActiveTab('blacklist')}
              >
                🚫 Blacklist ({blacklist.length})
              </button>
            </div>
          </div>

          <div className="card-body">
            {/* Live Feed Tab */}
            {activeTab === 'live' && (
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
                      className={`log-entry ${log.blocked ? 'blocked' : 'allowed'}`}
                    >
                      <span className={`log-status ${log.blocked ? 'blocked' : 'allowed'}`}>
                        {log.blocked ? '🚫 BLOCKED' : '✅ ALLOWED'}
                      </span>
                      <span className="log-method">{log.method}</span>
                      <span className="log-path">{log.path}</span>
                      <span className="log-ip">{log.sourceIp}</span>
                      <span className="log-type">{log.attackType}</span>
                      <span className="log-time">{formatTime(log.timestamp)}</span>
                    </div>
                  ))
                ) : (
                  <div className="empty-state">
                    <span className="empty-state-icon">📭</span>
                    <p>No requests logged yet</p>
                    <p style={{ fontSize: '0.85rem' }}>
                      Send requests to http://localhost:3000/proxy/* to see them here
                    </p>
                  </div>
                )}
              </div>
            )}

            {/* Top Attackers Tab */}
            {activeTab === 'attackers' && (
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
                        <tr key={attacker.ip} className={attacker.isBlacklisted ? 'blacklisted-row' : ''}>
                          <td className="rank">#{index + 1}</td>
                          <td className="ip-cell">
                            <code>{attacker.ip}</code>
                          </td>
                          <td className="location-cell">
                            <span className="country-flag">🌐</span>
                            {attacker.geo?.city}, {attacker.geo?.country}
                          </td>
                          <td className="attack-count">
                            <span className="count-badge">{attacker.attackCount}</span>
                          </td>
                          <td className="attack-type">
                            {attacker.attackTypes?.[0]?.type || 'N/A'}
                          </td>
                          <td className="status-cell">
                            {attacker.isBlacklisted ? (
                              <span className="status-badge blacklisted">🚫 Blacklisted</span>
                            ) : (
                              <span className="status-badge active">⚠️ Active</span>
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

            {/* Blacklist Tab */}
            {activeTab === 'blacklist' && (
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
                            <span className="country-flag">🌐</span>
                            {entry.geo?.city}, {entry.geo?.country}
                          </td>
                          <td className="reason-cell">{entry.reason}</td>
                          <td className="expires-cell">
                            {Math.floor(entry.remainingSeconds / 60)}m {entry.remainingSeconds % 60}s
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
      </main>
    </div>
  )
}

export default App

