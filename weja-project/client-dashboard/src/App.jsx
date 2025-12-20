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
  SAFE: '#26de81',
  ERROR: '#6c6c80'
}

function App() {
  const [logs, setLogs] = useState([])
  const [stats, setStats] = useState(null)
  const [health, setHealth] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const fetchData = useCallback(async () => {
    try {
      setError(null)
      const [logsRes, statsRes, healthRes] = await Promise.all([
        axios.get(`${API_URL}/logs?limit=50`),
        axios.get(`${API_URL}/stats`),
        axios.get(`${API_URL}/health`)
      ])
      setLogs(logsRes.data.logs)
      setStats(statsRes.data)
      setHealth(healthRes.data)
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

  const isHealthy = health &&
    health.waf === 'healthy' &&
    health.aiEngine === 'healthy' &&
    health.database === 'healthy'

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

        {/* Live Feed */}
        <div className="card" style={{ gridColumn: '1 / -1' }}>
          <div className="card-header">
            <h2 className="card-title">🔴 Live Request Feed</h2>
            <span className="log-count">{logs.length} entries</span>
          </div>
          <div className="card-body live-feed">
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
        </div>
      </main>
    </div>
  )
}

export default App
