import { useState, useEffect } from 'react'
import { api } from '../api'
import { RefreshCw, ShieldAlert, ShieldCheck, Clock, Zap, Activity, OctagonAlert, TriangleAlert, Info, AlertCircle } from 'lucide-react'
import {
  PieChart, Pie, Cell, Tooltip, ResponsiveContainer,
} from 'recharts'
import Badge from '../components/Badge'

const SEV_COLORS = { critical: '#dc2626', high: '#ca8a04', medium: '#7c3aed', info: '#16a34a' }

const PIE_COLORS = [
  '#3b82f6', '#ef4444', '#f59e0b', '#10b981', '#8b5cf6',
  '#ec4899', '#f97316', '#14b8a6', '#6366f1', '#e11d48', '#06b6d4',
]

const tooltipStyle = {
  background: 'var(--tooltip-bg)',
  border: '1px solid var(--tooltip-border)',
  borderRadius: 10,
  fontSize: 13,
  padding: '10px 14px',
  boxShadow: 'var(--tooltip-shadow)',
}

export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const [predictions, setPredictions] = useState([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)

  const load = async () => {
    setRefreshing(true)
    try {
      const [s, p] = await Promise.all([api.stats(), api.predictions({ limit: 20, attack_only: true })])
      setStats(s)
      setPredictions(p.results)
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
      setRefreshing(false)
    }
  }

  useEffect(() => { load() }, [])

  useEffect(() => {
    const id = setInterval(load, 5000)
    return () => clearInterval(id)
  }, [])

  if (loading) return <div className="loading"><div className="spinner" /> Loading dashboard...</div>

  const attackData = stats?.by_attack_type
    ? Object.entries(stats.by_attack_type).map(([name, value]) => ({ name, value }))
    : []

  const sevData = stats?.by_severity
    ? Object.entries(stats.by_severity).map(([name, value]) => ({ name, value }))
    : []

  const total      = stats?.total_predictions || 0
  const attacks    = stats?.total_attacks || 0
  const benign     = total - attacks
  const attackRate = total > 0 ? (attacks / total) * 100 : 0
  const isHighRate = attackRate > 20

  const topAttackSources = [...attackData]
    .filter(d => d.name !== 'BENIGN')
    .sort((a, b) => b.value - a.value)
    .slice(0, 5)

  return (
    <div className="dash">
      {/* Page Header */}
      <div className="dash-header">
        <div>
          <h2 className="dash-title">Dashboard</h2>
          <p className="dash-subtitle">Real-time overview of network intrusion detection</p>
        </div>
        <button className="btn btn-primary" onClick={load} disabled={refreshing}>
          <RefreshCw size={15} className={refreshing ? 'spin' : ''} /> {refreshing ? 'Refreshing…' : 'Refresh'}
        </button>
      </div>

      {/* Stat Cards */}
      <div className="dash-stats">
        <div className="dash-stat-card">
          <div className="dash-stat-icon" style={{ background: 'var(--stat-accent-bg)', color: 'var(--accent)' }}>
            <Activity size={22} />
          </div>
          <div className="dash-stat-info">
            <span className="dash-stat-label">Total Predictions</span>
            <span className="dash-stat-value" style={{ color: 'var(--accent)' }}>
              {total.toLocaleString()}
            </span>
            <span className="dash-stat-sub">All analyzed flows</span>
          </div>
        </div>

        <div className="dash-stat-card">
          <div className="dash-stat-icon" style={{ background: 'var(--stat-danger-bg)', color: 'var(--danger)' }}>
            <ShieldAlert size={22} />
          </div>
          <div className="dash-stat-info">
            <span className="dash-stat-label">Attacks Detected</span>
            <span className="dash-stat-value" style={{ color: 'var(--danger)' }}>
              {attacks.toLocaleString()}
            </span>
            <span className="dash-stat-sub">
              {total > 0 ? `${attackRate.toFixed(1)}% attack rate` : 'No data yet'}
              {' '}
              {isHighRate
                ? <span style={{ color: 'var(--danger)', fontWeight: 600 }}>▲ High</span>
                : <span style={{ color: 'var(--success)', fontWeight: 600 }}>▼ Normal</span>}
            </span>
          </div>
        </div>

        <div className="dash-stat-card">
          <div className="dash-stat-icon" style={{ background: 'var(--stat-success-bg)', color: 'var(--success)' }}>
            <ShieldCheck size={22} />
          </div>
          <div className="dash-stat-info">
            <span className="dash-stat-label">Benign Traffic</span>
            <span className="dash-stat-value" style={{ color: 'var(--success)' }}>
              {benign.toLocaleString()}
            </span>
            <span className="dash-stat-sub">
              {total > 0 ? `${(100 - attackRate).toFixed(1)}% clean traffic` : 'No data yet'}
            </span>
          </div>
        </div>

        <div className="dash-stat-card">
          <div className="dash-stat-icon" style={{ background: 'var(--stat-warning-bg)', color: 'var(--warning)' }}>
            <Zap size={22} />
          </div>
          <div className="dash-stat-info">
            <span className="dash-stat-label">Avg Confidence</span>
            <span className="dash-stat-value">
              {stats?.avg_confidence ? `${(stats.avg_confidence * 100).toFixed(1)}%` : '—'}
            </span>
            <span className="dash-stat-sub">Model certainty</span>
          </div>
        </div>

        <div className="dash-stat-card">
          <div className="dash-stat-icon" style={{ background: 'var(--stat-purple-bg)', color: 'var(--purple)' }}>
            <Clock size={22} />
          </div>
          <div className="dash-stat-info">
            <span className="dash-stat-label">Avg Inference</span>
            <span className="dash-stat-value">
              {stats?.avg_inference_ms ? `${stats.avg_inference_ms.toFixed(1)}ms` : '—'}
            </span>
            <span className="dash-stat-sub">Per-flow latency</span>
          </div>
        </div>
      </div>

      {/* Severity cards */}
      {sevData.length > 0 && (
        <div className="sev-grid">
          {['critical', 'high', 'medium', 'info'].map(sev => {
            const count = sevData.find(s => s.name === sev)?.value || 0
            const pct = total > 0 ? ((count / total) * 100).toFixed(1) : '0.0'
            const conf = {
              critical: { icon: <OctagonAlert size={16} />,   bg: 'var(--sev-critical-bg)', border: 'var(--sev-critical-border)', color: 'var(--danger)',  track: 'var(--sev-critical-track)' },
              high:     { icon: <TriangleAlert size={16} />,  bg: 'var(--sev-high-bg)',     border: 'var(--sev-high-border)',     color: 'var(--warning)', track: 'var(--sev-high-track)' },
              medium:   { icon: <AlertCircle size={16} />,    bg: 'var(--sev-medium-bg)',   border: 'var(--sev-medium-border)',   color: 'var(--purple)',  track: 'var(--sev-medium-track)' },
              info:     { icon: <Info size={16} />,            bg: 'var(--sev-info-bg)',     border: 'var(--sev-info-border)',     color: 'var(--success)', track: 'var(--sev-info-track)' },
            }[sev]
            return (
              <div key={sev} className="sev-card" style={{ background: conf.bg, borderColor: conf.border }}>
                <div className="sev-card-top">
                  <span className="sev-card-icon" style={{ background: conf.color, color: '#fff' }}>
                    {conf.icon}
                  </span>
                  <span className="sev-card-name" style={{ color: conf.color }}>
                    {sev}
                  </span>
                </div>
                <span className="sev-card-value" style={{ color: conf.color }}>
                  {count.toLocaleString()}
                </span>
                <div className="sev-card-bar" style={{ background: conf.track }}>
                  <div
                    className="sev-card-fill"
                    style={{ width: `${pct}%`, background: conf.color }}
                  />
                </div>
                <span className="sev-card-pct">{pct}% of total</span>
              </div>
            )
          })}
        </div>
      )}

      {/* Two‑column: Distribution + Top Attacks */}
      <div className="dash-row">
        {/* Left — Distribution donut + legend */}
        {attackData.length > 0 && (
          <div className="card dash-col-left">
            <div className="card-header"><h3>Attack Distribution</h3></div>
            <div className="dist-donut">
              <ResponsiveContainer width="100%" height={220}>
                <PieChart>
                  <Pie
                    data={attackData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    outerRadius={90}
                    innerRadius={56}
                    paddingAngle={3}
                    strokeWidth={2}
                    stroke="var(--pie-stroke)"
                  >
                    {attackData.map((_, i) => (
                      <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={tooltipStyle}
                    formatter={(value) => [value.toLocaleString(), 'Count']}
                    itemStyle={{ fontSize: 14, fontWeight: 500, color: 'var(--tooltip-text)' }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="dist-donut-center">
                <span className="dist-donut-total">{total.toLocaleString()}</span>
                <span className="dist-donut-label">Total</span>
              </div>
            </div>

            <div className="dist-legend">
              {[...attackData]
                .sort((a, b) => b.value - a.value)
                .map((item) => {
                  const pct = total > 0 ? ((item.value / total) * 100) : 0
                  const colorIdx = attackData.indexOf(item) % PIE_COLORS.length
                  return (
                    <div key={item.name} className="dist-legend-row">
                      <div className="dist-legend-dot" style={{ background: PIE_COLORS[colorIdx] }} />
                      <span className="dist-legend-name">{item.name}</span>
                      <span className="dist-legend-count">{item.value.toLocaleString()}</span>
                      <div className="dist-legend-bar-track">
                        <div
                          className="dist-legend-bar-fill"
                          style={{ width: `${pct}%`, background: PIE_COLORS[colorIdx] }}
                        />
                      </div>
                      <span className="dist-legend-pct">{pct.toFixed(1)}%</span>
                    </div>
                  )
                })}
            </div>
          </div>
        )}

        {/* Right — Top Attack Types */}
        {topAttackSources.length > 0 && (
          <div className="card dash-col-right">
            <div className="card-header">
              <h3>Top Attack Types</h3>
              <span className="mini-badge">{topAttackSources.length} types</span>
            </div>
            <div className="top-attacks-list">
              {topAttackSources.map((item, idx) => {
                const share = attacks > 0 ? ((item.value / attacks) * 100) : 0
                return (
                  <div key={item.name} className="top-attack-row">
                    <span className="top-attack-rank">{idx + 1}</span>
                    <div className="top-attack-info">
                      <div className="top-attack-name-row">
                        <span className="top-attack-name">{item.name}</span>
                        <span className="top-attack-count mono">{item.value.toLocaleString()}</span>
                      </div>
                      <div className="top-attack-bar-track">
                        <div
                          className="top-attack-bar-fill"
                          style={{
                            width: `${share}%`,
                            background: PIE_COLORS[idx % PIE_COLORS.length],
                          }}
                        />
                      </div>
                    </div>
                    <span className="top-attack-pct mono">{share.toFixed(1)}%</span>
                  </div>
                )
              })}
            </div>
          </div>
        )}
      </div>

      {/* Recent Predictions */}
      <div className="dash-section">
        <div className="pred-header">
          <div>
            <h3 className="pred-title">Recent Attacks</h3>
            <span className="pred-count">{predictions.length} latest attacks</span>
          </div>
          <button className="btn btn-primary" onClick={load} disabled={refreshing}>
            <RefreshCw size={16} className={refreshing ? 'spin' : ''} /> {refreshing ? 'Refreshing…' : 'Refresh'}
          </button>
        </div>

        {predictions.length === 0 ? (
          <div className="card empty-state">
            <ShieldCheck size={56} />
            <p style={{ fontSize: 17, marginTop: 14 }}>No attacks detected. Recent traffic is benign.</p>
          </div>
        ) : (
          <div className="pred-list">
            {predictions.map(p => (
              <div key={p.id} className={`pred-card ${p.is_attack ? 'pred-attack' : 'pred-benign'}`}>
                {/* Left: icon */}
                <div className={`pred-icon ${p.is_attack ? 'pred-icon-attack' : 'pred-icon-safe'}`}>
                  {p.is_attack
                    ? <ShieldAlert size={28} />
                    : <ShieldCheck size={28} />
                  }
                </div>

                {/* Middle: info */}
                <div className="pred-body">
                  <div className="pred-top-row">
                    <span className={`pred-type ${p.is_attack ? 'pred-type-attack' : 'pred-type-safe'}`}>
                      {p.attack_type}
                    </span>
                    <Badge severity={p.severity} />
                  </div>

                  <div className="pred-meta">
                    <span className="pred-meta-item">
                      <span className="pred-meta-label">IP</span>
                      <span className="pred-meta-val mono">{p.src_ip || '—'}</span>
                    </span>
                    <span className="pred-meta-sep" />
                    <span className="pred-meta-item">
                      <span className="pred-meta-label">Group</span>
                      <span className="pred-meta-val">{p.group_pred || '—'}</span>
                    </span>
                    <span className="pred-meta-sep" />
                    <span className="pred-meta-item">
                      <span className="pred-meta-label">Latency</span>
                      <span className="pred-meta-val mono">{p.inference_ms?.toFixed(1)}ms</span>
                    </span>
                    <span className="pred-meta-sep" />
                    <span className="pred-meta-item">
                      <span className="pred-meta-label">Time</span>
                      <span className="pred-meta-val mono">{new Date(p.created_at).toLocaleTimeString()}</span>
                    </span>
                  </div>
                </div>

                {/* Right: confidence */}
                <div className="pred-confidence">
                  <span className="pred-conf-label">Confidence</span>
                  <span className={`pred-conf-value mono ${
                    p.confidence >= 0.9 ? 'pred-conf-high' :
                    p.confidence >= 0.7 ? 'pred-conf-mid' : 'pred-conf-low'
                  }`}>
                    {(p.confidence * 100).toFixed(1)}%
                  </span>
                  <div className="pred-conf-track">
                    <div
                      className="pred-conf-fill"
                      style={{
                        width: `${(p.confidence * 100).toFixed(1)}%`,
                        background: p.confidence >= 0.9 ? '#10b981'
                          : p.confidence >= 0.7 ? '#3b82f6' : '#f59e0b',
                      }}
                    />
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
