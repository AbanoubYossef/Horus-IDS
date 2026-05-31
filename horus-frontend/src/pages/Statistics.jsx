import { useState, useEffect } from 'react'
import { api } from '../api'

const FEATURE_DESCRIPTIONS = {
  'Init_Win_bytes_forward':   'Initial TCP window size from client to server. Abnormal values reveal OS fingerprinting, scanners, and crafted packets.',
  'Init_Win_bytes_backward':  'Initial TCP window size from server to client. Mismatches with forward window help detect spoofed or tunneled connections.',
  'Flow IAT Min':             'Minimum inter-arrival time between packets in the flow. Near-zero values signal automated tools and flood attacks.',
  'Flow IAT Mean':            'Average inter-arrival time between packets. Distinguishes human-driven traffic from bot-generated patterns.',
  'Fwd IAT Min':              'Minimum inter-arrival time in the forward direction. Rapid bursts indicate scanning, brute-force, or DDoS.',
  'Flow Duration':            'Total time (µs) from first to last packet. Long flows suggest data exfiltration or persistent C2 channels.',
  'Fwd Header Length':        'Total bytes in forward packet headers. Unusual header sizes can indicate protocol abuse or tunneling.',
  'Flow Packets/s':           'Packet rate across the entire flow. Extreme spikes correlate with volumetric DDoS attacks.',
  'Bwd Packets/s':            'Backward packet rate (server to client). High rates may indicate amplification or reflection attacks.',
  'Flow Bytes/s':             'Total bytes transferred per second. Extremely high values correlate with DDoS flood patterns.',
  'Fwd Packets/s':            'Forward packet rate (client to server). Spikes identify SYN floods, brute-force, and scan traffic.',
  'Bwd Packet Length Max':    'Largest packet in the backward direction. Oversized responses can signal data leakage.',
  'Packet Length Mean':       'Average packet size across both directions. Deviations from protocol norms expose anomalous behavior.',
}

function MetricBar({ label, value, isFAR }) {
  if (value == null) return null
  const pct = value * 100
  const display = isFAR ? `${pct.toFixed(4)}%` : `${pct.toFixed(2)}%`
  const barWidth = isFAR ? Math.min(pct * 1000, 100) : pct
  const color = isFAR
    ? (value < 0.01 ? 'var(--success)' : 'var(--warning)')
    : pct >= 99 ? 'var(--success)' : pct >= 95 ? 'var(--accent)' : 'var(--warning)'

  return (
    <div className="stat-metric-row">
      <span className="stat-metric-label">{label}</span>
      <div className="stat-metric-bar-track">
        <div
          className="stat-metric-bar-fill"
          style={{ width: `${barWidth}%`, background: color }}
        />
      </div>
      <span className="stat-metric-value mono" style={{ color }}>{display}</span>
    </div>
  )
}

export default function Statistics() {
  const [health,   setHealth]   = useState(null)
  const [classes,  setClasses]  = useState(null)
  const [features, setFeatures] = useState(null)
  const [loading,  setLoading]  = useState(true)

  useEffect(() => {
    Promise.all([api.health(), api.classes(), api.features()])
      .then(([h, c, f]) => { setHealth(h); setClasses(c); setFeatures(f) })
      .catch(console.error)
      .finally(() => setLoading(false))
  }, [])

  if (loading) return <div className="loading"><div className="spinner" /> Loading statistics...</div>

  const perf = health?.performance || {}
  const groups = classes?.groups || {}

  const metrics = [
    { label: 'Accuracy',      value: perf.accuracy },
    { label: 'Precision',     value: perf.precision },
    { label: 'Recall',        value: perf.recall },
    { label: 'F1 (weighted)', value: perf.f1_weighted },
    { label: 'F1 (macro)',    value: perf.f1_macro },
    { label: 'AUC-ROC',      value: perf.auc },
    { label: 'L1 Accuracy',  value: perf.level1_accuracy },
  ]

  const topFeats = (features?.top_30 || []).slice(0, 20)
  const top5Feats = topFeats.slice(0, 5)

  return (
    <div className="stat-page">
      <div className="dash-header">
        <div>
          <h2 className="dash-title">Statistics</h2>
          <p className="dash-subtitle">Model architecture, performance metrics, and feature importance</p>
        </div>
      </div>

      {/* Model Info + Performance */}
      <div className="grid-2" style={{ marginBottom: 24 }}>
        <div className="card">
          <div className="card-header"><h3>Model Architecture</h3></div>
          <div className="stat-info-list">
            <div className="stat-info-row">
              <span className="stat-info-key">Model</span>
              <span className="stat-info-val">Hierarchical 11-class</span>
            </div>
            <div className="stat-info-row">
              <span className="stat-info-key">Level 1</span>
              <span className="stat-info-val mono">{health?.architecture?.level1 || '—'}</span>
            </div>
            <div className="stat-info-row">
              <span className="stat-info-key">Level 2</span>
              <span className="stat-info-val mono">{(health?.architecture?.level2 || []).join(', ')}</span>
            </div>
            <div className="stat-info-row">
              <span className="stat-info-key">Total Classes</span>
              <span className="stat-info-val mono">{health?.architecture?.classes || '—'}</span>
            </div>
            <div className="stat-info-row">
              <span className="stat-info-key">Features</span>
              <span className="stat-info-val mono">{health?.features} (69 CIC + 20 engineered)</span>
            </div>
            <div className="stat-info-row">
              <span className="stat-info-key">Tuning</span>
              <span className="stat-info-val mono">Optuna (30 trials, macro-F1)</span>
            </div>
            <div className="stat-info-row">
              <span className="stat-info-key">Datasets</span>
              <span className="stat-info-val mono">CIC-IDS2017 + 2018 + DDoS2019</span>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <h3>Performance on 1.6M Unseen Flows</h3>
          </div>
          <div className="stat-metrics-list">
            {metrics.map(m => (
              <MetricBar key={m.label} label={m.label} value={m.value} />
            ))}
            {perf.far != null && (
              <MetricBar label="False Alarm Rate" value={perf.far} isFAR />
            )}
          </div>
        </div>
      </div>

      {/* Attack Classes & Groups */}
      <div className="card" style={{ marginBottom: 24 }}>
        <div className="card-header"><h3>Attack Classes, Severity & Groups</h3></div>
        <table className="data-table stat-class-table">
          <thead>
            <tr>
              <th>Class</th>
              <th>Severity</th>
              <th>Group (Level 1)</th>
              <th>Level 2 Peers</th>
            </tr>
          </thead>
          <tbody>
            {(classes?.classes || []).map(cls => {
              const severity = classes?.severity_map?.[cls] || 'info'
              const group = Object.entries(groups).find(([_, m]) => m.includes(cls))
              const peers = group ? group[1].filter(m => m !== cls) : []
              return (
                <tr key={cls}>
                  <td style={{
                    fontWeight: 700,
                    fontSize: 16,
                    color: cls === 'BENIGN' ? 'var(--success)' : 'var(--text-primary)',
                  }}>
                    {cls}
                  </td>
                  <td>
                    <span className={`badge badge-${severity}`}>{severity}</span>
                  </td>
                  <td className="mono" style={{ fontWeight: 600, fontSize: 15 }}>
                    {group ? group[0] : '—'}
                  </td>
                  <td>
                    {peers.length > 0
                      ? peers.map(m => (
                          <span key={m} className="tag" style={{ marginRight: 6, marginBottom: 4, fontSize: 13, padding: '4px 12px' }}>{m}</span>
                        ))
                      : <span style={{ color: 'var(--text-muted)' }}>—</span>}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {/* Key feature insights — top 5 cards */}
      {top5Feats.length > 0 && (
        <div style={{ marginBottom: 24 }}>
          <h3 className="stat-section-title">Key Feature Insights</h3>
          <div className="stat-feat-grid">
            {top5Feats.map((f, idx) => {
              const colors = [
                { border: 'var(--landing-tag-border)', accent: 'var(--accent)' },
                { border: 'var(--sev-critical-border)', accent: 'var(--danger)' },
                { border: 'var(--sev-info-border)', accent: 'var(--success)' },
                { border: 'var(--sev-high-border)', accent: 'var(--warning)' },
                { border: 'var(--sev-medium-border)', accent: 'var(--purple)' },
              ][idx]
              return (
                <div key={f.name} className="stat-feat-card" style={{ borderColor: colors.border }}>
                  <div className="stat-feat-card-rank" style={{ background: colors.accent }}>
                    {idx + 1}
                  </div>
                  <span className="stat-feat-card-name">{f.name}</span>
                  <span className="stat-feat-card-desc">
                    {FEATURE_DESCRIPTIONS[f.name] ||
                      'A CICFlowMeter-derived flow statistic used as a discriminative signal.'}
                  </span>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Top 20 features — ranked list */}
      {topFeats.length > 0 && (
        <div className="card">
          <div className="card-header">
            <h3>Feature Importance Ranking</h3>
            <span className="mini-badge">Top {topFeats.length}</span>
          </div>
          <div className="stat-rank-list">
            {topFeats.map((f, idx) => {
              const barWidth = ((topFeats.length - idx) / topFeats.length) * 100
              const color = idx < 3 ? '#2563eb' : idx < 8 ? '#7c3aed' : '#8592a6'
              return (
                <div key={f.name} className="stat-rank-row">
                  <span className="stat-rank-num mono" style={{ color: idx < 3 ? 'var(--accent)' : 'var(--text-muted)' }}>
                    {idx + 1}
                  </span>
                  <div className="stat-rank-info">
                    <span className="stat-rank-name">{f.name}</span>
                    <div className="stat-rank-bar-track">
                      <div
                        className="stat-rank-bar-fill"
                        style={{ width: `${barWidth}%`, background: color }}
                      />
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}
    </div>
  )
}
