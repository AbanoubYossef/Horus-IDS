import { useState, useCallback } from 'react'
import { api } from '../api'
import { Database, Filter, ChevronLeft, ChevronRight, Search } from 'lucide-react'
import Badge from '../components/Badge'

export default function History() {
  const [predictions, setPredictions] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(false)
  const [loaded, setLoaded] = useState(false)
  const [page, setPage] = useState(0)
  const [filterMode, setFilterMode] = useState('all')
  const [filterSeverity, setFilterSeverity] = useState('')
  const limit = 50

  const load = useCallback(async (pageNum = 0, mode, severity) => {
    setLoading(true)
    try {
      const m = mode ?? filterMode
      const s = severity ?? filterSeverity
      const params = { limit, offset: pageNum * limit }
      if (m === 'attacks') params.attack_only = true
      if (s) params.severity = s
      const data = await api.predictions(params)
      setPredictions(data.results || [])
      setTotal(data.total || 0)
      setPage(pageNum)
      setLoaded(true)
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }, [filterMode, filterSeverity])

  const onModeChange = (val) => {
    setFilterMode(val)
    if (loaded) load(0, val, filterSeverity)
  }

  const onSeverityChange = (val) => {
    setFilterSeverity(val)
    if (loaded) load(0, filterMode, val)
  }

  const totalPages = Math.ceil(total / limit)

  return (
    <div>
      <div className="page-header">
        <h2 style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <Database size={22} /> Prediction History
        </h2>
        <p>Browse and filter all predictions stored in the database</p>
      </div>

      {/* Controls */}
      <div className="card" style={{ marginBottom: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <button className="btn btn-primary" onClick={() => load(0)} disabled={loading}>
            {loading
              ? <><div className="spinner" /> Loading...</>
              : <><Database size={16} /> {loaded ? 'Reload from DB' : 'Load from Database'}</>
            }
          </button>

          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginLeft: 'auto' }}>
            <Filter size={14} color="var(--text-muted)" />

            <select
              className="filter-select"
              value={filterMode}
              onChange={e => onModeChange(e.target.value)}
            >
              <option value="all">All Traffic</option>
              <option value="attacks">Attacks Only</option>
            </select>

            <select
              className="filter-select"
              value={filterSeverity}
              onChange={e => onSeverityChange(e.target.value)}
            >
              <option value="">All Severity</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="info">Info (Benign)</option>
            </select>
          </div>
        </div>
      </div>

      {!loaded ? (
        <div className="card" style={{ textAlign: 'center', padding: '64px 24px' }}>
          <Database size={56} color="var(--text-muted)" style={{ opacity: 0.4, marginBottom: 16 }} />
          <p style={{ fontSize: 16, fontWeight: 600, marginBottom: 8 }}>No data loaded yet</p>
          <p style={{ fontSize: 13, color: 'var(--text-muted)', marginBottom: 20 }}>
            Click "Load from Database" to fetch prediction history
          </p>
          <button className="btn btn-primary" onClick={() => load(0)}>
            <Database size={16} /> Load from Database
          </button>
        </div>
      ) : (
        <>
          {/* Summary */}
          <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)', marginBottom: 20 }}>
            <div className="stat-card">
              <div className="label">Total Records</div>
              <div className="value" style={{ color: 'var(--accent)', fontSize: 22 }}>{total.toLocaleString()}</div>
            </div>
            <div className="stat-card">
              <div className="label">Showing</div>
              <div className="value" style={{ fontSize: 22 }}>{predictions.length}</div>
              <div className="sub">Page {page + 1} of {totalPages || 1}</div>
            </div>
            <div className="stat-card">
              <div className="label">Attacks</div>
              <div className="value" style={{ color: 'var(--danger)', fontSize: 22 }}>
                {predictions.filter(p => p.is_attack).length}
              </div>
            </div>
            <div className="stat-card">
              <div className="label">Benign</div>
              <div className="value" style={{ color: 'var(--success)', fontSize: 22 }}>
                {predictions.filter(p => !p.is_attack).length}
              </div>
            </div>
          </div>

          {/* Table */}
          <div className="card">
            <div className="card-header">
              <h3>Predictions ({total.toLocaleString()} total)</h3>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <button
                  className="btn"
                  style={{ padding: '5px 10px', fontSize: 12 }}
                  disabled={page === 0}
                  onClick={() => load(page - 1)}
                >
                  <ChevronLeft size={14} /> Prev
                </button>
                <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>
                  {page + 1} / {totalPages || 1}
                </span>
                <button
                  className="btn"
                  style={{ padding: '5px 10px', fontSize: 12 }}
                  disabled={page >= totalPages - 1}
                  onClick={() => load(page + 1)}
                >
                  Next <ChevronRight size={14} />
                </button>
              </div>
            </div>

            {predictions.length === 0 ? (
              <div className="empty-state">
                <Search size={48} />
                <p>No predictions match your filters.</p>
              </div>
            ) : (
              <div style={{ overflowX: 'auto', maxHeight: 600, overflowY: 'auto' }}>
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Attack Type</th>
                      <th>Group</th>
                      <th>Confidence</th>
                      <th>Severity</th>
                      <th>Source IP</th>
                      <th>Dest IP</th>
                      <th>Port</th>
                      <th>Inference</th>
                    </tr>
                  </thead>
                  <tbody>
                    {predictions.map(p => (
                      <tr key={p.id}>
                        <td className="mono" style={{ fontSize: 11, whiteSpace: 'nowrap' }}>
                          {new Date(p.created_at).toLocaleString()}
                        </td>
                        <td style={{
                          color: p.is_attack ? 'var(--danger)' : 'var(--success)',
                          fontWeight: 600, fontSize: 13
                        }}>
                          {p.attack_type}
                        </td>
                        <td><span className="tag">{p.group_pred || '—'}</span></td>
                        <td className="mono" style={{ fontSize: 12 }}>
                          {(p.confidence * 100).toFixed(1)}%
                        </td>
                        <td><Badge severity={p.severity} /></td>
                        <td className="mono" style={{ fontSize: 12 }}>{p.src_ip || '—'}</td>
                        <td className="mono" style={{ fontSize: 12 }}>{p.dst_ip || '—'}</td>
                        <td className="mono" style={{ fontSize: 12 }}>{p.dst_port || '—'}</td>
                        <td className="mono" style={{ fontSize: 11 }}>{p.inference_ms?.toFixed(1)}ms</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            {/* Bottom pagination */}
            {totalPages > 1 && (
              <div style={{ display: 'flex', justifyContent: 'center', gap: 8, padding: '16px 0', alignItems: 'center' }}>
                <button className="btn" style={{ padding: '5px 10px', fontSize: 12 }} disabled={page === 0} onClick={() => load(0)}>
                  First
                </button>
                <button className="btn" style={{ padding: '5px 10px', fontSize: 12 }} disabled={page === 0} onClick={() => load(page - 1)}>
                  <ChevronLeft size={14} />
                </button>
                <span style={{ fontSize: 13, color: 'var(--text-secondary)', padding: '0 8px' }}>
                  Page {page + 1} of {totalPages}
                </span>
                <button className="btn" style={{ padding: '5px 10px', fontSize: 12 }} disabled={page >= totalPages - 1} onClick={() => load(page + 1)}>
                  <ChevronRight size={14} />
                </button>
                <button className="btn" style={{ padding: '5px 10px', fontSize: 12 }} disabled={page >= totalPages - 1} onClick={() => load(totalPages - 1)}>
                  Last
                </button>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  )
}
