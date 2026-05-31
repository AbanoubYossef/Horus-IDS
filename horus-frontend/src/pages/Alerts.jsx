import { useState, useEffect } from 'react'
import { createPortal } from 'react-dom'
import { api } from '../api'
import { Bell, Plus, Edit3, Trash2, X, Filter, RefreshCw, Zap } from 'lucide-react'

function Badge({ severity }) {
  return <span className={`badge badge-${severity}`}>{severity}</span>
}

function StatusBadge({ status }) {
  const colors = {
    open: 'var(--danger)',
    investigating: 'var(--warning)',
    resolved: 'var(--success)',
    closed: 'var(--text-muted)',
  }
  return (
    <span className="tag" style={{ color: colors[status] || 'var(--text-secondary)', borderColor: colors[status] }}>
      {status}
    </span>
  )
}

export default function Alerts() {
  const [alerts, setAlerts] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [showModal, setShowModal] = useState(false)
  const [editAlert, setEditAlert] = useState(null)
  const [filterStatus, setFilterStatus] = useState('')
  const [filterSeverity, setFilterSeverity] = useState('')

  const [form, setForm] = useState({ title: '', description: '', severity: 'medium', status: 'open', notes: '' })
  const [formError, setFormError] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [success, setSuccess] = useState('')

  const load = async (status, severity) => {
    setLoading(true)
    setError('')
    try {
      const params = {}
      const s = status !== undefined ? status : filterStatus
      const v = severity !== undefined ? severity : filterSeverity
      if (s) params.status = s
      if (v) params.severity = v
      params.limit = 200
      const data = await api.getAlerts(params)
      setAlerts(data.alerts || [])
      setTotal(data.total || 0)
    } catch (e) {
      console.error('Alerts load error:', e)
      setError(e.message || 'Failed to load alerts')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const openCreate = () => {
    setEditAlert(null)
    setForm({ title: '', description: '', severity: 'medium', status: 'open', notes: '' })
    setFormError('')
    setShowModal(true)
  }

  const openEdit = (a) => {
    setEditAlert(a)
    setForm({
      title: a.title,
      description: a.description || '',
      severity: a.severity,
      status: a.status,
      notes: a.notes || '',
    })
    setFormError('')
    setShowModal(true)
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setFormError('')
    setSubmitting(true)
    try {
      if (editAlert) {
        await api.updateAlert(editAlert.id, form)
        setSuccess('Alert updated successfully')
      } else {
        await api.createAlert({ title: form.title, description: form.description, severity: form.severity })
        setSuccess('Alert created successfully')
      }
      setShowModal(false)
      await load()
      setTimeout(() => setSuccess(''), 3000)
    } catch (err) {
      setFormError(err.message)
    } finally {
      setSubmitting(false)
    }
  }

  const handleDelete = async (id) => {
    if (!window.confirm('Delete this alert?')) return
    try {
      await api.deleteAlert(id)
      setSuccess('Alert deleted')
      await load()
      setTimeout(() => setSuccess(''), 3000)
    } catch (err) {
      setError(err.message)
    }
  }

  return (
    <div>
      <div className="page-header">
        <h2 style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <Bell size={22} /> Alerts
        </h2>
        <p>Manage security alerts — create, investigate, resolve</p>
      </div>

      {/* Controls */}
      <div className="card" style={{ marginBottom: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, flexWrap: 'wrap' }}>
          <button className="btn btn-primary" onClick={openCreate}>
            <Plus size={16} /> New Alert
          </button>
          <button className="btn" style={{ background: 'var(--success)', color: '#fff' }} onClick={async () => {
            try {
              const res = await api.generateAlerts()
              await load()
              if (res.created > 0) {
                setSuccess(`Generated ${res.created} alerts from detected attacks`)
              } else {
                setSuccess('All detected attacks already have alerts')
              }
              setTimeout(() => setSuccess(''), 4000)
            } catch (err) { setError(err.message) }
          }}>
            <Zap size={16} /> Generate from Attacks
          </button>
          <button className="btn" onClick={() => load()} disabled={loading}>
            <RefreshCw size={16} className={loading ? 'spin' : ''} /> Refresh
          </button>

          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginLeft: 'auto' }}>
            <Filter size={14} color="var(--text-muted)" />
            <select className="filter-select" value={filterStatus} onChange={e => { setFilterStatus(e.target.value); load(e.target.value, filterSeverity) }}>
              <option value="">All Status</option>
              <option value="open">Open</option>
              <option value="investigating">Investigating</option>
              <option value="resolved">Resolved</option>
              <option value="closed">Closed</option>
            </select>
            <select className="filter-select" value={filterSeverity} onChange={e => { setFilterSeverity(e.target.value); load(filterStatus, e.target.value) }}>
              <option value="">All Severity</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
          </div>
        </div>
      </div>

      {error && (
        <div className="card" style={{ background: 'var(--stat-danger-bg)', color: 'var(--danger)', padding: 16, marginBottom: 20, fontWeight: 600 }}>
          Error: {error}
        </div>
      )}
      {success && (
        <div className="card" style={{ background: 'rgba(34,197,94,0.1)', color: 'var(--success)', padding: 16, marginBottom: 20, fontWeight: 600, border: '1px solid var(--success)' }}>
          {success}
        </div>
      )}

      {/* Stats */}
      <div className="stats-grid" style={{ gridTemplateColumns: 'repeat(4, 1fr)', marginBottom: 20 }}>
        <div className="stat-card">
          <div className="label">Total Alerts</div>
          <div className="value" style={{ color: 'var(--accent)', fontSize: 22 }}>{total}</div>
        </div>
        <div className="stat-card">
          <div className="label">Open</div>
          <div className="value" style={{ color: 'var(--danger)', fontSize: 22 }}>
            {alerts.filter(a => a.status === 'open').length}
          </div>
        </div>
        <div className="stat-card">
          <div className="label">Investigating</div>
          <div className="value" style={{ color: 'var(--warning)', fontSize: 22 }}>
            {alerts.filter(a => a.status === 'investigating').length}
          </div>
        </div>
        <div className="stat-card">
          <div className="label">Resolved</div>
          <div className="value" style={{ color: 'var(--success)', fontSize: 22 }}>
            {alerts.filter(a => a.status === 'resolved').length}
          </div>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="card">
        <div className="card-header">
          <h3>Alerts ({alerts.length})</h3>
        </div>
        {loading ? (
          <div className="loading" style={{ padding: 40 }}><div className="spinner" /> Loading alerts...</div>
        ) : alerts.length === 0 ? (
          <div className="empty-state">
            <Bell size={48} />
            <p>No alerts found. Create one to get started.</p>
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Title</th>
                  <th>Severity</th>
                  <th>Status</th>
                  <th>Created By</th>
                  <th>Created At</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {alerts.map(a => (
                  <tr key={a.id}>
                    <td style={{ fontWeight: 600, maxWidth: 300 }}>
                      {a.title}
                      {a.description && (
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                          {a.description.length > 80 ? a.description.slice(0, 80) + '...' : a.description}
                        </div>
                      )}
                    </td>
                    <td><Badge severity={a.severity} /></td>
                    <td><StatusBadge status={a.status} /></td>
                    <td className="mono" style={{ fontSize: 12 }}>{a.creator_name || '—'}</td>
                    <td className="mono" style={{ fontSize: 11 }}>
                      {new Date(a.created_at).toLocaleString()}
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: 6 }}>
                        <button className="btn" style={{ padding: '4px 8px' }} onClick={() => openEdit(a)}>
                          <Edit3 size={14} />
                        </button>
                        <button className="btn btn-danger" style={{ padding: '4px 8px' }} onClick={() => handleDelete(a.id)}>
                          <Trash2 size={14} />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Modal */}
      {showModal && createPortal(
        <div className="modal-overlay" onClick={() => setShowModal(false)}>
          <div className="modal-content" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h3>{editAlert ? 'Edit Alert' : 'Create Alert'}</h3>
              <button className="btn" style={{ padding: '4px 8px' }} onClick={() => setShowModal(false)}>
                <X size={16} />
              </button>
            </div>
            <form onSubmit={handleSubmit} className="auth-form">
              {formError && (
                <div style={{ background: 'var(--stat-danger-bg)', color: 'var(--danger)', padding: '10px 14px', borderRadius: 8, fontSize: 13, fontWeight: 600 }}>
                  {formError}
                </div>
              )}
              <div className="form-group">
                <label>Title</label>
                <input
                  type="text"
                  value={form.title}
                  onChange={e => setForm({ ...form, title: e.target.value })}
                  placeholder="Alert title"
                  required
                />
              </div>
              <div className="form-group">
                <label>Description</label>
                <textarea
                  value={form.description}
                  onChange={e => setForm({ ...form, description: e.target.value })}
                  placeholder="Describe the alert..."
                  rows={3}
                />
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div className="form-group">
                  <label>Severity</label>
                  <select value={form.severity} onChange={e => setForm({ ...form, severity: e.target.value })}>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                    <option value="info">Info</option>
                  </select>
                </div>
                {editAlert && (
                  <div className="form-group">
                    <label>Status</label>
                    <select value={form.status} onChange={e => setForm({ ...form, status: e.target.value })}>
                      <option value="open">Open</option>
                      <option value="investigating">Investigating</option>
                      <option value="resolved">Resolved</option>
                      <option value="closed">Closed</option>
                    </select>
                  </div>
                )}
              </div>
              {editAlert && (
                <div className="form-group">
                  <label>Notes</label>
                  <textarea
                    value={form.notes}
                    onChange={e => setForm({ ...form, notes: e.target.value })}
                    placeholder="Investigation notes..."
                    rows={3}
                  />
                </div>
              )}
              <button type="submit" className="btn btn-primary auth-submit" disabled={submitting}>
                {submitting
                  ? <><div className="spinner" /> {editAlert ? 'Updating...' : 'Creating...'}</>
                  : editAlert ? 'Update Alert' : 'Create Alert'}
              </button>
            </form>
          </div>
        </div>,
        document.body
      )}
    </div>
  )
}
