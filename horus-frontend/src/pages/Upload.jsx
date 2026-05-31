import { useState, useRef, useMemo } from 'react'
import { api } from '../api'
import {
  Upload, FileText, CheckCircle, XCircle, File, CloudUpload,
  ShieldAlert, ShieldCheck, Zap, BarChart3, Activity,
  Download, ChevronLeft, ChevronRight, ArrowUpDown, Filter, Search,
} from 'lucide-react'
import {
  PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip,
} from 'recharts'
import Badge from '../components/Badge'

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1048576).toFixed(2)} MB`
}

const DONUT_COLORS = [
  '#3b82f6', '#ef4444', '#f59e0b', '#10b981', '#8b5cf6',
  '#ec4899', '#f97316', '#6366f1',
]

const tooltipStyle = {
  background: 'var(--tooltip-bg)',
  border: '1px solid var(--tooltip-border)',
  borderRadius: 10,
  fontSize: 13,
  padding: '10px 14px',
  boxShadow: 'var(--tooltip-shadow)',
}

const PAGE_SIZES = [10, 25, 50, 100]

function StepIndicator({ step }) {
  const steps = [
    { num: 1, label: 'Select File' },
    { num: 2, label: 'Analyze' },
    { num: 3, label: 'Results' },
  ]
  return (
    <div className="upload-steps">
      {steps.map((s, i) => (
        <div key={s.num} className="upload-step-wrapper">
          <div className={`upload-step ${step >= s.num ? 'upload-step-active' : ''} ${step > s.num ? 'upload-step-done' : ''}`}>
            {step > s.num
              ? <CheckCircle size={16} />
              : <span>{s.num}</span>}
          </div>
          <span className={`upload-step-label ${step >= s.num ? 'upload-step-label-active' : ''}`}>
            {s.label}
          </span>
          {i < steps.length - 1 && (
            <div className={`upload-step-line ${step > s.num ? 'upload-step-line-active' : ''}`} />
          )}
        </div>
      ))}
    </div>
  )
}

function exportData(results, format) {
  if (!results?.length) return
  let content, mime, ext
  if (format === 'json') {
    content = JSON.stringify(results, null, 2)
    mime = 'application/json'
    ext = 'json'
  } else {
    const keys = ['attack_type', 'is_attack', 'severity', 'confidence', 'src_ip', 'group_prediction', 'group_pred', 'ground_truth', 'inference_ms']
    const header = keys.join(',')
    const rows = results.map(r => keys.map(k => {
      const v = r[k]
      if (v == null) return ''
      if (typeof v === 'string' && v.includes(',')) return `"${v}"`
      return v
    }).join(','))
    content = [header, ...rows].join('\n')
    mime = 'text/csv'
    ext = 'csv'
  }
  const blob = new Blob([content], { type: mime })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `horus-results.${ext}`
  a.click()
  URL.revokeObjectURL(url)
}

export default function UploadPage() {
  const [file, setFile]         = useState(null)
  const [loading, setLoading]   = useState(false)
  const [result, setResult]     = useState(null)
  const [error, setError]       = useState(null)
  const [dragOver, setDragOver] = useState(false)
  const inputRef = useRef()

  const [page, setPage]             = useState(1)
  const [pageSize, setPageSize]     = useState(25)
  const [filterType, setFilterType] = useState('')
  const [filterSev, setFilterSev]   = useState('')
  const [searchIP, setSearchIP]     = useState('')
  const [sortBy, setSortBy]         = useState('index')
  const [sortDir, setSortDir]       = useState('asc')

  const handleFile = (f) => {
    if (!f || !f.name.endsWith('.csv')) {
      setError('Please select a .csv file')
      return
    }
    setFile(f)
    setError(null)
    setResult(null)
  }

  const analyze = async () => {
    if (!file) return
    setLoading(true)
    setError(null)
    try {
      const res = await api.uploadCsv(file)
      setResult(res)
      setPage(1)
      setFilterType('')
      setFilterSev('')
      setSearchIP('')
      setSortBy('index')
      setSortDir('asc')
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }

  const reset = () => {
    setFile(null)
    setResult(null)
    setError(null)
    setPage(1)
  }

  const attackCount = result?.attacks || 0
  const benignCount = result?.benign  || 0
  const totalCount  = result?.total   || 0
  const attackRate  = totalCount > 0 ? ((attackCount / totalCount) * 100) : 0

  const currentStep = result ? 3 : file ? 2 : 1

  const attackTypeData = useMemo(() => {
    if (!result?.results) return []
    const counts = {}
    for (const r of result.results) {
      const key = r.attack_type || 'Unknown'
      counts[key] = (counts[key] || 0) + 1
    }
    return Object.entries(counts)
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 8)
  }, [result])

  const confidenceHistogram = useMemo(() => {
    if (!result?.results) return []
    const bins = Array.from({ length: 10 }, (_, i) => ({
      bin: `${i * 10}–${i * 10 + 10}%`,
      count: 0,
    }))
    for (const r of result.results) {
      if (r.confidence == null) continue
      const idx = Math.min(Math.floor(r.confidence * 10), 9)
      bins[idx].count++
    }
    return bins
  }, [result])

  const attackTypes = useMemo(() => {
    if (!result?.results) return []
    return [...new Set(result.results.map(r => r.attack_type))].sort()
  }, [result])

  const severities = useMemo(() => {
    if (!result?.results) return []
    return [...new Set(result.results.map(r => r.severity).filter(Boolean))].sort()
  }, [result])

  const filteredResults = useMemo(() => {
    if (!result?.results) return []
    let items = result.results.map((r, i) => ({ ...r, _idx: i }))

    if (filterType) items = items.filter(r => r.attack_type === filterType)
    if (filterSev) items = items.filter(r => r.severity === filterSev)
    if (searchIP.trim()) {
      const q = searchIP.trim().toLowerCase()
      items = items.filter(r => r.src_ip?.toLowerCase().includes(q))
    }

    items.sort((a, b) => {
      let cmp = 0
      if (sortBy === 'confidence') cmp = (a.confidence || 0) - (b.confidence || 0)
      else if (sortBy === 'type') cmp = (a.attack_type || '').localeCompare(b.attack_type || '')
      else if (sortBy === 'severity') {
        const order = { critical: 0, high: 1, medium: 2, info: 3 }
        cmp = (order[a.severity] ?? 4) - (order[b.severity] ?? 4)
      } else cmp = a._idx - b._idx
      return sortDir === 'desc' ? -cmp : cmp
    })

    return items
  }, [result, filterType, filterSev, searchIP, sortBy, sortDir])

  const totalPages = Math.max(1, Math.ceil(filteredResults.length / pageSize))
  const safePage = Math.min(page, totalPages)
  const pagedResults = filteredResults.slice((safePage - 1) * pageSize, safePage * pageSize)

  const toggleSort = (field) => {
    if (sortBy === field) setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    else { setSortBy(field); setSortDir('asc') }
    setPage(1)
  }

  return (
    <div className="upload-page">
      {/* Header */}
      <div className="dash-header">
        <div>
          <h2 className="dash-title">Upload CSV</h2>
          <p className="dash-subtitle">Upload a CICFlowMeter CSV file for batch network flow analysis</p>
        </div>
      </div>

      {/* Step indicator */}
      <StepIndicator step={currentStep} />

      {/* Upload zone */}
      <div className="upload-card">
        <div
          className={`upload-drop ${dragOver ? 'upload-drop-active' : ''} ${file ? 'upload-drop-has-file' : ''}`}
          onClick={() => inputRef.current?.click()}
          onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
          onDragLeave={() => setDragOver(false)}
          onDrop={(e) => { e.preventDefault(); setDragOver(false); handleFile(e.dataTransfer.files[0]) }}
        >
          {file ? (
            <>
              <div className="upload-file-icon">
                <File size={30} />
              </div>
              <p className="upload-file-name">{file.name}</p>
              <p className="upload-file-meta">{formatBytes(file.size)} — Ready to analyze</p>
            </>
          ) : (
            <>
              <div className="upload-cloud-icon">
                <CloudUpload size={32} />
              </div>
              <p className="upload-drop-title">Drop CSV file here or click to browse</p>
              <p className="upload-drop-hint">CICFlowMeter format · Max 10,000 rows · .csv only</p>
            </>
          )}
          <input
            ref={inputRef}
            type="file"
            accept=".csv"
            style={{ display: 'none' }}
            onChange={(e) => handleFile(e.target.files[0])}
          />
        </div>

        <div className="upload-actions">
          <button className="btn btn-primary upload-btn" onClick={analyze} disabled={!file || loading}>
            {loading
              ? <><div className="spinner" /> Analyzing flows...</>
              : <><FileText size={18} /> Analyze Flows</>}
          </button>
          {file && (
            <button className="btn" onClick={reset}>
              Clear
            </button>
          )}
        </div>
      </div>

      {/* Loading overlay with progress */}
      {loading && (
        <div className="upload-progress-card">
          <div className="upload-progress-inner">
            <div className="spinner" style={{ width: 28, height: 28 }} />
            <div>
              <p className="upload-progress-title">Analyzing {file?.name}...</p>
              <p className="upload-progress-sub">Processing network flows through the model. This may take a moment for large files.</p>
            </div>
          </div>
          <div className="upload-progress-bar-track">
            <div className="upload-progress-bar-fill" />
          </div>
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="upload-error">
          <XCircle size={22} />
          <span>{error}</span>
        </div>
      )}

      {/* ── Results ────────────────────────────────────────────────────────────── */}
      {result && (
        <>
          {/* Summary stat cards */}
          <div className="dash-stats" style={{ marginTop: 8 }}>
            <div className="dash-stat-card">
              <div className="dash-stat-icon" style={{ background: 'var(--stat-accent-bg)', color: 'var(--accent)' }}>
                <Activity size={22} />
              </div>
              <div className="dash-stat-info">
                <span className="dash-stat-label">Total Flows</span>
                <span className="dash-stat-value" style={{ color: 'var(--accent)' }}>
                  {totalCount.toLocaleString()}
                </span>
              </div>
            </div>

            <div className="dash-stat-card">
              <div className="dash-stat-icon" style={{ background: 'var(--stat-danger-bg)', color: 'var(--danger)' }}>
                <ShieldAlert size={22} />
              </div>
              <div className="dash-stat-info">
                <span className="dash-stat-label">Attacks Found</span>
                <span className="dash-stat-value" style={{ color: 'var(--danger)' }}>
                  {attackCount.toLocaleString()}
                </span>
                <span className="dash-stat-sub">{attackRate.toFixed(1)}% of total</span>
              </div>
            </div>

            <div className="dash-stat-card">
              <div className="dash-stat-icon" style={{ background: 'var(--stat-success-bg)', color: 'var(--success)' }}>
                <ShieldCheck size={22} />
              </div>
              <div className="dash-stat-info">
                <span className="dash-stat-label">Benign</span>
                <span className="dash-stat-value" style={{ color: 'var(--success)' }}>
                  {benignCount.toLocaleString()}
                </span>
              </div>
            </div>

            <div className="dash-stat-card">
              <div className="dash-stat-icon" style={{ background: 'var(--stat-warning-bg)', color: 'var(--warning)' }}>
                <Zap size={22} />
              </div>
              <div className="dash-stat-info">
                <span className="dash-stat-label">Total Inference</span>
                <span className="dash-stat-value" style={{ color: 'var(--warning)' }}>
                  {result.inference_ms?.toFixed(0)}ms
                </span>
                <span className="dash-stat-sub">
                  {totalCount > 0 ? `${(result.inference_ms / totalCount).toFixed(2)}ms per flow` : ''}
                </span>
              </div>
            </div>

            {result.accuracy != null && (
              <div className="dash-stat-card">
                <div className="dash-stat-icon" style={{ background: 'var(--stat-emerald-bg)', color: 'var(--success)' }}>
                  <BarChart3 size={22} />
                </div>
                <div className="dash-stat-info">
                  <span className="dash-stat-label">Accuracy</span>
                  <span className="dash-stat-value" style={{ color: 'var(--success)' }}>
                    {(result.accuracy * 100).toFixed(2)}%
                  </span>
                  <span className="dash-stat-sub">vs ground truth labels</span>
                </div>
              </div>
            )}
          </div>

          {/* Charts: Distribution + Confidence */}
          {attackTypeData.length > 0 && (
            <div className="dash-row">
              {/* Donut + legend */}
              <div className="card dash-col-left">
                <div className="card-header"><h3>Attack Type Distribution</h3></div>
                <div className="dist-donut">
                  <ResponsiveContainer width="100%" height={220}>
                    <PieChart>
                      <Pie
                        data={attackTypeData}
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
                        {attackTypeData.map((_, i) => (
                          <Cell key={i} fill={DONUT_COLORS[i % DONUT_COLORS.length]} />
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
                    <span className="dist-donut-total">{totalCount.toLocaleString()}</span>
                    <span className="dist-donut-label">Total</span>
                  </div>
                </div>
                <div className="dist-legend">
                  {attackTypeData.map((item, i) => {
                    const pct = totalCount > 0 ? ((item.value / totalCount) * 100) : 0
                    return (
                      <div key={item.name} className="dist-legend-row">
                        <div className="dist-legend-dot" style={{ background: DONUT_COLORS[i % DONUT_COLORS.length] }} />
                        <span className="dist-legend-name">{item.name}</span>
                        <span className="dist-legend-count">{item.value.toLocaleString()}</span>
                        <div className="dist-legend-bar-track">
                          <div
                            className="dist-legend-bar-fill"
                            style={{ width: `${pct}%`, background: DONUT_COLORS[i % DONUT_COLORS.length] }}
                          />
                        </div>
                        <span className="dist-legend-pct">{pct.toFixed(1)}%</span>
                      </div>
                    )
                  })}
                </div>
              </div>

              {/* Confidence histogram */}
              <div className="card dash-col-right">
                <div className="card-header"><h3>Confidence Distribution</h3></div>
                <ResponsiveContainer width="100%" height={340}>
                  <BarChart data={confidenceHistogram} margin={{ left: -10 }}>
                    <XAxis
                      dataKey="bin"
                      tick={{ fontSize: 12, fill: 'var(--chart-tick)' }}
                      angle={-30}
                      textAnchor="end"
                      height={52}
                    />
                    <YAxis tick={{ fontSize: 13, fill: 'var(--chart-tick-muted)' }} />
                    <Tooltip contentStyle={tooltipStyle} />
                    <Bar dataKey="count" fill="#3b82f6" radius={[6, 6, 0, 0]} barSize={24} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}

          {/* Results list */}
          <div className="card dash-section">
            <div className="pred-header">
              <div>
                <h3 className="pred-title">Analysis Results</h3>
                <span className="pred-count">
                  {filteredResults.length === (result.results?.length || 0)
                    ? `${filteredResults.length} flows analyzed`
                    : `${filteredResults.length} of ${result.results?.length || 0} flows (filtered)`}
                </span>
              </div>
              <div className="upload-export-group">
                <button className="btn" onClick={() => exportData(result.results, 'csv')}>
                  <Download size={15} /> Export CSV
                </button>
                <button className="btn" onClick={() => exportData(result.results, 'json')}>
                  <Download size={15} /> Export JSON
                </button>
              </div>
            </div>

            {/* Filters & sort toolbar */}
            <div className="upload-toolbar">
              <div className="upload-toolbar-left">
                <div className="upload-filter-item">
                  <Filter size={14} />
                  <select value={filterType} onChange={e => { setFilterType(e.target.value); setPage(1) }}>
                    <option value="">All Types</option>
                    {attackTypes.map(t => <option key={t} value={t}>{t}</option>)}
                  </select>
                </div>
                <div className="upload-filter-item">
                  <select value={filterSev} onChange={e => { setFilterSev(e.target.value); setPage(1) }}>
                    <option value="">All Severities</option>
                    {severities.map(s => <option key={s} value={s}>{s}</option>)}
                  </select>
                </div>
                <div className="upload-filter-item upload-search">
                  <Search size={14} />
                  <input
                    type="text"
                    placeholder="Search IP..."
                    value={searchIP}
                    onChange={e => { setSearchIP(e.target.value); setPage(1) }}
                  />
                </div>
              </div>
              <div className="upload-toolbar-right">
                <div className="upload-sort-group">
                  <ArrowUpDown size={14} />
                  <span className="upload-sort-label">Sort:</span>
                  {[
                    { key: 'index', label: 'Order' },
                    { key: 'confidence', label: 'Confidence' },
                    { key: 'type', label: 'Type' },
                    { key: 'severity', label: 'Severity' },
                  ].map(s => (
                    <button
                      key={s.key}
                      className={`upload-sort-btn ${sortBy === s.key ? 'upload-sort-btn-active' : ''}`}
                      onClick={() => toggleSort(s.key)}
                    >
                      {s.label}
                      {sortBy === s.key && (
                        <span className="upload-sort-dir">{sortDir === 'asc' ? '↑' : '↓'}</span>
                      )}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {pagedResults.length === 0 ? (
              <div className="card empty-state">
                <Search size={40} />
                <p style={{ fontSize: 15, marginTop: 12 }}>No flows match your filters.</p>
              </div>
            ) : (
              <div className="upload-results-list">
                {pagedResults.map((r) => {
                  const match = r.ground_truth && r.ground_truth === r.attack_type
                  const confPct = r.confidence != null ? (r.confidence * 100).toFixed(1) : null
                  const confColor = r.confidence >= 0.9 ? 'var(--success)'
                    : r.confidence >= 0.7 ? 'var(--accent)' : 'var(--warning)'

                  return (
                    <div key={r.id || r._idx} className={`pred-card ${r.is_attack ? 'pred-attack' : 'pred-benign'}`}>
                      <div className={`pred-icon ${r.is_attack ? 'pred-icon-attack' : 'pred-icon-safe'}`}>
                        {r.is_attack
                          ? <ShieldAlert size={26} />
                          : <ShieldCheck size={26} />
                        }
                      </div>

                      <div className="pred-body">
                        <div className="pred-top-row">
                          <span className="upload-row-num">#{r._idx + 1}</span>
                          <span className={`pred-type ${r.is_attack ? 'pred-type-attack' : 'pred-type-safe'}`}>
                            {r.attack_type}
                          </span>
                          <Badge severity={r.severity} />
                        </div>

                        <div className="pred-meta">
                          {r.src_ip && (
                            <>
                              <span className="pred-meta-item">
                                <span className="pred-meta-label">IP</span>
                                <span className="pred-meta-val mono">{r.src_ip}</span>
                              </span>
                              <span className="pred-meta-sep" />
                            </>
                          )}
                          <span className="pred-meta-item">
                            <span className="pred-meta-label">Group</span>
                            <span className="pred-meta-val">{r.group_prediction || r.group_pred || '—'}</span>
                          </span>
                          {result.accuracy != null && r.ground_truth && (
                            <>
                              <span className="pred-meta-sep" />
                              <span className="pred-meta-item">
                                <span className="pred-meta-label">Ground Truth</span>
                                <span className="pred-meta-val mono">{r.ground_truth}</span>
                              </span>
                              <span className="pred-meta-sep" />
                              <span className="pred-meta-item">
                                <span className="pred-meta-label">Match</span>
                                <span className="pred-meta-val">
                                  {match
                                    ? <CheckCircle size={18} color="#16a34a" />
                                    : <XCircle size={18} color="#dc2626" />}
                                </span>
                              </span>
                            </>
                          )}
                        </div>
                      </div>

                      {confPct && (
                        <div className="pred-confidence">
                          <span className="pred-conf-label">Confidence</span>
                          <span className="pred-conf-value mono" style={{ color: confColor }}>
                            {confPct}%
                          </span>
                          <div className="pred-conf-track">
                            <div
                              className="pred-conf-fill"
                              style={{ width: `${confPct}%`, background: confColor }}
                            />
                          </div>
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            )}

            {/* Pagination */}
            {filteredResults.length > 0 && (
              <div className="upload-pagination">
                <div className="upload-pagination-info">
                  Showing {(safePage - 1) * pageSize + 1}–{Math.min(safePage * pageSize, filteredResults.length)} of {filteredResults.length}
                </div>
                <div className="upload-pagination-controls">
                  <button
                    className="btn upload-page-btn"
                    disabled={safePage <= 1}
                    onClick={() => setPage(p => Math.max(1, p - 1))}
                  >
                    <ChevronLeft size={16} />
                  </button>
                  {Array.from({ length: Math.min(totalPages, 5) }, (_, i) => {
                    let pageNum
                    if (totalPages <= 5) {
                      pageNum = i + 1
                    } else if (safePage <= 3) {
                      pageNum = i + 1
                    } else if (safePage >= totalPages - 2) {
                      pageNum = totalPages - 4 + i
                    } else {
                      pageNum = safePage - 2 + i
                    }
                    return (
                      <button
                        key={pageNum}
                        className={`btn upload-page-btn ${safePage === pageNum ? 'upload-page-btn-active' : ''}`}
                        onClick={() => setPage(pageNum)}
                      >
                        {pageNum}
                      </button>
                    )
                  })}
                  <button
                    className="btn upload-page-btn"
                    disabled={safePage >= totalPages}
                    onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                  >
                    <ChevronRight size={16} />
                  </button>
                </div>
                <div className="upload-pagination-size">
                  <span>Rows:</span>
                  <select value={pageSize} onChange={e => { setPageSize(Number(e.target.value)); setPage(1) }}>
                    {PAGE_SIZES.map(s => <option key={s} value={s}>{s}</option>)}
                  </select>
                </div>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  )
}
