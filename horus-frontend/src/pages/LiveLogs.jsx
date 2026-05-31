import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { api } from '../api'
import {
  Radio, Play, Square, Trash2, Zap, Wifi, WifiOff, Download, Search,
  ShieldAlert, ShieldCheck, Activity, TrendingUp, Timer, CircleStop, X,
  ArrowRight,
} from 'lucide-react'
import Badge from '../components/Badge'
import ConfidenceBar from '../components/ConfidenceBar'

const WS_CONNECTING = 'connecting'
const WS_OPEN       = 'open'
const WS_CLOSED     = 'closed'

function exportCSV(logs) {
  const headers = [
    'time', 'src_ip', 'dst_ip', 'dst_port',
    'prediction', 'is_attack', 'confidence',
    'severity', 'inference_ms', 'ground_truth',
  ]
  const rows = logs.map(log => [
    log.created_at || '',
    log.src_ip || '',
    log.dst_ip || '',
    log.dst_port || '',
    log.attack_type || '',
    log.is_attack ? '1' : '0',
    log.confidence != null ? (log.confidence * 100).toFixed(1) : '',
    log.severity || '',
    log.inference_ms != null ? log.inference_ms.toFixed(2) : '',
    log.ground_truth || '',
  ])
  const csv = [headers, ...rows].map(r => r.join(',')).join('\n')
  const blob = new Blob([csv], { type: 'text/csv' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `horus-logs-${Date.now()}.csv`
  a.click()
  URL.revokeObjectURL(url)
}

export default function LiveLogs() {
  const [logs, setLogs]                   = useState([])
  const [wsState, setWsState]             = useState(WS_CLOSED)
  const [demoRunning, setDemoRunning]     = useState(false)
  const [demoSpeed, setDemoSpeed]         = useState(1000)
  const [analyzing, setAnalyzing]         = useState(false)
  const [totalAnalyzed, setTotalAnalyzed] = useState(0)
  const [totalAttacks, setTotalAttacks]   = useState(0)
  const [startTime]                       = useState(() => Date.now())
  const [now, setNow]                     = useState(() => Date.now())
  const [viewFilter, setViewFilter]       = useState('all')
  const [searchIP, setSearchIP]           = useState('')
  const [selectedLog, setSelectedLog]     = useState(null)

  const wsRef        = useRef(null)
  const intervalRef  = useRef(null)
  const reconnectRef = useRef(null)
  const clockRef     = useRef(null)

  useEffect(() => {
    clockRef.current = setInterval(() => setNow(Date.now()), 1000)
    return () => clearInterval(clockRef.current)
  }, [])

  useEffect(() => {
    if (!selectedLog) return
    const onKey = (e) => { if (e.key === 'Escape') setSelectedLog(null) }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [selectedLog])

  const elapsed = Math.max(1, (now - startTime) / 1000)
  const flowsPerSec = (totalAnalyzed / elapsed).toFixed(1)

  const seenIds = useRef(new Set())

  const addLog = useCallback((entry) => {
    if (entry.id && seenIds.current.has(entry.id)) {
      if (entry.ground_truth) {
        setLogs(prev => prev.map(l => l.id === entry.id ? { ...l, ground_truth: entry.ground_truth, correct: entry.correct } : l))
      }
      return
    }
    if (entry.id) seenIds.current.add(entry.id)
    setLogs(prev => [entry, ...prev].slice(0, 200))
    setTotalAnalyzed(prev => prev + 1)
    if (entry.is_attack) setTotalAttacks(prev => prev + 1)
  }, [])

  const connectWs = useCallback(() => {
    if (wsRef.current && wsRef.current.readyState < 2) return
    setWsState(WS_CONNECTING)
    const ws = api.ws()
    wsRef.current = ws
    ws.onopen = () => setWsState(WS_OPEN)
    ws.onmessage = (e) => {
      try { addLog(JSON.parse(e.data)) } catch { /* ignore */ }
    }
    ws.onclose = () => {
      setWsState(WS_CLOSED)
      reconnectRef.current = setTimeout(connectWs, 3000)
    }
    ws.onerror = () => ws.close()
  }, [addLog])

  const disconnectWs = useCallback(() => {
    clearTimeout(reconnectRef.current)
    if (wsRef.current) {
      wsRef.current.onclose = null
      wsRef.current.close()
      wsRef.current = null
    }
    setWsState(WS_CLOSED)
  }, [])

  useEffect(() => {
    connectWs()
    return () => {
      clearTimeout(reconnectRef.current)
      if (wsRef.current) { wsRef.current.onclose = null; wsRef.current.close() }
      if (intervalRef.current) clearInterval(intervalRef.current)
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const analyzeOne = async () => {
    setAnalyzing(true)
    try {
      const sample = await api.sample()
      const result = await api.predict(
        sample.features_dict,
        `${Math.floor(Math.random() * 223)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`,
        `192.168.1.${Math.floor(Math.random() * 254) + 1}`,
        [80, 443, 22, 21, 53, 8080, 3389][Math.floor(Math.random() * 7)]
      )
      addLog({
        ...result,
        ground_truth: sample.ground_truth,
        source_file: sample.source_file,
        correct: sample.ground_truth === result.attack_type,
      })
    } catch (e) {
      console.error('Demo error:', e)
    } finally {
      setAnalyzing(false)
    }
  }

  const startDemo = () => {
    setDemoRunning(true)
    intervalRef.current = setInterval(analyzeOne, demoSpeed)
  }

  const stopDemo = () => {
    setDemoRunning(false)
    if (intervalRef.current) { clearInterval(intervalRef.current); intervalRef.current = null }
  }

  useEffect(() => {
    if (demoRunning) { stopDemo(); startDemo() }
  }, [demoSpeed]) // eslint-disable-line react-hooks/exhaustive-deps

  const filteredLogs = useMemo(() => {
    return logs.filter(log => {
      switch (viewFilter) {
        case 'attacks':  if (!log.is_attack) return false; break
        case 'benign':   if (log.is_attack)  return false; break
        case 'critical': if (log.severity !== 'critical') return false; break
        case 'high':     if (log.severity !== 'high')     return false; break
        case 'medium':   if (log.severity !== 'medium')   return false; break
      }
      if (searchIP.trim()) {
        const q = searchIP.trim().toLowerCase()
        if (!log.src_ip?.toLowerCase().includes(q) && !log.dst_ip?.toLowerCase().includes(q)) return false
      }
      return true
    })
  }, [logs, viewFilter, searchIP])

  const hasGroundTruth = logs.some(l => l.ground_truth)

  const wsLabel = {
    [WS_OPEN]: 'Live',
    [WS_CONNECTING]: 'Connecting…',
    [WS_CLOSED]: 'Disconnected',
  }[wsState]

  const attackRatio = totalAnalyzed > 0 ? (totalAttacks / totalAnalyzed) * 100 : 0
  const benignRatio = 100 - attackRatio

  const liveDotClass = demoRunning
    ? 'live-dot receiving'
    : wsState === WS_OPEN
      ? 'live-dot ws-open'
      : wsState === WS_CONNECTING
        ? 'live-dot ws-connecting'
        : 'live-dot'

  return (
    <div className="live-page">
      {/* Header */}
      <div className="dash-header">
        <div>
          <h2 className="dash-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            Live Logs
            <span className={liveDotClass} />
          </h2>
          <p className="dash-subtitle">Real-time IDS predictions via WebSocket — demo mode available when no live capture is running</p>
        </div>
        <div className={`ws-badge ws-${wsState}`}>
          {wsState === WS_OPEN
            ? <Wifi size={14} />
            : wsState === WS_CONNECTING
              ? <Wifi size={14} style={{ opacity: 0.7 }} />
              : <WifiOff size={14} />}
          <span>{wsLabel}</span>
          {wsState === WS_CLOSED && (
            <button className="btn live-reconnect-btn" onClick={connectWs}>Reconnect</button>
          )}
        </div>
      </div>

      {/* Controls */}
      <div className="live-controls">
        <div className="live-controls-left">
          <span className="live-controls-label">Demo Mode</span>
          {!demoRunning ? (
            <button className="btn btn-primary live-action-btn" onClick={startDemo}>
              <Play size={18} /> Auto-Sample
            </button>
          ) : (
            <button className="btn btn-danger live-action-btn" onClick={stopDemo}>
              <Square size={18} /> Stop
            </button>
          )}
          <button className="btn live-action-btn" onClick={analyzeOne} disabled={analyzing}>
            <Zap size={18} /> {analyzing ? 'Analyzing…' : 'One Sample'}
          </button>

          <button
            className="btn btn-danger live-action-btn"
            onClick={() => { stopDemo(); disconnectWs() }}
            disabled={!demoRunning && wsState === WS_CLOSED}
          >
            <CircleStop size={18} /> Stop All
          </button>

          <div className="live-controls-sep" />

          <span className="live-controls-label">Speed</span>
          <div className="live-speed-group">
            {[2000, 1000, 500, 200].map(ms => (
              <button
                key={ms}
                className={`btn live-speed-btn ${demoSpeed === ms ? 'live-speed-btn-active' : ''}`}
                onClick={() => setDemoSpeed(ms)}
              >
                {ms >= 1000 ? `${ms / 1000}s` : `${ms}ms`}
              </button>
            ))}
          </div>
        </div>

        <div className="live-controls-right">
          {logs.length > 0 && (
            <button className="btn live-action-btn" onClick={() => exportCSV(logs)}>
              <Download size={18} /> Export
            </button>
          )}
          <button
            className="btn live-action-btn"
            onClick={() => { setLogs([]); setTotalAnalyzed(0); setTotalAttacks(0); seenIds.current.clear() }}
          >
            <Trash2 size={18} /> Clear
          </button>
        </div>
      </div>

      {/* Stat cards */}
      <div className="dash-stats live-stats">
        <div className="dash-stat-card">
          <div className="dash-stat-icon" style={{ background: 'var(--stat-accent-bg)', color: 'var(--accent)' }}>
            <Activity size={22} />
          </div>
          <div className="dash-stat-info">
            <span className="dash-stat-label">Analyzed</span>
            <span className="dash-stat-value" style={{ color: 'var(--accent)' }}>
              {totalAnalyzed.toLocaleString()}
            </span>
          </div>
        </div>

        <div className="dash-stat-card">
          <div className="dash-stat-icon" style={{ background: 'var(--stat-danger-bg)', color: 'var(--danger)' }}>
            <ShieldAlert size={22} />
          </div>
          <div className="dash-stat-info">
            <span className="dash-stat-label">Attacks</span>
            <span className="dash-stat-value" style={{ color: 'var(--danger)' }}>
              {totalAttacks.toLocaleString()}
            </span>
          </div>
        </div>

        <div className="dash-stat-card">
          <div className="dash-stat-icon" style={{ background: 'var(--stat-success-bg)', color: 'var(--success)' }}>
            <ShieldCheck size={22} />
          </div>
          <div className="dash-stat-info">
            <span className="dash-stat-label">Benign</span>
            <span className="dash-stat-value" style={{ color: 'var(--success)' }}>
              {(totalAnalyzed - totalAttacks).toLocaleString()}
            </span>
          </div>
        </div>

        <div className="dash-stat-card">
          <div className="dash-stat-icon" style={{ background: 'var(--stat-warning-bg)', color: 'var(--warning)' }}>
            <TrendingUp size={22} />
          </div>
          <div className="dash-stat-info">
            <span className="dash-stat-label">Attack Rate</span>
            <span className="dash-stat-value" style={{ color: 'var(--warning)' }}>
              {totalAnalyzed > 0 ? `${attackRatio.toFixed(1)}%` : '—'}
            </span>
          </div>
        </div>

        <div className="dash-stat-card">
          <div className="dash-stat-icon" style={{ background: 'var(--stat-purple-bg)', color: 'var(--purple)' }}>
            <Timer size={22} />
          </div>
          <div className="dash-stat-info">
            <span className="dash-stat-label">Flows / sec</span>
            <span className="dash-stat-value" style={{ color: 'var(--purple)' }}>
              {totalAnalyzed > 0 ? flowsPerSec : '—'}
            </span>
            <span className="dash-stat-sub">Since session start</span>
          </div>
        </div>
      </div>

      {/* Ratio bar */}
      {totalAnalyzed > 0 && (
        <div className="live-ratio">
          <div className="live-ratio-labels">
            <span className="live-ratio-attack">Attacks {attackRatio.toFixed(1)}%</span>
            <span className="live-ratio-benign">Benign {benignRatio.toFixed(1)}%</span>
          </div>
          <div className="ratio-bar">
            <div className="ratio-fill-attack" style={{ width: `${attackRatio}%` }} />
            <div className="ratio-fill-benign" style={{ width: `${benignRatio}%` }} />
          </div>
        </div>
      )}

      {/* Log stream */}
      <div className="card live-stream-card">
        <div className="card-header">
          <h3 className="live-stream-title">
            <Radio size={16} />
            Network Log Stream
          </h3>
          <span className="mini-badge">
            {filteredLogs.length} / {logs.length} entries
          </span>
        </div>

        {/* Filters */}
        <div className="live-filter-bar">
          <div className="live-filter-group">
            <span className="live-filter-label">View</span>
            <div className="live-filter-pills">
              {[
                { key: 'all',      label: 'All' },
                { key: 'attacks',  label: 'Attacks' },
                { key: 'critical', label: 'Critical' },
                { key: 'high',     label: 'High' },
                { key: 'medium',   label: 'Medium' },
                { key: 'benign',   label: 'Benign' },
              ].map(f => (
                <button
                  key={f.key}
                  className={`live-pill ${viewFilter === f.key ? `live-pill-active live-pill-${f.key}` : ''}`}
                  onClick={() => setViewFilter(f.key)}
                >
                  {f.label}
                </button>
              ))}
            </div>
          </div>

          <div className="live-filter-group">
            <div className="live-ip-search">
              <Search size={15} />
              <input
                type="text"
                placeholder="Filter by IP..."
                value={searchIP}
                onChange={e => setSearchIP(e.target.value)}
              />
              {searchIP && (
                <button className="live-ip-clear" onClick={() => setSearchIP('')}>&times;</button>
              )}
            </div>
          </div>
        </div>

        {filteredLogs.length === 0 ? (
          <div className="empty-state">
            <Radio size={48} />
            <p style={{ fontSize: 15, marginTop: 14 }}>
              {logs.length === 0
                ? wsState === WS_OPEN
                  ? 'Waiting for live predictions from the capture service…'
                  : 'Connect to live feed or use Demo mode to sample test flows'
                : 'No entries match the current filters'}
            </p>
          </div>
        ) : (
          <div className="live-table-wrap">
            <table className="data-table live-table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Source IP</th>
                  <th>Dest IP</th>
                  <th>Port</th>
                  <th>Proto</th>
                  <th>Src VLAN</th>
                  <th>Dst VLAN</th>
                  <th>Prediction</th>
                  {hasGroundTruth && <th>Actual Label</th>}
                  <th>Confidence</th>
                  <th>Severity</th>
                  <th>Latency</th>
                </tr>
              </thead>
              <tbody>
                {filteredLogs.map((log, i) => {
                  const isNewest = i === 0 && log.is_attack
                  const rowClass = isNewest
                    ? 'row-attack attack-flash'
                    : log.is_attack ? 'row-attack' : 'row-benign'

                  return (
                    <tr
                      key={log.id || i}
                      className={`${rowClass} live-row-clickable`}
                      onClick={() => setSelectedLog(log)}
                    >
                      <td className="mono">
                        {new Date(log.created_at).toLocaleTimeString()}
                      </td>
                      <td className="mono">{log.src_ip || '—'}</td>
                      <td className="mono">{log.dst_ip || '—'}</td>
                      <td><PortCell port={log.dst_port} otherPort={log.src_port} /></td>
                      <td>
                        <span className={`live-cell-tag ${protoClass(log.protocol)}`}>
                          {protoLabel(log.protocol) || '—'}
                        </span>
                      </td>
                      <td><VlanCell vlan={log.src_vlan} /></td>
                      <td><VlanCell vlan={log.dst_vlan} /></td>
                      <td className={log.is_attack ? 'live-pred-attack' : 'live-pred-benign'}>
                        {log.attack_type}
                      </td>
                      {hasGroundTruth && (
                        <td>
                          {log.ground_truth ? (
                            <span className={log.correct ? 'live-gt-match' : 'live-gt-miss'}>
                              {log.ground_truth}
                            </span>
                          ) : (
                            <span className="live-gt-none">—</span>
                          )}
                        </td>
                      )}
                      <td><ConfidenceBar value={log.confidence} /></td>
                      <td><Badge severity={log.severity} /></td>
                      <td className="mono">{log.inference_ms?.toFixed(1)}ms</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {selectedLog && <LogDrawer log={selectedLog} now={now} onClose={() => setSelectedLog(null)} />}
    </div>
  )
}

function relTime(ts, now) {
  const diff = Math.max(0, Math.floor((now - new Date(ts).getTime()) / 1000))
  if (diff < 60)    return `${diff}s ago`
  if (diff < 3600)  return `${Math.floor(diff / 60)}m ${diff % 60}s ago`
  return `${Math.floor(diff / 3600)}h ${Math.floor((diff % 3600) / 60)}m ago`
}

const PROTO_NAMES = {
  1: 'ICMP', 2: 'IGMP', 6: 'TCP', 17: 'UDP', 41: 'IPv6',
  47: 'GRE', 50: 'ESP', 51: 'AH', 58: 'ICMPv6', 89: 'OSPF', 112: 'VRRP',
}
function protoLabel(num) {
  if (num == null || num === 0) return null
  return PROTO_NAMES[num] || `IP/${num}`
}

function protoClass(num) {
  if (num == null || num === 0) return 'log-flow-tag-proto-none'
  if (num === 6)  return 'log-flow-tag-proto-tcp'
  if (num === 17) return 'log-flow-tag-proto-udp'
  if (num === 1 || num === 58) return 'log-flow-tag-proto-icmp'
  return 'log-flow-tag-proto-other'
}

// VLAN names (B1=1xx, B2=2xx, B3=3xx, B4=4xx)
const _BASE_VLAN_NAMES = {
  10: 'General-Users', 11: 'Finance', 12: 'HR', 13: 'IT-Admin',
  50: 'VoIP', 51: 'Guest-WiFi', 52: 'IoT', 99: 'Management',
}
const _GLOBAL_VLAN_NAMES = {
  20: 'App-Servers', 21: 'File-Servers', 30: 'Database',
  40: 'Security', 60: 'DMZ', 61: 'VPN-Pool', 62: 'VPN-Admin',
  100: 'RSPAN-IDS', 999: 'Blackhole',
}
function vlanInfo(vlanId) {
  if (!vlanId) return null
  if (_GLOBAL_VLAN_NAMES[vlanId]) {
    return { name: _GLOBAL_VLAN_NAMES[vlanId], building: null }
  }
  if (vlanId >= 100 && vlanId < 500) {
    const bldg = Math.floor(vlanId / 100)
    const base = vlanId % 100
    const role = _BASE_VLAN_NAMES[base]
    if (role && bldg >= 1 && bldg <= 4) {
      return { name: `${role}-B${bldg}`, building: `B${bldg}` }
    }
  }
  return null
}

function VlanCell({ vlan }) {
  if (!vlan) {
    return <span className="live-cell-tag log-flow-tag-vlan-none">untag</span>
  }
  const info = vlanInfo(vlan)
  const title = info ? info.name : `VLAN ${vlan}`
  return (
    <span className="live-cell-vlan" title={title}>
      <span className="live-cell-tag log-flow-tag-vlan">{vlan}</span>
      {info?.building && <span className="live-cell-bldg">{info.building}</span>}
    </span>
  )
}

function DrawerVlanTag({ side, vlan }) {
  if (!vlan) {
    return (
      <span className="log-flow-tag log-flow-tag-vlan-none">{side} untagged</span>
    )
  }
  const info = vlanInfo(vlan)
  const label = info ? `${side} ${info.name} · VLAN ${vlan}` : `${side} VLAN ${vlan}`
  return <span className="log-flow-tag log-flow-tag-vlan">{label}</span>
}

// Well-known ports for flow labels
const WELL_KNOWN_PORTS = {
  20: 'FTP-Data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
  49: 'TACACS', 53: 'DNS', 67: 'DHCP', 68: 'DHCP', 69: 'TFTP',
  80: 'HTTP', 88: 'Kerberos', 110: 'POP3', 111: 'RPC', 123: 'NTP',
  135: 'MS-RPC', 137: 'NetBIOS', 138: 'NetBIOS', 139: 'NetBIOS',
  143: 'IMAP', 161: 'SNMP', 162: 'SNMP-Trap', 179: 'BGP', 389: 'LDAP',
  443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 514: 'Syslog', 515: 'LPD',
  587: 'SMTP-Sub', 636: 'LDAPS', 873: 'rsync', 989: 'FTPS', 990: 'FTPS',
  993: 'IMAPS', 995: 'POP3S',
  1080: 'SOCKS', 1433: 'MSSQL', 1434: 'MSSQL', 1521: 'Oracle',
  1701: 'L2TP', 1723: 'PPTP', 1812: 'RADIUS', 1813: 'RADIUS-Acct',
  1900: 'SSDP', 2049: 'NFS', 2055: 'NetFlow', 2082: 'cPanel',
  3128: 'HTTP-Proxy', 3268: 'LDAP-GC', 3306: 'MySQL', 3389: 'RDP',
  3478: 'STUN', 4444: 'Metasploit', 5060: 'SIP', 5061: 'SIP-TLS',
  5222: 'XMPP', 5353: 'mDNS', 5432: 'PostgreSQL', 5601: 'Kibana',
  5900: 'VNC', 5985: 'WinRM', 5986: 'WinRM-S', 6379: 'Redis',
  6443: 'k8s-API', 6667: 'IRC', 8000: 'HTTP-Alt', 8080: 'HTTP-Proxy',
  8443: 'HTTPS-Alt', 8888: 'HTTP-Alt', 9000: 'HTTP-Alt', 9090: 'Prometheus',
  9100: 'Node-Exp', 9200: 'Elastic', 10000: 'Webmin', 11211: 'Memcached',
  27017: 'MongoDB',
}
function serviceLabel(port) {
  if (port == null || port === 0) return null
  return WELL_KNOWN_PORTS[port] || null
}

function PortCell({ port, otherPort }) {
  // Prefer dst port service, fall back to src
  const svc = serviceLabel(port) || serviceLabel(otherPort)
  if (port == null || port === 0) {
    return <span className="mono">—</span>
  }
  return (
    <span className="live-cell-port" title={svc || ''}>
      <span className="mono">{port}</span>
      {svc && <span className="live-cell-svc">{svc}</span>}
    </span>
  )
}

function LogDrawer({ log, now, onClose }) {
  const isAttack = !!log.is_attack
  const ts = log.created_at ? new Date(log.created_at) : null

  const probEntries = useMemo(() => {
    const p = log.probabilities || {}
    return Object.entries(p)
      .map(([name, value]) => ({ name, value: Number(value) || 0 }))
      .sort((a, b) => b.value - a.value)
  }, [log])

  const topFeatures = useMemo(() => {
    const f = log.top_features || []
    if (!Array.isArray(f)) return []
    return [...f]
      .sort((a, b) => (a.rank ?? 999) - (b.rank ?? 999))
      .slice(0, 5)
  }, [log])

  return (
    <>
      <div className="log-drawer-overlay" onClick={onClose} />
      <aside className={`log-drawer ${isAttack ? 'log-drawer-attack' : 'log-drawer-benign'}`}>
        <div className="log-drawer-head">
          <div className="log-drawer-head-title">
            {isAttack ? <ShieldAlert size={18} /> : <ShieldCheck size={18} />}
            <span>Flow Details</span>
          </div>
          <button className="log-drawer-close" onClick={onClose} aria-label="Close">
            <X size={18} />
          </button>
        </div>

        <div className="log-drawer-body">
          {/* Verdict */}
          <div className="log-verdict">
            <div className={`log-verdict-pill ${isAttack ? 'log-verdict-attack' : 'log-verdict-benign'}`}>
              {log.attack_type}
            </div>
            {log.group_pred && log.group_pred !== log.attack_type && (
              <div className="log-verdict-group">{log.group_pred}</div>
            )}
            <div className="log-verdict-row">
              <Badge severity={log.severity} />
              <div className="log-verdict-conf">
                <ConfidenceBar value={log.confidence ?? 0} />
              </div>
            </div>
          </div>

          {/* Timestamp */}
          <div className="log-drawer-section">
            <div className="log-drawer-label">Timestamp</div>
            <div className="log-drawer-val mono">
              {ts ? ts.toLocaleString() : '—'}
              {ts && <span className="log-drawer-rel"> · {relTime(log.created_at, now)}</span>}
            </div>
          </div>

          {/* Flow identity */}
          <div className="log-drawer-section">
            <div className="log-drawer-label">Flow</div>
            <div className="log-flow">
              <span className="log-flow-ip mono">{log.src_ip || '—'}</span>
              {log.src_port ? (
                <>
                  <span className="log-flow-sep mono">:</span>
                  <span className="log-flow-port mono">{log.src_port}</span>
                </>
              ) : null}
              <ArrowRight size={16} className="log-flow-arrow" />
              <span className="log-flow-ip mono">{log.dst_ip || '—'}</span>
              {log.dst_port != null && (
                <>
                  <span className="log-flow-sep mono">:</span>
                  <span className="log-flow-port mono">{log.dst_port}</span>
                </>
              )}
            </div>
            <div className="log-flow-tags">
              <span className={`log-flow-tag ${protoClass(log.protocol)}`}>
                {protoLabel(log.protocol) || 'Proto —'}
              </span>
              {(() => {
                const svc = serviceLabel(log.dst_port) || serviceLabel(log.src_port)
                return svc ? (
                  <span className="log-flow-tag log-flow-tag-svc">{svc}</span>
                ) : null
              })()}
              <DrawerVlanTag side="Src" vlan={log.src_vlan} />
              <DrawerVlanTag side="Dst" vlan={log.dst_vlan} />
            </div>
          </div>

          {/* Probability breakdown */}
          {probEntries.length > 0 && (
            <div className="log-drawer-section">
              <div className="log-drawer-label">Class probabilities</div>
              <div className="log-prob-list">
                {probEntries.map((p, idx) => {
                  const pct = p.value * 100
                  const isTop = idx === 0
                  const isPredicted = p.name === log.attack_type
                  return (
                    <div key={p.name} className={`log-prob-row ${isTop ? 'log-prob-row-top' : ''}`}>
                      <div className="log-prob-head">
                        <span className={`log-prob-name ${isPredicted ? 'log-prob-name-top' : ''}`}>
                          {p.name}
                        </span>
                        <span className={`log-prob-pct mono ${isTop ? 'log-prob-pct-top' : ''}`}>
                          {pct.toFixed(2)}%
                        </span>
                      </div>
                      <div className="log-prob-track">
                        <div
                          className={`log-prob-fill ${isTop ? 'log-prob-fill-top' : ''}`}
                          style={{ width: `${Math.max(pct, 0.5)}%` }}
                        />
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {/* Top contributing features */}
          {topFeatures.length > 0 && (
            <div className="log-drawer-section">
              <div className="log-drawer-label">Top features (by global importance)</div>
              <div className="log-feat-list">
                {topFeatures.map((f, idx) => {
                  const name = f.name ?? f.feature ?? `feature_${idx}`
                  const value = f.value
                  const rank = f.rank
                  const isNeg = typeof value === 'number' && value < 0
                  return (
                    <div key={idx} className="log-feat-row">
                      <span className="log-feat-rank mono">#{rank ?? idx + 1}</span>
                      <span className="log-feat-name mono">{name}</span>
                      {value != null && (
                        <span className={`log-feat-val mono ${isNeg ? 'log-feat-val-neg' : ''}`}>
                          {typeof value === 'number' ? value.toFixed(3) : String(value)}
                        </span>
                      )}
                    </div>
                  )
                })}
              </div>
              <div className="log-drawer-sub">
                Values are standardized (z-score). Features are pre-ranked by overall model importance, not per-flow contribution.
              </div>
            </div>
          )}
        </div>
      </aside>
    </>
  )
}
