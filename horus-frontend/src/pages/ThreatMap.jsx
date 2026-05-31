import { useState, useEffect, useMemo } from 'react'
import { api } from '../api'
import { MapPin, RefreshCw, ShieldAlert } from 'lucide-react'
import Badge from '../components/Badge'
import {
  ComposableMap,
  Geographies,
  Geography,
  Marker,
} from 'react-simple-maps'

const GEO_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json'

const SEV_COLORS = { critical: '#dc2626', high: '#ca8a04', medium: '#7c3aed', info: '#16a34a' }

const REGIONS = [
  { lat: 39.9, lng: 116.4, label: 'China' },
  { lat: 55.7, lng: 37.6, label: 'Russia' },
  { lat: 38.9, lng: -77.0, label: 'USA' },
  { lat: 51.5, lng: -0.1, label: 'UK' },
  { lat: 48.8, lng: 2.3, label: 'France' },
  { lat: 52.5, lng: 13.4, label: 'Germany' },
  { lat: 35.6, lng: 139.7, label: 'Japan' },
  { lat: -23.5, lng: -46.6, label: 'Brazil' },
  { lat: 37.5, lng: 127.0, label: 'S. Korea' },
  { lat: 28.6, lng: 77.2, label: 'India' },
]

function ipToCoords(ip) {
  if (!ip) return null
  const parts = ip.split('.').map(Number)
  const region = REGIONS[parts[0] % REGIONS.length]
  return {
    lat: region.lat + ((parts[2] - 128) / 256) * 3,
    lng: region.lng + ((parts[3] - 128) / 256) * 4,
    country: region.label,
  }
}

export default function ThreatMap() {
  const [predictions, setPredictions] = useState([])
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [tooltip, setTooltip] = useState(null)

  const load = async () => {
    setRefreshing(true)
    try {
      const data = await api.predictions({ limit: 200, attack_only: true })
      setPredictions(data.results || [])
    } catch (e) { console.error(e) }
    finally { setLoading(false); setRefreshing(false) }
  }

  useEffect(() => { load() }, [])
  useEffect(() => { const id = setInterval(load, 8000); return () => clearInterval(id) }, [])

  const points = useMemo(() => predictions
    .filter(p => p.src_ip && p.is_attack)
    .map(p => {
      const geo = ipToCoords(p.src_ip)
      if (!geo) return null
      return { ...p, ...geo }
    })
    .filter(Boolean), [predictions])

  const byCountry = useMemo(() => {
    const map = {}
    points.forEach(p => {
      if (!map[p.country]) map[p.country] = { count: 0, critical: 0, types: new Set() }
      map[p.country].count++
      if (p.severity === 'critical') map[p.country].critical++
      map[p.country].types.add(p.attack_type)
    })
    return Object.entries(map).sort((a, b) => b[1].count - a[1].count)
  }, [points])

  const totalAttacks = points.length
  const totalCritical = points.filter(p => p.severity === 'critical').length

  if (loading) return <div className="loading"><div className="spinner" /> Loading threat map...</div>

  return (
    <div className="threat-page">
      <div className="dash-header">
        <div>
          <h2 className="dash-title" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            Threat Map
            {points.length > 0 && <span className="live-dot receiving" />}
          </h2>
          <p className="dash-subtitle">Geographic visualization of detected attack origins (simulated GeoIP)</p>
        </div>
        <button className="btn btn-primary" onClick={load} disabled={refreshing}>
          <RefreshCw size={15} className={refreshing ? 'spin' : ''} /> {refreshing ? 'Refreshing…' : 'Refresh'}
        </button>
      </div>

      <div className="threat-summary">
        <div className="threat-summary-item">
          <span className="threat-summary-value mono" style={{ color: 'var(--danger)' }}>{totalAttacks}</span>
          <span className="threat-summary-label">Total Attacks</span>
        </div>
        <div className="threat-summary-sep" />
        <div className="threat-summary-item">
          <span className="threat-summary-value mono" style={{ color: '#dc2626' }}>{totalCritical}</span>
          <span className="threat-summary-label">Critical</span>
        </div>
        <div className="threat-summary-sep" />
        <div className="threat-summary-item">
          <span className="threat-summary-value mono" style={{ color: 'var(--accent)' }}>{byCountry.length}</span>
          <span className="threat-summary-label">Countries</span>
        </div>
        <div className="threat-summary-sep" />
        <div className="threat-summary-item">
          <span className="threat-summary-value mono" style={{ color: 'var(--purple)' }}>
            {new Set(points.map(p => p.attack_type)).size}
          </span>
          <span className="threat-summary-label">Attack Types</span>
        </div>
      </div>

      <div className="card threat-map-card">
        <ComposableMap
          projection="geoMercator"
          projectionConfig={{ scale: 130, center: [10, 30] }}
          className="threat-map-svg"
        >
          <Geographies geography={GEO_URL}>
            {({ geographies }) =>
              geographies.map(geo => (
                <Geography
                  key={geo.rsmKey}
                  geography={geo}
                  strokeWidth={0.5}
                  style={{
                    default: { fill: 'var(--geo-fill)', stroke: 'var(--geo-stroke)', outline: 'none' },
                    hover: { fill: 'var(--geo-hover)', stroke: 'var(--geo-stroke)', outline: 'none' },
                    pressed: { fill: 'var(--geo-fill)', outline: 'none' },
                  }}
                />
              ))
            }
          </Geographies>

          {points.map((p, i) => {
            const r = p.severity === 'critical' ? 6 : p.severity === 'high' ? 5 : 4
            return (
              <Marker
                key={`${p.id}-${i}`}
                coordinates={[p.lng, p.lat]}
                onMouseEnter={() => setTooltip(p)}
                onMouseLeave={() => setTooltip(null)}
              >
                <circle r={r * 2.5} fill={SEV_COLORS[p.severity] || '#5a6678'} opacity={0.15} />
                <circle r={r} fill={SEV_COLORS[p.severity] || '#5a6678'} opacity={0.85} />
              </Marker>
            )
          })}
        </ComposableMap>

        {tooltip && (
          <div className="threat-map-tooltip">
            <strong>{tooltip.attack_type}</strong>
            <span>{tooltip.country} &middot; {tooltip.src_ip}</span>
            <span className={`badge badge-${tooltip.severity}`} style={{ alignSelf: 'flex-start' }}>
              {tooltip.severity}
            </span>
          </div>
        )}

        <div className="threat-map-legend">
          {Object.entries(SEV_COLORS).filter(([s]) => s !== 'info').map(([sev, color]) => (
            <div key={sev} className="threat-map-legend-item">
              <span className="threat-map-legend-dot" style={{ background: color }} />
              <span>{sev}</span>
            </div>
          ))}
        </div>
      </div>

      <div className="grid-2 threat-bottom">
        <div className="card">
          <div className="card-header">
            <h3>Attack Sources by Country</h3>
            <span className="mini-badge">{byCountry.length} countries</span>
          </div>
          {byCountry.length === 0 ? (
            <div className="empty-state">
              <MapPin size={40} />
              <p style={{ fontSize: 15, marginTop: 12 }}>No attack data yet. Run predictions first.</p>
            </div>
          ) : (
            <div className="threat-country-list">
              {byCountry.slice(0, 10).map(([country, data], idx) => {
                const pct = totalAttacks > 0 ? (data.count / totalAttacks) * 100 : 0
                return (
                  <div key={country} className="threat-country-row">
                    <span className="threat-country-rank mono">{idx + 1}</span>
                    <div className="threat-country-info">
                      <div className="threat-country-name-row">
                        <span className="threat-country-name">{country}</span>
                        <span className="threat-country-count mono">{data.count}</span>
                      </div>
                      <div className="threat-country-bar-track">
                        <div
                          className="threat-country-bar-fill"
                          style={{ width: `${pct}%`, background: data.critical > 0 ? '#dc2626' : 'var(--accent)' }}
                        />
                      </div>
                    </div>
                    {data.critical > 0 && (
                      <span className="badge badge-critical">{data.critical}</span>
                    )}
                  </div>
                )
              })}
            </div>
          )}
        </div>

        <div className="card">
          <div className="card-header">
            <h3>Recent Attacks</h3>
            <span className="mini-badge">{predictions.filter(p => p.is_attack).length} total</span>
          </div>
          {predictions.filter(p => p.is_attack).length === 0 ? (
            <div className="empty-state">
              <ShieldAlert size={40} />
              <p style={{ fontSize: 15, marginTop: 12 }}>No attacks detected yet.</p>
            </div>
          ) : (
            <div className="threat-attack-list">
              {predictions.filter(p => p.is_attack).slice(0, 10).map(p => (
                <div key={p.id} className="threat-attack-row">
                  <div className="threat-attack-info">
                    <div className="threat-attack-top">
                      <span className="threat-attack-type">{p.attack_type}</span>
                      <Badge severity={p.severity} />
                    </div>
                    <div className="threat-attack-meta">
                      <span className="mono">{p.src_ip || '—'}</span>
                      <span className="threat-attack-time mono">
                        {new Date(p.created_at).toLocaleTimeString()}
                      </span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
