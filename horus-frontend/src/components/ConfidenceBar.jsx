export default function ConfidenceBar({ value }) {
  const pct = (value * 100).toFixed(1)
  const color = value >= 0.9
    ? 'var(--success)'
    : value >= 0.7
      ? 'var(--accent)'
      : 'var(--warning)'

  return (
    <div className="confidence-bar">
      <div className="confidence-track">
        <div
          className="confidence-fill"
          style={{ width: `${pct}%`, background: color }}
        />
      </div>
      <span className="confidence-label">{pct}%</span>
    </div>
  )
}
