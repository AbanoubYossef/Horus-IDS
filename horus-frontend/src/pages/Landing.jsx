import { useNavigate } from 'react-router-dom'
import { Shield, ArrowRight, ChevronRight, Lock, Gauge, Layers, Activity, Zap, Database, Network, Sun, Moon, LogIn } from 'lucide-react'
import { useTheme } from '../useTheme'

const METRICS = [
  { val: '98.70%', lbl: 'F1 Score',        icon: Gauge },
  { val: '0.178%', lbl: 'False Alarm Rate', icon: Lock },
  { val: '11',     lbl: 'Attack Classes',   icon: Layers },
  { val: '1.6M',   lbl: 'Flows Tested',     icon: Activity },
]

const CAPABILITIES = [
  { icon: Zap,      label: 'Live Flow Analysis' },
  { icon: Database,  label: 'CSV Batch Upload' },
  { icon: Network,   label: 'Threat Visualization' },
]

const PIPELINE = ['Capture', 'Feature Eng.', 'Level 1', 'Level 2', '11 Classes']

export default function Landing() {
  const nav = useNavigate()
  const [theme, toggleTheme] = useTheme()

  return (
    <div className="landing">
      <nav className="landing-nav">
        <div className="landing-nav-brand">
          <div className="landing-logo-icon"><Shield size={18} /></div>
          <h1>HORUS</h1>
          <span className="landing-nav-tag">IDS</span>
        </div>
        <div className="landing-nav-right">
          <button className="theme-toggle" onClick={toggleTheme} title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}>
            {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
          </button>
          <button className="btn btn-primary" onClick={() => nav('/login')}>
            <LogIn size={15} /> Sign In
          </button>
        </div>
      </nav>

      <main className="landing-main">
        <div className="landing-hero">
          <div className="landing-badge">
            <span className="landing-badge-dot" />
            Model Ready
          </div>

          <h2>
            Network Intrusion Detection<br />
            <span className="accent">Powered by Machine Learning</span>
          </h2>

          <p>
            Hierarchical XGBoost ensemble trained on 4.9 million flows from
            CIC-IDS2017, CIC-IDS2018, and CIC-DDoS2019.
          </p>

          <div className="landing-cta-row">
            <button className="btn btn-primary landing-cta" onClick={() => nav('/login')}>
              Get Started <ArrowRight size={16} />
            </button>
          </div>
        </div>

        <div className="landing-cards">
          <div className="landing-metrics">
            {METRICS.map(m => {
              const Icon = m.icon
              return (
                <div className="landing-metric" key={m.lbl}>
                  <div className="landing-metric-top">
                    <Icon size={15} className="landing-metric-icon" />
                    <span className="landing-metric-lbl">{m.lbl}</span>
                  </div>
                  <div className="landing-metric-val">{m.val}</div>
                </div>
              )
            })}
          </div>

          <div className="landing-bottom-row">
            <div className="landing-pipeline">
              <span className="landing-pipeline-title">Detection Pipeline</span>
              <div className="landing-pipeline-steps">
                {PIPELINE.map((step, i) => (
                  <span key={step} className="landing-pipeline-step">
                    <span className="landing-pipeline-num">{i + 1}</span>
                    {step}
                    {i < PIPELINE.length - 1 && <ChevronRight size={13} className="landing-pipeline-arrow" />}
                  </span>
                ))}
              </div>
            </div>

            <div className="landing-caps">
              {CAPABILITIES.map(({ icon: Icon, label }) => (
                <div className="landing-cap" key={label}>
                  <Icon size={16} />
                  <span>{label}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </main>

      <footer className="landing-footer">
        Technical University of Cluj-Napoca — Bachelor Thesis 2025–2026
      </footer>
    </div>
  )
}
