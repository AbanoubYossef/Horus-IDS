import { useState, useEffect } from 'react'
import { Routes, Route, NavLink, useLocation, Navigate } from 'react-router-dom'
import { Shield, Home, LayoutDashboard, Upload, Radio, BarChart3, Globe, Bell, Database, UserPlus, Sun, Moon, LogOut, LogIn, User } from 'lucide-react'
import { useTheme } from './useTheme'
import { useAuth } from './context/AuthContext'
import ErrorBoundary from './components/ErrorBoundary'
import Landing from './pages/Landing'
import Login from './pages/Login'
import Register from './pages/Register'
import Dashboard from './pages/Dashboard'
import UploadPage from './pages/Upload'
import LiveLogs from './pages/LiveLogs'
import Statistics from './pages/Statistics'
import ThreatMap from './pages/ThreatMap'
import Alerts from './pages/Alerts'
import History from './pages/History'
import AiChatbot from './components/AiChatbot'

const PUBLIC_NAV = [
  { to: '/dashboard',  icon: LayoutDashboard, label: 'Dashboard' },
  { to: '/statistics', icon: BarChart3,       label: 'Statistics' },
  { to: '/map',        icon: Globe,           label: 'Threat Map' },
]

const AUTH_NAV = [
  { to: '/alerts',     icon: Bell,            label: 'Alerts' },
  { to: '/history',    icon: Database,         label: 'History' },
  { to: '/upload',     icon: Upload,          label: 'Upload CSV' },
  { to: '/live',       icon: Radio,           label: 'Live Logs' },
  { to: '/register',   icon: UserPlus,        label: 'Create User' },
]

function ProtectedRoute({ children }) {
  const { user, loading } = useAuth()
  if (loading) return <div className="loading"><div className="spinner" /> Loading...</div>
  if (!user) return <Navigate to="/login" replace />
  if (user.role === 'visitor') return <Navigate to="/dashboard" replace />
  return children
}

function useClock() {
  const [time, setTime] = useState(() => new Date().toTimeString().slice(0, 8))
  useEffect(() => {
    const id = setInterval(() => setTime(new Date().toTimeString().slice(0, 8)), 1000)
    return () => clearInterval(id)
  }, [])
  return time
}

function Sidebar() {
  const clock = useClock()
  const [theme, toggleTheme] = useTheme()
  const { user, logout } = useAuth()

  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <div className="logo-row">
          <Shield size={18} color="var(--accent)" />
          <h1>HORUS IDS</h1>
        </div>
        <span>Intrusion Detection System</span>
      </div>

      <nav className="sidebar-nav">
        {PUBLIC_NAV.map(({ to, icon: Icon, label }) => (
          <NavLink key={to} to={to} className={({ isActive }) => isActive ? 'active' : ''}>
            <Icon />
            <span className="nav-label">{label}</span>
          </NavLink>
        ))}
        {user && user.role !== 'visitor' && AUTH_NAV.map(({ to, icon: Icon, label }) => (
          <NavLink key={to} to={to} className={({ isActive }) => isActive ? 'active' : ''}>
            <Icon />
            <span className="nav-label">{label}</span>
          </NavLink>
        ))}
      </nav>

      {user ? (
        <div className="sidebar-user">
          <div className="sidebar-user-info">
            <User size={14} />
            <div>
              <div style={{ fontWeight: 600, fontSize: 12 }}>{user.username}</div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>{user.role}</div>
            </div>
          </div>
          <button className="sidebar-logout" onClick={logout} title="Logout">
            <LogOut size={14} />
          </button>
        </div>
      ) : (
        <div className="sidebar-user">
          <NavLink to="/login" className="btn btn-primary" style={{ width: '100%', textAlign: 'center', textDecoration: 'none' }}>
            <LogIn size={14} /> Sign In
          </NavLink>
        </div>
      )}

      <div className="sidebar-bottom">
        <div className="sidebar-status">
          <div className="status-line">
            <span className="status-dot" />
            <span className="status-text">Model Ready</span>
          </div>
          <div className="status-clock">{clock}</div>
        </div>
        <button className="theme-toggle" onClick={toggleTheme} title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}>
          {theme === 'dark' ? <Sun size={16} /> : <Moon size={16} />}
        </button>
      </div>
    </aside>
  )
}

function AppLayout({ children }) {
  const { user } = useAuth()
  return (
    <div className="app-layout">
      <Sidebar />
      <main className="main-content">
        <div className="page-fade-in">
          {children}
        </div>
      </main>
      {user && <AiChatbot />}
    </div>
  )
}

export default function App() {
  const loc = useLocation()
  const isLanding = ['/', '/login'].includes(loc.pathname)

  if (isLanding) {
    return (
      <Routes>
        <Route path="/" element={<Landing />} />
        <Route path="/login" element={<Login />} />
      </Routes>
    )
  }

  return (
    <AppLayout>
      <ErrorBoundary>
        <Routes>
          {/* Public — visible to everyone */}
          <Route path="/dashboard"  element={<Dashboard />} />
          <Route path="/statistics" element={<Statistics />} />
          <Route path="/map"        element={<ThreatMap />} />

          {/* Protected — requires login */}
          <Route path="/alerts"    element={<ProtectedRoute><Alerts /></ProtectedRoute>} />
          <Route path="/history"   element={<ProtectedRoute><History /></ProtectedRoute>} />
          <Route path="/upload"    element={<ProtectedRoute><UploadPage /></ProtectedRoute>} />
          <Route path="/live"      element={<ProtectedRoute><LiveLogs /></ProtectedRoute>} />
          <Route path="/register"  element={<ProtectedRoute><Register /></ProtectedRoute>} />

          <Route path="*" element={<Dashboard />} />
        </Routes>
      </ErrorBoundary>
    </AppLayout>
  )
}
