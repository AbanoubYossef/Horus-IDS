import { useState } from 'react'
import { api } from '../api'
import { UserPlus, Eye, EyeOff, CheckCircle } from 'lucide-react'

export default function Register() {
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPwd, setConfirmPwd] = useState('')
  const [role, setRole] = useState('visitor')
  const [showPwd, setShowPwd] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [loading, setLoading] = useState(false)

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setSuccess('')

    if (password !== confirmPwd) {
      setError('Passwords do not match')
      return
    }
    if (password.length < 6) {
      setError('Password must be at least 6 characters')
      return
    }

    setLoading(true)
    try {
      await api.register(username, email, password, role)
      setSuccess(`User "${username}" created successfully as ${role}`)
      setUsername('')
      setEmail('')
      setPassword('')
      setConfirmPwd('')
      setRole('visitor')
    } catch (err) {
      setError(err.message || 'Registration failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div>
      <div className="page-header">
        <h2 style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <UserPlus size={22} /> Create User
        </h2>
        <p>Register a new visitor or SOC analyst account</p>
      </div>

      <div className="card" style={{ maxWidth: 520, margin: '0 auto' }}>
        <form onSubmit={handleSubmit} className="auth-form" style={{ padding: 24 }}>
          {error && <div className="auth-error">{error}</div>}
          {success && (
            <div style={{
              background: 'var(--stat-success-bg)', color: 'var(--success)',
              padding: '12px 16px', borderRadius: 8, fontSize: 13, fontWeight: 600,
              display: 'flex', alignItems: 'center', gap: 8, marginBottom: 16
            }}>
              <CheckCircle size={16} /> {success}
            </div>
          )}

          <div className="form-group">
            <label htmlFor="username">Username</label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={e => setUsername(e.target.value)}
              placeholder="Choose a username"
              required
              autoFocus
              minLength={3}
            />
          </div>

          <div className="form-group">
            <label htmlFor="email">Email</label>
            <input
              id="email"
              type="email"
              value={email}
              onChange={e => setEmail(e.target.value)}
              placeholder="user@email.com"
              required
            />
          </div>

          <div className="form-group">
            <label htmlFor="role">Role</label>
            <select id="role" value={role} onChange={e => setRole(e.target.value)}>
              <option value="visitor">Visitor</option>
              <option value="analyst">SOC Analyst</option>
            </select>
          </div>

          <div className="form-group">
            <label htmlFor="password">Password</label>
            <div className="input-with-icon">
              <input
                id="password"
                type={showPwd ? 'text' : 'password'}
                value={password}
                onChange={e => setPassword(e.target.value)}
                placeholder="Min 6 characters"
                required
                minLength={6}
              />
              <button type="button" className="input-icon-btn" onClick={() => setShowPwd(!showPwd)}>
                {showPwd ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
          </div>

          <div className="form-group">
            <label htmlFor="confirm">Confirm Password</label>
            <input
              id="confirm"
              type={showPwd ? 'text' : 'password'}
              value={confirmPwd}
              onChange={e => setConfirmPwd(e.target.value)}
              placeholder="Repeat password"
              required
            />
          </div>

          <button type="submit" className="btn btn-primary auth-submit" disabled={loading}>
            {loading ? <><div className="spinner" /> Creating...</> : <><UserPlus size={16} /> Create User</>}
          </button>
        </form>
      </div>
    </div>
  )
}
