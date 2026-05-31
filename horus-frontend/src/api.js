const API = import.meta.env.VITE_API_URL || ''
const WS_BASE = API.replace(/^http/, 'ws')
const API_KEY = import.meta.env.VITE_API_KEY || ''

function authHeaders() {
  const headers = { 'Content-Type': 'application/json' }
  if (API_KEY) headers['X-API-Key'] = API_KEY
  return headers
}

async function request(path, opts = {}) {
  const res = await fetch(`${API}${path}`, {
    credentials: 'include',
    headers: { ...authHeaders(), ...opts.headers },
    ...opts,
  })
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }))
    throw new Error(err.detail || `HTTP ${res.status}`)
  }
  return res.json()
}

export const api = {
  // auth
  login:    (username, password) => request('/auth/login', { method: 'POST', body: JSON.stringify({ username, password }) }),
  register: (username, email, password, role) => request('/auth/register', { method: 'POST', body: JSON.stringify({ username, email, password, role }) }),
  logout:   () => request('/auth/logout', { method: 'POST' }),
  me:       () => request('/auth/me'),

  // endpoints
  health:      ()          => request('/health'),
  classes:     ()          => request('/classes'),
  features:    ()          => request('/features'),
  sample:      ()          => request('/data/sample'),
  stats:       (window)    => request(`/predictions/stats${window ? `?window=${window}` : ''}`),
  dbStats:     ()          => request('/db/stats'),
  ws:          ()          => new WebSocket(`${WS_BASE}/ws/predictions`),
  predictions: (params)    => request(`/predictions?${new URLSearchParams(params)}`),
  clear:       ()          => request('/predictions/clear', { method: 'DELETE' }),
  retain:      (days = 30) => request(`/predictions/retain?days=${days}`, { method: 'DELETE' }),

  predict: (features_dict, src_ip, dst_ip, dst_port) =>
    request('/predict', {
      method: 'POST',
      body: JSON.stringify({ features_dict, src_ip, dst_ip, dst_port }),
    }),

  predictBatch: (flows) =>
    request('/predict/batch', {
      method: 'POST',
      body: JSON.stringify(flows),
    }),

  uploadCsv: async (file) => {
    const form = new FormData()
    form.append('file', file)
    const headers = {}
    if (API_KEY) headers['X-API-Key'] = API_KEY
    const res = await fetch(`${API}/upload/csv`, { method: 'POST', body: form, headers, credentials: 'include' })
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: res.statusText }))
      throw new Error(err.detail || `HTTP ${res.status}`)
    }
    return res.json()
  },

  // alerts
  getAlerts:    (params = {}) => request(`/alerts?${new URLSearchParams(params)}`),
  getAlert:     (id)          => request(`/alerts/${id}`),
  createAlert:  (data)        => request('/alerts', { method: 'POST', body: JSON.stringify(data) }),
  updateAlert:  (id, data)    => request(`/alerts/${id}`, { method: 'PUT', body: JSON.stringify(data) }),
  deleteAlert:  (id)          => request(`/alerts/${id}`, { method: 'DELETE' }),
  generateAlerts: ()          => request('/alerts/generate', { method: 'POST' }),


  // ai
  aiChat: (message, history = []) => request('/ai/chat', { method: 'POST', body: JSON.stringify({ message, history }) }),
}
