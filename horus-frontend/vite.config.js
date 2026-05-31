import { defineConfig, loadEnv } from 'vite'
import react from '@vitejs/plugin-react'

function apiOnly(target) {
  return {
    target,
    changeOrigin: true,
    bypass(req) {
      if (req.headers.accept?.includes('text/html')) {
        return req.url
      }
    },
  }
}

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, process.cwd(), '')
  const apiTarget = env.VITE_API_URL || 'http://localhost:8000'

  return {
    plugins: [react()],
    server: {
      port: 3000,
      proxy: {
        '/health':      { target: apiTarget, changeOrigin: true },
        '/classes':     { target: apiTarget, changeOrigin: true },
        '/features':    { target: apiTarget, changeOrigin: true },
        '/data':        { target: apiTarget, changeOrigin: true },
        '/predict':     { target: apiTarget, changeOrigin: true },
        '/predictions': { target: apiTarget, changeOrigin: true },
        '/db':          { target: apiTarget, changeOrigin: true },
        '/upload':      apiOnly(apiTarget),
        '/ws':          { target: apiTarget, changeOrigin: true, ws: true },
        '/auth':        { target: apiTarget, changeOrigin: true },
        '/alerts':      apiOnly(apiTarget),
        '/ai':          { target: apiTarget, changeOrigin: true },
      },
    },
  }
})
