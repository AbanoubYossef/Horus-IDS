import { Component } from 'react'
import { AlertTriangle } from 'lucide-react'

export default class ErrorBoundary extends Component {
  constructor(props) {
    super(props)
    this.state = { hasError: false, error: null }
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error }
  }

  componentDidCatch(error, info) {
    console.error('[ErrorBoundary]', error, info.componentStack)
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          padding: '64px 24px',
          textAlign: 'center',
          minHeight: '50vh',
        }}>
          <AlertTriangle size={48} color="var(--danger)" style={{ marginBottom: 16, opacity: 0.7 }} />
          <h3 style={{ fontSize: 18, fontWeight: 600, marginBottom: 8 }}>
            Something went wrong
          </h3>
          <p style={{ fontSize: 13, color: 'var(--text-muted)', maxWidth: 400, marginBottom: 20 }}>
            {this.state.error?.message || 'An unexpected error occurred in this component.'}
          </p>
          <button
            className="btn btn-primary"
            onClick={() => {
              this.setState({ hasError: false, error: null })
              window.location.reload()
            }}
          >
            Reload Page
          </button>
        </div>
      )
    }

    return this.props.children
  }
}
