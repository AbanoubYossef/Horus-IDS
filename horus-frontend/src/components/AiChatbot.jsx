import { useState, useRef, useEffect } from 'react'
import { api } from '../api'
import { MessageSquare, Send, X, Minimize2, Maximize2, Bot, User } from 'lucide-react'

export default function AiChatbot() {
  const [open, setOpen] = useState(false)
  const [minimized, setMinimized] = useState(false)
  const [messages, setMessages] = useState([
    { role: 'assistant', content: 'Hello! I\'m the HORUS IDS AI Assistant. I can help you analyze threats, understand attack patterns, and provide security recommendations based on your platform data. How can I help?' }
  ])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const messagesEnd = useRef(null)
  const inputRef = useRef(null)

  useEffect(() => {
    messagesEnd.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  useEffect(() => {
    if (open && !minimized) inputRef.current?.focus()
  }, [open, minimized])

  const sendMessage = async (e) => {
    e.preventDefault()
    if (!input.trim() || loading) return

    const userMsg = input.trim()
    setInput('')
    setMessages(prev => [...prev, { role: 'user', content: userMsg }])
    setLoading(true)

    try {
      const history = messages.map(m => ({ role: m.role, content: m.content }))
      const data = await api.aiChat(userMsg, history)
      setMessages(prev => [...prev, { role: 'assistant', content: data.response }])
    } catch (err) {
      setMessages(prev => [...prev, { role: 'assistant', content: `Error: ${err.message}` }])
    } finally {
      setLoading(false)
    }
  }

  if (!open) {
    return (
      <button className="chatbot-fab" onClick={() => setOpen(true)} title="AI Assistant">
        <MessageSquare size={24} />
      </button>
    )
  }

  return (
    <div className={`chatbot-container ${minimized ? 'minimized' : ''}`}>
      {/* Header */}
      <div className="chatbot-header">
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <Bot size={18} />
          <span style={{ fontWeight: 600, fontSize: 13 }}>HORUS AI Assistant</span>
        </div>
        <div style={{ display: 'flex', gap: 4 }}>
          <button onClick={() => setMinimized(!minimized)} className="chatbot-header-btn">
            {minimized ? <Maximize2 size={14} /> : <Minimize2 size={14} />}
          </button>
          <button onClick={() => setOpen(false)} className="chatbot-header-btn">
            <X size={14} />
          </button>
        </div>
      </div>

      {!minimized && (
        <>
          {/* Messages */}
          <div className="chatbot-messages">
            {messages.map((msg, i) => (
              <div key={i} className={`chatbot-msg ${msg.role}`}>
                <div className="chatbot-msg-icon">
                  {msg.role === 'assistant' ? <Bot size={14} /> : <User size={14} />}
                </div>
                <div className="chatbot-msg-content">
                  {msg.content.split('\n').map((line, j) => (
                    <p key={j} style={{ margin: line ? '4px 0' : '0' }}>{line}</p>
                  ))}
                </div>
              </div>
            ))}
            {loading && (
              <div className="chatbot-msg assistant">
                <div className="chatbot-msg-icon"><Bot size={14} /></div>
                <div className="chatbot-msg-content">
                  <div className="chatbot-typing">
                    <span /><span /><span />
                  </div>
                </div>
              </div>
            )}
            <div ref={messagesEnd} />
          </div>

          {/* Input */}
          <form onSubmit={sendMessage} className="chatbot-input-area">
            <input
              ref={inputRef}
              type="text"
              value={input}
              onChange={e => setInput(e.target.value)}
              placeholder="Ask about threats, attacks, recommendations..."
              disabled={loading}
            />
            <button type="submit" disabled={!input.trim() || loading} className="chatbot-send-btn">
              <Send size={16} />
            </button>
          </form>
        </>
      )}
    </div>
  )
}
