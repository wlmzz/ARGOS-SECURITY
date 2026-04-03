import { useState, useRef, useEffect } from 'react'
import { api } from '../api'

interface Message {
  id: number
  role: 'user' | 'assistant'
  content: string
  loading?: boolean
  timestamp: string
}

const SUGGESTIONS = [
  'What are the most common attack vectors in brute force attempts?',
  'Explain what a port scan indicates about attacker intent',
  'How should I respond to a ransomware detection?',
  'What IP ranges are commonly used by Tor exit nodes?',
  'Explain the difference between block_ip and isolate_process actions',
]

let _id = 0
function mkId() { return ++_id }

export function AiChat() {
  const [messages, setMessages] = useState<Message[]>([
    {
      id: mkId(), role: 'assistant',
      content: 'ARGOS-AI online. I have access to your threat intelligence context. Ask me anything about security events, threat analysis, or incident response.',
      timestamp: new Date().toISOString(),
    }
  ])
  const [input, setInput] = useState('')
  const [sending, setSending] = useState(false)
  const bottomRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLTextAreaElement>(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  const send = async (text?: string) => {
    const msg = (text ?? input).trim()
    if (!msg || sending) return
    setInput('')

    const userMsg: Message = { id: mkId(), role: 'user', content: msg, timestamp: new Date().toISOString() }
    const loadingMsg: Message = { id: mkId(), role: 'assistant', content: '', loading: true, timestamp: new Date().toISOString() }
    setMessages(prev => [...prev, userMsg, loadingMsg])
    setSending(true)

    const history = messages
      .filter(m => !m.loading)
      .map(m => ({ role: m.role as 'user' | 'assistant', content: m.content }))

    try {
      const res = await api.aiChat(msg, history)
      setMessages(prev => prev.map(m =>
        m.id === loadingMsg.id ? { ...m, content: res.reply, loading: false } : m
      ))
    } catch (e: any) {
      setMessages(prev => prev.map(m =>
        m.id === loadingMsg.id ? { ...m, content: `ERROR: ${e?.message ?? 'AI backend unavailable'}`, loading: false } : m
      ))
    }
    setSending(false)
    inputRef.current?.focus()
  }

  const handleKey = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send() }
  }

  const clearConversation = () => {
    setMessages([{
      id: mkId(), role: 'assistant',
      content: 'Conversation cleared. ARGOS-AI online. How can I help?',
      timestamp: new Date().toISOString(),
    }])
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', padding: 20, gap: 16 }}>

      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0, paddingBottom: 12, borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ width: 2, height: 16, background: '#a78bfa', borderRadius: 1 }} />
          <span style={{ color: '#fff', fontSize: 11, letterSpacing: '2.5px', fontWeight: 700, textTransform: 'uppercase' }}>AI Assistant</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{
            display: 'flex', alignItems: 'center', gap: 6,
            background: 'rgba(34,197,94,0.08)', border: '1px solid rgba(34,197,94,0.2)',
            borderRadius: 4, padding: '4px 10px',
          }}>
            <div style={{ width: 6, height: 6, borderRadius: '50%', background: '#22c55e', animation: 'pulse-dot 2s infinite' }} />
            <span style={{ color: '#22c55e', fontSize: 9, letterSpacing: '1.5px', fontWeight: 600 }}>ONLINE</span>
          </div>
          <button
            onClick={clearConversation}
            style={{
              background: 'none', border: '1px solid rgba(255,255,255,0.08)',
              borderRadius: 3, color: '#444', padding: '3px 10px',
              fontSize: 9, letterSpacing: '1.5px', cursor: 'pointer',
              textTransform: 'uppercase', fontWeight: 600, transition: 'all 0.12s',
            }}
            onMouseEnter={e => { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.2)'; e.currentTarget.style.color = '#aaa' }}
            onMouseLeave={e => { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.08)'; e.currentTarget.style.color = '#444' }}
          >
            CLEAR
          </button>
        </div>
      </div>

      {/* Suggestions */}
      {messages.length === 1 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, flexShrink: 0 }}>
          {SUGGESTIONS.map((s, i) => (
            <button
              key={i} onClick={() => send(s)}
              style={{
                background: '#111', border: '1px solid rgba(255,255,255,0.08)',
                borderRadius: 4, color: '#aaa', fontSize: 11, padding: '5px 10px',
                cursor: 'pointer', transition: 'all 0.15s', textAlign: 'left', fontWeight: 400,
              }}
              onMouseEnter={e => { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.2)'; e.currentTarget.style.color = '#fff' }}
              onMouseLeave={e => { e.currentTarget.style.borderColor = 'rgba(255,255,255,0.08)'; e.currentTarget.style.color = '#aaa' }}
            >
              {s}
            </button>
          ))}
        </div>
      )}

      {/* Messages */}
      <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 12, paddingRight: 4 }}>
        {messages.map(m => <ChatBubble key={m.id} msg={m} />)}
        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <div style={{
        flexShrink: 0, background: '#111',
        border: '1px solid rgba(255,255,255,0.07)', borderRadius: 6,
        padding: '10px 12px', display: 'flex', gap: 10, alignItems: 'flex-end',
      }}>
        <textarea
          ref={inputRef} value={input}
          onChange={e => setInput(e.target.value)} onKeyDown={handleKey}
          placeholder="Ask about threats, incidents, CVEs, tactics... (Enter to send)"
          rows={1}
          style={{
            flex: 1, background: 'none', border: 'none',
            color: '#fff', fontSize: 13, resize: 'none',
            lineHeight: 1.5, maxHeight: 120, overflow: 'auto', fontWeight: 400,
          }}
        />
        <button
          onClick={() => send()} disabled={!input.trim() || sending}
          style={{
            background: input.trim() && !sending ? '#fff' : '#2a2a2a',
            border: 'none', borderRadius: 5,
            color: input.trim() && !sending ? '#0a0a0a' : '#444',
            padding: '6px 16px', fontSize: 10, letterSpacing: '1.5px',
            cursor: input.trim() && !sending ? 'pointer' : 'not-allowed',
            fontWeight: 700, flexShrink: 0, transition: 'all 0.15s',
          }}
        >
          {sending ? '...' : 'SEND'}
        </button>
      </div>
    </div>
  )
}

function ChatBubble({ msg }: { msg: Message }) {
  const isUser = msg.role === 'user'
  const [copied, setCopied] = useState(false)
  const [hovered, setHovered] = useState(false)

  const handleCopy = () => {
    navigator.clipboard.writeText(msg.content).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    })
  }

  if (isUser) {
    return (
      <div style={{ display: 'flex', justifyContent: 'flex-end', animation: 'fadeIn 0.2s ease' }}>
        <div>
          <div style={{
            maxWidth: '72%',
            background: '#161616',
            border: '1px solid rgba(255,255,255,0.08)',
            borderRadius: '8px 8px 2px 8px',
            padding: '9px 13px', color: '#fff',
            fontSize: 13, lineHeight: 1.55, whiteSpace: 'pre-wrap', fontWeight: 400,
          }}>
            {msg.content}
          </div>
          {msg.timestamp && (
            <div style={{ fontSize: 8, color: '#333', marginTop: 3, textAlign: 'right' }}>
              {new Date(msg.timestamp).toLocaleTimeString('it-IT', { hour: '2-digit', minute: '2-digit' })}
            </div>
          )}
        </div>
      </div>
    )
  }

  return (
    <div style={{ display: 'flex', gap: 10, animation: 'fadeIn 0.2s ease' }}
      onMouseEnter={() => setHovered(true)}
      onMouseLeave={() => setHovered(false)}
    >
      <div style={{
        width: 28, height: 28, borderRadius: '50%',
        background: '#161616', border: '1px solid rgba(255,255,255,0.1)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        flexShrink: 0, marginTop: 2, fontSize: 9, color: '#fff', fontWeight: 700, letterSpacing: '1px',
      }}>
        AI
      </div>
      <div>
        <div style={{
          maxWidth: '80%', background: '#111',
          border: '1px solid rgba(255,255,255,0.07)',
          borderRadius: '2px 8px 8px 8px', padding: '9px 13px',
        }}>
          {msg.loading ? (
            <div style={{ display: 'flex', gap: 4, alignItems: 'center', padding: '4px 0' }}>
              {[0, 1, 2].map(i => (
                <div key={i} style={{
                  width: 5, height: 5, borderRadius: '50%', background: '#fff',
                  animation: `typing-dot 1.2s ease ${i * 0.2}s infinite`,
                }} />
              ))}
            </div>
          ) : (
            <div style={{ color: '#fff', fontSize: 13, lineHeight: 1.65, whiteSpace: 'pre-wrap', wordBreak: 'break-word', fontWeight: 400 }}>
              {msg.content}
            </div>
          )}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginTop: 4, gap: 8 }}>
          {msg.timestamp && (
            <span style={{ fontSize: 8, color: '#333' }}>
              {new Date(msg.timestamp).toLocaleTimeString('it-IT', { hour: '2-digit', minute: '2-digit' })}
            </span>
          )}
          {!msg.loading && hovered && (
            <button
              onClick={handleCopy}
              style={{
                background: 'none', border: '1px solid rgba(255,255,255,0.08)',
                borderRadius: 3, color: copied ? '#22c55e' : '#444',
                padding: '2px 8px', fontSize: 8, letterSpacing: '1px',
                cursor: 'pointer', fontWeight: 600, transition: 'all 0.1s',
              }}
            >
              {copied ? 'COPIED' : 'COPY'}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}
