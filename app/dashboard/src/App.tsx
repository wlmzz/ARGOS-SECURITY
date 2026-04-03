import { useState, useEffect, useCallback } from 'react'
import { Overview } from './pages/Overview'
import { ThreatFeed } from './pages/ThreatFeed'
import { DeviceList } from './pages/DeviceList'
import { Intelligence } from './pages/Intelligence'
import { LiveFeed } from './pages/LiveFeed'
import { AiChat } from './pages/AiChat'
import { LiveIndicator } from './components/LiveIndicator'
import { ToastContainer, type Toast } from './components/ToastNotification'
import { CommandPalette } from './components/CommandPalette'
import { useWebSocket } from './hooks/useWebSocket'
import { setToken, getToken } from './api'
import { wsClient } from './ws'

type Page = 'overview' | 'live' | 'threats' | 'devices' | 'intelligence' | 'chat'

const Icon = {
  overview: (
    <svg width="14" height="14" viewBox="0 0 20 20" fill="currentColor">
      <rect x="1" y="1" width="8" height="8" rx="1.5"/>
      <rect x="11" y="1" width="8" height="8" rx="1.5"/>
      <rect x="1" y="11" width="8" height="8" rx="1.5"/>
      <rect x="11" y="11" width="8" height="8" rx="1.5"/>
    </svg>
  ),
  live: (
    <svg width="14" height="14" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="2,10 5,10 7,4 9,16 11,8 13,12 15,10 18,10"/>
    </svg>
  ),
  threats: (
    <svg width="14" height="14" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10 2L3 5v5c0 4.5 3.5 7.5 7 9 3.5-1.5 7-4.5 7-9V5L10 2z"/>
    </svg>
  ),
  devices: (
    <svg width="14" height="14" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
      <rect x="2" y="3" width="16" height="5" rx="1"/>
      <rect x="2" y="12" width="16" height="5" rx="1"/>
      <circle cx="5.5" cy="5.5" r="0.7" fill="currentColor"/>
      <circle cx="5.5" cy="14.5" r="0.7" fill="currentColor"/>
    </svg>
  ),
  intelligence: (
    <svg width="14" height="14" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round">
      <circle cx="10" cy="10" r="7"/>
      <circle cx="10" cy="10" r="2.5"/>
    </svg>
  ),
  chat: (
    <svg width="14" height="14" viewBox="0 0 20 20" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 3h14a1 1 0 0 1 1 1v9a1 1 0 0 1-1 1H7l-4 3V4a1 1 0 0 1 1-1z"/>
    </svg>
  ),
}

const NAV: { id: Page; label: string; icon: React.ReactNode }[] = [
  { id: 'overview',     label: 'OVERVIEW',       icon: Icon.overview     },
  { id: 'live',         label: 'AI ANALYSIS',    icon: Icon.live         },
  { id: 'chat',         label: 'AI ASSISTANT',   icon: Icon.chat         },
  { id: 'threats',      label: 'THREAT EVENTS',  icon: Icon.threats      },
  { id: 'devices',      label: 'DEVICES',        icon: Icon.devices      },
  { id: 'intelligence', label: 'INTELLIGENCE',   icon: Icon.intelligence },
]

function LoginScreen({ onLogin }: { onLogin: () => void }) {
  const [token, setTokenInput] = useState('')
  const [serverUrl, setServerUrl] = useState('http://localhost:8443')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    const style = document.createElement('style')
    style.id = 'argos-mobile'
    style.textContent = `
      @media (max-width: 520px) {
        .argos-login-root { align-items: flex-start !important; padding-top: 0 !important; }
        .argos-login-modal { width: 100% !important; max-width: 100% !important; border-radius: 0 !important; margin: 0 !important; min-height: 100vh; }
      }
    `
    document.head.appendChild(style)
    return () => { document.getElementById('argos-mobile')?.remove() }
  }, [])

  const handleLogin = async () => {
    if (!token.trim()) { setError('API token required'); return }
    setLoading(true); setError('')
    try {
      const base = serverUrl === 'http://localhost:8443' ? '' : serverUrl
      const r = await fetch(`${base}/api/auth/me`, {
        headers: { Authorization: `Bearer ${token.trim()}` }
      })
      if (r.ok) {
        setToken(token.trim())
        localStorage.setItem('argos_server_url', serverUrl)
        onLogin()
      } else {
        setError('Authentication failed — verify token and server endpoint')
      }
    } catch {
      setError('Connection refused — verify server is running')
    }
    setLoading(false)
  }

  const INP: React.CSSProperties = {
    width: '100%',
    background: '#0a0a0a',
    border: '1px solid rgba(255,255,255,0.1)',
    borderRadius: 4,
    padding: '10px 13px',
    color: '#e0e0e0',
    fontFamily: 'inherit',
    fontSize: 13,
    fontWeight: 400,
  }

  return (
    <div className="argos-login-root" style={{
      display: 'flex', height: '100vh',
      alignItems: 'center', justifyContent: 'center',
      background: '#0a0a0a',
    }}>
      {/* Subtle grid */}
      <div style={{
        position: 'fixed', inset: 0, pointerEvents: 'none',
        backgroundImage:
          'linear-gradient(rgba(255,255,255,0.02) 1px, transparent 1px), ' +
          'linear-gradient(90deg, rgba(255,255,255,0.02) 1px, transparent 1px)',
        backgroundSize: '48px 48px',
      }} />

      <div className="argos-login-modal" style={{
        background: '#131313',
        border: '1px solid rgba(255,255,255,0.08)',
        borderRadius: 10,
        width: 440, maxWidth: '90vw',
        position: 'relative', zIndex: 1,
        boxShadow: '0 24px 64px rgba(0,0,0,0.8)',
        overflow: 'hidden',
      }}>
        <div style={{
          position: 'absolute', top: 0, left: 0, right: 0, height: 1,
          background: 'linear-gradient(90deg, transparent, rgba(255,255,255,0.15), transparent)',
        }} />

        <div style={{ padding: '28px 28px 24px', borderBottom: '1px solid rgba(255,255,255,0.06)', textAlign: 'center' }}>
          <div style={{
            fontSize: 28, fontWeight: 800, letterSpacing: '6px',
            color: '#fff',
          }}>
            ARGOS
          </div>
        </div>

        <div style={{ padding: '24px 28px 28px' }}>
          <div style={{ marginBottom: 16 }}>
            <div style={{ color: '#555', fontSize: 10, letterSpacing: '1.5px', textTransform: 'uppercase', fontWeight: 600, marginBottom: 6 }}>
              Server Endpoint
            </div>
            <input style={INP} value={serverUrl} onChange={e => setServerUrl(e.target.value)} placeholder="http://localhost:8443" spellCheck={false}/>
          </div>

          <div style={{ marginBottom: 20 }}>
            <div style={{ color: '#555', fontSize: 10, letterSpacing: '1.5px', textTransform: 'uppercase', fontWeight: 600, marginBottom: 6 }}>
              API Token
            </div>
            <input style={INP} type="password" value={token} onChange={e => setTokenInput(e.target.value)} onKeyDown={e => e.key === 'Enter' && handleLogin()} placeholder="Bearer token" spellCheck={false}/>
          </div>

          {error && (
            <div style={{
              border: '1px solid rgba(239,68,68,0.3)',
              background: 'rgba(239,68,68,0.06)',
              borderRadius: 4, padding: '8px 12px',
              color: '#f87171', fontSize: 12, marginBottom: 16, fontWeight: 500,
            }}>
              {error}
            </div>
          )}

          <button
            onClick={handleLogin} disabled={loading}
            style={{
              width: '100%',
              background: loading ? '#1a1a1a' : '#fff',
              border: 'none', borderRadius: 5,
              color: loading ? '#555' : '#0a0a0a',
              padding: '11px', fontSize: 12,
              letterSpacing: '2px', textTransform: 'uppercase',
              cursor: loading ? 'not-allowed' : 'pointer',
              fontWeight: 700, transition: 'all 0.15s',
            }}
          >
            {loading ? 'AUTHENTICATING...' : 'AUTHENTICATE'}
          </button>

          <a
            href="https://github.com/wlmzz"
            target="_blank"
            rel="noopener noreferrer"
            style={{
              display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 7,
              marginTop: 20, textDecoration: 'none',
              color: '#444', fontSize: 11, letterSpacing: '1px', fontWeight: 500,
              transition: 'color 0.15s',
            }}
            onMouseEnter={e => (e.currentTarget.style.color = '#aaa')}
            onMouseLeave={e => (e.currentTarget.style.color = '#444')}
          >
            {/* GitHub icon */}
            <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12 2C6.477 2 2 6.477 2 12c0 4.418 2.865 8.166 6.839 9.489.5.092.682-.217.682-.482 0-.237-.009-.868-.013-1.703-2.782.605-3.369-1.34-3.369-1.34-.454-1.156-1.11-1.463-1.11-1.463-.908-.62.069-.608.069-.608 1.003.07 1.531 1.03 1.531 1.03.892 1.529 2.341 1.087 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.11-4.555-4.943 0-1.091.39-1.984 1.029-2.683-.103-.253-.446-1.27.098-2.647 0 0 .84-.269 2.75 1.025A9.578 9.578 0 0 1 12 6.836a9.59 9.59 0 0 1 2.504.337c1.909-1.294 2.747-1.025 2.747-1.025.546 1.377.202 2.394.1 2.647.64.699 1.028 1.592 1.028 2.683 0 3.842-2.339 4.687-4.566 4.935.359.309.678.919.678 1.852 0 1.336-.012 2.415-.012 2.743 0 .267.18.578.688.48C19.138 20.163 22 16.418 22 12c0-5.523-4.477-10-10-10z"/>
            </svg>
            Powered by WLMZZ
          </a>
        </div>
      </div>
    </div>
  )
}

export default function App() {
  const [page, setPage] = useState<Page>(() =>
    (sessionStorage.getItem('argos_page') as Page) ?? 'overview'
  )
  const [loggedIn, setLoggedIn] = useState(!!getToken())
  const [toasts, setToasts] = useState<Toast[]>([])
  const [paletteOpen, setPaletteOpen] = useState(false)
  const [theme, setTheme] = useState<'black' | 'dim'>(() =>
    (sessionStorage.getItem('argos_theme') as 'black' | 'dim') ?? 'black'
  )
  const { connected } = useWebSocket(loggedIn)

  const navigateTo = useCallback((p: Page) => {
    setPage(p)
    sessionStorage.setItem('argos_page', p)
  }, [])

  const handleLogout = useCallback(() => {
    sessionStorage.removeItem('argos_token')
    sessionStorage.removeItem('argos_token_ts')
    setLoggedIn(false)
  }, [])

  // Theme effect
  useEffect(() => {
    sessionStorage.setItem('argos_theme', theme)
    document.documentElement.style.setProperty('--argos-bg', theme === 'black' ? '#0a0a0a' : '#121212')
  }, [theme])

  // Idle auto-logout (15 minutes)
  useEffect(() => {
    if (!loggedIn) return
    const TIMEOUT_MS = 15 * 60 * 1000
    let timer = setTimeout(handleLogout, TIMEOUT_MS)
    const reset = () => { clearTimeout(timer); timer = setTimeout(handleLogout, TIMEOUT_MS) }
    const evts = ['mousedown', 'keydown', 'touchstart', 'scroll'] as const
    evts.forEach(e => window.addEventListener(e, reset, { passive: true }))
    return () => { clearTimeout(timer); evts.forEach(e => window.removeEventListener(e, reset)) }
  }, [loggedIn, handleLogout])

  // WebSocket toast subscription
  useEffect(() => {
    if (!loggedIn) return
    const unsub = wsClient.on((msg: any) => {
      if (msg.type === 'new_threat' && (msg.severity === 'critical' || msg.severity === 'high')) {
        setToasts(prev => [
          ...prev,
          {
            id: Date.now(),
            message: `${(msg.threat_type ?? 'Unknown threat').replace(/_/g, ' ')} from ${msg.source_ip ?? 'unknown'}`,
            severity: msg.severity as 'critical' | 'high',
          },
        ].slice(-4))
      }
    })
    return unsub
  }, [loggedIn])

  // Keyboard shortcuts
  useEffect(() => {
    if (!loggedIn) return
    const map: Record<string, Page> = {
      '1': 'overview', '2': 'live', '3': 'chat',
      '4': 'threats', '5': 'devices', '6': 'intelligence',
    }
    const handler = (e: KeyboardEvent) => {
      if (['INPUT', 'TEXTAREA'].includes((e.target as HTMLElement)?.tagName ?? '')) return
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') { e.preventDefault(); setPaletteOpen(p => !p); return }
      if (e.key === 'Escape') { setPaletteOpen(false); return }
      if (map[e.key]) navigateTo(map[e.key])
      if ((e.key === 'r' || e.key === 'R') && !e.metaKey && !e.ctrlKey) {
        window.dispatchEvent(new CustomEvent('argos:refresh'))
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [loggedIn, navigateTo])

  if (!loggedIn) return <LoginScreen onLogin={() => setLoggedIn(true)} />

  return (
    <div style={{ display: 'flex', height: '100vh', background: '#0a0a0a' }}>

      {/* Sidebar */}
      <nav style={{
        width: 210,
        background: '#0f0f0f',
        borderRight: '1px solid rgba(255,255,255,0.06)',
        display: 'flex', flexDirection: 'column', flexShrink: 0,
      }}>
        {/* Logo */}
        <div style={{ padding: '20px 18px 18px', borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
          <div style={{ fontSize: 20, fontWeight: 800, letterSpacing: '5px', color: '#fff', marginBottom: 4 }}>
            ARGOS
          </div>
          <div style={{ color: '#333', fontSize: 9, letterSpacing: '1.5px', textTransform: 'uppercase', fontWeight: 500 }}>
            Security Platform
          </div>
        </div>

        {/* Nav */}
        <div style={{ flex: 1, paddingTop: 6 }}>
          {NAV.map(item => {
            const active = page === item.id
            return (
              <div
                key={item.id}
                onClick={() => navigateTo(item.id)}
                style={{
                  padding: '9px 18px',
                  cursor: 'pointer',
                  display: 'flex', alignItems: 'center', gap: 10,
                  color: active ? '#fff' : '#4a4a4a',
                  background: active ? 'rgba(255,255,255,0.05)' : 'transparent',
                  borderLeft: active ? '2px solid #fff' : '2px solid transparent',
                  fontSize: 10, letterSpacing: '1px',
                  fontWeight: active ? 600 : 400,
                  userSelect: 'none', transition: 'all 0.12s',
                }}
                onMouseEnter={e => { if (!active) e.currentTarget.style.color = '#888' }}
                onMouseLeave={e => { if (!active) e.currentTarget.style.color = '#4a4a4a' }}
              >
                <span style={{ flexShrink: 0, opacity: active ? 1 : 0.5 }}>{item.icon}</span>
                {item.label}
              </div>
            )
          })}
        </div>

        {/* Keyboard hint */}
        <div style={{ padding: '8px 18px', color: '#222', fontSize: 8, letterSpacing: '1px' }}>
          ⌘K SEARCH · 1-6 NAVIGATE
        </div>

        <div style={{ height: 1, background: 'rgba(255,255,255,0.05)', margin: '0 18px' }} />

        {/* Footer */}
        <div style={{ padding: '14px 18px' }}>
          <LiveIndicator connected={connected} />
          <a
            href="https://github.com/wlmzz" target="_blank" rel="noopener noreferrer"
            style={{ display: 'block', color: '#333', fontSize: 9, marginTop: 10, letterSpacing: '0.5px', textDecoration: 'none', fontWeight: 500, transition: 'color 0.12s' }}
            onMouseEnter={e => (e.currentTarget.style.color = '#aaa')}
            onMouseLeave={e => (e.currentTarget.style.color = '#333')}
          >
            Powered by WLMZZ
          </a>
          <div
            onClick={() => setTheme(t => t === 'black' ? 'dim' : 'black')}
            style={{ color: '#333', fontSize: 9, marginTop: 5, cursor: 'pointer', letterSpacing: '0.5px', fontWeight: 500, transition: 'color 0.12s' }}
            onMouseEnter={e => (e.currentTarget.style.color = '#aaa')}
            onMouseLeave={e => (e.currentTarget.style.color = '#333')}
          >
            {theme === 'black' ? '◑ DIM MODE' : '● DARK MODE'}
          </div>
          <div
            onClick={handleLogout}
            style={{ color: '#333', fontSize: 9, marginTop: 5, cursor: 'pointer', letterSpacing: '0.5px', fontWeight: 500, transition: 'color 0.12s' }}
            onMouseEnter={e => (e.currentTarget.style.color = '#ef4444')}
            onMouseLeave={e => (e.currentTarget.style.color = '#333')}
          >
            DISCONNECT
          </div>
        </div>
      </nav>

      {/* Content */}
      <main style={{ flex: 1, overflow: 'auto', background: '#0a0a0a' }}>
        {page === 'overview'     && <Overview />}
        {page === 'live'         && <LiveFeed />}
        {page === 'chat'         && <AiChat />}
        {page === 'threats'      && <ThreatFeed />}
        {page === 'devices'      && <DeviceList />}
        {page === 'intelligence' && <Intelligence />}
      </main>

      <ToastContainer toasts={toasts} onDismiss={id => setToasts(prev => prev.filter(t => t.id !== id))} />
      <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} onNavigate={navigateTo} />
    </div>
  )
}
