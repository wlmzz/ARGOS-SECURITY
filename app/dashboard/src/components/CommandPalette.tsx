import { useState, useEffect, useRef, useCallback } from 'react'
import { api } from '../api'
import type { ThreatEvent, Device } from '../types'

type Page = 'overview' | 'live' | 'threats' | 'devices' | 'intelligence' | 'chat'

interface PaletteItem {
  id: string
  label: string
  sub?: string
  type: 'page' | 'device' | 'event'
  page?: Page
}

const PAGE_ITEMS: PaletteItem[] = [
  { id: 'p-overview', label: 'Overview', sub: 'Dashboard & KPIs', type: 'page', page: 'overview' },
  { id: 'p-live', label: 'AI Analysis', sub: 'Live threat decisions', type: 'page', page: 'live' },
  { id: 'p-chat', label: 'AI Assistant', sub: 'Chat with ARGOS-AI', type: 'page', page: 'chat' },
  { id: 'p-threats', label: 'Threat Events', sub: 'Event feed & filters', type: 'page', page: 'threats' },
  { id: 'p-devices', label: 'Devices', sub: 'Registered agents', type: 'page', page: 'devices' },
  { id: 'p-intelligence', label: 'Intelligence', sub: 'IP lookup & blocklist', type: 'page', page: 'intelligence' },
]

const TYPE_COLOR: Record<string, string> = {
  page: '#3b82f6', device: '#16a34a', event: '#dc2626',
}

interface CommandPaletteProps {
  open: boolean
  onClose: () => void
  onNavigate: (page: Page) => void
}

export function CommandPalette({ open, onClose, onNavigate }: CommandPaletteProps) {
  const [query, setQuery] = useState('')
  const [devices, setDevices] = useState<Device[]>([])
  const [events, setEvents] = useState<ThreatEvent[]>([])
  const [activeIdx, setActiveIdx] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)
  const loadedRef = useRef(false)

  useEffect(() => {
    if (open) {
      setQuery('')
      setActiveIdx(0)
      setTimeout(() => inputRef.current?.focus(), 50)
      if (!loadedRef.current) {
        loadedRef.current = true
        api.devices().then(setDevices).catch(() => {})
        api.events({ limit: 100 }).then(setEvents).catch(() => {})
      }
    }
  }, [open])

  const allItems: PaletteItem[] = [
    ...PAGE_ITEMS,
    ...devices.map(d => ({
      id: `d-${d.id}`, label: d.name, sub: `${d.ip} · ${d.platform} · ${d.status}`,
      type: 'device' as const, page: 'devices' as Page,
    })),
    ...events.slice(0, 50).map(e => ({
      id: `e-${e.id}`, label: e.threat_type.replace(/_/g, ' ').toUpperCase(),
      sub: `${e.source_ip} · ${e.severity} · ${new Date(e.timestamp).toLocaleTimeString('it-IT')}`,
      type: 'event' as const, page: 'threats' as Page,
    })),
  ]

  const filtered = query.trim()
    ? allItems.filter(item =>
        item.label.toLowerCase().includes(query.toLowerCase()) ||
        (item.sub ?? '').toLowerCase().includes(query.toLowerCase())
      )
    : allItems

  const handleSelect = useCallback((item: PaletteItem) => {
    if (item.page) onNavigate(item.page)
    onClose()
  }, [onNavigate, onClose])

  useEffect(() => {
    setActiveIdx(0)
  }, [query])

  const handleKey = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setActiveIdx(i => Math.min(i + 1, filtered.length - 1)) }
    if (e.key === 'ArrowUp') { e.preventDefault(); setActiveIdx(i => Math.max(i - 1, 0)) }
    if (e.key === 'Enter') { e.preventDefault(); if (filtered[activeIdx]) handleSelect(filtered[activeIdx]) }
    if (e.key === 'Escape') { e.preventDefault(); onClose() }
  }

  if (!open) return null

  return (
    <div
      style={{
        position: 'fixed', inset: 0, zIndex: 99998,
        background: 'rgba(0,0,0,0.75)',
        backdropFilter: 'blur(6px)',
        display: 'flex', alignItems: 'flex-start', justifyContent: 'center',
        paddingTop: '12vh',
      }}
      onClick={onClose}
    >
      <div
        style={{
          background: '#111', border: '1px solid rgba(255,255,255,0.1)',
          borderRadius: 8, width: 580, maxWidth: '90vw',
          maxHeight: '60vh', display: 'flex', flexDirection: 'column',
          overflow: 'hidden',
          boxShadow: '0 24px 64px rgba(0,0,0,0.8)',
        }}
        onClick={e => e.stopPropagation()}
      >
        {/* Search input */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 10,
          padding: '12px 16px', borderBottom: '1px solid rgba(255,255,255,0.06)',
        }}>
          <svg width="13" height="13" viewBox="0 0 20 20" fill="none" stroke="#555" strokeWidth="2" strokeLinecap="round">
            <circle cx="9" cy="9" r="6"/><path d="M20 20l-4.35-4.35"/>
          </svg>
          <input
            ref={inputRef}
            value={query}
            onChange={e => setQuery(e.target.value)}
            onKeyDown={handleKey}
            placeholder="Search pages, devices, events..."
            style={{
              flex: 1, background: 'none', border: 'none',
              color: '#fff', fontSize: 14, fontFamily: 'inherit', fontWeight: 400,
            }}
          />
          <span style={{ fontSize: 9, color: '#333', letterSpacing: '1px', border: '1px solid #222', borderRadius: 3, padding: '2px 6px' }}>ESC</span>
        </div>

        {/* Results */}
        <div style={{ flex: 1, overflowY: 'auto' }}>
          {filtered.length === 0 ? (
            <div style={{ padding: 24, color: '#333', fontSize: 11, letterSpacing: '2px', textAlign: 'center' }}>NO RESULTS</div>
          ) : filtered.map((item, i) => (
            <div
              key={item.id}
              onClick={() => handleSelect(item)}
              style={{
                padding: '9px 16px', cursor: 'pointer',
                background: i === activeIdx ? 'rgba(255,255,255,0.05)' : 'transparent',
                display: 'flex', alignItems: 'center', gap: 12,
                transition: 'background 0.08s',
                borderLeft: i === activeIdx ? `2px solid ${TYPE_COLOR[item.type]}` : '2px solid transparent',
              }}
              onMouseEnter={() => setActiveIdx(i)}
            >
              <div style={{
                width: 5, height: 5, borderRadius: '50%',
                background: TYPE_COLOR[item.type], flexShrink: 0,
              }} />
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontSize: 12, color: '#fff', fontWeight: 500 }}>{item.label}</div>
                {item.sub && <div style={{ fontSize: 10, color: '#444', marginTop: 2, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{item.sub}</div>}
              </div>
              <span style={{ fontSize: 8, color: '#2a2a2a', letterSpacing: '1.5px', textTransform: 'uppercase' }}>{item.type}</span>
            </div>
          ))}
        </div>

        {/* Footer */}
        <div style={{
          padding: '7px 16px', borderTop: '1px solid rgba(255,255,255,0.04)',
          display: 'flex', gap: 16,
        }}>
          {[['↑↓', 'navigate'], ['↵', 'select'], ['esc', 'close']].map(([key, label]) => (
            <span key={key} style={{ fontSize: 9, color: '#333' }}>
              <span style={{ border: '1px solid #222', borderRadius: 3, padding: '1px 5px', marginRight: 5, color: '#444' }}>{key}</span>
              {label}
            </span>
          ))}
        </div>
      </div>
    </div>
  )
}
