import { useState, useEffect, useMemo, useCallback, useRef } from 'react'
import { ThreatTable } from '../components/ThreatTable'
import { useThreatFeed } from '../hooks/useThreatFeed'
import { useDebounce } from '../hooks/useDebounce'
import { sanitizeQuery } from '../utils/sanitize'
import type { Severity } from '../types'

const FILTERS: { label: string; value: Severity | 'all' }[] = [
  { label: 'ALL',      value: 'all'      },
  { label: 'CRITICAL', value: 'critical' },
  { label: 'HIGH',     value: 'high'     },
  { label: 'MEDIUM',   value: 'medium'   },
  { label: 'LOW',      value: 'low'      },
]

const FILTER_COLOR: Record<string, string> = {
  all: '#aaaaaa', critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e',
}

const PANEL: React.CSSProperties = {
  background: '#111',
  border: '1px solid rgba(255,255,255,0.07)',
  borderRadius: 6,
}

function PanelHeader({ title, right }: { title: string; right?: React.ReactNode }) {
  return (
    <div style={{
      padding: '8px 14px', borderBottom: '1px solid rgba(255,255,255,0.05)',
      background: '#0d0d0d', borderRadius: '6px 6px 0 0',
      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
    }}>
      <span style={{ fontSize: 9, color: '#555', letterSpacing: '2px', fontWeight: 700, textTransform: 'uppercase' }}>{title}</span>
      {right && <span style={{ fontSize: 10, color: '#3a3a3a' }}>{right}</span>}
    </div>
  )
}

export function ThreatFeed() {
  const [filter, setFilter] = useState<Severity | 'all'>(() =>
    (sessionStorage.getItem('argos_threat_filter') as Severity | 'all') ?? 'all'
  )
  const [searchTerm, setSearchTerm] = useState('')
  const debouncedSearch = useDebounce(searchTerm, 300)
  const lastReloadRef = useRef(0)
  const { events, loading, reload } = useThreatFeed()

  useEffect(() => { sessionStorage.setItem('argos_threat_filter', filter) }, [filter])

  useEffect(() => {
    const handler = () => reload()
    window.addEventListener('argos:refresh', handler)
    return () => window.removeEventListener('argos:refresh', handler)
  }, [reload])

  const counts = useMemo(() => {
    const c: Record<string, number> = { all: events.length }
    for (const ev of events) c[ev.severity] = (c[ev.severity] || 0) + 1
    return c
  }, [events])

  const filteredEvents = useMemo(() => {
    let result = filter === 'all' ? events : events.filter(e => e.severity === filter)
    if (debouncedSearch) {
      const q = debouncedSearch.toLowerCase()
      result = result.filter(e =>
        e.source_ip.includes(debouncedSearch) ||
        e.threat_type.toLowerCase().includes(q) ||
        (e.description ?? '').toLowerCase().includes(q) ||
        (e.action_taken ?? '').toLowerCase().includes(q)
      )
    }
    return result
  }, [events, filter, debouncedSearch])

  const exportCSV = useCallback(() => {
    const headers = ['Time', 'Severity', 'Type', 'Source IP', 'Port', 'Action', 'Description']
    const rows = filteredEvents.map(e => [
      new Date(e.timestamp).toISOString(),
      e.severity,
      e.threat_type,
      e.source_ip,
      String(e.target_port ?? ''),
      e.action_taken ?? '',
      `"${(e.description ?? '').replace(/"/g, '""')}"`,
    ])
    const csv = [headers, ...rows].map(r => r.join(',')).join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `argos-threats-${Date.now()}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }, [filteredEvents])

  const handleReload = useCallback(() => {
    if (Date.now() - lastReloadRef.current < 2000) return
    lastReloadRef.current = Date.now()
    reload()
  }, [reload])

  return (
    <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 16, height: '100%', boxSizing: 'border-box' }}>

      {/* Enterprise page header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingBottom: 12, borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ width: 2, height: 16, background: '#3b82f6', borderRadius: 1 }} />
          <span style={{ color: '#fff', fontSize: 11, letterSpacing: '2.5px', fontWeight: 700, textTransform: 'uppercase' }}>Threat Events</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <span style={{ color: '#444', fontSize: 11, fontVariantNumeric: 'tabular-nums' }}>
            {filteredEvents.length} RECORDS
          </span>
          <input
            value={searchTerm}
            onChange={e => setSearchTerm(sanitizeQuery(e.target.value))}
            placeholder="Search IP, type, action..."
            style={{
              background: '#0a0a0a', border: '1px solid rgba(255,255,255,0.1)',
              borderRadius: 4, color: '#fff', padding: '4px 10px',
              fontSize: 11, width: 200, fontFamily: 'inherit',
            }}
          />
          <button
            onClick={exportCSV}
            style={{
              background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.12)',
              borderRadius: 4, color: '#aaa', padding: '4px 12px',
              fontSize: 10, letterSpacing: '1.5px', cursor: 'pointer',
              textTransform: 'uppercase', fontWeight: 600,
            }}
            onMouseEnter={e => (e.currentTarget.style.color = '#fff')}
            onMouseLeave={e => (e.currentTarget.style.color = '#aaa')}
          >
            EXPORT CSV
          </button>
          <button
            onClick={handleReload}
            style={{
              background: 'rgba(255,255,255,0.06)', border: '1px solid rgba(255,255,255,0.12)',
              borderRadius: 4, color: '#fff', padding: '4px 14px',
              fontSize: 10, letterSpacing: '1.5px', cursor: 'pointer',
              textTransform: 'uppercase', fontWeight: 600, transition: 'all 0.12s',
            }}
            onMouseEnter={e => (e.currentTarget.style.background = 'rgba(255,255,255,0.1)')}
            onMouseLeave={e => (e.currentTarget.style.background = 'rgba(255,255,255,0.06)')}
          >
            REFRESH
          </button>
        </div>
      </div>

      <div style={{ display: 'flex', gap: 4 }}>
        {FILTERS.map(f => {
          const active = filter === f.value
          const col = FILTER_COLOR[f.value]
          return (
            <button
              key={f.value}
              onClick={() => setFilter(f.value)}
              style={{
                background: active ? `${col}18` : 'transparent',
                border: `1px solid ${active ? col + '55' : 'rgba(255,255,255,0.08)'}`,
                borderRadius: 3, color: active ? col : '#777',
                padding: '4px 16px', fontSize: 10, letterSpacing: '1.5px',
                cursor: 'pointer', textTransform: 'uppercase', fontWeight: 600, transition: 'all 0.12s',
              }}
            >
              {f.label}{counts[f.value] != null ? ` (${counts[f.value]})` : ''}
            </button>
          )
        })}
      </div>

      <div style={{ ...PANEL, flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
        <PanelHeader title="Events" right={`${filteredEvents.length} records`} />
        <div style={{ flex: 1, overflow: 'auto' }}>
          {loading && events.length === 0 ? (
            <div style={{ padding: 24, color: '#444', fontSize: 11, letterSpacing: '2px', fontWeight: 500 }}>LOADING...</div>
          ) : (
            <ThreatTable events={filteredEvents} />
          )}
        </div>
      </div>

    </div>
  )
}
