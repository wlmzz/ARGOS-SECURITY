import { useState, useEffect, useMemo, useCallback } from 'react'
import { api } from '../api'
import { useDebounce } from '../hooks/useDebounce'
import type { Device } from '../types'

const PLATFORM_LABEL: Record<string, string> = {
  darwin: 'MACOS', linux: 'LINUX', windows: 'WINDOWS',
}

const PLATFORM_COLOR: Record<string, string> = {
  darwin: '#a78bfa', linux: '#3b82f6', windows: '#22c55e',
}
const AUTONOMY_COLOR: Record<string, string> = {
  full: '#ef4444', semi: '#eab308', supervised: '#22c55e',
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

const TH: React.CSSProperties = {
  padding: '7px 14px', color: '#555', fontSize: 9,
  letterSpacing: '1.5px', textTransform: 'uppercase',
  fontWeight: 600, textAlign: 'left',
  borderBottom: '1px solid rgba(255,255,255,0.05)',
  background: '#0d0d0d', position: 'sticky', top: 0,
}
const TD: React.CSSProperties = {
  padding: '8px 14px', fontSize: 12,
  borderBottom: '1px solid rgba(255,255,255,0.03)',
  whiteSpace: 'nowrap',
}

function agoString(lastSeen: string): string {
  const ago = Math.round((Date.now() - new Date(lastSeen).getTime()) / 1000)
  if (ago < 60) return `${ago}s ago`
  if (ago < 3600) return `${Math.round(ago / 60)}m ago`
  return `${Math.round(ago / 3600)}h ago`
}

export function DeviceList() {
  const [devices, setDevices] = useState<Device[]>([])
  const [loading, setLoading] = useState(true)
  const [searchTerm, setSearchTerm] = useState('')
  const debouncedSearch = useDebounce(searchTerm, 300)
  const [sortKey, setSortKey] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc')

  useEffect(() => {
    api.devices().then(setDevices).catch(() => {}).finally(() => setLoading(false))
  }, [])

  const online = devices.filter(d => d.status === 'online').length

  const platformCounts = useMemo(() => {
    const counts: Record<string, number> = {}
    for (const d of devices) counts[d.platform] = (counts[d.platform] || 0) + 1
    return counts
  }, [devices])

  const filteredDevices = useMemo(() => {
    let result = devices
    if (debouncedSearch) {
      const q = debouncedSearch.toLowerCase()
      result = result.filter(d =>
        d.name.toLowerCase().includes(q) ||
        (d.ip ?? '').includes(debouncedSearch) ||
        d.platform.toLowerCase().includes(q) ||
        d.status.includes(q)
      )
    }
    if (sortKey) {
      result = [...result].sort((a, b) => {
        const av = (a as any)[sortKey]
        const bv = (b as any)[sortKey]
        const cmp = String(av ?? '').localeCompare(String(bv ?? ''), undefined, { numeric: true })
        return sortDir === 'asc' ? cmp : -cmp
      })
    }
    return result
  }, [devices, debouncedSearch, sortKey, sortDir])

  const handleSort = useCallback((key: string) => {
    setSortDir(prev => sortKey === key ? (prev === 'asc' ? 'desc' : 'asc') : 'desc')
    setSortKey(key)
  }, [sortKey])

  const exportCSV = useCallback(() => {
    const headers = ['Name', 'Platform', 'IP', 'Status', 'Autonomy', 'Version', 'Threats Today', 'Last Seen']
    const rows = filteredDevices.map(d => [
      d.name, d.platform, d.ip ?? '', d.status, d.autonomy,
      d.version ?? '', String(d.threats_today ?? 0),
      new Date(d.last_seen).toISOString(),
    ])
    const csv = [headers, ...rows].map(r => r.join(',')).join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `argos-devices-${Date.now()}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }, [filteredDevices])

  return (
    <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>

      {/* Enterprise page header */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingBottom: 12, borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ width: 2, height: 16, background: '#16a34a', borderRadius: 1 }} />
          <span style={{ color: '#fff', fontSize: 11, letterSpacing: '2.5px', fontWeight: 700, textTransform: 'uppercase' }}>Registered Devices</span>
        </div>
        <div style={{ display: 'flex', gap: 20, alignItems: 'center' }}>
          <div style={{ borderTop: '2px solid #16a34a', padding: '10px 14px 8px', minWidth: 60 }}>
            <div style={{ fontSize: 24, fontWeight: 700, lineHeight: 1, color: '#22c55e', fontVariantNumeric: 'tabular-nums' }}>{online}</div>
            <div style={{ color: '#555', fontSize: 9, letterSpacing: '1.5px', textTransform: 'uppercase', marginTop: 4, fontWeight: 600 }}>ONLINE</div>
          </div>
          <div style={{ borderTop: '2px solid transparent', padding: '10px 14px 8px', minWidth: 60 }}>
            <div style={{ color: '#fff', fontSize: 24, fontWeight: 700, lineHeight: 1, fontVariantNumeric: 'tabular-nums' }}>{devices.length}</div>
            <div style={{ color: '#555', fontSize: 9, letterSpacing: '1.5px', textTransform: 'uppercase', marginTop: 4, fontWeight: 600 }}>TOTAL</div>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <input
              value={searchTerm}
              onChange={e => setSearchTerm(e.target.value)}
              placeholder="Search devices..."
              style={{
                background: '#0a0a0a', border: '1px solid rgba(255,255,255,0.1)',
                borderRadius: 4, color: '#fff', padding: '4px 10px',
                fontSize: 11, width: 160, fontFamily: 'inherit',
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
              EXPORT
            </button>
          </div>
        </div>
      </div>

      {devices.length > 0 && (
        <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          <div style={{ flex: 1, display: 'flex', height: 4, borderRadius: 2, overflow: 'hidden', gap: 1 }}>
            {Object.entries(platformCounts).map(([p, n]) => (
              <div key={p} style={{ flex: n, background: PLATFORM_COLOR[p] ?? '#444', transition: 'flex 0.3s' }} />
            ))}
          </div>
          <div style={{ display: 'flex', gap: 12 }}>
            {Object.entries(platformCounts).map(([p, n]) => (
              <div key={p} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                <div style={{ width: 5, height: 5, borderRadius: 1, background: PLATFORM_COLOR[p] ?? '#444' }} />
                <span style={{ fontSize: 9, color: '#555', textTransform: 'uppercase', letterSpacing: '1px' }}>{PLATFORM_LABEL[p] ?? p} {n}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div style={{ ...PANEL, overflow: 'auto' }}>
        <PanelHeader title="Device Registry" right={`${filteredDevices.length} agents`} />
        <table style={{ width: '100%', borderCollapse: 'collapse' }}>
          <thead>
            <tr>
              {['STATUS','NAME','PLATFORM','IP ADDRESS','AUTONOMY','VERSION','THREATS TODAY','LAST SEEN','DEVICE ID'].map(h => {
                const keyMap: Record<string, string> = {
                  'NAME': 'name', 'PLATFORM': 'platform', 'AUTONOMY': 'autonomy',
                  'THREATS TODAY': 'threats_today', 'LAST SEEN': 'last_seen',
                }
                const key = keyMap[h]
                return (
                  <th key={h} style={{ ...TH, cursor: key ? 'pointer' : 'default', userSelect: 'none' }}
                    onClick={() => key && handleSort(key)}>
                    {h}{key && sortKey === key ? (sortDir === 'asc' ? ' ↑' : ' ↓') : ''}
                  </th>
                )
              })}
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={9} style={{ ...TD, color: '#444', letterSpacing: '2px', fontWeight: 500 }}>LOADING...</td></tr>
            ) : devices.length === 0 ? (
              <tr>
                <td colSpan={9} style={{ ...TD, color: '#333', letterSpacing: '2px', textAlign: 'center', padding: 40, fontWeight: 500 }}>
                  NO DEVICES REGISTERED
                </td>
              </tr>
            ) : filteredDevices.map(d => {
              const isOnline = d.status === 'online'
              return (
                <tr key={d.id} style={{ transition: 'background 0.08s' }}
                  onMouseEnter={e => (e.currentTarget.style.background = 'rgba(255,255,255,0.025)')}
                  onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                >
                  <td style={TD}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                      <div style={{
                        width: 6, height: 6, borderRadius: '50%',
                        background: isOnline ? '#22c55e' : '#ef4444', flexShrink: 0,
                      }} />
                      <span style={{ fontSize: 10, letterSpacing: '1px', color: isOnline ? '#22c55e' : '#ef4444', textTransform: 'uppercase', fontWeight: 600 }}>
                        {d.status.toUpperCase()}
                      </span>
                    </div>
                  </td>
                  <td style={{ ...TD, color: '#fff', fontWeight: 700 }}>{d.name}</td>
                  <td style={{ ...TD, color: '#888', fontSize: 10, letterSpacing: '0.5px', fontWeight: 500 }}>
                    {PLATFORM_LABEL[d.platform] ?? d.platform.toUpperCase()}
                  </td>
                  <td style={{ ...TD, color: '#00d4ff', fontVariantNumeric: 'tabular-nums', fontWeight: 500 }}>{d.ip || '—'}</td>
                  <td style={TD}>
                    <span style={{ color: AUTONOMY_COLOR[d.autonomy] ?? '#666', fontSize: 10, letterSpacing: '1px', textTransform: 'uppercase', fontWeight: 600 }}>
                      {d.autonomy}
                    </span>
                  </td>
                  <td style={{ ...TD, color: '#888' }}>{d.version || '—'}</td>
                  <td style={{ ...TD, color: d.threats_today ? '#f97316' : '#444', fontVariantNumeric: 'tabular-nums', fontWeight: d.threats_today ? 600 : 400 }}>
                    {d.threats_today ?? 0}
                  </td>
                  <td style={{ ...TD, color: '#888', fontVariantNumeric: 'tabular-nums', fontSize: 11 }}>
                    {agoString(d.last_seen)}
                  </td>
                  <td style={{ ...TD, color: '#444', fontSize: 11, fontVariantNumeric: 'tabular-nums', letterSpacing: '0.3px' }}>
                    {d.id}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

    </div>
  )
}
