import { useState, useEffect, useMemo, useRef } from 'react'
import { api } from '../api'
import { sanitizeIp, sanitizeQuery } from '../utils/sanitize'
import type { BlockedIP } from '../types'

const PANEL: React.CSSProperties = {
  background: '#111',
  border: '1px solid rgba(255,255,255,0.07)',
  borderRadius: 6,
  overflow: 'hidden',
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

function fmtDate(s: string) {
  return new Date(s).toLocaleString('it-IT', { dateStyle: 'short', timeStyle: 'medium', timeZone: 'Europe/Rome' })
}

export function Intelligence() {
  const [blockedIps, setBlockedIps]       = useState<BlockedIP[]>([])
  const [loading, setLoading]             = useState(true)
  const [lookupIp, setLookupIp]           = useState('')
  const [lookupResult, setLookupResult]   = useState<any>(null)
  const [lookupLoading, setLookupLoading] = useState(false)
  const [lookupError, setLookupError]     = useState('')
  const [page, setPage] = useState(0)
  const PAGE_SIZE = 20
  const [blockForm, setBlockForm] = useState({ ip: '', reason: '' })
  const [blockMsg, setBlockMsg] = useState('')
  const lastQueryRef = useRef(0)

  useEffect(() => {
    api.blockedIps().then(setBlockedIps).catch(() => {}).finally(() => setLoading(false))
  }, [])

  const threatScore = useMemo(() => {
    const base = Math.min(80, blockedIps.length * 2)
    const community = blockedIps.filter(b => b.community).length
    const permanent = blockedIps.filter(b => !b.expires_at).length
    return Math.round(Math.min(100, base + community * 0.3 + permanent * 1.2))
  }, [blockedIps])

  const pagedIps = useMemo(() =>
    blockedIps.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE),
    [blockedIps, page]
  )
  const totalPages = Math.ceil(blockedIps.length / PAGE_SIZE)

  const handleLookup = async () => {
    if (!lookupIp.trim()) return
    if (Date.now() - lastQueryRef.current < 2000) return
    lastQueryRef.current = Date.now()
    setLookupLoading(true); setLookupError(''); setLookupResult(null)
    try { setLookupResult(await api.lookupIp(sanitizeIp(lookupIp.trim()))) }
    catch { setLookupError('LOOKUP FAILED — CHECK IP FORMAT OR NETWORK CONNECTIVITY') }
    setLookupLoading(false)
  }

  const handleUnblock = async (ip: string) => {
    try { await api.unblockIp(ip); setBlockedIps(prev => prev.filter(b => b.ip !== ip)) }
    catch {}
  }

  return (
    <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>

      {/* Enterprise page header */}
      <div style={{ display: 'flex', alignItems: 'center', paddingBottom: 12, borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
        <div style={{ width: 2, height: 16, background: '#7c3aed', borderRadius: 1, marginRight: 12 }} />
        <span style={{ color: '#fff', fontSize: 11, letterSpacing: '2.5px', fontWeight: 700, textTransform: 'uppercase' }}>Intelligence</span>
      </div>

      {/* IP Lookup */}
      <div style={PANEL}>
        <PanelHeader title="IP Intelligence Lookup" />
        <div style={{ padding: '14px 16px', display: 'flex', gap: 8 }}>
          <input
            style={{
              flex: 1, background: '#0a0a0a',
              border: '1px solid rgba(255,255,255,0.1)', borderRadius: 4,
              color: '#fff', padding: '8px 12px', fontSize: 12, fontWeight: 400,
            }}
            value={lookupIp} onChange={e => setLookupIp(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && handleLookup()}
            placeholder="Enter IP address (e.g. 185.220.101.42)"
            spellCheck={false}
          />
          <button
            onClick={handleLookup} disabled={lookupLoading}
            style={{
              background: lookupLoading ? '#1a1a1a' : '#fff',
              border: 'none', borderRadius: 4,
              color: lookupLoading ? '#555' : '#0a0a0a',
              padding: '8px 20px', fontSize: 10,
              letterSpacing: '2px', textTransform: 'uppercase',
              cursor: lookupLoading ? 'not-allowed' : 'pointer',
              fontWeight: 700, whiteSpace: 'nowrap', transition: 'all 0.12s',
            }}
          >
            {lookupLoading ? 'QUERYING...' : 'QUERY'}
          </button>
        </div>

        {lookupError && (
          <div style={{ padding: '0 16px 14px', color: '#ef4444', fontSize: 11, fontWeight: 500 }}>
            {lookupError}
          </div>
        )}

        {lookupResult && (
          <div style={{
            margin: '0 16px 16px', background: '#0a0a0a',
            border: '1px solid rgba(255,255,255,0.07)', borderRadius: 4, padding: '12px 14px',
          }}>
            <div style={{ color: '#fff', fontSize: 13, fontWeight: 700, marginBottom: 10, letterSpacing: '1px' }}>
              {lookupIp}
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '140px 1fr', gap: '6px 12px' }}>
              {Object.entries(lookupResult).map(([k, v]) => (
                <div key={k} style={{ display: 'contents' }}>
                  <div style={{ color: '#555', fontSize: 9, letterSpacing: '1px', textTransform: 'uppercase', alignSelf: 'center', fontWeight: 600 }}>
                    {k}
                  </div>
                  <div style={{ color: '#fff', fontSize: 12 }}>{String(v)}</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Threat Intelligence KPIs */}
      <div style={{ display: 'flex', background: '#111', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 6, overflow: 'hidden' }}>
        {[
          { label: 'Blocked IPs', value: blockedIps.length, accent: '#dc2626' },
          { label: 'Community Intel', value: blockedIps.filter(b => b.community).length, accent: '#7c3aed' },
          { label: 'Permanent Rules', value: blockedIps.filter(b => !b.expires_at).length, accent: '#ea580c' },
          { label: 'Threat Score', value: `${threatScore}/100`, accent: threatScore > 75 ? '#dc2626' : threatScore > 50 ? '#ea580c' : threatScore > 25 ? '#eab308' : '#22c55e' },
        ].map((k, i, arr) => (
          <div key={k.label} style={{
            flex: 1, padding: '14px 16px 12px',
            borderRight: i < arr.length - 1 ? '1px solid rgba(255,255,255,0.05)' : 'none',
            borderTop: `2px solid ${k.accent}`,
          }}>
            <div style={{ fontSize: 9, color: '#555', letterSpacing: '1.5px', fontWeight: 600, textTransform: 'uppercase', marginBottom: 5 }}>{k.label}</div>
            <div style={{ fontSize: 24, fontWeight: 700, color: '#fff', fontVariantNumeric: 'tabular-nums', lineHeight: 1 }}>{k.value}</div>
          </div>
        ))}
      </div>

      {/* Manual Block Form */}
      <div style={PANEL}>
        <PanelHeader title="Manual Block" />
        <div style={{ padding: '14px 16px', display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'flex-end' }}>
          <div style={{ flex: '1 1 160px' }}>
            <div style={{ color: '#555', fontSize: 9, letterSpacing: '1.5px', textTransform: 'uppercase', fontWeight: 600, marginBottom: 5 }}>IP Address</div>
            <input
              value={blockForm.ip}
              onChange={e => setBlockForm(f => ({ ...f, ip: sanitizeIp(e.target.value) }))}
              placeholder="e.g. 1.2.3.4"
              style={{ width: '100%', background: '#0a0a0a', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 4, color: '#fff', padding: '8px 12px', fontSize: 12, fontFamily: 'inherit', boxSizing: 'border-box' }}
            />
          </div>
          <div style={{ flex: '2 1 220px' }}>
            <div style={{ color: '#555', fontSize: 9, letterSpacing: '1.5px', textTransform: 'uppercase', fontWeight: 600, marginBottom: 5 }}>Reason</div>
            <input
              value={blockForm.reason}
              onChange={e => setBlockForm(f => ({ ...f, reason: sanitizeQuery(e.target.value) }))}
              placeholder="e.g. manual_block, suspicious activity..."
              style={{ width: '100%', background: '#0a0a0a', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 4, color: '#fff', padding: '8px 12px', fontSize: 12, fontFamily: 'inherit', boxSizing: 'border-box' }}
            />
          </div>
          <button
            onClick={() => setBlockMsg('Manual blocking requires a threat event. Use Threat Events page to block from a specific event.')}
            disabled={!blockForm.ip.trim()}
            style={{
              background: blockForm.ip.trim() ? '#fff' : '#2a2a2a',
              border: 'none', borderRadius: 4,
              color: blockForm.ip.trim() ? '#0a0a0a' : '#444',
              padding: '8px 20px', fontSize: 10,
              letterSpacing: '2px', textTransform: 'uppercase',
              cursor: blockForm.ip.trim() ? 'pointer' : 'not-allowed',
              fontWeight: 700, whiteSpace: 'nowrap', flexShrink: 0,
            }}
          >
            BLOCK IP
          </button>
        </div>
        {blockMsg && (
          <div style={{ padding: '0 16px 12px', color: '#d97706', fontSize: 11 }}>{blockMsg}</div>
        )}
      </div>

      {/* Blocklist */}
      <div style={PANEL}>
        <PanelHeader title="Blocklist" right={totalPages > 1 ? `page ${page + 1}/${totalPages} · ${blockedIps.length} entries` : `${blockedIps.length} entries`} />
        <div style={{ overflow: 'auto', maxHeight: 400 }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr>
                {['IP ADDRESS','REASON','BLOCKED AT','EXPIRES','SOURCE','ACTION'].map(h => (
                  <th key={h} style={TH}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={6} style={{ ...TD, color: '#444', letterSpacing: '2px', fontWeight: 500 }}>LOADING...</td></tr>
              ) : blockedIps.length === 0 ? (
                <tr>
                  <td colSpan={6} style={{ ...TD, color: '#333', textAlign: 'center', padding: 40, letterSpacing: '2px', fontWeight: 500 }}>
                    NO BLOCKED IPs
                  </td>
                </tr>
              ) : pagedIps.map(b => (
                <tr
                  key={b.ip}
                  style={{ transition: 'background 0.08s' }}
                  onMouseEnter={e => (e.currentTarget.style.background = 'rgba(255,255,255,0.025)')}
                  onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                >
                  <td style={{ ...TD, color: '#ef4444', fontVariantNumeric: 'tabular-nums', fontWeight: 700 }}>{b.ip}</td>
                  <td style={{ ...TD, color: '#fff', textTransform: 'uppercase', fontSize: 10, fontWeight: 500 }}>
                    {b.reason.replace(/_/g, ' ')}
                  </td>
                  <td style={{ ...TD, color: '#888', fontVariantNumeric: 'tabular-nums' }}>{fmtDate(b.blocked_at)}</td>
                  <td style={{ ...TD, color: b.expires_at ? '#eab308' : '#444', fontVariantNumeric: 'tabular-nums' }}>
                    {b.expires_at ? fmtDate(b.expires_at) : 'PERMANENT'}
                  </td>
                  <td style={{ ...TD, color: b.community ? '#a78bfa' : '#666', fontSize: 10, fontWeight: 500 }}>
                    {b.community ? 'COMMUNITY' : 'LOCAL'}
                  </td>
                  <td style={TD}>
                    <button
                      onClick={() => handleUnblock(b.ip)}
                      style={{
                        background: 'none', border: '1px solid rgba(239,68,68,0.2)', borderRadius: 3,
                        color: '#666', padding: '2px 8px', fontSize: 9, letterSpacing: '1px',
                        cursor: 'pointer', textTransform: 'uppercase', fontWeight: 600, transition: 'all 0.1s',
                      }}
                      onMouseEnter={e => { e.currentTarget.style.borderColor = 'rgba(239,68,68,0.5)'; e.currentTarget.style.color = '#ef4444' }}
                      onMouseLeave={e => { e.currentTarget.style.borderColor = 'rgba(239,68,68,0.2)'; e.currentTarget.style.color = '#666' }}
                    >
                      UNBLOCK
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {totalPages > 1 && (
          <div style={{ padding: '10px 16px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderTop: '1px solid rgba(255,255,255,0.05)' }}>
            <span style={{ fontSize: 9, color: '#444', letterSpacing: '1px' }}>
              {page * PAGE_SIZE + 1}–{Math.min((page + 1) * PAGE_SIZE, blockedIps.length)} OF {blockedIps.length}
            </span>
            <div style={{ display: 'flex', gap: 6 }}>
              <button
                onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}
                style={{ background: 'none', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 3, color: page === 0 ? '#333' : '#888', padding: '3px 10px', fontSize: 10, cursor: page === 0 ? 'not-allowed' : 'pointer' }}
              >←</button>
              <button
                onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))} disabled={page >= totalPages - 1}
                style={{ background: 'none', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 3, color: page >= totalPages - 1 ? '#333' : '#888', padding: '3px 10px', fontSize: 10, cursor: page >= totalPages - 1 ? 'not-allowed' : 'pointer' }}
              >→</button>
            </div>
          </div>
        )}
      </div>

    </div>
  )
}
