import { useState, useRef, useEffect } from 'react'
import { SeverityBadge } from './SeverityBadge'
import type { ThreatEvent } from '../types'

interface ThreatTableProps {
  events: ThreatEvent[]
  maxHeight?: number
}

const ROW_HEIGHT = 33 // pixels per row
const OVERSCAN = 5   // extra rows above/below visible area
const VIRT_THRESHOLD = 50 // only virtualize when events.length > this

const ROME = { timeZone: 'Europe/Rome' }

function fmtTime(ts: string) {
  return new Date(ts).toLocaleTimeString('it-IT', { hour: '2-digit', minute: '2-digit', second: '2-digit', ...ROME })
}

function fmtFull(ts: string) {
  return new Date(ts).toLocaleString('it-IT', { dateStyle: 'short', timeStyle: 'medium', ...ROME })
}

const ACTION_COLOR: Record<string, string> = {
  block_ip:        '#ef4444',
  isolate_process: '#ef4444',
  close_port:      '#f97316',
  deploy_honeypot: '#f97316',
  alert_human:     '#a78bfa',
  monitor:         '#22c55e',
  log:             '#555',
}

function EventModal({ event, onClose }: { event: ThreatEvent; onClose: () => void }) {
  const action = event.action_taken || 'monitor'
  const aCol = ACTION_COLOR[action] || '#666'

  return (
    <div
      onClick={onClose}
      style={{
        position: 'fixed', inset: 0, zIndex: 9999,
        background: 'rgba(0,0,0,0.75)', backdropFilter: 'blur(4px)',
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        animation: 'fadeIn 0.15s ease',
      }}
    >
      <div
        onClick={e => e.stopPropagation()}
        style={{
          background: '#141414', border: '1px solid rgba(255,255,255,0.1)',
          borderRadius: 10, width: 560, maxWidth: '90vw', maxHeight: '85vh',
          overflow: 'auto', boxShadow: '0 24px 64px rgba(0,0,0,0.9)',
          position: 'relative',
        }}
      >
        {/* Top bar */}
        <div style={{
          position: 'sticky', top: 0, zIndex: 1,
          background: '#141414', borderBottom: '1px solid rgba(255,255,255,0.07)',
          padding: '14px 20px', display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <SeverityBadge severity={event.severity} />
            <span style={{ color: '#fff', fontSize: 12, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1px' }}>
              {event.threat_type.replace(/_/g, ' ')}
            </span>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'transparent', border: 'none', color: '#555',
              fontSize: 18, cursor: 'pointer', lineHeight: 1, padding: '0 4px',
              transition: 'color 0.12s',
            }}
            onMouseEnter={e => (e.currentTarget.style.color = '#fff')}
            onMouseLeave={e => (e.currentTarget.style.color = '#555')}
          >×</button>
        </div>

        <div style={{ padding: '20px 20px 24px', display: 'flex', flexDirection: 'column', gap: 16 }}>

          {/* Meta grid */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
            {[
              ['TIMESTAMP',  fmtFull(event.timestamp)],
              ['SOURCE IP',  event.source_ip],
              ['TARGET PORT', event.target_port ? String(event.target_port) : '—'],
              ['PROTOCOL',   event.protocol || '—'],
            ].map(([label, val]) => (
              <div key={label} style={{
                background: '#0f0f0f', border: '1px solid rgba(255,255,255,0.05)',
                borderRadius: 6, padding: '10px 14px',
              }}>
                <div style={{ color: '#444', fontSize: 9, letterSpacing: '1.5px', fontWeight: 600, marginBottom: 4 }}>{label}</div>
                <div style={{ color: label === 'SOURCE IP' ? '#00d4ff' : '#ccc', fontSize: 12, fontVariantNumeric: 'tabular-nums', fontWeight: 500 }}>{val}</div>
              </div>
            ))}
          </div>

          {/* Action */}
          <div style={{
            background: '#0f0f0f', border: `1px solid ${aCol}33`,
            borderLeft: `3px solid ${aCol}`, borderRadius: '0 6px 6px 0',
            padding: '12px 14px', display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          }}>
            <div>
              <div style={{ color: '#444', fontSize: 9, letterSpacing: '1.5px', fontWeight: 600, marginBottom: 4 }}>ACTION TAKEN</div>
              <div style={{ color: aCol, fontSize: 13, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1px' }}>
                {action.replace(/_/g, ' ')}
              </div>
            </div>
            {event.ai_confidence != null && (
              <div style={{ textAlign: 'right' }}>
                <div style={{ color: '#444', fontSize: 9, letterSpacing: '1.5px', fontWeight: 600, marginBottom: 4 }}>AI CONFIDENCE</div>
                <div style={{ color: '#fff', fontSize: 20, fontWeight: 800, fontVariantNumeric: 'tabular-nums' }}>
                  {(event.ai_confidence * 100).toFixed(0)}%
                </div>
              </div>
            )}
          </div>

          {/* Description */}
          <div style={{ background: '#0f0f0f', border: '1px solid rgba(255,255,255,0.05)', borderRadius: 6, padding: '12px 14px' }}>
            <div style={{ color: '#444', fontSize: 9, letterSpacing: '1.5px', fontWeight: 600, marginBottom: 8 }}>DESCRIPTION</div>
            <div style={{ color: '#ccc', fontSize: 12, lineHeight: 1.7 }}>{event.description || '—'}</div>
          </div>

          {/* AI Analysis */}
          {event.ai_analysis && (
            <div style={{ background: '#0f0f0f', border: '1px solid rgba(0,212,255,0.15)', borderRadius: 6, padding: '12px 14px' }}>
              <div style={{ color: '#00d4ff', fontSize: 9, letterSpacing: '1.5px', fontWeight: 600, marginBottom: 8 }}>AI ANALYSIS</div>
              <div style={{ color: '#aaa', fontSize: 12, lineHeight: 1.7 }}>{event.ai_analysis}</div>
            </div>
          )}

          {/* Event ID */}
          <div style={{ color: '#333', fontSize: 10, fontFamily: 'monospace', letterSpacing: '0.5px' }}>
            ID: {event.id}
          </div>
        </div>
      </div>
    </div>
  )
}

export function ThreatTable({ events, maxHeight }: ThreatTableProps) {
  const [selected, setSelected] = useState<ThreatEvent | null>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const [scrollTop, setScrollTop] = useState(0)
  const [containerHeight, setContainerHeight] = useState(400)

  useEffect(() => {
    if (!containerRef.current) return
    const obs = new ResizeObserver(entries => {
      setContainerHeight(entries[0]?.contentRect.height ?? 400)
    })
    obs.observe(containerRef.current)
    return () => obs.disconnect()
  }, [])

  const startIndex = Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - OVERSCAN)
  const visibleCount = Math.ceil(containerHeight / ROW_HEIGHT) + OVERSCAN * 2
  const endIndex = Math.min(events.length, startIndex + visibleCount)
  const visibleEvents = events.length > VIRT_THRESHOLD ? events.slice(startIndex, endIndex) : events
  const paddingTop = events.length > VIRT_THRESHOLD ? startIndex * ROW_HEIGHT : 0
  const paddingBottom = events.length > VIRT_THRESHOLD ? Math.max(0, (events.length - endIndex) * ROW_HEIGHT) : 0

  const TH: React.CSSProperties = {
    padding: '7px 12px',
    color: '#444', fontSize: 9, letterSpacing: '1.5px',
    textTransform: 'uppercase', fontWeight: 600, textAlign: 'left',
    borderBottom: '1px solid rgba(255,255,255,0.05)',
    whiteSpace: 'nowrap', background: 'rgba(10,10,10,0.8)',
    position: 'sticky', top: 0, zIndex: 1,
  }
  const TD: React.CSSProperties = {
    padding: '6px 12px', fontSize: 12,
    borderBottom: '1px solid rgba(255,255,255,0.03)',
    whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
  }

  return (
    <>
      {selected && <EventModal event={selected} onClose={() => setSelected(null)} />}

      <div ref={containerRef} style={{ overflowY: 'auto', maxHeight }} onScroll={e => setScrollTop(e.currentTarget.scrollTop)}>
        <table style={{ width: '100%', borderCollapse: 'collapse', tableLayout: 'fixed' }}>
          <colgroup>
            <col style={{ width: 90 }} />
            <col style={{ width: 90 }} />
            <col style={{ width: 150 }} />
            <col style={{ width: 150 }} />
            <col style={{ width: 60 }} />
            <col style={{ width: 140 }} />
            <col />
          </colgroup>
          <thead>
            <tr>
              <th style={TH}>TIME</th>
              <th style={TH}>SEV</th>
              <th style={TH}>TYPE</th>
              <th style={TH}>SOURCE IP</th>
              <th style={TH}>PORT</th>
              <th style={TH}>ACTION</th>
              <th style={TH}>DESCRIPTION</th>
            </tr>
          </thead>
          <tbody>
            {paddingTop > 0 && <tr><td colSpan={7} style={{ padding: 0, height: paddingTop, border: 'none' }} /></tr>}
            {visibleEvents.map(e => {
              const action = e.action_taken || 'monitor'
              return (
                <tr
                  key={e.id}
                  onClick={() => setSelected(e)}
                  style={{ cursor: 'pointer', transition: 'background 0.08s' }}
                  onMouseEnter={ev => (ev.currentTarget.style.background = 'rgba(255,255,255,0.03)')}
                  onMouseLeave={ev => (ev.currentTarget.style.background = 'transparent')}
                >
                  <td style={{ ...TD, color: '#555', fontVariantNumeric: 'tabular-nums' }}>
                    {fmtTime(e.timestamp)}
                  </td>
                  <td style={TD}><SeverityBadge severity={e.severity} /></td>
                  <td style={{ ...TD, color: '#ccc', textTransform: 'uppercase', fontSize: 10, letterSpacing: '0.5px', fontWeight: 500 }}>
                    {e.threat_type.replace(/_/g, ' ')}
                  </td>
                  <td style={{ ...TD, color: '#00d4ff', fontVariantNumeric: 'tabular-nums' }}>
                    {e.source_ip}
                  </td>
                  <td style={{ ...TD, color: '#555' }}>{e.target_port || '—'}</td>
                  <td style={TD}>
                    <span style={{ color: ACTION_COLOR[action] || '#666', fontSize: 10, letterSpacing: '0.5px', textTransform: 'uppercase', fontWeight: 600 }}>
                      {action.replace(/_/g, ' ')}
                    </span>
                  </td>
                  <td style={{ ...TD, color: '#555', maxWidth: 0 }}>{e.description}</td>
                </tr>
              )
            })}
            {paddingBottom > 0 && <tr><td colSpan={7} style={{ padding: 0, height: paddingBottom, border: 'none' }} /></tr>}
            {events.length === 0 && (
              <tr>
                <td colSpan={7} style={{ ...TD, textAlign: 'center', color: '#333', padding: '24px', fontWeight: 500, letterSpacing: '1px' }}>
                  NO EVENTS
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  )
}
