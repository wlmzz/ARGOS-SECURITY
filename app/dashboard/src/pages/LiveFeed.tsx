import { useState, useEffect, useRef, useMemo, useCallback, memo } from 'react'
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts'
import { wsClient } from '../ws'
import { api } from '../api'
import type { ThreatEvent } from '../types'

// ── Types ──────────────────────────────────────────────────────────────────────

interface LiveEvent {
  id: string; timestamp: string; threat_type: string; severity: string
  source_ip: string; target_port: number; description: string
  action: string; reasoning: string; confidence: number
  escalate: boolean; fromWs: boolean
}

interface LogLine {
  id: number; ts: string; tag: string; tagColor: string; text: string
}

// ── Constants ──────────────────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = {
  critical: '#dc2626', high: '#ea580c', medium: '#d97706', low: '#16a34a',
}
const ACTION_COLOR: Record<string, string> = {
  block_ip: '#dc2626', isolate_process: '#dc2626',
  close_port: '#ea580c', deploy_honeypot: '#d97706',
  alert_human: '#7c3aed', monitor: '#16a34a', log: '#4a5568',
}
const ACTION_LABEL: Record<string, string> = {
  block_ip: 'Block IP', isolate_process: 'Isolate', close_port: 'Close Port',
  deploy_honeypot: 'Honeypot', alert_human: 'Escalate', monitor: 'Monitor', log: 'Log',
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function fromApi(e: ThreatEvent): LiveEvent {
  return {
    id: e.id, timestamp: e.timestamp, threat_type: e.threat_type,
    severity: e.severity, source_ip: e.source_ip, target_port: e.target_port,
    description: e.description, action: e.action_taken || 'monitor',
    reasoning: e.ai_analysis || '', confidence: e.ai_confidence || 0,
    escalate: false, fromWs: false,
  }
}

function fmt(ts: string) {
  return new Date(ts).toLocaleTimeString('it-IT', { hour: '2-digit', minute: '2-digit', second: '2-digit', timeZone: 'Europe/Rome' })
}

let _logId = 0
function logId() { return ++_logId }

const ACTION_DESC: Record<string, (ev: LiveEvent) => string> = {
  block_ip:        ev => `Blocked ${ev.source_ip} — firewall rule added`,
  isolate_process: ev => `Process on ${ev.source_ip} isolated — execution suspended`,
  deploy_honeypot: ev => `Honeypot deployed${ev.target_port ? ` on port ${ev.target_port}` : ''} — lure active`,
  close_port:      ev => `Port ${ev.target_port || '?'} closed — service disabled`,
  alert_human:     ev => `Human escalation requested for ${ev.source_ip}`,
  monitor:         ev => `${ev.source_ip} flagged — monitoring traffic`,
  log:             ev => `Event logged from ${ev.source_ip}`,
}

function eventToLogs(ev: LiveEvent): LogLine[] {
  const ts = fmt(ev.timestamp)
  const sCol = SEV_COLOR[ev.severity] || '#888'
  const aCol = ACTION_COLOR[ev.action] || '#888'
  const desc = (ACTION_DESC[ev.action] ?? (() => ev.action))(ev)
  return [
    { id: logId(), ts, tag: 'DETECT', tagColor: sCol,
      text: `${ev.threat_type.replace(/_/g, ' ').toUpperCase()}  ${ev.source_ip}  [${ev.severity.toUpperCase()}]` },
    { id: logId(), ts, tag: 'AI    ', tagColor: '#00d4ff',
      text: `Analyzing · conf ${(ev.confidence * 100).toFixed(0)}%${ev.escalate ? ' · ⚠ ESCALATE' : ''}` },
    { id: logId(), ts, tag: 'ACTION', tagColor: aCol, text: desc },
  ]
}

// ── Shared panel style ─────────────────────────────────────────────────────────

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
      display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0,
    }}>
      <span style={{ fontSize: 9, color: '#555', letterSpacing: '2px', fontWeight: 700, textTransform: 'uppercase' }}>{title}</span>
      {right && <span style={{ fontSize: 10, color: '#3a3a3a', fontVariantNumeric: 'tabular-nums' }}>{right}</span>}
    </div>
  )
}

// ── KPI card ──────────────────────────────────────────────────────────────────

const Kpi = memo(function Kpi({ label, value, sub, accent, divider = true }: {
  label: string; value: string | number; sub?: string; accent?: string; divider?: boolean
}) {
  return (
    <div style={{
      flex: 1, padding: '14px 16px 12px',
      borderRight: divider ? '1px solid rgba(255,255,255,0.05)' : 'none',
      borderTop: accent ? `2px solid ${accent}` : '2px solid transparent',
    }}>
      <div style={{ fontSize: 9, color: '#555', letterSpacing: '1.5px', fontWeight: 600, textTransform: 'uppercase', marginBottom: 5 }}>{label}</div>
      <div style={{ fontSize: 24, fontWeight: 700, color: '#fff', fontVariantNumeric: 'tabular-nums', lineHeight: 1, letterSpacing: '-0.5px' }}>{value}</div>
      {sub && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginTop: 4 }}>
          {accent && <div style={{ width: 4, height: 4, borderRadius: '50%', background: accent }} />}
          <span style={{ color: '#3a3a3a', fontSize: 9, letterSpacing: '1px', fontWeight: 500 }}>{sub}</span>
        </div>
      )}
    </div>
  )
})

// ── Action distribution chart ──────────────────────────────────────────────────

const ActionDonut = memo(function ActionDonut({ events }: { events: LiveEvent[] }) {
  const counts: Record<string, number> = {}
  events.forEach(e => { counts[e.action] = (counts[e.action] || 0) + 1 })
  const data = Object.entries(counts)
    .map(([action, value]) => ({ name: ACTION_LABEL[action] || action, value, fill: ACTION_COLOR[action] || '#4a5568' }))
    .sort((a, b) => b.value - a.value)
  const total = data.reduce((s, d) => s + d.value, 0)

  if (total === 0) return <div style={{ color: '#333', fontSize: 10, padding: 16, letterSpacing: '1.5px' }}>NO DATA</div>

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12, padding: '12px 14px' }}>
      <div style={{ position: 'relative', height: 140 }}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie data={data} cx="50%" cy="50%" innerRadius={40} outerRadius={60}
              startAngle={90} endAngle={-270} paddingAngle={2} dataKey="value"
              animationBegin={0} animationDuration={600}>
              {data.map((d, i) => <Cell key={i} fill={d.fill} stroke="transparent" />)}
            </Pie>
            <Tooltip
              contentStyle={{ background: '#161616', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 4, fontSize: 11 }}
              itemStyle={{ color: '#ccc' }}
              formatter={(v: any) => [v, '']}
            />
          </PieChart>
        </ResponsiveContainer>
        <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', pointerEvents: 'none' }}>
          <div style={{ fontSize: 20, fontWeight: 700, color: '#fff', lineHeight: 1 }}>{total}</div>
          <div style={{ fontSize: 8, color: '#444', letterSpacing: '1.5px', marginTop: 2 }}>ACTIONS</div>
        </div>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
        {data.slice(0, 5).map((d, i) => (
          <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
            <div style={{ width: 5, height: 5, borderRadius: 1, background: d.fill, flexShrink: 0 }} />
            <span style={{ color: '#555', fontSize: 9, letterSpacing: '0.5px', flex: 1, textTransform: 'uppercase' }}>{d.name}</span>
            <span style={{ color: '#888', fontSize: 10, fontWeight: 600, fontVariantNumeric: 'tabular-nums' }}>{d.value}</span>
            <span style={{ color: '#333', fontSize: 9 }}>{Math.round(d.value / total * 100)}%</span>
          </div>
        ))}
      </div>
    </div>
  )
})

// ── Confidence distribution ────────────────────────────────────────────────────

const ConfidenceChart = memo(function ConfidenceChart({ events }: { events: LiveEvent[] }) {
  const buckets = [
    { label: '90 – 100%', min: 0.9, max: 1.01,  color: '#16a34a' },
    { label: '75 – 90%',  min: 0.75, max: 0.9,  color: '#d97706' },
    { label: '60 – 75%',  min: 0.6, max: 0.75,  color: '#ea580c' },
    { label: '< 60%',     min: 0,   max: 0.6,   color: '#dc2626' },
  ]
  const total = events.length || 1
  const counted = buckets.map(b => ({
    ...b,
    count: events.filter(e => e.confidence >= b.min && e.confidence < b.max).length,
  }))

  return (
    <div style={{ padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: 8 }}>
      {counted.map((b, i) => {
        const pct = (b.count / total) * 100
        return (
          <div key={i}>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
              <span style={{ color: '#555', fontSize: 9, letterSpacing: '0.5px' }}>{b.label}</span>
              <span style={{ color: '#888', fontSize: 9, fontVariantNumeric: 'tabular-nums', fontWeight: 600 }}>{b.count}</span>
            </div>
            <div style={{ background: 'rgba(255,255,255,0.04)', borderRadius: 2, height: 5, overflow: 'hidden' }}>
              <div style={{
                width: `${pct}%`, height: '100%', background: b.color, borderRadius: 2,
                transition: 'width 0.6s ease',
              }} />
            </div>
          </div>
        )
      })}
      <div style={{ marginTop: 4, paddingTop: 8, borderTop: '1px solid rgba(255,255,255,0.04)' }}>
        <div style={{ color: '#444', fontSize: 9, letterSpacing: '1.5px', marginBottom: 3 }}>AVG CONFIDENCE</div>
        <div style={{ color: '#fff', fontSize: 18, fontWeight: 700, fontVariantNumeric: 'tabular-nums' }}>
          {events.length ? Math.round(events.reduce((s, e) => s + e.confidence, 0) / events.length * 100) : 0}%
        </div>
      </div>
    </div>
  )
})

// ── Main page ──────────────────────────────────────────────────────────────────

export function LiveFeed() {
  const [events, setEvents] = useState<LiveEvent[]>([])
  const [logs, setLogs] = useState<LogLine[]>([])
  const [loading, setLoading] = useState(true)
  const [connected, setConnected] = useState(false)
  const [evPerMin, setEvPerMin] = useState(0)
  const logTopRef = useRef<HTMLDivElement>(null)
  const recentTs = useRef<number[]>([])

  const loadEvents = useCallback(() => {
    api.events({ limit: 30 }).then(d => {
      const evs = d.map(fromApi)
      setEvents(evs)
      setLogs(evs.flatMap(eventToLogs))
    }).catch(() => {}).finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    loadEvents()
  }, [loadEvents])

  useEffect(() => {
    return wsClient.on((msg: any) => {
      if (msg.type === 'connected')    { setConnected(true); return }
      if (msg.type === 'disconnected') { setConnected(false); return }
      if (msg.type !== 'new_threat') return

      const dec = msg.ai_decision || {}
      const ev: LiveEvent = {
        id: msg.event_id, timestamp: msg.timestamp, threat_type: msg.threat_type,
        severity: msg.severity, source_ip: msg.source_ip, target_port: 0,
        description: msg.description,
        action: dec.action || msg.action_taken || 'monitor',
        reasoning: dec.reasoning || '', confidence: dec.confidence || 0,
        escalate: dec.escalate_to_human || false, fromWs: true,
      }
      setEvents(prev => [ev, ...prev].slice(0, 100))

      const lines = eventToLogs(ev)
      lines.slice().reverse().forEach((line, i) => {
        setTimeout(() => setLogs(prev => [line, ...prev].slice(0, 200)), i * 400)
      })

      const now = Date.now()
      recentTs.current = [...recentTs.current.filter(t => now - t < 60000), now]
      setEvPerMin(recentTs.current.length)
    })
  }, [])

  useEffect(() => { logTopRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [logs])
  useEffect(() => { setConnected(wsClient.isConnected?.() ?? false) }, [])

  useEffect(() => {
    const handler = () => {
      setEvents([])
      setLogs([])
      loadEvents()
    }
    window.addEventListener('argos:refresh', handler)
    return () => window.removeEventListener('argos:refresh', handler)
  }, [loadEvents])

  // Computed stats
  const kpiStats = useMemo(() => ({
    total: events.length,
    blocked: events.filter(e => e.action === 'block_ip').length,
    isolated: events.filter(e => e.action === 'isolate_process').length,
    honeypots: events.filter(e => e.action === 'deploy_honeypot').length,
    escalated: events.filter(e => e.escalate).length,
    avgConf: events.length ? Math.round(events.reduce((s, e) => s + (e.confidence ?? 0), 0) / events.length * 100) : 0,
    escRate: events.length ? Math.round(events.filter(e => e.escalate).length / events.length * 100) : 0,
    eventsPerMin: evPerMin,
  }), [events, evPerMin])

  const hourHeatmap = useMemo(() => {
    const buckets = Array(24).fill(0)
    for (const e of events) {
      const h = new Date(e.timestamp).getHours()
      if (h >= 0 && h < 24) buckets[h]++
    }
    const max = Math.max(...buckets, 1)
    return buckets.map((count, hour) => ({ hour, count, pct: count / max }))
  }, [events])

  return (
    <div style={{ padding: '18px 22px', display: 'flex', flexDirection: 'column', gap: 12, height: '100%', boxSizing: 'border-box', background: '#0a0a0a' }}>

      {/* ── Header ── */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingBottom: 12, borderBottom: '1px solid rgba(255,255,255,0.05)', flexShrink: 0 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ width: 2, height: 16, background: '#00d4ff', borderRadius: 1 }} />
          <span style={{ color: '#fff', fontSize: 11, letterSpacing: '2.5px', fontWeight: 700, textTransform: 'uppercase' }}>AI Analysis</span>
          <div style={{ display: 'flex', alignItems: 'center', gap: 5, background: 'rgba(220,38,38,0.08)', border: '1px solid rgba(220,38,38,0.2)', borderRadius: 3, padding: '2px 7px' }}>
            <div style={{ width: 4, height: 4, borderRadius: '50%', background: '#dc2626', animation: 'pulse-dot 1.5s infinite' }} />
            <span style={{ color: '#dc2626', fontSize: 8, letterSpacing: '1.5px', fontWeight: 700 }}>LIVE</span>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <div style={{ width: 4, height: 4, borderRadius: '50%', background: connected ? '#16a34a' : '#dc2626', animation: connected ? 'pulse-dot 2s infinite' : 'none' }} />
          <span style={{ color: connected ? '#16a34a' : '#dc2626', fontSize: 9, letterSpacing: '1px', fontWeight: 600 }}>{connected ? 'WS CONNECTED' : 'WS OFFLINE'}</span>
        </div>
      </div>

      {/* ── KPI strip ── */}
      <div style={{ ...PANEL, display: 'flex', overflow: 'hidden', flexShrink: 0 }}>
        <Kpi label="Total Decisions" value={kpiStats.total}              sub="ANALYZED"  />
        <Kpi label="Blocked IPs"     value={kpiStats.blocked}            accent="#dc2626" sub="FIREWALL" />
        <Kpi label="Isolated"        value={kpiStats.isolated}           accent="#dc2626" sub="PROCESSES" />
        <Kpi label="Honeypots"       value={kpiStats.honeypots}          accent="#d97706" sub="DEPLOYED" />
        <Kpi label="Escalated"       value={kpiStats.escalated}          accent="#7c3aed" sub="TO HUMAN" />
        <Kpi label="Esc Rate"        value={`${kpiStats.escRate}%`}      accent="#7c3aed" sub="ESCALATED" />
        <Kpi label="Evt / Min"       value={kpiStats.eventsPerMin}       sub="SESSION"    />
        <Kpi label="Avg Confidence"  value={`${kpiStats.avgConf}%`}      accent="#16a34a" sub="AI MODEL" divider={false} />
      </div>

      {/* ── Main 3-column layout ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '240px 1fr 360px', gap: 12, flex: 1, minHeight: 0 }}>

        {/* ── Col 1: Analytics ── */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12, overflow: 'hidden' }}>

          {/* Action distribution */}
          <div style={{ ...PANEL, display: 'flex', flexDirection: 'column' }}>
            <PanelHeader title="Action Distribution" />
            <ActionDonut events={events} />
          </div>

          {/* Confidence distribution */}
          <div style={{ ...PANEL }}>
            <PanelHeader title="AI Confidence" />
            <ConfidenceChart events={events} />
          </div>

          {/* Hourly Heatmap */}
          <div style={{ background: '#111', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 6 }}>
            <div style={{ padding: '8px 14px', borderBottom: '1px solid rgba(255,255,255,0.05)', background: '#0d0d0d', borderRadius: '6px 6px 0 0' }}>
              <span style={{ fontSize: 9, color: '#555', letterSpacing: '2px', fontWeight: 700, textTransform: 'uppercase' }}>Activity by Hour</span>
            </div>
            <div style={{ padding: '12px 14px' }}>
              <div style={{ display: 'flex', gap: 2, alignItems: 'flex-end', height: 48 }}>
                {hourHeatmap.map(({ hour, count, pct }) => (
                  <div key={hour} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 3 }}>
                    <div style={{
                      width: '100%', borderRadius: 2,
                      background: pct === 0 ? '#1a1a1a' : `rgba(124,58,237,${0.15 + pct * 0.85})`,
                      height: Math.max(3, pct * 40),
                      transition: 'height 0.3s ease',
                    }} title={`${hour}:00 — ${count} events`} />
                  </div>
                ))}
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 4 }}>
                {[0, 6, 12, 18, 23].map(h => (
                  <span key={h} style={{ fontSize: 8, color: '#333', fontVariantNumeric: 'tabular-nums' }}>{String(h).padStart(2,'0')}</span>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* ── Col 2: Decision cards ── */}
        <div style={{ ...PANEL, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          <PanelHeader title="Decision Log" right={`${events.length} decisions`} />
          <div style={{ flex: 1, overflow: 'auto', display: 'flex', flexDirection: 'column', gap: 1, padding: '4px 0' }}>
            {loading && events.length === 0 && (
              <div style={{ padding: 20, color: '#333', fontSize: 10, letterSpacing: '2px' }}>LOADING...</div>
            )}
            {!loading && events.length === 0 && (
              <div style={{ padding: '40px 20px', textAlign: 'center', color: '#2a2a2a', fontSize: 10, letterSpacing: '1.5px' }}>
                NO EVENTS — RUN: python simulate.py
              </div>
            )}
            {events.map(ev => {
              const sCol = SEV_COLOR[ev.severity] || '#555'
              const aCol = ACTION_COLOR[ev.action] || '#555'
              return (
                <div key={ev.id} style={{
                  padding: '10px 14px',
                  borderBottom: '1px solid rgba(255,255,255,0.04)',
                  borderLeft: `2px solid ${sCol}`,
                  animation: ev.fromWs ? 'fadeSlide 0.2s ease' : 'none',
                  background: ev.fromWs ? 'rgba(255,255,255,0.01)' : 'transparent',
                  transition: 'background 0.3s',
                }}>
                  {/* Row 1: time + severity + type + ip */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 5 }}>
                    <span style={{ color: '#3a3a3a', fontSize: 10, fontVariantNumeric: 'tabular-nums', flexShrink: 0 }}>{fmt(ev.timestamp)}</span>
                    <span style={{ color: sCol, fontSize: 8, letterSpacing: '1.5px', fontWeight: 700, textTransform: 'uppercase', background: `${sCol}18`, padding: '1px 5px', border: `1px solid ${sCol}33`, borderRadius: 2, flexShrink: 0 }}>
                      {ev.severity}
                    </span>
                    <span style={{ color: '#ccc', fontSize: 10, fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.5px', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {ev.threat_type.replace(/_/g, ' ')}
                    </span>
                    <span style={{ color: '#2563eb', fontSize: 10, fontVariantNumeric: 'tabular-nums', flexShrink: 0 }}>{ev.source_ip}</span>
                  </div>

                  {/* Row 2: AI decision block */}
                  <div style={{ background: '#0d0d0d', border: '1px solid rgba(255,255,255,0.05)', borderRadius: 3, padding: '6px 10px', display: 'flex', alignItems: 'flex-start', gap: 12 }}>
                    <div style={{ flexShrink: 0 }}>
                      <div style={{ fontSize: 8, color: '#444', letterSpacing: '1px', marginBottom: 2 }}>ACTION</div>
                      <div style={{ color: aCol, fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.5px', whiteSpace: 'nowrap' }}>
                        {(ACTION_LABEL[ev.action] || ev.action).replace(/_/g, ' ')}
                      </div>
                    </div>
                    <div style={{ width: 1, background: 'rgba(255,255,255,0.06)', alignSelf: 'stretch', flexShrink: 0 }} />
                    <div style={{ flexShrink: 0 }}>
                      <div style={{ fontSize: 8, color: '#444', letterSpacing: '1px', marginBottom: 2 }}>CONF</div>
                      <div style={{ color: '#fff', fontSize: 12, fontWeight: 700, fontVariantNumeric: 'tabular-nums' }}>{(ev.confidence * 100).toFixed(0)}%</div>
                    </div>
                    {ev.escalate && (
                      <>
                        <div style={{ width: 1, background: 'rgba(255,255,255,0.06)', alignSelf: 'stretch', flexShrink: 0 }} />
                        <span style={{ color: '#7c3aed', fontSize: 8, letterSpacing: '1px', fontWeight: 700, alignSelf: 'center' }}>⚠ ESCALATE</span>
                      </>
                    )}
                    <div style={{ flex: 1, overflow: 'hidden' }}>
                      <div style={{ fontSize: 8, color: '#444', letterSpacing: '1px', marginBottom: 2 }}>REASONING</div>
                      <div style={{ color: '#666', fontSize: 10, lineHeight: 1.4, overflow: 'hidden', display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical' } as any}>
                        {ev.reasoning || '—'}
                      </div>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* ── Col 3: Terminal (unchanged) ── */}
        <div style={{
          background: '#0a0a0a', border: '1px solid rgba(255,255,255,0.07)', borderRadius: 6,
          display: 'flex', flexDirection: 'column', overflow: 'hidden',
        }}>
          {/* macOS-style terminal header */}
          <div style={{ padding: '8px 12px', borderBottom: '1px solid rgba(255,255,255,0.05)', background: '#0d0d0d', borderRadius: '6px 6px 0 0', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', gap: 5 }}>
              <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#dc2626', opacity: 0.7 }} />
              <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#d97706', opacity: 0.7 }} />
              <div style={{ width: 8, height: 8, borderRadius: '50%', background: '#16a34a', opacity: 0.7 }} />
            </div>
            <span style={{ color: '#333', fontSize: 9, letterSpacing: '2px', fontWeight: 600 }}>ARGOS — LIVE LOG</span>
            <span style={{ color: '#2a2a2a', fontSize: 9, fontVariantNumeric: 'tabular-nums' }}>{logs.length} lines</span>
          </div>

          {/* Log lines — newest on top */}
          <div style={{ flex: 1, overflow: 'auto', padding: '8px 0', fontFamily: 'monospace' }}>
            <div ref={logTopRef} />
            {logs.length === 0 && (
              <div style={{ color: '#2a2a2a', fontSize: 11, padding: '12px 14px', letterSpacing: '1px' }}>Waiting for events...</div>
            )}
            {logs.map(line => (
              <div key={line.id} style={{ display: 'flex', alignItems: 'baseline', gap: 8, padding: '2px 14px', fontSize: 11, lineHeight: 1.6, animation: 'fadeIn 0.2s ease' }}>
                <span style={{ color: '#2a2a2a', flexShrink: 0, fontSize: 10 }}>{line.ts}</span>
                <span style={{ color: line.tagColor, fontWeight: 700, fontSize: 9, letterSpacing: '1px', flexShrink: 0, width: 48, textAlign: 'right' }}>{line.tag}</span>
                <span style={{ color: line.tag === 'ACTION' ? line.tagColor : line.tag === 'AI    ' ? '#444' : '#555', wordBreak: 'break-all' }}>{line.text}</span>
              </div>
            ))}
          </div>

          {/* Cursor */}
          <div style={{ padding: '5px 14px', borderTop: '1px solid rgba(255,255,255,0.04)', background: '#0d0d0d', borderRadius: '0 0 6px 6px' }}>
            <span style={{ color: '#2a2a2a', fontSize: 11, fontFamily: 'monospace' }}>argos@soc:~$ </span>
            <span style={{ color: '#16a34a', animation: 'pulse-dot 1s infinite', fontSize: 11 }}>█</span>
          </div>
        </div>

      </div>
    </div>
  )
}
