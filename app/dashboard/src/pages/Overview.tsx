import { useState, useEffect, useMemo, memo } from 'react'
import { HourlyChart } from '../components/HourlyChart'
import { ThreatTypeChart } from '../components/ThreatTypeChart'
import { ThreatTable } from '../components/ThreatTable'
import { ThreatMap } from '../components/ThreatMap'
import { LiveActivityChart } from '../components/LiveActivityChart'
import { ThreatGauge } from '../components/ThreatGauge'
import { useOverview } from '../hooks/useOverview'
import { useWebSocket } from '../hooks/useWebSocket'

const ROME = { timeZone: 'Europe/Rome' }

function Clock() {
  const [now, setNow] = useState(new Date())
  useEffect(() => { const t = setInterval(() => setNow(new Date()), 1000); return () => clearInterval(t) }, [])
  return <>{now.toLocaleString('it-IT', { dateStyle: 'short', timeStyle: 'medium', ...ROME })}</>
}

// ── Sparkline ──────────────────────────────────────────────────────────────────

const Sparkline = memo(function Sparkline({ data, color }: { data: number[]; color: string }) {
  if (!data || data.length < 2) return null
  const max = Math.max(...data, 1)
  const W = 70, H = 20
  const pts = data.map((v, i) => `${(i / (data.length - 1)) * W},${H - (v / max) * (H - 2) + 1}`)
  return (
    <svg width={W} height={H} style={{ display: 'block', marginTop: 5 }}>
      <polyline points={pts.join(' ')} fill="none" stroke={color} strokeWidth={1.5} opacity={0.5} strokeLinecap="round" strokeLinejoin="round"/>
    </svg>
  )
})

// ── KPI metric card ────────────────────────────────────────────────────────────

const Kpi = memo(function Kpi({ label, value, sub, accent, divider = true, sparkData }: {
  label: string; value: string | number; sub?: string; accent?: string; divider?: boolean; sparkData?: number[]
}) {
  return (
    <div style={{
      flex: 1, padding: '16px 18px 14px',
      borderRight: divider ? '1px solid rgba(255,255,255,0.05)' : 'none',
      borderTop: accent ? `2px solid ${accent}` : '2px solid transparent',
    }}>
      <div style={{ fontSize: 9, color: '#555', letterSpacing: '1.5px', fontWeight: 600, textTransform: 'uppercase', marginBottom: 6 }}>
        {label}
      </div>
      <div style={{ fontSize: 26, fontWeight: 700, color: '#fff', fontVariantNumeric: 'tabular-nums', lineHeight: 1, letterSpacing: '-0.5px' }}>
        {value}
      </div>
      {sub && (
        <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginTop: 5 }}>
          {accent && <div style={{ width: 4, height: 4, borderRadius: '50%', background: accent }} />}
          <span style={{ color: '#3a3a3a', fontSize: 9, letterSpacing: '1px', fontWeight: 500 }}>{sub}</span>
        </div>
      )}
      {sparkData && accent && <Sparkline data={sparkData} color={accent} />}
    </div>
  )
})

// ── Panel wrapper ──────────────────────────────────────────────────────────────

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
      {right && <span style={{ fontSize: 10, color: '#3a3a3a', fontVariantNumeric: 'tabular-nums' }}>{right}</span>}
    </div>
  )
}

// ── Severity color map ─────────────────────────────────────────────────────────

const SEV_COLOR: Record<string, string> = { critical: '#dc2626', high: '#f97316', medium: '#eab308', low: '#22c55e' }

// ── Main page ──────────────────────────────────────────────────────────────────

export function Overview() {
  const { data, loading, refresh } = useOverview()
  const { connected } = useWebSocket(true)
  const stats = data?.stats

  const criticalCount = useMemo(() => stats?.critical_today ?? 0, [stats])
  const totalToday    = useMemo(() => stats?.threats_today ?? 0, [stats])
  const highCount     = useMemo(() => stats?.threats_today != null ? Math.round(stats.threats_today * 0.3) : 0, [stats])
  const mediumCount   = useMemo(() => stats?.threats_today != null ? Math.round(stats.threats_today * 0.2) : 0, [stats])

  const avgConfidence = useMemo(() => {
    const evs = data?.recent_events ?? []
    if (!evs.length) return 0
    return Math.round(evs.reduce((s, e) => s + (e.ai_confidence ?? 0), 0) / evs.length * 100)
  }, [data?.recent_events])

  const hourlyData = useMemo(() => (data?.hourly_chart ?? []).map(h => h.count), [data?.hourly_chart])
  const last7Hours = useMemo(() => hourlyData.slice(-7), [hourlyData])

  const topAttackers = useMemo(() => {
    const counts: Record<string, { count: number; severity: string; lastSeen: string; threatType: string }> = {}
    const rank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 }
    for (const ev of data?.recent_events ?? []) {
      if (!counts[ev.source_ip]) counts[ev.source_ip] = { count: 0, severity: ev.severity, lastSeen: ev.timestamp, threatType: ev.threat_type }
      counts[ev.source_ip].count++
      if ((rank[ev.severity] ?? 0) > (rank[counts[ev.source_ip].severity] ?? 0)) {
        counts[ev.source_ip].severity = ev.severity
        counts[ev.source_ip].threatType = ev.threat_type
      }
      if (ev.timestamp > counts[ev.source_ip].lastSeen) counts[ev.source_ip].lastSeen = ev.timestamp
    }
    return Object.entries(counts).map(([ip, d]) => ({ ip, ...d })).sort((a, b) => b.count - a.count).slice(0, 8)
  }, [data?.recent_events])

  const actionBreakdown = useMemo(() => {
    const actions: Record<string, number> = {}
    for (const ev of data?.recent_events ?? []) {
      actions[ev.action_taken] = (actions[ev.action_taken] || 0) + 1
    }
    const total = Object.values(actions).reduce((s, v) => s + v, 0) || 1
    const ACTION_COLOR: Record<string, string> = {
      block_ip: '#dc2626', isolate_process: '#ef4444', close_port: '#ea580c',
      deploy_honeypot: '#d97706', alert_human: '#7c3aed', monitor: '#22c55e', log: '#3b82f6',
    }
    return Object.entries(actions).sort((a, b) => b[1] - a[1]).map(([action, count]) => ({
      action, count, pct: Math.round(count / total * 100), color: ACTION_COLOR[action] ?? '#444'
    }))
  }, [data?.recent_events])

  useEffect(() => {
    const handler = () => refresh()
    window.addEventListener('argos:refresh', handler)
    return () => window.removeEventListener('argos:refresh', handler)
  }, [refresh])

  if (loading && !data) {
    return <div style={{ padding: 32, color: '#333', letterSpacing: '2px', fontSize: 10, fontWeight: 600 }}>LOADING DATA...</div>
  }

  return (
    <div style={{ padding: '18px 22px', display: 'flex', flexDirection: 'column', gap: 12, background: '#0a0a0a', minHeight: '100%', boxSizing: 'border-box' }}>

      {/* ── Page header ── */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingBottom: 12, borderBottom: '1px solid rgba(255,255,255,0.05)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ width: 2, height: 16, background: '#dc2626', borderRadius: 1 }} />
          <span style={{ color: '#fff', fontSize: 11, letterSpacing: '2.5px', fontWeight: 700, textTransform: 'uppercase' }}>Threat Overview</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 18 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <div style={{ width: 5, height: 5, borderRadius: '50%', background: connected ? '#16a34a' : '#dc2626', animation: connected ? 'pulse-dot 2s infinite' : 'none' }} />
            <span style={{ color: connected ? '#16a34a' : '#dc2626', fontSize: 9, letterSpacing: '1px', fontWeight: 600 }}>{connected ? 'LIVE' : 'OFFLINE'}</span>
          </div>
          <span style={{ color: '#444', fontSize: 11, fontVariantNumeric: 'tabular-nums' }}><Clock /></span>
        </div>
      </div>

      {/* ── KPI strip ── */}
      <div style={{ ...PANEL, display: 'flex', overflow: 'hidden' }}>
        <Kpi label="Incidents Today" value={totalToday}                         accent="#dc2626" sub="LAST 24H"     sparkData={last7Hours} />
        <Kpi label="Critical"        value={criticalCount}                       accent="#dc2626" sub="SEVERITY"    sparkData={last7Hours} />
        <Kpi label="High Severity"   value={highCount}                           accent="#ea580c" sub="SEVERITY" />
        <Kpi label="Blocked IPs"     value={stats?.blocked_ips ?? '—'}           accent="#ea580c" sub="ACTIVE RULES" />
        <Kpi label="Devices Online"  value={`${stats?.devices_online ?? 0} / ${stats?.devices_total ?? 0}`} sub="AGENTS" />
        <Kpi label="Honeypots"       value={stats?.active_honeypots ?? 0}        accent="#7c3aed" sub="DEPLOYED" />
        <Kpi label="Total Events"    value={stats?.total_threats ?? '—'}         sub="ALL TIME" />
        <Kpi label="Avg AI Conf"     value={`${avgConfidence}%`}                 accent="#00d4ff" sub="RESPONSE QUALITY" divider={false} />
      </div>

      {/* ── Map + Live Activity side by side ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 340px', gap: 12, height: 400 }}>

        {/* Map */}
        <div style={{ ...PANEL, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          <PanelHeader title="Global Attack Origin Map" right={`${data?.recent_events?.length ?? 0} origins`} />
          <div style={{ flex: 1 }}>
            <ThreatMap initialEvents={data?.recent_events ?? []} />
          </div>
        </div>

        {/* Live activity */}
        <div style={{ ...PANEL, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          <PanelHeader title="Live Activity" right="30s buckets" />
          <div style={{ flex: 1, padding: '12px 14px 10px', minHeight: 0 }}>
            <LiveActivityChart />
          </div>
        </div>
      </div>

      {/* ── Charts row: 24H area | Threat donut | Gauge ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 260px 260px', gap: 12 }}>

        {/* 24h area chart */}
        <div style={{ ...PANEL, display: 'flex', flexDirection: 'column' }}>
          <PanelHeader title="24h Event Distribution" />
          <div style={{ flex: 1, padding: '12px 14px 8px', minHeight: 160 }}>
            <HourlyChart data={data?.hourly_chart ?? []} />
          </div>
        </div>

        {/* Threat classification donut */}
        <div style={{ ...PANEL }}>
          <PanelHeader title="Threat Classification" />
          <div style={{ padding: '14px 14px 12px' }}>
            <ThreatTypeChart data={data?.threat_types ?? []} />
          </div>
        </div>

        {/* Threat level gauge */}
        <div style={{ ...PANEL, display: 'flex', flexDirection: 'column' }}>
          <PanelHeader title="Threat Level" />
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'flex-start', padding: '14px 16px 12px' }}>
            <ThreatGauge critical={criticalCount} high={highCount} medium={mediumCount} />
          </div>
        </div>
      </div>

      {/* ── Top Attackers + Action Breakdown ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 300px', gap: 12 }}>

        {/* Top Attackers */}
        <div style={{ ...PANEL }}>
          <PanelHeader title="Top Attackers" right={`${topAttackers.length} sources`} />
          {topAttackers.length === 0 ? (
            <div style={{ padding: 20, color: '#333', fontSize: 10, letterSpacing: '2px', textAlign: 'center' }}>NO DATA</div>
          ) : (
            <table style={{ width: '100%', borderCollapse: 'collapse' }}>
              <thead>
                <tr>
                  {['IP ADDRESS', 'HITS', 'SEVERITY', 'LAST TYPE', 'LAST SEEN'].map(h => (
                    <th key={h} style={{ padding: '6px 14px', color: '#555', fontSize: 9, letterSpacing: '1.5px', textTransform: 'uppercase', fontWeight: 600, textAlign: 'left', borderBottom: '1px solid rgba(255,255,255,0.05)', background: '#0d0d0d' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {topAttackers.map((a, i) => (
                  <tr key={a.ip}
                    style={{ transition: 'background 0.08s' }}
                    onMouseEnter={e => (e.currentTarget.style.background = 'rgba(255,255,255,0.025)')}
                    onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                  >
                    <td style={{ padding: '7px 14px', fontSize: 12, borderBottom: '1px solid rgba(255,255,255,0.03)', color: '#00d4ff', fontVariantNumeric: 'tabular-nums', whiteSpace: 'nowrap' }}>
                      <span style={{ color: '#333', fontSize: 9, marginRight: 8, fontVariantNumeric: 'tabular-nums' }}>{i + 1}</span>{a.ip}
                    </td>
                    <td style={{ padding: '7px 14px', fontSize: 13, borderBottom: '1px solid rgba(255,255,255,0.03)', color: '#fff', fontWeight: 700, fontVariantNumeric: 'tabular-nums' }}>{a.count}</td>
                    <td style={{ padding: '7px 14px', fontSize: 9, borderBottom: '1px solid rgba(255,255,255,0.03)', color: SEV_COLOR[a.severity] ?? '#666', letterSpacing: '1px', fontWeight: 600, textTransform: 'uppercase' }}>{a.severity}</td>
                    <td style={{ padding: '7px 14px', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.03)', color: '#666', textTransform: 'uppercase', letterSpacing: '0.5px' }}>{a.threatType.replace(/_/g, ' ')}</td>
                    <td style={{ padding: '7px 14px', fontSize: 10, borderBottom: '1px solid rgba(255,255,255,0.03)', color: '#444', fontVariantNumeric: 'tabular-nums' }}>{new Date(a.lastSeen).toLocaleTimeString('it-IT')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        {/* Action Breakdown */}
        <div style={{ ...PANEL }}>
          <PanelHeader title="Action Breakdown" />
          <div style={{ padding: '14px' }}>
            {actionBreakdown.map(({ action, count, pct, color }) => (
              <div key={action} style={{ marginBottom: 10 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <span style={{ fontSize: 9, color: '#666', textTransform: 'uppercase', letterSpacing: '1px' }}>{action.replace(/_/g, ' ')}</span>
                  <span style={{ fontSize: 10, color: '#888', fontVariantNumeric: 'tabular-nums' }}>{count}</span>
                </div>
                <div style={{ background: 'rgba(255,255,255,0.04)', borderRadius: 2, height: 3, overflow: 'hidden' }}>
                  <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: 2, transition: 'width 0.5s ease' }} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* ── Recent events ── */}
      <div style={{ ...PANEL }}>
        <PanelHeader title="Recent Events" right={`${data?.recent_events?.length ?? 0} shown · click row for details`} />
        <ThreatTable events={data?.recent_events ?? []} maxHeight={260} />
      </div>

    </div>
  )
}
