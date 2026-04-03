import { useState, useEffect } from 'react'
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import { wsClient } from '../ws'

interface Bucket { label: string; critical: number; high: number; other: number }

function makeBuckets(n = 20): Bucket[] {
  return Array.from({ length: n }, (_, i) => {
    const d = new Date(Date.now() - (n - 1 - i) * 30000)
    return {
      label: d.toLocaleTimeString('it-IT', { hour: '2-digit', minute: '2-digit', second: '2-digit', timeZone: 'Europe/Rome' }),
      critical: 0, high: 0, other: 0,
    }
  })
}

const CustomTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null
  return (
    <div style={{ background: '#161616', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 4, padding: '6px 10px', fontSize: 11 }}>
      <div style={{ color: '#555', marginBottom: 4, fontSize: 10 }}>{label}</div>
      {payload.map((p: any) => (
        <div key={p.name} style={{ color: p.color, fontWeight: 600 }}>
          {p.name}: {p.value}
        </div>
      ))}
    </div>
  )
}

export function LiveActivityChart() {
  const [buckets, setBuckets] = useState<Bucket[]>(makeBuckets)
  const [total, setTotal] = useState(0)

  // Roll window every 30s
  useEffect(() => {
    const t = setInterval(() => {
      const label = new Date().toLocaleTimeString('it-IT', { hour: '2-digit', minute: '2-digit', second: '2-digit', timeZone: 'Europe/Rome' })
      setBuckets(prev => [...prev.slice(1), { label, critical: 0, high: 0, other: 0 }])
    }, 30000)
    return () => clearInterval(t)
  }, [])

  // WebSocket listener
  useEffect(() => {
    return wsClient.on((msg: any) => {
      if (msg.type !== 'new_threat') return
      setTotal(n => n + 1)
      setBuckets(prev => {
        const copy = [...prev]
        const last = { ...copy[copy.length - 1] }
        const sev = msg.severity?.toLowerCase()
        if (sev === 'critical') last.critical++
        else if (sev === 'high') last.high++
        else last.other++
        copy[copy.length - 1] = last
        return copy
      })
    })
  }, [])

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 8, paddingBottom: 8, borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
        <div>
          <div style={{ fontSize: 9, color: '#555', letterSpacing: '1.5px', fontWeight: 600 }}>SESSION EVENTS</div>
          <div style={{ fontSize: 22, fontWeight: 700, color: '#fff', fontVariantNumeric: 'tabular-nums', lineHeight: 1.2 }}>{total}</div>
        </div>
        <div style={{ display: 'flex', gap: 12, marginLeft: 'auto', alignItems: 'center' }}>
          {[['CRITICAL', '#dc2626'], ['HIGH', '#ea580c'], ['OTHER', '#4a5568']].map(([l, c]) => (
            <div key={l} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <div style={{ width: 6, height: 6, borderRadius: 1, background: c as string }} />
              <span style={{ color: '#555', fontSize: 9, letterSpacing: '1px' }}>{l}</span>
            </div>
          ))}
        </div>
      </div>

      <div style={{ flex: 1, minHeight: 0 }}>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={buckets} margin={{ top: 4, right: 4, left: -28, bottom: 0 }}>
            <defs>
              <linearGradient id="gCrit" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#dc2626" stopOpacity={0.4} />
                <stop offset="100%" stopColor="#dc2626" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="gHigh" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#ea580c" stopOpacity={0.3} />
                <stop offset="100%" stopColor="#ea580c" stopOpacity={0} />
              </linearGradient>
              <linearGradient id="gOther" x1="0" y1="0" x2="0" y2="1">
                <stop offset="0%" stopColor="#4a5568" stopOpacity={0.3} />
                <stop offset="100%" stopColor="#4a5568" stopOpacity={0} />
              </linearGradient>
            </defs>
            <XAxis dataKey="label" tick={{ fill: '#333', fontSize: 8, fontFamily: 'inherit' }} axisLine={false} tickLine={false} interval={4} />
            <YAxis tick={{ fill: '#333', fontSize: 8, fontFamily: 'inherit' }} axisLine={false} tickLine={false} allowDecimals={false} />
            <Tooltip content={<CustomTooltip />} cursor={{ stroke: 'rgba(255,255,255,0.05)', strokeWidth: 1 }} />
            <Area type="monotone" dataKey="other"    stackId="1" stroke="#4a5568" strokeWidth={1} fill="url(#gOther)" dot={false} isAnimationActive={false} />
            <Area type="monotone" dataKey="high"     stackId="1" stroke="#ea580c" strokeWidth={1} fill="url(#gHigh)"  dot={false} isAnimationActive={false} />
            <Area type="monotone" dataKey="critical" stackId="1" stroke="#dc2626" strokeWidth={1.5} fill="url(#gCrit)" dot={false} isAnimationActive={false} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}
