import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts'

interface ThreatTypeChartProps {
  data: { type: string; count: number }[]
}

const COLORS = ['#dc2626', '#ea580c', '#d97706', '#16a34a', '#2563eb', '#7c3aed', '#64748b', '#374151']

const CustomTooltip = ({ active, payload }: any) => {
  if (!active || !payload?.length) return null
  const d = payload[0]
  return (
    <div style={{
      background: '#161616', border: '1px solid rgba(255,255,255,0.08)',
      borderRadius: 4, padding: '6px 10px', fontSize: 11,
    }}>
      <div style={{ color: d.payload.fill, fontWeight: 700, marginBottom: 2, textTransform: 'uppercase', letterSpacing: '0.5px' }}>
        {d.name.replace(/_/g, ' ')}
      </div>
      <div style={{ color: '#ccc' }}>{d.value} <span style={{ color: '#555' }}>events</span></div>
    </div>
  )
}

export function ThreatTypeChart({ data }: ThreatTypeChartProps) {
  const sorted = [...data].sort((a, b) => b.count - a.count).slice(0, 8)
  const total = sorted.reduce((s, d) => s + d.count, 0)

  if (total === 0) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 180, color: '#333', fontSize: 11, letterSpacing: '1.5px' }}>
        NO DATA
      </div>
    )
  }

  const chartData = sorted.map((d, i) => ({ name: d.type, value: d.count, fill: COLORS[i] ?? '#374151' }))

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Donut */}
      <div style={{ position: 'relative', height: 180 }}>
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={chartData}
              cx="50%" cy="50%"
              innerRadius={52} outerRadius={76}
              startAngle={90} endAngle={-270}
              paddingAngle={2}
              dataKey="value"
              animationBegin={0}
              animationDuration={700}
              animationEasing="ease-out"
            >
              {chartData.map((d, i) => <Cell key={i} fill={d.fill} stroke="transparent" />)}
            </Pie>
            <Tooltip content={<CustomTooltip />} />
          </PieChart>
        </ResponsiveContainer>
        {/* Center label */}
        <div style={{
          position: 'absolute', inset: 0,
          display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
          pointerEvents: 'none',
        }}>
          <div style={{ fontSize: 22, fontWeight: 700, color: '#fff', fontVariantNumeric: 'tabular-nums', lineHeight: 1 }}>{total}</div>
          <div style={{ fontSize: 8, color: '#555', letterSpacing: '1.5px', marginTop: 3 }}>TOTAL</div>
        </div>
      </div>

      {/* Legend */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
        {chartData.slice(0, 5).map((d, i) => {
          const pct = Math.round((d.value / total) * 100)
          return (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{ width: 6, height: 6, borderRadius: 1, background: d.fill, flexShrink: 0 }} />
              <span style={{ color: '#666', fontSize: 9, textTransform: 'uppercase', letterSpacing: '0.5px', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {d.name.replace(/_/g, ' ')}
              </span>
              <span style={{ color: '#888', fontSize: 10, fontVariantNumeric: 'tabular-nums', fontWeight: 600 }}>{d.value}</span>
              <span style={{ color: '#3a3a3a', fontSize: 9 }}>{pct}%</span>
            </div>
          )
        })}
      </div>
    </div>
  )
}
