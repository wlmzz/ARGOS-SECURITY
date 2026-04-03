import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts'

interface HourlyChartProps {
  data: { hour: string; count: number }[]
}

const CustomTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null
  return (
    <div style={{
      background: '#161616', border: '1px solid rgba(255,255,255,0.08)',
      borderRadius: 4, padding: '6px 10px', fontSize: 11,
    }}>
      <div style={{ color: '#555', marginBottom: 2, fontSize: 10 }}>{label}:00</div>
      <div style={{ color: '#fff', fontWeight: 700 }}>{payload[0].value} <span style={{ color: '#444', fontWeight: 400 }}>events</span></div>
    </div>
  )
}

export function HourlyChart({ data }: HourlyChartProps) {
  return (
    <ResponsiveContainer width="100%" height="100%">
      <AreaChart data={data} margin={{ top: 6, right: 4, left: -28, bottom: 0 }}>
        <defs>
          <linearGradient id="hourGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%"   stopColor="#ef4444" stopOpacity={0.25} />
            <stop offset="100%" stopColor="#ef4444" stopOpacity={0.01} />
          </linearGradient>
        </defs>
        <CartesianGrid vertical={false} stroke="rgba(255,255,255,0.03)" />
        <XAxis
          dataKey="hour"
          tick={{ fill: '#444', fontSize: 9, fontFamily: 'inherit' }}
          axisLine={false} tickLine={false} interval={3}
        />
        <YAxis
          tick={{ fill: '#444', fontSize: 9, fontFamily: 'inherit' }}
          axisLine={false} tickLine={false}
        />
        <Tooltip content={<CustomTooltip />} cursor={{ stroke: 'rgba(255,255,255,0.06)', strokeWidth: 1 }} />
        <Area
          type="monotone"
          dataKey="count"
          stroke="#ef4444"
          strokeWidth={1.5}
          fill="url(#hourGrad)"
          dot={false}
          activeDot={{ r: 3, fill: '#ef4444', strokeWidth: 0 }}
          isAnimationActive={true}
          animationDuration={800}
          animationEasing="ease-out"
        />
      </AreaChart>
    </ResponsiveContainer>
  )
}
