interface StatCardProps {
  label: string
  value: string | number
  sub?: string
  accent?: string
  wide?: boolean
}

export function StatCard({ label, value, sub, accent = '#ffffff', wide }: StatCardProps) {
  // Convert hex to rgb for glow
  const hex = accent.replace('#', '')
  const r = parseInt(hex.substring(0, 2), 16)
  const g = parseInt(hex.substring(2, 4), 16)
  const b = parseInt(hex.substring(4, 6), 16)
  const rgba = (a: number) => `rgba(${r},${g},${b},${a})`

  return (
    <div style={{
      flex: 1,
      minWidth: wide ? 200 : 140,
      minHeight: 100,
      background: `linear-gradient(135deg, #171717 0%, #111111 100%)`,
      border: '1px solid rgba(255,255,255,0.07)',
      borderLeft: `3px solid ${accent}`,
      borderRadius: 8,
      padding: '18px 20px',
      position: 'relative',
      overflow: 'hidden',
      boxShadow: `0 4px 24px rgba(0,0,0,0.6), inset 0 0 60px ${rgba(0.04)}`,
      transition: 'box-shadow 0.2s',
    }}
    onMouseEnter={e => {
      (e.currentTarget as HTMLDivElement).style.boxShadow =
        `0 4px 32px rgba(0,0,0,0.7), 0 0 0 1px ${rgba(0.2)}, inset 0 0 60px ${rgba(0.07)}`
    }}
    onMouseLeave={e => {
      (e.currentTarget as HTMLDivElement).style.boxShadow =
        `0 4px 24px rgba(0,0,0,0.6), inset 0 0 60px ${rgba(0.04)}`
    }}
    >
      {/* Background glow circle decoration */}
      <div style={{
        position: 'absolute',
        bottom: -30, right: -20,
        width: 100, height: 100,
        borderRadius: '50%',
        background: `radial-gradient(circle, ${rgba(0.12)} 0%, transparent 70%)`,
        pointerEvents: 'none',
      }} />

      {/* Label */}
      <div style={{
        color: '#555',
        fontSize: 9,
        letterSpacing: '2px',
        textTransform: 'uppercase',
        fontWeight: 700,
        marginBottom: 14,
      }}>
        {label}
      </div>

      {/* Value */}
      <div style={{
        fontSize: 36,
        fontWeight: 800,
        lineHeight: 1,
        color: '#fff',
        letterSpacing: '-1px',
        fontVariantNumeric: 'tabular-nums',
      }}>
        {value}
      </div>

      {/* Accent dot + sub */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 10 }}>
        <div style={{
          width: 5, height: 5, borderRadius: '50%',
          background: accent, flexShrink: 0,
          boxShadow: `0 0 6px ${rgba(0.8)}`,
        }} />
        <span style={{ color: '#444', fontSize: 9, letterSpacing: '1px', fontWeight: 600 }}>
          {sub ?? 'LIVE'}
        </span>
      </div>
    </div>
  )
}
