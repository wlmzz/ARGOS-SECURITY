const COLORS: Record<string, { bg: string; text: string; border: string }> = {
  critical: { bg: '#ff3b3b14', text: '#ff3b3b', border: '#ff3b3b44' },
  high:     { bg: '#ff770014', text: '#ff7700', border: '#ff770044' },
  medium:   { bg: '#f5a62314', text: '#f5a623', border: '#f5a62344' },
  low:      { bg: '#27c47e14', text: '#27c47e', border: '#27c47e44' },
}

export function SeverityBadge({ severity }: { severity: string }) {
  const c = COLORS[severity] ?? { bg: '#1c2a3a', text: '#6a8099', border: '#1c2a3a' }
  return (
    <span style={{
      display: 'inline-block',
      background: c.bg, color: c.text,
      border: `1px solid ${c.border}`,
      padding: '1px 7px', fontSize: 9,
      letterSpacing: '1px', fontWeight: 700,
      textTransform: 'uppercase',
      whiteSpace: 'nowrap',
      borderRadius: 3,
    }}>
      {severity}
    </span>
  )
}
