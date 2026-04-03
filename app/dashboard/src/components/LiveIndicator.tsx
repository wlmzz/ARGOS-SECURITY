export function LiveIndicator({ connected }: { connected: boolean }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
      <div style={{
        width: 6, height: 6, borderRadius: '50%',
        background: connected ? '#22c55e' : '#ef4444',
        animation: connected ? 'pulse-dot 2s infinite' : 'none',
        flexShrink: 0,
        boxShadow: connected ? '0 0 6px rgba(39,196,126,0.6)' : '0 0 6px rgba(255,59,59,0.5)',
      }} />
      <span style={{
        fontSize: 9, letterSpacing: '1.5px',
        color: connected ? '#22c55e' : '#ef4444',
        textTransform: 'uppercase', fontWeight: 600,
      }}>
        {connected ? 'CONNECTED' : 'OFFLINE'}
      </span>
    </div>
  )
}
