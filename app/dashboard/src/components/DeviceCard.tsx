import type { Device } from '../types'

export function DeviceCard({ device }: { device: Device }) {
  const isOnline = device.status === 'online'
  const icon =
    device.platform === 'linux'
      ? '🐧'
      : device.platform === 'darwin'
      ? '🍎'
      : '🪟'

  return (
    <div style={{
      background: '#0d1117',
      border: `1px solid ${isOnline ? '#3fb95033' : '#21262d'}`,
      borderRadius: 8,
      padding: '16px 20px',
      display: 'flex',
      alignItems: 'center',
      gap: 16
    }}>
      <span style={{ fontSize: 28 }}>{icon}</span>
      <div style={{ flex: 1 }}>
        <div style={{ color: '#e6edf3', fontWeight: 600 }}>{device.name}</div>
        <div style={{ color: '#8b949e', fontSize: 12, fontFamily: 'monospace' }}>
          {device.ip} · {device.autonomy} · v{device.version}
        </div>
      </div>
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: 6,
        color: isOnline ? '#3fb950' : '#8b949e'
      }}>
        <span style={{
          width: 8,
          height: 8,
          borderRadius: '50%',
          background: isOnline ? '#3fb950' : '#8b949e',
          display: 'inline-block',
          boxShadow: isOnline ? '0 0 6px #3fb950' : 'none'
        }} />
        {isOnline ? 'Online' : 'Offline'}
      </div>
      {device.threats_today !== undefined && (
        <div style={{
          color: device.threats_today > 0 ? '#ff8800' : '#3fb950',
          fontFamily: 'monospace',
          fontSize: 14
        }}>
          {device.threats_today} today
        </div>
      )}
    </div>
  )
}
