import { useEffect, useState } from 'react'

export interface Toast {
  id: number
  message: string
  severity: 'critical' | 'high'
}

const SEV_COLOR: Record<string, string> = {
  critical: '#dc2626',
  high: '#ea580c',
}

function ToastItem({ toast, onDismiss }: { toast: Toast; onDismiss: (id: number) => void }) {
  const [progress, setProgress] = useState(100)
  const color = SEV_COLOR[toast.severity] ?? '#dc2626'

  useEffect(() => {
    const start = Date.now()
    const duration = 5000
    const raf = setInterval(() => {
      const elapsed = Date.now() - start
      setProgress(Math.max(0, 100 - (elapsed / duration) * 100))
      if (elapsed >= duration) onDismiss(toast.id)
    }, 50)
    return () => clearInterval(raf)
  }, [toast.id, onDismiss])

  return (
    <div style={{
      background: '#0f0a0a',
      border: `1px solid ${color}33`,
      borderLeft: `3px solid ${color}`,
      borderRadius: 4,
      padding: '10px 14px',
      minWidth: 280, maxWidth: 380,
      position: 'relative',
      overflow: 'hidden',
      animation: 'fadeSlide 0.2s ease',
      cursor: 'pointer',
    }} onClick={() => onDismiss(toast.id)}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
        <div style={{ width: 6, height: 6, borderRadius: '50%', background: color, flexShrink: 0 }} />
        <span style={{ fontSize: 9, color: color, letterSpacing: '2px', fontWeight: 700, textTransform: 'uppercase' }}>
          {toast.severity}
        </span>
      </div>
      <div style={{ fontSize: 11, color: '#ccc', lineHeight: 1.4 }}>{toast.message}</div>
      {/* Progress bar */}
      <div style={{
        position: 'absolute', bottom: 0, left: 0,
        height: 2, background: color,
        width: `${progress}%`,
        transition: 'width 0.05s linear',
        opacity: 0.6,
      }} />
    </div>
  )
}

export function ToastContainer({ toasts, onDismiss }: { toasts: Toast[]; onDismiss: (id: number) => void }) {
  return (
    <div style={{
      position: 'fixed', top: 16, right: 16,
      zIndex: 99999,
      display: 'flex', flexDirection: 'column', gap: 8,
      pointerEvents: toasts.length ? 'all' : 'none',
    }}>
      {toasts.map(t => <ToastItem key={t.id} toast={t} onDismiss={onDismiss} />)}
    </div>
  )
}
