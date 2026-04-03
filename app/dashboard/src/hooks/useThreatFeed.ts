import { useState, useEffect, useCallback } from 'react'
import { api } from '../api'
import { wsClient } from '../ws'
import type { ThreatEvent, Severity } from '../types'

export function useThreatFeed(severity?: Severity) {
  const [events, setEvents] = useState<ThreatEvent[]>([])
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const params: Record<string, string | number> = { limit: 200 }
      if (severity) params.severity = severity
      const data = await api.events(params)
      setEvents(data)
    } catch {
      // ignore
    }
    setLoading(false)
  }, [severity])

  useEffect(() => {
    load()
    const off = wsClient.on((msg: object) => {
      const m = msg as { type?: string } & ThreatEvent
      if (m.type === 'new_threat') {
        setEvents(prev => {
          const ev = m as ThreatEvent
          if (severity && ev.severity !== severity) return prev
          return [ev, ...prev].slice(0, 200)
        })
      }
    })
    return off
  }, [load, severity])

  return { events, loading, reload: load }
}
