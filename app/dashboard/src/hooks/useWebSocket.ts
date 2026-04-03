import { useState, useEffect } from 'react'
import { wsClient } from '../ws'

export function useWebSocket(enabled = true) {
  const [connected, setConnected] = useState(wsClient.connected)

  useEffect(() => {
    if (!enabled) return
    const clientId = `dashboard-${Date.now()}`
    const wsUrl = `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws/${clientId}`
    wsClient.connect(wsUrl)

    const interval = setInterval(() => {
      setConnected(wsClient.connected)
      if (wsClient.connected) wsClient.ping()
    }, 1000)

    return () => clearInterval(interval)
  }, [enabled])

  return { connected }
}
