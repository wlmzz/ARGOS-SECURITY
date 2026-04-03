type Handler = (msg: object) => void

class WSClient {
  private ws: WebSocket | null = null
  private handlers: Handler[] = []
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null
  private pendingMessages: object[] = []
  private flushTimer: ReturnType<typeof setInterval> | null = null
  connected = false

  connect(url: string) {
    try {
      this.ws = new WebSocket(url)
      this.ws.onopen = () => {
        this.connected = true
        if (this.reconnectTimer) clearTimeout(this.reconnectTimer)
        console.log('[WS] Connected')
      }
      this.ws.onmessage = (e) => {
        try {
          const msg = JSON.parse(e.data as string) as Record<string, unknown>
          const isUrgent =
            msg.type === 'new_threat' &&
            (msg.severity === 'critical' || msg.severity === 'high')
          if (isUrgent) {
            this.handlers.forEach(h => h(msg))
          } else {
            this.pendingMessages.push(msg)
          }
        } catch {
          // ignore parse errors
        }
      }
      this.ws.onclose = () => {
        this.connected = false
        if (this.flushTimer !== null) {
          clearInterval(this.flushTimer)
          this.flushTimer = null
        }
        this.reconnectTimer = setTimeout(() => this.connect(url), 5000)
      }
      this.ws.onerror = () => this.ws?.close()

      this.flushTimer = setInterval(() => {
        if (this.pendingMessages.length === 0) return
        const batch = [...this.pendingMessages]
        this.pendingMessages = []
        this.handlers.forEach(h => batch.forEach(msg => h(msg as any)))
      }, 500)
    } catch {
      // ignore connection errors
    }
  }

  isConnected(): boolean {
    return this.connected
  }

  on(handler: Handler) {
    this.handlers.push(handler)
    return () => {
      this.handlers = this.handlers.filter(h => h !== handler)
    }
  }

  send(data: object) {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(data))
    }
  }

  ping() {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send('ping')
    }
  }
}

export const wsClient = new WSClient()
