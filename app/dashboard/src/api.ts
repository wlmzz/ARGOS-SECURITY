const BASE = import.meta.env.VITE_API_BASE ?? ''

const EIGHT_HOURS = 8 * 60 * 60 * 1000

function loadToken(): string | null {
  const ts = sessionStorage.getItem('argos_token_ts')
  if (ts && Date.now() - Number(ts) > EIGHT_HOURS) {
    sessionStorage.removeItem('argos_token')
    sessionStorage.removeItem('argos_token_ts')
    return null
  }
  return sessionStorage.getItem('argos_token')
}

let _token: string | null = loadToken()

export function setToken(t: string) {
  _token = t
  sessionStorage.setItem('argos_token', t)
  sessionStorage.setItem('argos_token_ts', String(Date.now()))
}

export function getToken() { return _token }

const _cache = new Map<string, { data: unknown; ts: number }>()
const CACHE_TTL: Record<string, number> = {
  '/api/devices': 30_000,
  '/api/intelligence/blocked': 20_000,
}

export function invalidateCache(path?: string) {
  if (path) _cache.delete(path)
  else _cache.clear()
}

async function req<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const method = (opts.method ?? 'GET').toUpperCase()

  if (method === 'GET' && CACHE_TTL[path] !== undefined) {
    const cached = _cache.get(path)
    if (cached && Date.now() - cached.ts < CACHE_TTL[path]) {
      return cached.data as T
    }
  }

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...((opts.headers as Record<string, string>) ?? {})
  }
  if (_token) headers['Authorization'] = `Bearer ${_token}`
  const r = await fetch(BASE + path, { ...opts, headers })
  if (!r.ok) throw new Error(`${r.status} ${r.statusText}`)
  const data = await r.json() as T

  if (method === 'GET' && CACHE_TTL[path] !== undefined) {
    _cache.set(path, { data, ts: Date.now() })
  }

  return data
}

export const api = {
  overview: () => req<import('./types').OverviewData>('/api/dashboard/overview'),
  events: (params?: Record<string, string | number>) => {
    const qs = params
      ? '?' + new URLSearchParams(params as Record<string, string>).toString()
      : ''
    return req<import('./types').ThreatEvent[]>(`/api/events${qs}`)
  },
  devices: () => req<import('./types').Device[]>('/api/devices'),
  blockedIps: () => req<import('./types').BlockedIP[]>('/api/intelligence/blocked'),
  unblockIp: (ip: string) =>
    req<unknown>(`/api/intelligence/blocked/${encodeURIComponent(ip)}`, { method: 'DELETE' }),
  lookupIp: (ip: string) => req<unknown>(`/api/intelligence/lookup/${ip}`),
  decide: (eventId: string, action: string, reasoning: string) =>
    req<unknown>(`/api/events/${eventId}/decide`, {
      method: 'POST',
      body: JSON.stringify({ action, reasoning, source: 'human' }),
    }),
  aiChat: (message: string, history: { role: string; content: string }[], context?: string) =>
    req<{ reply: string; model: string }>('/api/ai/chat', {
      method: 'POST',
      body: JSON.stringify({ message, history, context }),
    }),
}
