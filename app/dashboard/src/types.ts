export type Severity = 'critical' | 'high' | 'medium' | 'low'

export interface ThreatEvent {
  id: string
  device_id: string
  timestamp: string
  threat_type: string
  severity: Severity
  source_ip: string
  source_port: number
  target_port: number
  protocol: string
  description: string
  action_taken: string
  ai_analysis: string
  ai_confidence: number
  resolved: boolean
}

export interface Device {
  id: string
  name: string
  platform: 'linux' | 'darwin' | 'windows'
  ip: string
  version: string
  autonomy: 'full' | 'semi' | 'supervised'
  status: 'online' | 'offline'
  last_seen: string
  created_at: string
  threats_total?: number
  threats_today?: number
}

export interface BlockedIP {
  ip: string
  reason: string
  device_id: string | null
  blocked_at: string
  expires_at: string | null
  community: boolean
}

export interface OverviewData {
  stats: {
    total_threats: number
    threats_today: number
    threats_week: number
    blocked_ips: number
    devices_online: number
    devices_total: number
    critical_today: number
    active_honeypots: number
  }
  recent_events: ThreatEvent[]
  threat_types: { type: string; count: number }[]
  hourly_chart: { hour: string; count: number }[]
}
