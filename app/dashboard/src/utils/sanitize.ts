export function escapeHtml(raw: string): string {
  return String(raw)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
}

export function sanitizeIp(ip: string): string {
  return ip.replace(/[^0-9a-fA-F.:]/g, '').slice(0, 45)
}

export function sanitizeQuery(q: string): string {
  return q.replace(/[<>"'&]/g, '').slice(0, 500)
}
