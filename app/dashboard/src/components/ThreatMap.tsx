import { useEffect, useRef, useState, useCallback } from 'react'
import L from 'leaflet'
import 'leaflet/dist/leaflet.css'
import { wsClient } from '../ws'
import { api } from '../api'
import type { ThreatEvent } from '../types'
import { escapeHtml } from '../utils/sanitize'

const SERVER_LAT = 41.9028
const SERVER_LNG = 12.4964

const SEVERITY_COLOR: Record<string, string> = {
  critical: '#ff3b3b',
  high:     '#ff7700',
  medium:   '#f5a623',
  low:      '#27c47e',
}

function isPublicIp(ip: string): boolean {
  return !/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|0\.0\.0\.0|::1|localhost)/.test(ip)
}

interface GeoPoint {
  ip: string; lat: number; lng: number
  city: string; country: string
  severity: string; threat_type: string; timestamp: string
}

const geoCache = new Map<string, { lat: number; lng: number; city: string; country: string } | null>()

async function geoLookup(ip: string) {
  if (geoCache.has(ip)) return geoCache.get(ip)!
  try {
    const r = await api.lookupIp(ip) as any
    if (r?.lat && r?.lon) {
      const result = { lat: r.lat, lng: r.lon, city: r.city || '', country: r.country || '' }
      geoCache.set(ip, result)
      return result
    }
  } catch {}
  geoCache.set(ip, null)
  return null
}

// ── 2D map — vanilla Leaflet via ref ─────────────────────────────────────────

function Map2D({ points }: { points: GeoPoint[] }) {
  const divRef = useRef<HTMLDivElement>(null)
  const mapRef = useRef<L.Map | null>(null)
  const layersRef = useRef<L.Layer[]>([])

  // Init map once
  useEffect(() => {
    if (!divRef.current) return
    const map = L.map(divRef.current, {
      center: [20, 10],
      zoom: 2,
      minZoom: 1,
      maxZoom: 8,
      zoomControl: false,
      attributionControl: false,
    })
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
      subdomains: 'abcd',
      maxZoom: 19,
    }).addTo(map)

    // Server pin — pulsing DivIcon
    L.marker([SERVER_LAT, SERVER_LNG], {
      icon: L.divIcon({
        className: '',
        html: `<div style="position:relative;width:12px;height:12px">
          <div style="position:absolute;inset:0;border-radius:50%;background:#00d4ff;z-index:1"></div>
          <div style="position:absolute;inset:-6px;border-radius:50%;border:1.5px solid #00d4ff;animation:map-pulse-ring 2s ease-out infinite"></div>
        </div>`,
        iconSize: [12, 12],
        iconAnchor: [6, 6],
      }),
    }).bindPopup(`<div style="font-family:monospace;font-size:11px;color:#00d4ff;font-weight:700">SERVER — ARGOS Central</div>`).addTo(map)

    mapRef.current = map
    requestAnimationFrame(() => { requestAnimationFrame(() => { map.invalidateSize() }) })
    return () => { map.remove(); mapRef.current = null }
  }, [])

  // Sync markers + attack lines when points change
  useEffect(() => {
    const map = mapRef.current
    if (!map) return
    layersRef.current.forEach(l => l.remove())
    layersRef.current = []

    points.forEach(p => {
      const col = SEVERITY_COLOR[p.severity] || '#6a8099'
      const popup = `
        <div style="font-family:monospace;font-size:11px;min-width:150px">
          <div style="color:${col};font-weight:700;margin-bottom:4px">${escapeHtml(p.severity).toUpperCase()}</div>
          <div style="color:#00d4ff">${escapeHtml(p.ip)}</div>
          <div style="color:#6a8099;margin-top:2px">${escapeHtml(p.city)}${p.city && p.country ? ', ' : ''}${escapeHtml(p.country)}</div>
          <div style="color:#c8d8ea;margin-top:4px;text-transform:uppercase;letter-spacing:.5px">${escapeHtml(p.threat_type).replace(/_/g, ' ')}</div>
        </div>`

      // Animated attack line
      const line = L.polyline([[p.lat, p.lng], [SERVER_LAT, SERVER_LNG]], {
        color: col,
        weight: 1,
        opacity: 0.45,
        className: 'attack-dash-line',
      }).addTo(map)
      layersRef.current.push(line)

      // Pulsing DivIcon marker
      const marker = L.marker([p.lat, p.lng], {
        icon: L.divIcon({
          className: '',
          html: `<div style="position:relative;width:8px;height:8px">
            <div style="position:absolute;inset:0;border-radius:50%;background:${col}"></div>
            <div style="position:absolute;inset:-5px;border-radius:50%;border:1px solid ${col};opacity:0.6;animation:map-pulse-ring 2s ease-out infinite;animation-delay:${Math.random() * 1}s"></div>
          </div>`,
          iconSize: [8, 8],
          iconAnchor: [4, 4],
        }),
      }).bindPopup(popup).addTo(map)
      layersRef.current.push(marker)
    })
  }, [points])

  return (
    <div
      ref={divRef}
      style={{ width: '100%', height: '100%', background: '#0a0a0a' }}
    />
  )
}

// ── 3D Globe ──────────────────────────────────────────────────────────────────

function Map3D({ points }: { points: GeoPoint[] }) {
  const globeRef = useRef<any>(null)
  const containerRef = useRef<HTMLDivElement>(null)
  const [Globe, setGlobe] = useState<any>(null)
  const [dims, setDims] = useState({ w: 600, h: 400 })

  useEffect(() => {
    import('react-globe.gl').then(m => setGlobe(() => m.default))
  }, [])

  useEffect(() => {
    if (!containerRef.current) return
    const ro = new ResizeObserver(e => {
      setDims({ w: e[0].contentRect.width, h: e[0].contentRect.height })
    })
    ro.observe(containerRef.current)
    return () => ro.disconnect()
  }, [])

  useEffect(() => {
    if (!globeRef.current) return
    globeRef.current.controls().autoRotate = true
    globeRef.current.controls().autoRotateSpeed = 0.4
    globeRef.current.controls().enableZoom = true
    globeRef.current.pointOfView({ lat: 20, lng: 10, altitude: 2.2 }, 0)
  }, [Globe])

  const arcs = points.map(p => ({
    startLat: p.lat, startLng: p.lng,
    endLat: SERVER_LAT, endLng: SERVER_LNG,
    color: [SEVERITY_COLOR[p.severity] || '#ff7700', '#00d4ff'],
  }))

  const rings = points.map(p => ({
    lat: p.lat, lng: p.lng,
    maxR: 3, propagationSpeed: 2.5, repeatPeriod: 1000,
    color: SEVERITY_COLOR[p.severity] || '#ff7700',
  }))

  return (
    <div ref={containerRef} style={{ width: '100%', height: '100%', background: '#0a0a0a' }}>
      {Globe && (
        <Globe
          ref={globeRef}
          width={dims.w} height={dims.h}
          backgroundColor="#0a0a0a"
          globeImageUrl="https://unpkg.com/three-globe/example/img/earth-night.jpg"
          bumpImageUrl="https://unpkg.com/three-globe/example/img/earth-topology.png"
          atmosphereColor="#ffffff"
          atmosphereAltitude={0.12}
          arcsData={arcs}
          arcColor="color"
          arcAltitude={0.3}
          arcStroke={0.4}
          arcDashLength={0.4}
          arcDashGap={0.15}
          arcDashAnimateTime={1200}
          ringsData={rings}
          ringColor="color"
          ringMaxRadius="maxR"
          ringPropagationSpeed="propagationSpeed"
          ringRepeatPeriod="repeatPeriod"
          pointsData={[{ lat: SERVER_LAT, lng: SERVER_LNG, size: 0.5, color: '#00d4ff' }]}
          pointColor="color"
          pointAltitude={0.01}
          pointRadius="size"
          pointsMerge={false}
        />
      )}
    </div>
  )
}

// ── Main ──────────────────────────────────────────────────────────────────────

export function ThreatMap({ initialEvents = [] }: { initialEvents?: ThreatEvent[] }) {
  const [mode, setMode] = useState<'2d' | '3d'>('3d')
  const [points, setPoints] = useState<GeoPoint[]>([])

  const addPoint = useCallback(async (
    ip: string, severity: string, threat_type: string, timestamp: string
  ) => {
    if (!isPublicIp(ip)) return
    const geo = await geoLookup(ip)
    if (!geo) return
    setPoints(prev => {
      if (prev.find(p => p.ip === ip && p.threat_type === threat_type)) return prev
      return [{ ip, ...geo, severity, threat_type, timestamp }, ...prev].slice(0, 80)
    })
  }, [])

  useEffect(() => {
    initialEvents.forEach(e => addPoint(e.source_ip, e.severity, e.threat_type, e.timestamp))
  }, [])

  useEffect(() => {
    return wsClient.on((msg: any) => {
      if (msg.type !== 'new_threat') return
      addPoint(msg.source_ip, msg.severity, msg.threat_type, msg.timestamp)
    })
  }, [addPoint])

  return (
    <div style={{ position: 'relative', width: '100%', height: '100%', background: '#080c12', overflow: 'hidden' }}>
      {mode === '2d' ? <Map2D points={points} /> : <Map3D points={points} />}

      {/* Toggle 2D / 3D */}
      <div style={{ position: 'absolute', top: 10, right: 10, zIndex: 1000, display: 'flex', gap: 2 }}>
        {(['2d', '3d'] as const).map(m => (
          <button key={m} onClick={() => setMode(m)} style={{
            background: mode === m ? '#0d3f54' : '#0c1219ee',
            border: `1px solid ${mode === m ? '#00d4ff66' : '#1c2a3a'}`,
            color: mode === m ? '#00d4ff' : '#6a8099',
            padding: '4px 10px', fontSize: 10, letterSpacing: '1px',
            textTransform: 'uppercase', cursor: 'pointer', fontFamily: 'inherit',
          }}>
            {m}
          </button>
        ))}
      </div>

      {/* Legend */}
      <div style={{
        position: 'absolute', bottom: 10, left: 10, zIndex: 1000,
        background: '#0c1219ee', border: '1px solid #1c2a3a',
        padding: '7px 12px', display: 'flex', gap: 12, alignItems: 'center',
      }}>
        {Object.entries(SEVERITY_COLOR).map(([sev, col]) => (
          <div key={sev} style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
            <div style={{ width: 7, height: 7, borderRadius: '50%', background: col }} />
            <span style={{ color: '#6a8099', fontSize: 9, letterSpacing: '1px', textTransform: 'uppercase' }}>{sev}</span>
          </div>
        ))}
        <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
          <div style={{ width: 7, height: 7, borderRadius: '50%', background: '#00d4ff' }} />
          <span style={{ color: '#6a8099', fontSize: 9, letterSpacing: '1px', textTransform: 'uppercase' }}>server</span>
        </div>
      </div>

      {points.length > 0 && (
        <div style={{
          position: 'absolute', top: 10, left: 10, zIndex: 1000,
          background: '#0c1219ee', border: '1px solid #1c2a3a',
          padding: '4px 10px', color: '#6a8099', fontSize: 10, letterSpacing: '1px',
        }}>
          {points.length} ORIGINS MAPPED
        </div>
      )}
    </div>
  )
}
