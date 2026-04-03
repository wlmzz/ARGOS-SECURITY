import { useEffect, useState } from 'react'

interface ThreatGaugeProps {
  critical: number
  high: number
  medium: number
}

const CX = 100, CY = 95, R = 72
const TOTAL_DEG = 220  // arc span
const START_DEG = 200  // starting angle (lower-left)

function toRad(deg: number) { return deg * Math.PI / 180 }

function arcPoint(deg: number) {
  return {
    x: CX + R * Math.cos(toRad(deg)),
    y: CY + R * Math.sin(toRad(deg)),
  }
}

function arcPath(startDeg: number, endDeg: number, r = R) {
  const s = { x: CX + r * Math.cos(toRad(startDeg)), y: CY + r * Math.sin(toRad(startDeg)) }
  const e = { x: CX + r * Math.cos(toRad(endDeg)), y: CY + r * Math.sin(toRad(endDeg)) }
  const span = Math.abs(endDeg - startDeg)
  const large = span > 180 ? 1 : 0
  // sweep: going from startDeg to endDeg clockwise (increasing angle)
  return `M ${s.x.toFixed(2)} ${s.y.toFixed(2)} A ${r} ${r} 0 ${large} 1 ${e.x.toFixed(2)} ${e.y.toFixed(2)}`
}

// Total arc circumference (arc length = R * radians)
const ARC_LEN = R * (TOTAL_DEG * Math.PI / 180)

const LEVELS = [
  { max: 25,  label: 'NORMAL',   color: '#16a34a' },
  { max: 50,  label: 'ELEVATED', color: '#d97706' },
  { max: 75,  label: 'HIGH',     color: '#ea580c' },
  { max: 100, label: 'CRITICAL', color: '#dc2626' },
]

// Tick positions (0, 25, 50, 75, 100)
const TICKS = [0, 25, 50, 75, 100]

export function ThreatGauge({ critical, high, medium }: ThreatGaugeProps) {
  const rawScore = Math.min(100, critical * 6 + high * 2.5 + medium * 0.5)
  const value = Math.round(Math.min(100, rawScore))

  const [displayed, setDisplayed] = useState(0)
  useEffect(() => {
    const t = setTimeout(() => setDisplayed(value), 100)
    return () => clearTimeout(t)
  }, [value])

  const level = LEVELS.find(l => displayed <= l.max) ?? LEVELS[3]

  // Background arc: full span
  const bgPath = arcPath(START_DEG, START_DEG + TOTAL_DEG)

  // Fill arc using stroke-dashoffset
  const fillEnd = START_DEG + TOTAL_DEG
  const fillPath = arcPath(START_DEG, fillEnd)
  const dashOffset = ARC_LEN * (1 - displayed / 100)

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', width: '100%' }}>
      <svg viewBox="0 0 200 172" style={{ width: '100%', maxWidth: 220, display: 'block' }}>

        {/* Background track */}
        <path
          d={bgPath}
          fill="none"
          stroke="rgba(255,255,255,0.05)"
          strokeWidth={10}
          strokeLinecap="round"
        />

        {/* Colored segment ticks */}
        {TICKS.map(t => {
          const deg = START_DEG + (TOTAL_DEG * t / 100)
          const inner = arcPoint(deg)
          const outerP = { x: CX + (R + 12) * Math.cos(toRad(deg)), y: CY + (R + 12) * Math.sin(toRad(deg)) }
          return (
            <line key={t}
              x1={inner.x.toFixed(2)} y1={inner.y.toFixed(2)}
              x2={outerP.x.toFixed(2)} y2={outerP.y.toFixed(2)}
              stroke="rgba(255,255,255,0.15)" strokeWidth={1}
            />
          )
        })}

        {/* Animated fill using dashoffset — same path as background */}
        <path
          d={fillPath}
          fill="none"
          stroke={level.color}
          strokeWidth={10}
          strokeLinecap="round"
          strokeDasharray={`${ARC_LEN} ${ARC_LEN}`}
          strokeDashoffset={dashOffset}
          style={{ transition: 'stroke-dashoffset 1.2s cubic-bezier(0.4,0,0.2,1), stroke 0.5s ease' }}
        />

        {/* Needle dot at tip */}
        {displayed > 0 && (() => {
          const tipDeg = START_DEG + (TOTAL_DEG * displayed / 100)
          const tip = arcPoint(tipDeg)
          return (
            <circle cx={tip.x.toFixed(2)} cy={tip.y.toFixed(2)} r="5"
              fill={level.color}
              style={{ filter: `drop-shadow(0 0 4px ${level.color})`, transition: 'all 1.2s cubic-bezier(0.4,0,0.2,1)' }}
            />
          )
        })()}

        {/* Center: value */}
        <text x={CX} y={CY - 4} textAnchor="middle" fill="#fff"
          fontSize={28} fontWeight={700} fontFamily="inherit" style={{ fontVariantNumeric: 'tabular-nums' }}>
          {displayed}
        </text>
        <text x={CX} y={CY + 13} textAnchor="middle" fill={level.color}
          fontSize={8} fontWeight={700} fontFamily="inherit" letterSpacing={2}>
          {level.label}
        </text>

        {/* Min/Max labels */}
        {(() => {
          const minP = arcPoint(START_DEG)
          const maxP = arcPoint(START_DEG + TOTAL_DEG)
          return <>
            <text x={(minP.x - 8).toFixed(1)} y={(minP.y + 4).toFixed(1)} fill="#333" fontSize={8} fontFamily="inherit" textAnchor="middle">0</text>
            <text x={(maxP.x + 8).toFixed(1)} y={(maxP.y + 4).toFixed(1)} fill="#333" fontSize={8} fontFamily="inherit" textAnchor="middle">100</text>
          </>
        })()}
      </svg>

      {/* Legend row */}
      <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
        {LEVELS.map(l => (
          <div key={l.label} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <div style={{ width: 5, height: 5, borderRadius: '50%', background: l.color }} />
            <span style={{ color: '#444', fontSize: 8, letterSpacing: '1px' }}>{l.label}</span>
          </div>
        ))}
      </div>
    </div>
  )
}
