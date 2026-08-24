import React from 'react'

interface DonutSegment {
  value: number
  color: string
  label: string
}

interface DonutChartProps {
  segments: DonutSegment[]
  size?: number
  strokeWidth?: number
  centerLabel?: string
  centerValue?: string | number
}

export default function DonutChart({
  segments,
  size = 200,
  strokeWidth = 28,
  centerLabel,
  centerValue,
}: DonutChartProps) {
  const radius = (size - strokeWidth) / 2
  const circumference = 2 * Math.PI * radius
  const total = segments.reduce((sum, s) => sum + s.value, 0)

  let offset = 0
  const paths = segments.map((seg, i) => {
    const pct = total > 0 ? seg.value / total : 0
    const dasharray = pct * circumference
    const dashoffset = circumference - offset * circumference / total

    const path = (
      <circle
        key={i}
        cx={size / 2}
        cy={size / 2}
        r={radius}
        fill="none"
        stroke={seg.color}
        strokeWidth={strokeWidth}
        strokeDasharray={`${dasharray} ${circumference - dasharray}`}
        strokeDashoffset={dashoffset}
        strokeLinecap="butt"
        style={{ transition: 'all 0.5s ease' }}
      />
    )
    offset += seg.value
    return path
  })

  return (
    <div className="flex items-center gap-6">
      <div className="relative flex-shrink-0">
        <svg
          width={size}
          height={size}
          style={{ transform: 'rotate(-90deg)' }}
        >
          {/* Background circle */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            fill="none"
            stroke="#2a2d3e"
            strokeWidth={strokeWidth}
          />
          {total > 0 ? paths : null}
        </svg>
        {/* Center text */}
        {(centerLabel || centerValue !== undefined) && (
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            {centerValue !== undefined && (
              <span className="text-2xl font-bold text-text-primary">
                {typeof centerValue === 'number' ? centerValue.toLocaleString() : centerValue}
              </span>
            )}
            {centerLabel && (
              <span className="text-xs text-text-muted mt-0.5">{centerLabel}</span>
            )}
          </div>
        )}
      </div>

      {/* Legend */}
      <div className="flex flex-col gap-2">
        {segments.map((seg, i) => (
          <div key={i} className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-sm flex-shrink-0" style={{ backgroundColor: seg.color }} />
            <span className="text-sm text-text-secondary">{seg.label}</span>
            <span className="text-sm font-medium text-text-primary ml-auto pl-4">
              {seg.value.toLocaleString()}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}
