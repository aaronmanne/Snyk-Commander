import React from 'react'

interface ProgressBarProps {
  value: number
  max?: number
  showPercent?: boolean
  label?: string
  animated?: boolean
  color?: 'purple' | 'green' | 'red'
  size?: 'sm' | 'md' | 'lg'
}

export default function ProgressBar({
  value,
  max = 100,
  showPercent = false,
  label,
  animated = false,
  color = 'purple',
  size = 'md',
}: ProgressBarProps) {
  const pct = max > 0 ? Math.min(100, (value / max) * 100) : 0

  const sizeClasses = {
    sm: 'h-1.5',
    md: 'h-3',
    lg: 'h-4',
  }

  const colorClasses = {
    purple: animated ? 'progress-shimmer' : 'bg-accent-purple',
    green: 'bg-accent-green',
    red: 'bg-red-500',
  }

  return (
    <div className="w-full">
      {(label || showPercent) && (
        <div className="flex justify-between items-center mb-2">
          {label && <span className="text-sm text-text-secondary">{label}</span>}
          {showPercent && (
            <span className="text-sm font-mono text-text-primary">{Math.round(pct)}%</span>
          )}
        </div>
      )}
      <div className={`w-full bg-bg-tertiary rounded-full overflow-hidden ${sizeClasses[size]}`}>
        <div
          className={`h-full rounded-full transition-all duration-500 ease-out ${colorClasses[color]}`}
          style={{ width: `${pct}%` }}
          role="progressbar"
          aria-valuenow={value}
          aria-valuemin={0}
          aria-valuemax={max}
        />
      </div>
    </div>
  )
}
