import React from 'react'
import type { Severity } from '../types'

interface SeverityBadgeProps {
  severity: Severity
  size?: 'sm' | 'md'
  showDot?: boolean
}

const severityConfig: Record<Severity, { label: string; classes: string; dot: string }> = {
  critical: {
    label: 'Critical',
    classes: 'bg-red-950/60 text-red-400 border border-red-800/50',
    dot: 'bg-red-400',
  },
  high: {
    label: 'High',
    classes: 'bg-orange-950/60 text-orange-400 border border-orange-800/50',
    dot: 'bg-orange-400',
  },
  medium: {
    label: 'Medium',
    classes: 'bg-yellow-950/60 text-yellow-400 border border-yellow-800/50',
    dot: 'bg-yellow-400',
  },
  low: {
    label: 'Low',
    classes: 'bg-gray-900/60 text-gray-400 border border-gray-700/50',
    dot: 'bg-gray-400',
  },
}

export default function SeverityBadge({ severity, size = 'sm', showDot = false }: SeverityBadgeProps) {
  const config = severityConfig[severity]
  const sizeClasses = size === 'sm' ? 'text-xs px-2 py-0.5' : 'text-sm px-3 py-1'

  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full font-medium ${config.classes} ${sizeClasses}`}>
      {showDot && <span className={`w-1.5 h-1.5 rounded-full ${config.dot}`} />}
      {config.label}
    </span>
  )
}
