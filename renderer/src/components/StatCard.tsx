import React from 'react'

interface StatCardProps {
  title: string
  value: string | number
  icon: React.ReactNode
  color?: 'purple' | 'red' | 'green' | 'orange' | 'yellow' | 'gray'
  subtitle?: string
}

const colorClasses = {
  purple: {
    icon: 'text-accent-purple bg-accent-purple/10',
    value: 'text-accent-purple',
    border: 'border-accent-purple/20',
  },
  red: {
    icon: 'text-red-400 bg-red-400/10',
    value: 'text-red-400',
    border: 'border-red-800/30',
  },
  green: {
    icon: 'text-accent-green bg-accent-green/10',
    value: 'text-accent-green',
    border: 'border-accent-green/20',
  },
  orange: {
    icon: 'text-orange-400 bg-orange-400/10',
    value: 'text-orange-400',
    border: 'border-orange-800/30',
  },
  yellow: {
    icon: 'text-yellow-400 bg-yellow-400/10',
    value: 'text-yellow-400',
    border: 'border-yellow-800/30',
  },
  gray: {
    icon: 'text-gray-400 bg-gray-400/10',
    value: 'text-gray-300',
    border: 'border-gray-700/30',
  },
}

export default function StatCard({ title, value, icon, color = 'purple', subtitle }: StatCardProps) {
  const colors = colorClasses[color]

  return (
    <div className={`bg-bg-secondary rounded-xl border ${colors.border} p-5 flex items-start gap-4 hover:border-opacity-60 transition-all duration-200`}>
      <div className={`${colors.icon} p-3 rounded-lg flex-shrink-0`}>
        {icon}
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-text-muted text-sm font-medium mb-1">{title}</p>
        <p className={`text-2xl font-bold ${colors.value}`}>
          {typeof value === 'number' ? value.toLocaleString() : value}
        </p>
        {subtitle && (
          <p className="text-text-muted text-xs mt-1">{subtitle}</p>
        )}
      </div>
    </div>
  )
}
