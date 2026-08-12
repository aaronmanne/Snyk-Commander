import React from 'react'
import {
  LayoutDashboard, Shield, Ban, Wrench, FileText,
  FlaskConical, Settings, ChevronRight
} from 'lucide-react'
import type { View } from '../types'
import { useApp } from '../context/AppContext'

interface NavItem {
  view: View
  label: string
  icon: React.ReactNode
}

const navItems: NavItem[] = [
  { view: 'dashboard', label: 'Dashboard', icon: <LayoutDashboard size={18} /> },
  { view: 'vulnerabilities', label: 'Vulnerabilities', icon: <Shield size={18} /> },
  { view: 'ignore-manager', label: 'Ignore Manager', icon: <Ban size={18} /> },
  { view: 'fix-prs', label: 'Fix PRs', icon: <Wrench size={18} /> },
  { view: 'reports', label: 'Reports', icon: <FileText size={18} /> },
  { view: 'reachability', label: 'Reachability', icon: <FlaskConical size={18} /> },
  { view: 'settings', label: 'Settings', icon: <Settings size={18} /> },
]

export default function Sidebar() {
  const { state, setView } = useApp()

  return (
    <aside className="w-56 flex-shrink-0 bg-bg-secondary border-r border-border flex flex-col h-full">
      {/* Logo area */}
      <div className="px-4 py-5 border-b border-border">
        <div className="flex items-center gap-2">
          <div className="w-8 h-8 bg-accent-purple rounded-lg flex items-center justify-center">
            <Shield size={16} className="text-white" />
          </div>
          <div>
            <p className="text-sm font-bold text-text-primary leading-none">Snyk</p>
            <p className="text-xs text-accent-purple font-medium">Commander</p>
          </div>
        </div>
      </div>

      {/* Org name — clickable to switch org */}
      {state.selectedOrg && (
        <button
          onClick={() => setView('org-select')}
          className="w-full px-4 py-3 border-b border-border text-left hover:bg-bg-tertiary transition-colors group"
          title="Click to switch organization"
        >
          <p className="text-xs text-text-muted uppercase tracking-wider mb-1">Active Org</p>
          <div className="flex items-center justify-between gap-1">
            <p className="text-sm text-text-primary font-medium truncate group-hover:text-accent-purple transition-colors" title={state.selectedOrg.name}>
              {state.selectedOrg.name}
            </p>
            <ChevronRight size={12} className="text-text-muted group-hover:text-accent-purple transition-colors flex-shrink-0" />
          </div>
        </button>
      )}

      {/* Navigation */}
      <nav className="flex-1 px-2 py-3 overflow-y-auto">
        {navItems.map((item) => {
          const isActive = state.currentView === item.view
          return (
            <button
              key={item.view}
              onClick={() => setView(item.view)}
              className={`
                w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium
                transition-all duration-150 mb-0.5 group text-left
                ${isActive
                  ? 'bg-accent-purple/15 text-accent-purple border border-accent-purple/25'
                  : 'text-text-secondary hover:text-text-primary hover:bg-bg-tertiary border border-transparent'
                }
              `}
            >
              <span className={isActive ? 'text-accent-purple' : 'text-text-muted group-hover:text-text-secondary'}>
                {item.icon}
              </span>
              {item.label}
              {isActive && <ChevronRight size={14} className="ml-auto text-accent-purple" />}
            </button>
          )
        })}
      </nav>

      {/* Scan timestamp */}
      {state.scanTimestamp && (
        <div className="px-4 py-3 border-t border-border">
          <p className="text-xs text-text-muted">Last scan</p>
          <p className="text-xs text-text-secondary mt-0.5">
            {new Date(state.scanTimestamp).toLocaleString()}
          </p>
        </div>
      )}
    </aside>
  )
}
