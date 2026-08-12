import React, { useMemo } from 'react'
import { Shield, Bug, Wrench, FolderOpen, RefreshCw, TrendingUp, ChevronDown } from 'lucide-react'
import { useApp } from '../context/AppContext'
import { deleteOrgCache } from '../api'
import StatCard from '../components/StatCard'
import DonutChart from '../components/DonutChart'
import SeverityBadge from '../components/SeverityBadge'
import type { ScanResult } from '../types'

export default function DashboardView() {
  const { state, setView } = useApp()
  const results = state.scanResults

  const stats = useMemo(() => {
    let totalVulns = 0, critical = 0, fixable = 0
    for (const r of results) {
      totalVulns += r.total_vulns
      critical += r.severity.critical
      if (r.fixable) fixable++
    }
    return { totalVulns, critical, fixable, projects: results.length }
  }, [results])

  const severityTotals = useMemo(() => {
    const t = { critical: 0, high: 0, medium: 0, low: 0 }
    for (const r of results) {
      t.critical += r.severity.critical
      t.high += r.severity.high
      t.medium += r.severity.medium
      t.low += r.severity.low
    }
    return t
  }, [results])

  const top10 = useMemo(() => {
    return [...results]
      .sort((a, b) => (b.severity.critical * 1000 + b.severity.high) - (a.severity.critical * 1000 + a.severity.high))
      .slice(0, 10)
  }, [results])

  const donutSegments = [
    { value: severityTotals.critical, color: '#ef4444', label: 'Critical' },
    { value: severityTotals.high, color: '#f97316', label: 'High' },
    { value: severityTotals.medium, color: '#eab308', label: 'Medium' },
    { value: severityTotals.low, color: '#6b7280', label: 'Low' },
  ]

  return (
    <div className="flex-1 overflow-y-auto bg-bg-primary">
      <div className="max-w-7xl mx-auto p-6">
        {/* Header */}
        <div className="flex items-start justify-between mb-8">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="text-xs text-text-muted uppercase tracking-wider">Active Organization</span>
            </div>
            {/* Org name — click to switch org */}
            <button
              onClick={() => setView('org-select')}
              className="flex items-center gap-2 group hover:opacity-80 transition-opacity text-left"
              title="Click to switch organization"
            >
              <h1 className="text-2xl font-bold text-text-primary group-hover:text-accent-purple transition-colors">
                {state.selectedOrg?.name ?? 'No organization selected'}
              </h1>
              <ChevronDown size={18} className="text-text-muted group-hover:text-accent-purple transition-colors mt-0.5 flex-shrink-0" />
            </button>
            {state.scanTimestamp && (
              <p className="text-text-muted text-sm mt-1">
                Last scan: {new Date(state.scanTimestamp).toLocaleString()}
              </p>
            )}
          </div>
          <button 
            onClick={async () => {
              // Clear cache before rescanning
              if (state.selectedOrg) {
                try {
                  await deleteOrgCache(state.selectedOrg.id)
                } catch (err) {
                  console.error('Failed to clear cache:', err)
                }
              }
              setView('scanning')
            }} 
            className="btn-secondary"
          >
            <RefreshCw size={16} />
            Rescan
          </button>
        </div>

        {/* Stat cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
          <StatCard
            title="Total Vulnerabilities"
            value={stats.totalVulns}
            icon={<Bug size={20} />}
            color="purple"
          />
          <StatCard
            title="Critical Issues"
            value={stats.critical}
            icon={<Shield size={20} />}
            color="red"
          />
          <StatCard
            title="Fixable Projects"
            value={stats.fixable}
            icon={<Wrench size={20} />}
            color="green"
          />
          <StatCard
            title="Projects Scanned"
            value={stats.projects}
            icon={<FolderOpen size={20} />}
            color="gray"
          />
        </div>

        {/* Charts & top projects row */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
          {/* Donut chart */}
          <div className="bg-bg-secondary border border-border rounded-xl p-6">
            <div className="flex items-center gap-2 mb-6">
              <TrendingUp size={16} className="text-accent-purple" />
              <h2 className="text-base font-semibold text-text-primary">Severity Breakdown</h2>
            </div>
            <DonutChart
              segments={donutSegments}
              size={180}
              strokeWidth={28}
              centerValue={stats.totalVulns}
              centerLabel="Total"
            />
          </div>

          {/* Quick stats */}
          <div className="bg-bg-secondary border border-border rounded-xl p-6">
            <h2 className="text-base font-semibold text-text-primary mb-4">Severity Summary</h2>
            <div className="space-y-4">
              {(
                [
                  { label: 'Critical', key: 'critical' as const, color: 'bg-red-500', count: severityTotals.critical },
                  { label: 'High', key: 'high' as const, color: 'bg-orange-500', count: severityTotals.high },
                  { label: 'Medium', key: 'medium' as const, color: 'bg-yellow-500', count: severityTotals.medium },
                  { label: 'Low', key: 'low' as const, color: 'bg-gray-500', count: severityTotals.low },
                ] as const
              ).map(item => {
                const pct = stats.totalVulns > 0 ? (item.count / stats.totalVulns) * 100 : 0
                return (
                  <div key={item.key}>
                    <div className="flex justify-between text-sm mb-1.5">
                      <span className="text-text-secondary">{item.label}</span>
                      <span className="font-mono text-text-primary">{item.count.toLocaleString()}</span>
                    </div>
                    <div className="h-2 bg-bg-tertiary rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full ${item.color} transition-all duration-700`}
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                )
              })}
            </div>
          </div>
        </div>

        {/* Top 10 projects table */}
        <div className="bg-bg-secondary border border-border rounded-xl overflow-hidden">
          <div className="px-6 py-4 border-b border-border flex items-center justify-between">
            <h2 className="text-base font-semibold text-text-primary">Top 10 Most Vulnerable Projects</h2>
            <button onClick={() => setView('vulnerabilities')} className="text-xs text-accent-purple hover:text-accent-purple-light transition-colors">
              View all →
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border">
                  <th className="px-4 py-3 text-left text-text-muted font-medium">#</th>
                  <th className="px-4 py-3 text-left text-text-muted font-medium">Project</th>
                  <th className="px-4 py-3 text-center text-red-400 font-medium">Critical</th>
                  <th className="px-4 py-3 text-center text-orange-400 font-medium">High</th>
                  <th className="px-4 py-3 text-center text-yellow-400 font-medium">Medium</th>
                  <th className="px-4 py-3 text-center text-gray-400 font-medium">Low</th>
                  <th className="px-4 py-3 text-left text-text-muted font-medium">Fixable</th>
                </tr>
              </thead>
              <tbody>
                {top10.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="px-4 py-12 text-center text-text-muted">
                      No scan results available
                    </td>
                  </tr>
                ) : (
                  top10.map((r: ScanResult, i: number) => (
                    <tr key={r.id} className="border-b border-border/50 table-row-hover">
                      <td className="px-4 py-3 text-text-muted font-mono text-xs">{i + 1}</td>
                      <td className="px-4 py-3">
                        <div>
                          <p className="text-text-primary font-medium truncate max-w-xs" title={r.name}>{r.name}</p>
                          <p className="text-text-muted text-xs font-mono">{r.type}</p>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-center">
                        <span className={`font-bold ${r.severity.critical > 0 ? 'text-red-400' : 'text-text-muted'}`}>
                          {r.severity.critical}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-center">
                        <span className={`font-bold ${r.severity.high > 0 ? 'text-orange-400' : 'text-text-muted'}`}>
                          {r.severity.high}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-center">
                        <span className={`font-bold ${r.severity.medium > 0 ? 'text-yellow-400' : 'text-text-muted'}`}>
                          {r.severity.medium}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-center">
                        <span className="text-gray-400 font-bold">{r.severity.low}</span>
                      </td>
                      <td className="px-4 py-3">
                        {r.fixable ? (
                          <span className="inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full bg-accent-green/10 text-accent-green border border-accent-green/20">
                            ✓ Fixable
                          </span>
                        ) : (
                          <span className="text-text-muted text-xs">—</span>
                        )}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  )
}
