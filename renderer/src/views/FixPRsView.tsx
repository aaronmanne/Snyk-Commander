import React, { useState, useEffect } from 'react'
import { Wrench, Play, Loader2, AlertCircle, CheckCircle, XCircle } from 'lucide-react'
import { useApp } from '../context/AppContext'
import { getFixable, triggerFixPR } from '../api'
import type { FixableProject } from '../types'

type PRStatus = 'idle' | 'pending' | 'success' | 'failed'

interface ProjectStatus {
  status: PRStatus
  message?: string
}

export default function FixPRsView() {
  const { state } = useApp()
  const [projects, setProjects] = useState<FixableProject[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [statuses, setStatuses] = useState<Record<string, ProjectStatus>>({})
  const [triggeringAll, setTriggeringAll] = useState(false)

  useEffect(() => {
    const load = async () => {
      setLoading(true)
      try {
        const res = await getFixable(state.scanResults)
        setProjects(res.projects || [])
      } catch (e: unknown) {
        setError(e instanceof Error ? e.message : String(e))
      } finally {
        setLoading(false)
      }
    }
    if (state.scanResults.length > 0) {
      load()
    } else {
      setLoading(false)
    }
  }, [state.scanResults])

  const triggerOne = async (project: FixableProject) => {
    if (!state.selectedOrg) return
    setStatuses(prev => ({ ...prev, [project.id]: { status: 'pending' } }))
    try {
      const res = await triggerFixPR(state.selectedOrg.slug, project.id, state.token)
      setStatuses(prev => ({
        ...prev,
        [project.id]: { status: res.ok ? 'success' : 'failed', message: res.message }
      }))
    } catch (e: unknown) {
      setStatuses(prev => ({
        ...prev,
        [project.id]: { status: 'failed', message: e instanceof Error ? e.message : String(e) }
      }))
    }
  }

  const triggerAll = async () => {
    setTriggeringAll(true)
    for (const p of projects) {
      const status = statuses[p.id]
      if (status?.status === 'success') continue
      await triggerOne(p)
    }
    setTriggeringAll(false)
  }

  const getStatusBadge = (status: PRStatus) => {
    switch (status) {
      case 'pending': return (
        <span className="flex items-center gap-1.5 text-xs text-accent-purple bg-accent-purple/10 border border-accent-purple/30 px-2 py-0.5 rounded-full">
          <Loader2 size={11} className="animate-spin" /> Triggering...
        </span>
      )
      case 'success': return (
        <span className="flex items-center gap-1.5 text-xs text-accent-green bg-accent-green/10 border border-accent-green/30 px-2 py-0.5 rounded-full">
          <CheckCircle size={11} /> PR Created
        </span>
      )
      case 'failed': return (
        <span className="flex items-center gap-1.5 text-xs text-red-400 bg-red-900/20 border border-red-700/30 px-2 py-0.5 rounded-full">
          <XCircle size={11} /> Failed
        </span>
      )
      default: return (
        <span className="text-xs text-text-muted">Ready</span>
      )
    }
  }

  const totalSucceeded = Object.values(statuses).filter(s => s.status === 'success').length

  return (
    <div className="flex-1 overflow-y-auto bg-bg-primary p-6">
      <div className="max-w-5xl mx-auto">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-accent-purple/10 border border-accent-purple/30 rounded-xl flex items-center justify-center">
              <Wrench size={20} className="text-accent-purple" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-text-primary">Fix PRs</h1>
              <p className="text-text-muted text-sm">Trigger automated fix pull requests</p>
            </div>
          </div>

          {projects.length > 0 && (
            <button
              onClick={triggerAll}
              disabled={triggeringAll}
              className="btn-primary"
            >
              {triggeringAll ? <Loader2 size={16} className="animate-spin" /> : <Play size={16} />}
              Trigger All
            </button>
          )}
        </div>

        {/* Stats bar */}
        {projects.length > 0 && totalSucceeded > 0 && (
          <div className="flex items-center gap-3 p-3 bg-accent-green/10 border border-accent-green/20 rounded-lg mb-5 text-sm">
            <CheckCircle size={16} className="text-accent-green" />
            <span className="text-accent-green font-medium">{totalSucceeded}</span>
            <span className="text-text-secondary">of {projects.length} PRs triggered successfully</span>
          </div>
        )}

        {error && (
          <div className="flex items-start gap-2 p-3 bg-red-950/40 border border-red-800/50 rounded-lg mb-5 text-red-400 text-sm">
            <AlertCircle size={16} className="flex-shrink-0 mt-0.5" />
            {error}
          </div>
        )}

        {loading ? (
          <div className="flex items-center justify-center py-16">
            <Loader2 size={32} className="text-accent-purple animate-spin" />
          </div>
        ) : projects.length === 0 ? (
          <div className="text-center py-16 bg-bg-secondary border border-border rounded-xl">
            <Wrench size={40} className="mx-auto text-text-muted mb-3 opacity-40" />
            <p className="text-text-muted">No fixable projects found</p>
            <p className="text-text-muted text-sm mt-1">Run a scan to discover fixable vulnerabilities</p>
          </div>
        ) : (
          <div className="bg-bg-secondary border border-border rounded-xl overflow-hidden">
            <div className="px-4 py-3 border-b border-border">
              <span className="text-sm text-text-muted">{projects.length} fixable projects</span>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-border bg-bg-tertiary">
                    <th className="px-4 py-3 text-left text-text-muted font-medium">Project</th>
                    <th className="px-4 py-3 text-center text-red-400 font-medium">Critical</th>
                    <th className="px-4 py-3 text-center text-orange-400 font-medium">High</th>
                    <th className="px-4 py-3 text-center text-yellow-400 font-medium">Medium</th>
                    <th className="px-4 py-3 text-center text-gray-400 font-medium">Low</th>
                    <th className="px-4 py-3 text-left text-text-muted font-medium">Status</th>
                    <th className="px-4 py-3 text-right text-text-muted font-medium">Action</th>
                  </tr>
                </thead>
                <tbody>
                  {projects.map(p => {
                    const ps = statuses[p.id]
                    return (
                      <React.Fragment key={p.id}>
                        <tr className="border-b border-border/50 table-row-hover">
                          <td className="px-4 py-3">
                            <p className="text-text-primary font-medium text-xs max-w-xs truncate" title={p.name}>{p.name}</p>
                            <p className="text-text-muted text-xs font-mono mt-0.5">{p.id}</p>
                          </td>
                          <td className="px-4 py-3 text-center">
                            <span className={`font-bold text-sm ${p.severity.critical > 0 ? 'text-red-400' : 'text-text-muted'}`}>
                              {p.severity.critical}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-center">
                            <span className={`font-bold text-sm ${p.severity.high > 0 ? 'text-orange-400' : 'text-text-muted'}`}>
                              {p.severity.high}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-center">
                            <span className={`font-bold text-sm ${p.severity.medium > 0 ? 'text-yellow-400' : 'text-text-muted'}`}>
                              {p.severity.medium}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-center">
                            <span className="text-gray-400 font-bold text-sm">{p.severity.low}</span>
                          </td>
                          <td className="px-4 py-3">
                            {getStatusBadge(ps?.status || 'idle')}
                            {ps?.message && (
                              <p className="text-xs text-text-muted mt-1 max-w-xs truncate" title={ps.message}>{ps.message}</p>
                            )}
                          </td>
                          <td className="px-4 py-3 text-right">
                            <button
                              onClick={() => triggerOne(p)}
                              disabled={ps?.status === 'pending' || ps?.status === 'success'}
                              className="btn-primary py-1.5 px-3 text-xs disabled:opacity-40"
                            >
                              {ps?.status === 'pending'
                                ? <Loader2 size={12} className="animate-spin" />
                                : <Play size={12} />
                              }
                              Trigger
                            </button>
                          </td>
                        </tr>
                      </React.Fragment>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
