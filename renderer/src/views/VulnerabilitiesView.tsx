import React, { useState, useMemo, useCallback } from 'react'
import { Search, ChevronLeft, ChevronRight, FlaskConical, X, AlertCircle, ShieldOff, Loader2, CheckCircle } from 'lucide-react'
import { useApp } from '../context/AppContext'
import { applyIgnores, ignoreSingleIssue } from '../api'
import SeverityBadge from '../components/SeverityBadge'
import type { FlatIssue, Severity } from '../types'

const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low']
const PAGE_SIZE = 50

export default function VulnerabilitiesView() {
  const { state, setView, setSelectedIssue } = useApp()

  // Ignore all state
  const [ignoringAll, setIgnoringAll] = useState(false)
  const [ignoreAllSuccess, setIgnoreAllSuccess] = useState(false)
  const [ignoreAllError, setIgnoreAllError] = useState('')

  // Individual ignore state
  const [ignoringItem, setIgnoringItem] = useState<string | null>(null)
  const [ignoreSuccess, setIgnoreSuccess] = useState<string | null>(null)
  const [ignoreError, setIgnoreError] = useState<string | null>(null)

  // Flatten all issues
  const allIssues = useMemo<FlatIssue[]>(() => {
    const flat: FlatIssue[] = []
    for (const project of state.scanResults) {
      for (const issue of (project.issues || [])) {
        flat.push({
          projectId: project.id,
          projectName: project.name,
          projectType: project.type,
          issue,
          riskScore: issue.priority?.score ?? project.risk_score,
        })
      }
    }
    return flat
  }, [state.scanResults])

  const [search, setSearch] = useState('')
  const [severityFilter, setSeverityFilter] = useState<Set<Severity>>(new Set())
  const [fixableOnly, setFixableOnly] = useState(false)
  const [hideIgnored, setHideIgnored] = useState(true)  // On by default
  const [reachabilityFilter, setReachabilityFilter] = useState<'all' | 'reachable' | 'no-path'>('all')
  const [fixedInFilter, setFixedInFilter] = useState<'all' | 'yes' | 'no'>('all')
  const [fixabilityFilter, setFixabilityFilter] = useState<'all' | 'fixable' | 'partially-fixable' | 'no-fix'>('all')
  const [page, setPage] = useState(1)
  const [expandedKey, setExpandedKey] = useState<string | null>(null)
  const [sortKey, setSortKey] = useState<string>('severity')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc')

  const severityOrder: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 }

  const filtered = useMemo(() => {
    let list = allIssues
    if (search.trim()) {
      const q = search.toLowerCase()
      list = list.filter(fi =>
        fi.projectName.toLowerCase().includes(q) ||
        fi.issue.issueData.title.toLowerCase().includes(q) ||
        fi.issue.pkgName.toLowerCase().includes(q)
      )
    }
    if (severityFilter.size > 0) {
      list = list.filter(fi => severityFilter.has(fi.issue.issueData.severity))
    }
    if (fixableOnly) {
      list = list.filter(fi => fi.issue.isUpgradable || fi.issue.isPatchable)
    }
    if (hideIgnored) {
      // Filter out issues that are in the ignoredIssueIds list
      list = list.filter(fi => {
        const project = state.scanResults.find(p => p.id === fi.projectId)
        return !project?.ignoredIssueIds?.includes(fi.issue.id)
      })
    }
    // Reachability filter
    if (reachabilityFilter === 'reachable') {
      list = list.filter(fi => fi.issue.reachability === 'reachable')
    } else if (reachabilityFilter === 'no-path') {
      list = list.filter(fi => fi.issue.reachability === 'no-path' || !fi.issue.reachability)
    }
    // Fixed In filter
    if (fixedInFilter === 'yes') {
      list = list.filter(fi => fi.issue.isUpgradable || fi.issue.isPatchable || fi.issue.isPinnable)
    } else if (fixedInFilter === 'no') {
      list = list.filter(fi => !fi.issue.isUpgradable && !fi.issue.isPatchable && !fi.issue.isPinnable)
    }
    // Fixability filter
    if (fixabilityFilter === 'fixable') {
      list = list.filter(fi => {
        const issue = fi.issue
        return issue.isUpgradable || issue.isPatchable || issue.isPinnable || 
               issue.fixInfo?.isUpgradable || issue.fixInfo?.isPatchable || issue.fixInfo?.isFixable
      })
    } else if (fixabilityFilter === 'partially-fixable') {
      list = list.filter(fi => {
        const issue = fi.issue
        const directlyFixable = issue.isUpgradable || issue.isPatchable || issue.isPinnable
        const hasFixInfo = issue.fixInfo?.isUpgradable || issue.fixInfo?.isPatchable || issue.fixInfo?.isFixable
        return !directlyFixable && hasFixInfo
      })
    } else if (fixabilityFilter === 'no-fix') {
      list = list.filter(fi => {
        const issue = fi.issue
        const isFixable = issue.isUpgradable || issue.isPatchable || issue.isPinnable || 
                         issue.fixInfo?.isUpgradable || issue.fixInfo?.isPatchable || issue.fixInfo?.isFixable
        return !isFixable
      })
    }

    // Sort
    list = [...list].sort((a, b) => {
      let cmp = 0
      if (sortKey === 'severity') {
        cmp = (severityOrder[b.issue.issueData.severity] ?? 0) - (severityOrder[a.issue.issueData.severity] ?? 0)
      } else if (sortKey === 'risk') {
        cmp = (b.riskScore ?? 0) - (a.riskScore ?? 0)
      } else if (sortKey === 'project') {
        cmp = a.projectName.localeCompare(b.projectName)
      } else if (sortKey === 'title') {
        cmp = a.issue.issueData.title.localeCompare(b.issue.issueData.title)
      }
      return sortDir === 'asc' ? -cmp : cmp
    })
    return list
  }, [allIssues, search, severityFilter, fixableOnly, hideIgnored, reachabilityFilter, fixedInFilter, fixabilityFilter, sortKey, sortDir, state.scanResults])

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE))
  const paginated = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE)

  const handleIgnoreAll = async () => {
    if (!state.selectedOrg || filtered.length === 0) return
    
    setIgnoringAll(true)
    setIgnoreAllError('')
    setIgnoreAllSuccess(false)

    try {
      // Create operations for all filtered issues
      const operations = filtered.map(fi => ({
        action: 'ignore' as const,
        vuln_id: fi.issue.id,
        project_id: fi.projectId,
        title: fi.issue.issueData.title,
        severity: fi.issue.issueData.severity,
        risk_score: fi.riskScore,
        project_name: fi.projectName,
      }))

      // Use the applyIgnores API — all ignores expire 90 days from now.
      // disregardIfFixable=false because this list is based on whatever the
      // user has filtered to (severity, reachability, etc.) and may include
      // vulnerabilities that DO have a fix available. Snyk silently skips
      // creating an ignore when disregardIfFixable=true and a fix exists, so
      // we must pass false to guarantee the ignore is actually applied.
      const expires = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString()
      const result = await applyIgnores(
        state.selectedOrg.id,
        state.token,
        operations,
        'Bulk ignored from vulnerabilities view based on applied filters.',
        expires,
        () => {}, // No progress callback needed
        false
      )

      setIgnoreAllSuccess(true)
      setTimeout(() => setIgnoreAllSuccess(false), 5000)
    } catch (e: unknown) {
      setIgnoreAllError(e instanceof Error ? e.message : String(e))
    } finally {
      setIgnoringAll(false)
    }
  }

  const handleIgnoreSingle = async (fi: FlatIssue) => {
    if (!state.selectedOrg) return
    
    const key = `${fi.projectId}-${fi.issue.id}`
    setIgnoringItem(key)
    setIgnoreError(null)
    setIgnoreSuccess(null)

    try {
      // Get reachability analysis if available
      const reachabilityKey = `${fi.projectId}:${fi.issue.id}`
      const reachability = state.reachabilityResults[reachabilityKey]
      
      // Build reason from LLM analysis or default
      let reason = 'Ignored from vulnerabilities view.'
      if (reachability?.ollama_reasoning) {
        reason = `AI Analysis: ${reachability.ollama_reasoning}`
      }

      await ignoreSingleIssue(
        state.selectedOrg.id,
        state.token,
        fi.projectId,
        fi.issue.id,
        reason
      )

      setIgnoreSuccess(key)
      setTimeout(() => setIgnoreSuccess(null), 5000)
    } catch (e: unknown) {
      setIgnoreError(key)
      console.error('Failed to ignore issue:', e)
    } finally {
      setIgnoringItem(null)
    }
  }

  const toggleSeverity = (s: Severity) => {
    setSeverityFilter(prev => {
      const next = new Set(prev)
      if (next.has(s)) next.delete(s)
      else next.add(s)
      return next
    })
    setPage(1)
  }

  const handleSort = (key: string) => {
    if (sortKey === key) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    } else {
      setSortKey(key)
      setSortDir('desc')
    }
    setPage(1)
  }

  const handleExpandRow = useCallback((key: string) => {
    setExpandedKey(prev => prev === key ? null : key)
  }, [])

  const riskLabel = (score: number | null) => {
    if (score === null) return { label: '—', cls: 'text-text-muted' }
    if (score >= 700) return { label: 'Critical', cls: 'text-red-400' }
    if (score >= 400) return { label: 'High', cls: 'text-orange-400' }
    if (score >= 200) return { label: 'Medium', cls: 'text-yellow-400' }
    return { label: 'Low', cls: 'text-gray-400' }
  }

  const SortIcon = ({ k }: { k: string }) => (
    <span className={`text-xs ml-1 ${sortKey === k ? 'text-accent-purple' : 'text-text-muted opacity-40'}`}>
      {sortKey === k ? (sortDir === 'asc' ? '↑' : '↓') : '↕'}
    </span>
  )

  // Calculate metrics from filtered issues
  const metrics = useMemo(() => {
    const issues = filtered

    // Fixed In Available
    const fixedInYes = issues.filter(fi => fi.issue.isUpgradable || fi.issue.isPatchable || fi.issue.isPinnable).length
    const fixedInNo = issues.length - fixedInYes

    // Computed Fixability
    const fixable = issues.filter(fi => {
      const issue = fi.issue
      return issue.isUpgradable || issue.isPatchable || issue.isPinnable || 
             issue.fixInfo?.isUpgradable || issue.fixInfo?.isPatchable || issue.fixInfo?.isFixable
    }).length
    
    // For partially fixable, we need to check if some but not all paths have fixes
    // For simplicity, we'll count issues with fixInfo but not directly fixable
    const partiallyFixable = issues.filter(fi => {
      const issue = fi.issue
      const directlyFixable = issue.isUpgradable || issue.isPatchable || issue.isPinnable
      const hasFixInfo = issue.fixInfo?.isUpgradable || issue.fixInfo?.isPatchable || issue.fixInfo?.isFixable
      return !directlyFixable && hasFixInfo
    }).length
    
    const noSupportedFix = issues.length - fixable

    // Reachable Vulns
    const reachable = issues.filter(fi => fi.issue.reachability === 'reachable').length
    const noPathFound = issues.filter(fi => fi.issue.reachability === 'no-path' || !fi.issue.reachability).length

    // Exploit Maturity
    const matureExploit = issues.filter(fi => fi.issue.exploitMaturity === 'mature').length
    const proofOfConcept = issues.filter(fi => fi.issue.exploitMaturity === 'proof-of-concept').length
    const noKnownExploit = issues.filter(fi => fi.issue.exploitMaturity === 'no-known-exploit').length
    const noExploitData = issues.filter(fi => !fi.issue.exploitMaturity || fi.issue.exploitMaturity === 'no-data').length

    // CVSS 4 Exploit Maturity (check if cvss version is 4.0)
    const cvss4Issues = issues.filter(fi => fi.issue.cvss?.version?.startsWith('4'))
    const cvss4Attacked = cvss4Issues.filter(fi => fi.issue.exploitMaturity === 'mature').length
    const cvss4ProofOfConcept = cvss4Issues.filter(fi => fi.issue.exploitMaturity === 'proof-of-concept').length
    const cvss4NotDefined = cvss4Issues.filter(fi => !fi.issue.exploitMaturity).length

    return {
      fixedInYes, fixedInNo,
      fixable, partiallyFixable, noSupportedFix,
      reachable, noPathFound,
      matureExploit, proofOfConcept, noKnownExploit, noExploitData,
      cvss4Attacked, cvss4ProofOfConcept, cvss4NotDefined,
      totalIssues: issues.length
    }
  }, [filtered])

  return (
    <div className="flex-1 flex flex-col overflow-hidden bg-bg-primary">
      {/* Metrics Dashboard */}
      <div className="border-b border-border bg-bg-secondary px-6 py-4">
        <div className="grid grid-cols-5 gap-4">
          {/* Fixed In Available */}
          <div className="bg-bg-tertiary border border-border rounded-lg p-3">
            <h3 className="text-xs font-semibold text-text-muted mb-2 uppercase">Fixed In Available</h3>
            <div className="space-y-1">
              <div className="flex justify-between items-center">
                <span className="text-xs text-text-secondary">Yes</span>
                <span className="text-sm font-bold text-accent-green">{metrics.fixedInYes}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-xs text-text-secondary">No</span>
                <span className="text-sm font-bold text-text-muted">{metrics.fixedInNo}</span>
              </div>
            </div>
          </div>

          {/* Computed Fixability */}
          <div className="bg-bg-tertiary border border-border rounded-lg p-3">
            <h3 className="text-xs font-semibold text-text-muted mb-2 uppercase">Computed Fixability</h3>
            <div className="space-y-1">
              <div className="flex justify-between items-center">
                <span className="text-xs text-text-secondary">Fixable</span>
                <span className="text-sm font-bold text-accent-green">{metrics.fixable}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-xs text-text-secondary">Partially fixable</span>
                <span className="text-sm font-bold text-yellow-400">{metrics.partiallyFixable}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-xs text-text-secondary">No supported fix</span>
                <span className="text-sm font-bold text-red-400">{metrics.noSupportedFix}</span>
              </div>
            </div>
          </div>

          {/* Reachable Vulns */}
          <div className="bg-bg-tertiary border border-border rounded-lg p-3">
            <h3 className="text-xs font-semibold text-text-muted mb-2 uppercase">Reachable Vulns</h3>
            <div className="space-y-1">
              <div className="flex justify-between items-center">
                <span className="text-xs text-text-secondary">Reachable</span>
                <span className="text-sm font-bold text-red-400">{metrics.reachable}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-xs text-text-secondary">No path found</span>
                <span className="text-sm font-bold text-accent-green">{metrics.noPathFound}</span>
              </div>
            </div>
          </div>

          {/* Exploit Maturity */}
          <div className="bg-bg-tertiary border border-border rounded-lg p-3">
            <h3 className="text-xs font-semibold text-text-muted mb-2 uppercase">Exploit Maturity</h3>
            <div className="space-y-1">
              <div className="flex justify-between items-center">
                <span className="text-xs text-text-secondary">Mature</span>
                <span className="text-sm font-bold text-red-400">{metrics.matureExploit}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-xs text-text-secondary">Proof of concept</span>
                <span className="text-sm font-bold text-orange-400">{metrics.proofOfConcept}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-xs text-text-secondary">No known exploit</span>
                <span className="text-sm font-bold text-accent-green">{metrics.noKnownExploit}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-xs text-text-secondary">No data</span>
                <span className="text-sm font-bold text-text-muted">{metrics.noExploitData}</span>
              </div>
            </div>
          </div>

          {/* CVSS 4 Exploit Maturity */}
          <div className="bg-bg-tertiary border border-border rounded-lg p-3">
            <h3 className="text-xs font-semibold text-text-muted mb-2 uppercase">CVSS 4 Exploit Maturity</h3>
            <div className="space-y-1">
              <div className="flex justify-between items-center">
                <span className="text-xs text-text-secondary">Attacked</span>
                <span className="text-sm font-bold text-red-400">{metrics.cvss4Attacked}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-xs text-text-secondary">Proof of concept</span>
                <span className="text-sm font-bold text-orange-400">{metrics.cvss4ProofOfConcept}</span>
              </div>
              <div className="flex justify-between items-center">
                <span className="text-xs text-text-secondary">Not defined</span>
                <span className="text-sm font-bold text-text-muted">{metrics.cvss4NotDefined}</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Toolbar */}
      <div className="border-b border-border bg-bg-secondary px-6 py-4">
        <div className="flex flex-wrap items-center gap-3">
          {/* Search */}
          <div className="relative flex-1 min-w-48">
            <Search size={15} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
            <input
              type="text"
              placeholder="Search project, package, or vulnerability..."
              value={search}
              onChange={e => { setSearch(e.target.value); setPage(1) }}
              className="input-base pl-9 text-sm"
            />
          </div>

          {/* Severity chips */}
          <div className="flex items-center gap-2 flex-wrap">
            {SEVERITIES.map(s => {
              const active = severityFilter.has(s)
              const colorMap = {
                critical: active ? 'bg-red-900/60 border-red-600 text-red-300' : 'border-border text-text-muted hover:border-red-700 hover:text-red-400',
                high: active ? 'bg-orange-900/60 border-orange-600 text-orange-300' : 'border-border text-text-muted hover:border-orange-700 hover:text-orange-400',
                medium: active ? 'bg-yellow-900/60 border-yellow-600 text-yellow-300' : 'border-border text-text-muted hover:border-yellow-700 hover:text-yellow-400',
                low: active ? 'bg-gray-700/60 border-gray-500 text-gray-300' : 'border-border text-text-muted hover:border-gray-500 hover:text-gray-400',
              }
              return (
                <button
                  key={s}
                  onClick={() => toggleSeverity(s)}
                  className={`text-xs px-3 py-1.5 rounded-full border capitalize font-medium transition-all ${colorMap[s]}`}
                >
                  {s}
                </button>
              )
            })}
          </div>

          {/* Fixable toggle */}
          <button
            onClick={() => { setFixableOnly(v => !v); setPage(1) }}
            className={`flex items-center gap-2 text-xs px-3 py-1.5 rounded-full border font-medium transition-all ${
              fixableOnly ? 'bg-accent-green/20 border-accent-green/50 text-accent-green' : 'border-border text-text-muted hover:border-accent-green/40 hover:text-accent-green'
            }`}
          >
            Fix Available
          </button>

          {/* Hide Ignored toggle */}
          <button
            onClick={() => { setHideIgnored(v => !v); setPage(1) }}
            className={`flex items-center gap-2 text-xs px-3 py-1.5 rounded-full border font-medium transition-all ${
              hideIgnored ? 'bg-accent-purple/20 border-accent-purple/50 text-accent-purple' : 'border-border text-text-muted hover:border-accent-purple/40 hover:text-accent-purple'
            }`}
          >
            Hide Ignored
          </button>

          {/* Reachability filter */}
          <select
            value={reachabilityFilter}
            onChange={e => { setReachabilityFilter(e.target.value as typeof reachabilityFilter); setPage(1) }}
            className={`text-xs px-3 py-1.5 rounded-full border font-medium transition-all ${
              reachabilityFilter !== 'all' ? 'bg-blue-900/20 border-blue-600/50 text-blue-300' : 'border-border text-text-muted hover:border-blue-600/40 hover:text-blue-300'
            } bg-bg-secondary`}
          >
            <option value="all">All Reachability</option>
            <option value="reachable">Reachable Only</option>
            <option value="no-path">No Path Found</option>
          </select>

          {/* Fixed In filter */}
          <select
            value={fixedInFilter}
            onChange={e => { setFixedInFilter(e.target.value as typeof fixedInFilter); setPage(1) }}
            className={`text-xs px-3 py-1.5 rounded-full border font-medium transition-all ${
              fixedInFilter !== 'all' ? 'bg-green-900/20 border-green-600/50 text-green-300' : 'border-border text-text-muted hover:border-green-600/40 hover:text-green-300'
            } bg-bg-secondary`}
          >
            <option value="all">All Fixed In</option>
            <option value="yes">Fix Available</option>
            <option value="no">No Fix</option>
          </select>

          {/* Computed Fixability filter */}
          <select
            value={fixabilityFilter}
            onChange={e => { setFixabilityFilter(e.target.value as typeof fixabilityFilter); setPage(1) }}
            className={`text-xs px-3 py-1.5 rounded-full border font-medium transition-all ${
              fixabilityFilter !== 'all' ? 'bg-orange-900/20 border-orange-600/50 text-orange-300' : 'border-border text-text-muted hover:border-orange-600/40 hover:text-orange-300'
            } bg-bg-secondary`}
          >
            <option value="all">All Fixability</option>
            <option value="fixable">Fixable</option>
            <option value="partially-fixable">Partially Fixable</option>
            <option value="no-fix">No Fix</option>
          </select>

          {/* Clear */}
          {(severityFilter.size > 0 || fixableOnly || search || !hideIgnored || reachabilityFilter !== 'all' || fixedInFilter !== 'all' || fixabilityFilter !== 'all') && (
            <button
              onClick={() => { 
                setSeverityFilter(new Set())
                setFixableOnly(false)
                setSearch('')
                setHideIgnored(true)
                setReachabilityFilter('all')
                setFixedInFilter('all')
                setFixabilityFilter('all')
                setPage(1)
              }}
              className="text-xs text-text-muted hover:text-text-primary flex items-center gap-1"
            >
              <X size={12} /> Clear
            </button>
          )}

          <span className="text-xs text-text-muted ml-auto">{filtered.length.toLocaleString()} issues</span>

          {/* Ignore All button */}
          {filtered.length > 0 && state.selectedOrg && (
            <button
              onClick={handleIgnoreAll}
              disabled={ignoringAll}
              className="btn-danger text-xs px-3 py-1.5"
              title="Ignore all currently filtered vulnerabilities"
            >
              {ignoringAll ? <Loader2 size={12} className="animate-spin" /> : <ShieldOff size={12} />}
              Ignore All ({filtered.length})
            </button>
          )}
        </div>

        {/* Success/Error messages */}
        {ignoreAllSuccess && (
          <div className="px-6 py-2 bg-accent-green/10 border-b border-accent-green/30 text-accent-green text-xs">
            Successfully ignored {filtered.length} vulnerabilities.
          </div>
        )}
        {ignoreAllError && (
          <div className="px-6 py-2 bg-red-950/40 border-b border-red-800/50 text-red-400 text-xs">
            Error: {ignoreAllError}
          </div>
        )}
      </div>

      {/* Table */}
      <div className="flex-1 overflow-auto">
        <table className="w-full text-sm">
          <thead className="sticky top-0 bg-bg-secondary border-b border-border z-10">
            <tr>
              <th className="px-4 py-3 text-left text-text-muted font-medium w-10">#</th>
              <th
                className="px-4 py-3 text-left text-text-muted font-medium cursor-pointer hover:text-text-primary select-none"
                onClick={() => handleSort('project')}
              >Project <SortIcon k="project" /></th>
              <th className="px-4 py-3 text-left text-text-muted font-medium">Package</th>
              <th
                className="px-4 py-3 text-left text-text-muted font-medium cursor-pointer hover:text-text-primary select-none"
                onClick={() => handleSort('severity')}
              >Severity <SortIcon k="severity" /></th>
              <th
                className="px-4 py-3 text-left text-text-muted font-medium cursor-pointer hover:text-text-primary select-none"
                onClick={() => handleSort('title')}
              >Vulnerability <SortIcon k="title" /></th>
              <th className="px-4 py-3 text-left text-text-muted font-medium">Fix</th>
              <th
                className="px-4 py-3 text-left text-text-muted font-medium cursor-pointer hover:text-text-primary select-none"
                onClick={() => handleSort('risk')}
              >Risk Score <SortIcon k="risk" /></th>
              <th className="px-4 py-3 text-left text-text-muted font-medium">Rating</th>
              <th className="px-4 py-3 text-left text-text-muted font-medium w-10"></th>
            </tr>
          </thead>
          <tbody>
            {paginated.length === 0 ? (
              <tr>
                <td colSpan={9} className="px-4 py-16 text-center text-text-muted">
                  <AlertCircle size={32} className="mx-auto mb-3 opacity-40" />
                  No vulnerabilities match your filters
                </td>
              </tr>
            ) : (
              paginated.map((fi, idx) => {
                const key = `${fi.projectId}-${fi.issue.id}-${idx}`
                const isExpanded = expandedKey === key
                const risk = riskLabel(fi.riskScore)
                const canFix = fi.issue.isUpgradable || fi.issue.isPatchable

                return (
                  <React.Fragment key={key}>
                    <tr
                      className={`border-b border-border/50 transition-colors cursor-pointer ${isExpanded ? 'bg-accent-purple/5' : 'table-row-hover'}`}
                      onClick={() => handleExpandRow(key)}
                    >
                      <td className="px-4 py-3 text-text-muted font-mono text-xs">{(page - 1) * PAGE_SIZE + idx + 1}</td>
                      <td className="px-4 py-3">
                        <p className="text-text-primary font-medium text-xs max-w-[160px] truncate" title={fi.projectName}>{fi.projectName}</p>
                        <p className="text-text-muted text-xs font-mono">{fi.projectType}</p>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-text-secondary font-mono text-xs">{fi.issue.pkgName}</span>
                        {fi.issue.pkgVersions?.length > 0 && (
                          <p className="text-text-muted text-xs mt-0.5">{fi.issue.pkgVersions.slice(0, 2).join(', ')}</p>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        <SeverityBadge severity={fi.issue.issueData.severity} showDot />
                      </td>
                      <td className="px-4 py-3">
                        <p className="text-text-primary text-xs max-w-[200px] truncate" title={fi.issue.issueData.title}>
                          {fi.issue.issueData.title}
                        </p>
                        <p className="text-text-muted text-xs font-mono mt-0.5">{fi.issue.issueData.id}</p>
                      </td>
                      <td className="px-4 py-3">
                        {canFix ? (
                          <span className="text-xs px-2 py-0.5 rounded-full bg-accent-green/10 text-accent-green border border-accent-green/20">
                            {fi.issue.isUpgradable ? 'Upgrade' : 'Patch'}
                          </span>
                        ) : (
                          <span className="text-text-muted text-xs">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3 font-mono text-text-secondary text-xs">
                        {fi.riskScore !== null ? fi.riskScore : '—'}
                      </td>
                      <td className={`px-4 py-3 text-xs font-medium ${risk.cls}`}>{risk.label}</td>
                      <td className="px-4 py-3">
                        <button
                          onClick={(e) => {
                            e.stopPropagation()
                            setSelectedIssue(fi)
                            setView('reachability')
                          }}
                          title="Launch Reachability Analysis"
                          className="text-text-muted hover:text-accent-purple transition-colors"
                        >
                          <FlaskConical size={14} />
                        </button>
                      </td>
                    </tr>
                    {isExpanded && (
                      <tr className="bg-bg-tertiary/40 border-b border-border">
                        <td colSpan={9} className="px-6 py-5">
                          <div className="space-y-6">
                            {/* Reachability Analysis Results */}
                            {(() => {
                              const reachabilityKey = `${fi.projectId}:${fi.issue.id}`
                              const reachability = state.reachabilityResults[reachabilityKey]
                              
                              if (reachability) {
                                return (
                                  <div className="p-4 bg-bg-secondary border border-border rounded-lg">
                                    <div className="flex items-center justify-between mb-3">
                                      <h4 className="text-sm font-semibold text-text-primary flex items-center gap-2">
                                        <FlaskConical size={16} className="text-accent-purple" />
                                        Reachability Analysis
                                      </h4>
                                      <span className={`text-xs px-2 py-1 rounded-full font-medium ${
                                        reachability.verdict === 'NOT REACHABLE' ? 'bg-accent-green/10 text-accent-green border border-accent-green/20' :
                                        reachability.verdict === 'LIKELY REACHABLE' ? 'bg-red-950/40 text-red-400 border border-red-800/50' :
                                        reachability.verdict === 'LIKELY NOT REACHABLE' ? 'bg-yellow-950/40 text-yellow-400 border border-yellow-800/50' :
                                        'bg-gray-700/40 text-gray-400 border border-gray-600/50'
                                      }`}>
                                        {reachability.verdict}
                                      </span>
                                    </div>
                                    {reachability.ollama_reasoning && (
                                      <div className="text-xs text-text-secondary leading-relaxed mb-3 p-3 bg-bg-primary/50 rounded border border-border/50">
                                        <p className="font-semibold text-text-primary mb-1">AI Analysis:</p>
                                        {reachability.ollama_reasoning}
                                      </div>
                                    )}
                                    <div className="grid grid-cols-3 gap-4 text-xs">
                                      <div>
                                        <span className="text-text-muted">Imports Found</span>
                                        <p className="text-text-primary font-mono mt-0.5">{reachability.import_count || 0}</p>
                                      </div>
                                      <div>
                                        <span className="text-text-muted">Functions Found</span>
                                        <p className="text-text-primary font-mono mt-0.5">{reachability.func_count || 0}</p>
                                      </div>
                                      <div>
                                        <span className="text-text-muted">Repository</span>
                                        <p className="text-text-primary font-mono mt-0.5">{reachability.repo_cloned ? 'Cloned' : 'Not Cloned'}</p>
                                      </div>
                                    </div>
                                  </div>
                                )
                              }
                              return null
                            })()}

                            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                              {/* Description */}
                              <div>
                                <h4 className="text-sm font-semibold text-text-primary mb-2">{fi.issue.issueData.title}</h4>
                                <p className="text-text-secondary text-xs leading-relaxed">{fi.issue.issueData.description || 'No description available.'}</p>
                              </div>
                              {/* Details */}
                              <div className="space-y-2 text-xs">
                                {fi.issue.issueData.cvssScore !== undefined && (
                                  <div className="flex justify-between">
                                    <span className="text-text-muted">CVSS Score</span>
                                    <span className="text-text-primary font-mono">{fi.issue.issueData.cvssScore}</span>
                                  </div>
                                )}
                                <div className="flex justify-between">
                                  <span className="text-text-muted">Package</span>
                                  <span className="text-text-primary font-mono">{fi.issue.issueData.packageName}</span>
                                </div>
                                <div className="flex justify-between">
                                  <span className="text-text-muted">Affected Versions</span>
                                  <span className="text-text-primary font-mono">{fi.issue.pkgVersions?.join(', ') || '—'}</span>
                                </div>
                                <div className="flex justify-between">
                                  <span className="text-text-muted">Upgradable</span>
                                  <span className={fi.issue.isUpgradable ? 'text-accent-green' : 'text-text-muted'}>{fi.issue.isUpgradable ? 'Yes' : 'No'}</span>
                                </div>
                                <div className="flex justify-between">
                                  <span className="text-text-muted">Patchable</span>
                                  <span className={fi.issue.isPatchable ? 'text-accent-green' : 'text-text-muted'}>{fi.issue.isPatchable ? 'Yes' : 'No'}</span>
                                </div>
                                {fi.issue.priority?.factors && fi.issue.priority.factors.length > 0 && (
                                  <div className="mt-3">
                                    <p className="text-text-muted mb-1.5">Risk Factors</p>
                                    {fi.issue.priority.factors.map((f, fi2) => (
                                      <div key={fi2} className="text-text-secondary mb-1">
                                        <span className="text-accent-purple">{f.name}: </span>{f.description}
                                      </div>
                                    ))}
                                  </div>
                                )}
                              </div>
                            </div>

                            {/* Action Buttons */}
                            <div className="flex items-center gap-3 pt-3 border-t border-border">
                              <button
                                onClick={(e) => {
                                  e.stopPropagation()
                                  handleIgnoreSingle(fi)
                                }}
                                disabled={ignoringItem === `${fi.projectId}-${fi.issue.id}`}
                                className="btn-danger text-xs px-4 py-2 flex items-center gap-2"
                                title={state.reachabilityResults[`${fi.projectId}:${fi.issue.id}`]?.ollama_reasoning 
                                  ? 'Ignore with AI analysis as reason' 
                                  : 'Ignore this vulnerability'}
                              >
                                {ignoringItem === `${fi.projectId}-${fi.issue.id}` ? (
                                  <>
                                    <Loader2 size={14} className="animate-spin" />
                                    Ignoring...
                                  </>
                                ) : ignoreSuccess === `${fi.projectId}-${fi.issue.id}` ? (
                                  <>
                                    <CheckCircle size={14} />
                                    Ignored
                                  </>
                                ) : (
                                  <>
                                    <ShieldOff size={14} />
                                    Ignore in Snyk
                                    {state.reachabilityResults[`${fi.projectId}:${fi.issue.id}`]?.ollama_reasoning && (
                                      <span className="text-xs opacity-75">(with AI analysis)</span>
                                    )}
                                  </>
                                )}
                              </button>
                              {ignoreError === `${fi.projectId}-${fi.issue.id}` && (
                                <span className="text-red-400 text-xs">Failed to ignore</span>
                              )}
                            </div>
                          </div>
                        </td>
                      </tr>
                    )}
                  </React.Fragment>
                )
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between px-6 py-3 border-t border-border bg-bg-secondary">
          <span className="text-xs text-text-muted">
            Page {page} of {totalPages} · {filtered.length.toLocaleString()} total
          </span>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={page === 1}
              className="btn-secondary py-1.5 px-3 text-sm disabled:opacity-30"
            >
              <ChevronLeft size={14} />
            </button>
            {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
              const p = Math.max(1, Math.min(page - 2, totalPages - 4)) + i
              if (p < 1 || p > totalPages) return null
              return (
                <button
                  key={p}
                  onClick={() => setPage(p)}
                  className={`w-8 h-8 rounded-lg text-xs font-medium transition-colors ${page === p ? 'bg-accent-purple text-white' : 'text-text-muted hover:text-text-primary hover:bg-bg-tertiary'}`}
                >
                  {p}
                </button>
              )
            })}
            <button
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              disabled={page === totalPages}
              className="btn-secondary py-1.5 px-3 text-sm disabled:opacity-30"
            >
              <ChevronRight size={14} />
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
