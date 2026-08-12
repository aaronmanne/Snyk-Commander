import React, { useState, useEffect, useMemo, useRef } from 'react'
import {
  FlaskConical, Search, FolderOpen, Play, Loader2, AlertCircle,
  ChevronDown, ChevronUp, CheckCircle, XCircle, Github,
  RefreshCw, Folder, AlertTriangle, Clock, Settings, ShieldOff
} from 'lucide-react'
import { useApp } from '../context/AppContext'
import { analyzeReachabilityFull, analyzeReachabilityBackground, getReachabilityJobStatus, openFolderDialog, getOllamaStatus, getStoredTokens, ignoreSingleIssue } from '../api'
import type { Issue, FlatIssue, ReachabilityAnalysisResult, OllamaStatus, OllamaModel } from '../types'
import SeverityBadge from '../components/SeverityBadge'
import VerdictBanner from '../components/VerdictBanner'
import MarkdownRenderer from '../components/MarkdownRenderer'

type AnalysisSource = 'github' | 'local'
type AnalysisPhase = 'idle' | 'resolving' | 'cloning' | 'scanning' | 'analyzing' | 'complete'

interface PhaseStatus {
  phase: AnalysisPhase
  status: 'pending' | 'active' | 'done' | 'error'
  message: string
  pct?: number
}

const PHASES: AnalysisPhase[] = ['resolving', 'cloning', 'scanning', 'analyzing']

function extractRepoFromProjectName(
  projectName: string,
  origin: string,
): { owner: string; repo: string; fullName: string } | null {
  const sources = [origin, projectName]
  for (const src of sources) {
    if (!src) continue
    const m1 = src.match(/github(?:\.com|-enterprise)\/([^/\s]+)\/([^/:()\s]+)/i)
    if (m1) {
      const owner = m1[1], repo = stripRepoSuffix(m1[2])
      return { owner, repo, fullName: `${owner}/${repo}` }
    }
    const m2 = src.match(/^([^/\s]+)\/([^/(:\s]+)/)
    if (m2) {
      const owner = m2[1], repo = stripRepoSuffix(m2[2])
      return { owner, repo, fullName: `${owner}/${repo}` }
    }
  }
  return null
}

function stripRepoSuffix(s: string): string {
  return s.replace(/\.git$/, '').replace(/[():#\s].*$/, '')
}

function phaseLabel(p: AnalysisPhase): string {
  switch (p) {
    case 'resolving': return 'Resolving repository'
    case 'cloning': return 'Cloning repository'
    case 'scanning': return 'Scanning codebase'
    case 'analyzing': return 'AI analysis'
    default: return p
  }
}

function PhaseIcon({ status }: { status: PhaseStatus['status'] }) {
  switch (status) {
    case 'done': return <CheckCircle size={14} className="text-accent-green flex-shrink-0" />
    case 'active': return <Loader2 size={14} className="animate-spin text-accent-purple flex-shrink-0" />
    case 'error': return <XCircle size={14} className="text-red-400 flex-shrink-0" />
    default: return <div className="w-3.5 h-3.5 rounded-full border border-border-light flex-shrink-0" />
  }
}

export default function ReachabilityView() {
  const { state, setView, setGithubToken, setSelectedIssue, updateReachabilityResult, loadReachabilityResults, addBackgroundJob, updateBackgroundJob, removeBackgroundJob } = useApp()
  const [githubToken, setLocalGithubToken] = useState(state.githubToken || '')
  const [gheHost, setGheHost] = useState<string | null>(null)

  useEffect(() => {
    getStoredTokens()
      .then(res => {
        if (res.github && res.github !== githubToken) {
          setLocalGithubToken(res.github)
          setGithubToken(res.github)
        }
        if (res.ghe_host) setGheHost(res.ghe_host)
      })
      .catch(() => {})
  }, [])

  // ── Issues ───────────────────────────────────────────────────────────────────
  const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 }

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
    flat.sort((a, b) => {
      const sevA = SEV_RANK[a.issue.issueData.severity] ?? 4
      const sevB = SEV_RANK[b.issue.issueData.severity] ?? 4
      if (sevA !== sevB) return sevA - sevB
      return (b.riskScore ?? 0) - (a.riskScore ?? 0)
    })
    return flat
  }, [state.scanResults])

  const [issueSearch, setIssueSearch] = useState('')
  const [selectedIssue, setLocalSelectedIssue] = useState<FlatIssue | null>(null)
  const [showIssuePicker, setShowIssuePicker] = useState(false)

  // Auto-select issue from context when navigating from Vulnerabilities page
  useEffect(() => {
    if (state.selectedIssue) {
      setLocalSelectedIssue(state.selectedIssue)
      setSelectedIssue(null) // Clear from context after loading
    }
  }, [state.selectedIssue, setSelectedIssue])

  const filteredIssues = useMemo(() => {
    if (!issueSearch.trim()) return allIssues.slice(0, 100)
    const q = issueSearch.toLowerCase()
    return allIssues.filter(fi =>
      fi.issue.issueData.title.toLowerCase().includes(q) ||
      fi.issue.pkgName.toLowerCase().includes(q) ||
      fi.projectName.toLowerCase().includes(q)
    ).slice(0, 100)
  }, [allIssues, issueSearch])

  // ── Source ───────────────────────────────────────────────────────────────────
  const [source, setSource] = useState<AnalysisSource>(githubToken ? 'github' : 'local')
  const [codebasePath, setCodebasePath] = useState('')

  const { projectOrigin, projectName: selectedProjectName, extractedRepo } = useMemo(() => {
    if (!selectedIssue) return { projectOrigin: '', projectName: '', extractedRepo: null }
    const project = state.scanResults.find(p => p.id === selectedIssue.projectId)
    const name = project?.name || ''
    const origin = project?.origin || ''
    const extracted = extractRepoFromProjectName(name, origin)
    return { projectOrigin: origin, projectName: name, extractedRepo: extracted }
  }, [selectedIssue, state.scanResults])

  // ── Ollama ───────────────────────────────────────────────────────────────────
  const [ollamaStatus, setOllamaStatus] = useState<OllamaStatus | null>(null)
  const [ollamaLoading, setOllamaLoading] = useState(false)
  const [selectedModel, setSelectedModel] = useState('llama3')

  const refreshOllama = async () => {
    setOllamaLoading(true)
    try {
      const status = await getOllamaStatus()
      setOllamaStatus(status)
      if (status.available && status.models.length > 0 && !selectedModel) {
        setSelectedModel(status.models[0].name)
      }
    } catch {
      setOllamaStatus({ available: false, version: null, models: [], error: 'Failed to connect to Ollama' })
    } finally {
      setOllamaLoading(false)
    }
  }

  useEffect(() => { refreshOllama() }, [])

  // ── Analysis State ───────────────────────────────────────────────────────────
  const [running, setRunning] = useState(false)
  const [phases, setPhases] = useState<PhaseStatus[]>([])
  const [currentPhaseName, setCurrentPhaseName] = useState('')
  const [currentPct, setCurrentPct] = useState(0)
  const [result, setResult] = useState<ReachabilityAnalysisResult | null>(null)
  const [error, setError] = useState('')
  const [reasoningExpanded, setReasoningExpanded] = useState(true)
  const [rawMarkdown, setRawMarkdown] = useState(false)

  // ── Ignore State ─────────────────────────────────────────────────────────────
  const [showIgnoreModal, setShowIgnoreModal] = useState(false)
  const [ignoreNotes, setIgnoreNotes] = useState('')
  const [ignoreLoading, setIgnoreLoading] = useState(false)
  const [ignoreSuccess, setIgnoreSuccess] = useState(false)
  const [ignoreError, setIgnoreError] = useState('')

  // ── Batch Analysis State ─────────────────────────────────────────────────────
  type BatchResultItem = {
    issue: FlatIssue
    result: ReachabilityAnalysisResult | null
    error: string | null
  }
  const [batchMode, setBatchMode] = useState(false)
  const [batchResults, setBatchResults] = useState<BatchResultItem[]>([])
  const [batchProgress, setBatchProgress] = useState({ current: 0, total: 0 })
  const [batchComplete, setBatchComplete] = useState(false)
  const [showBatchReport, setShowBatchReport] = useState(false)

  const initPhases = (): PhaseStatus[] =>
    PHASES.map(p => ({ phase: p, status: 'pending' as const, message: '' }))

  const phaseQueue = useRef<Array<{ phaseName: string; message: string; pct?: number }>>([])
  const rafPending = useRef(false)
  const rafId = useRef<number>(0)
  const runId = useRef(0)   // incremented each run so stale callbacks are ignored

  const flushPhaseQueue = () => {
    rafPending.current = false
    const queue = phaseQueue.current.splice(0)
    if (queue.length === 0) return

    const byPhase = new Map<string, typeof queue[0]>()
    for (const item of queue) byPhase.set(item.phaseName, item)
    const updates = Array.from(byPhase.values())

    const last = queue[queue.length - 1]
    setCurrentPhaseName(last.phaseName)
    if (last.pct !== undefined) setCurrentPct(last.pct)

    setPhases(prev => {
      let next = [...prev]
      for (const { phaseName, message, pct } of updates) {
        next = next.map(p => {
          if (p.phase === phaseName) {
            return { ...p, status: 'active' as const, message, pct }
          }
          const idx = PHASES.indexOf(p.phase as AnalysisPhase)
          const curIdx = PHASES.indexOf(phaseName as AnalysisPhase)
          if (idx < curIdx && p.status !== 'done' && p.status !== 'error') {
            return { ...p, status: 'done' as const }
          }
          return p
        })
      }
      return next
    })
  }

  const updatePhase = (phaseName: string, message: string, pct?: number) => {
    phaseQueue.current.push({ phaseName, message, pct })
    if (!rafPending.current) {
      rafPending.current = true
      rafId.current = requestAnimationFrame(flushPhaseQueue)
    }
  }

  const handleBrowse = async () => {
    try {
      const p = await openFolderDialog()
      if (p) setCodebasePath(p)
    } catch { /* typed manually */ }
  }

  const canRun = !running && !!selectedIssue && (
    (source === 'github' && !!githubToken && !!extractedRepo) ||
    (source === 'local' && !!codebasePath.trim())
  )

  const handleRun = async () => {
    if (!selectedIssue) return

    // Cancel any pending RAF from a previous run
    if (rafId.current) cancelAnimationFrame(rafId.current)
    phaseQueue.current = []
    rafPending.current = false

    // Increment run ID so any stale callbacks from a previous run are ignored
    const thisRunId = ++runId.current

    const isRescan = result !== null  // true if we already have a result → force fresh clone

    setRunning(true)
    setResult(null)
    setError('')
    setIgnoreSuccess(false)
    setIgnoreError('')
    setPhases(initPhases())
    setCurrentPct(0)
    setCurrentPhaseName('')

    try {
      // Start background analysis if we have all required IDs
      if (state.selectedOrg && selectedIssue.projectId && selectedIssue.issue.id) {
        const bgRes = await analyzeReachabilityBackground(
          state.selectedOrg.id,
          selectedIssue.projectId,
          selectedIssue.issue.id,
          selectedIssue.issue,
          selectedIssue.projectName,
          projectOrigin,
          source === 'github' ? githubToken : null,
          selectedModel || 'llama3',
          source === 'local' ? codebasePath.trim() : null,
          gheHost,
          isRescan
        )

        // Add to background jobs
        addBackgroundJob({
          jobId: bgRes.jobId,
          projectId: selectedIssue.projectId,
          issueId: selectedIssue.issue.id,
          issueName: selectedIssue.issue.issueData?.title || 'Unknown Issue',
          projectName: selectedIssue.projectName,
          status: 'queued',
          progress: { phase: 'queued', message: 'Starting analysis...', pct: 0 },
          startedAt: Date.now(),
        })

        // Poll for job status
        const jobId = bgRes.jobId
        let jobComplete = false
        
        while (!jobComplete && runId.current === thisRunId) {
          await new Promise(resolve => setTimeout(resolve, 1000))
          
          const jobStatus = await getReachabilityJobStatus(jobId)
          
          if (jobStatus.progress) {
            updatePhase(jobStatus.progress.phase, jobStatus.progress.message, jobStatus.progress.pct)
            updateBackgroundJob(jobId, jobStatus.status, jobStatus.progress)
          }
          
          if (jobStatus.status === 'completed') {
            jobComplete = true
            if (runId.current !== thisRunId) return
            setPhases(prev => prev.map(p => ({ ...p, status: 'done' as const })))
            setResult(jobStatus.result as any)
            
            // Update context with result
            updateReachabilityResult(selectedIssue.projectId, selectedIssue.issue.id, jobStatus.result as any)
            
            // Remove from background jobs after 3 seconds
            setTimeout(() => removeBackgroundJob(jobId), 3000)
          } else if (jobStatus.status === 'failed') {
            if (runId.current !== thisRunId) return
            setError(jobStatus.error || 'Analysis failed')
            setPhases(prev => prev.map(p =>
              p.status === 'active' ? { ...p, status: 'error' as const } : p
            ))
            updateBackgroundJob(jobId, 'failed', { phase: 'error', message: jobStatus.error || 'Failed', pct: 0 })
            // Remove from background jobs after 5 seconds
            setTimeout(() => removeBackgroundJob(jobId), 5000)
            return
          }
        }
      } else {
        // Fallback to non-background mode
        const res = await analyzeReachabilityFull(
          selectedIssue.issue,
          selectedIssue.projectName,
          projectOrigin,
          source === 'github' ? githubToken : null,
          selectedModel || 'llama3',
          source === 'local' ? codebasePath.trim() : null,
          gheHost,
          (phase: string, message: string, pct?: number) => {
            if (runId.current !== thisRunId) return  // stale callback — ignore
            updatePhase(phase, message, pct)
          },
          isRescan  // force_reclone on every re-run
        )
        if (runId.current !== thisRunId) return
        setPhases(prev => prev.map(p => ({ ...p, status: 'done' as const })))
        setResult(res.result)
        
        // Update context with result if we have IDs
        if (state.selectedOrg && selectedIssue.projectId && selectedIssue.issue.id) {
          updateReachabilityResult(selectedIssue.projectId, selectedIssue.issue.id, res.result)
        }
      }
    } catch (e: unknown) {
      if (runId.current !== thisRunId) return
      setError(e instanceof Error ? e.message : String(e))
      setPhases(prev => prev.map(p =>
        p.status === 'active' ? { ...p, status: 'error' as const } : p
      ))
    } finally {
      if (runId.current === thisRunId) setRunning(false)
    }
  }

  // ── Ignore Handler ───────────────────────────────────────────────────────────
  const isNotReachableVerdict = result &&
    (result.verdict === 'NOT REACHABLE' || result.verdict === 'LIKELY NOT REACHABLE')

  const handleIgnoreConfirm = async () => {
    if (!selectedIssue || !state.selectedOrg) return
    setIgnoreLoading(true)
    setIgnoreError('')
    try {
      const reason = ignoreNotes.trim()
        || 'Reachability analysis confirmed this vulnerability is not reachable in the codebase.'
      await ignoreSingleIssue(
        state.selectedOrg.id,
        state.token,
        selectedIssue.projectId,
        selectedIssue.issue.id,
        reason
      )
      setIgnoreSuccess(true)
      setShowIgnoreModal(false)
      setIgnoreNotes('')
    } catch (e: unknown) {
      setIgnoreError(e instanceof Error ? e.message : String(e))
    } finally {
      setIgnoreLoading(false)
    }
  }

  // ── Batch Analysis Handler ───────────────────────────────────────────────────
  const handleAnalyzeAll = async () => {
    if (allIssues.length === 0) return

    setBatchMode(true)
    setBatchComplete(false)
    setShowBatchReport(false)
    setBatchResults([])
    setBatchProgress({ current: 0, total: allIssues.length })

    // Add a fake background job to show batch progress
    const batchJobId = `batch-${Date.now()}`
    addBackgroundJob({
      jobId: batchJobId,
      projectId: 'batch',
      issueId: 'batch',
      issueName: 'Batch Analysis',
      projectName: `Analyzing ${allIssues.length} vulnerabilities`,
      status: 'running',
      progress: { phase: 'analyzing', message: 'Running batch analysis...', pct: 0 },
      startedAt: Date.now(),
    })

    const results: BatchResultItem[] = []
    
    for (let i = 0; i < allIssues.length; i++) {
      const issue = allIssues[i]
      setBatchProgress({ current: i + 1, total: allIssues.length })
      
      // Update batch job progress
      updateBackgroundJob(batchJobId, 'running', {
        phase: 'analyzing',
        message: `Analyzing ${i + 1} of ${allIssues.length}`,
        pct: Math.round(((i + 1) / allIssues.length) * 100)
      })
      
      try {
        const project = state.scanResults.find(p => p.id === issue.projectId)
        const projectOrigin = project?.origin || ''
        
        const res = await analyzeReachabilityFull(
          issue.issue,
          issue.projectName,
          projectOrigin,
          source === 'github' ? githubToken : null,
          selectedModel || 'llama3',
          source === 'local' ? codebasePath.trim() : null,
          gheHost,
          () => {}, // No progress callback for batch
          false // Don't force reclone for each analysis
        )
        
        // Save result to context
        if (state.selectedOrg && issue.projectId && issue.issue.id) {
          updateReachabilityResult(issue.projectId, issue.issue.id, res.result)
        }
        
        results.push({
          issue,
          result: res.result,
          error: null
        })
      } catch (e: unknown) {
        // Continue on error
        results.push({
          issue,
          result: null,
          error: e instanceof Error ? e.message : String(e)
        })
      }
    }

    setBatchResults(results)
    setBatchComplete(true)
    setShowBatchReport(true)
    setBatchMode(false)
    
    // Mark batch job as complete and remove after 3 seconds
    updateBackgroundJob(batchJobId, 'completed', {
      phase: 'done',
      message: `Analyzed ${allIssues.length} vulnerabilities`,
      pct: 100
    })
    setTimeout(() => removeBackgroundJob(batchJobId), 3000)
  }

  // ── Batch Ignore All Unreachable ─────────────────────────────────────────────
  const handleIgnoreAllUnreachable = async () => {
    if (!state.selectedOrg) return
    
    const unreachable = batchResults.filter(r => 
      r.result && (r.result.verdict === 'NOT REACHABLE' || r.result.verdict === 'LIKELY NOT REACHABLE')
    )

    setIgnoreLoading(true)
    let successCount = 0
    let failCount = 0

    for (const item of unreachable) {
      try {
        await ignoreSingleIssue(
          state.selectedOrg.id,
          state.token,
          item.issue.projectId,
          item.issue.issue.id,
          'Batch reachability analysis confirmed this vulnerability is not reachable in the codebase.'
        )
        successCount++
      } catch (e) {
        failCount++
      }
    }

    setIgnoreLoading(false)
    alert(`Ignored ${successCount} unreachable vulnerabilities. ${failCount > 0 ? `Failed to ignore ${failCount}.` : ''}`)
  }

  const matchTypeColor = (type: string) => {
    switch (type.toLowerCase()) {
      case 'import': return 'text-blue-400 bg-blue-900/20 border-blue-700/30'
      case 'function_call': return 'text-accent-purple bg-accent-purple/10 border-accent-purple/30'
      case 'usage': return 'text-orange-400 bg-orange-900/20 border-orange-700/30'
      default: return 'text-text-muted bg-bg-tertiary border-border'
    }
  }

  return (
    <div className="flex-1 overflow-y-auto bg-bg-primary p-6">
      <div className="max-w-5xl mx-auto">
        {/* Header */}
        <div className="flex items-center gap-3 mb-6">
          <div className="w-10 h-10 bg-accent-purple/10 border border-accent-purple/30 rounded-xl flex items-center justify-center">
            <FlaskConical size={20} className="text-accent-purple" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-text-primary">Reachability Analysis</h1>
            <p className="text-text-muted text-sm">Analyze if a vulnerability is reachable in your codebase</p>
          </div>
        </div>

        {/* Config panel */}
        <div className="bg-bg-secondary border border-border rounded-xl p-5 mb-6 space-y-5">

          {/* Row 1: Issue picker */}
          <div>
            <label className="block text-sm font-medium text-text-secondary mb-2">
              Vulnerability to Analyze
            </label>
            <div className="relative">
              <button
                onClick={() => setShowIssuePicker(v => !v)}
                className="input-base text-left flex items-center justify-between w-full"
              >
                {selectedIssue ? (
                  <div className="flex items-center gap-3 flex-1 min-w-0">
                    <SeverityBadge severity={selectedIssue.issue.issueData.severity} />
                    <span className="text-text-primary text-sm truncate">{selectedIssue.issue.issueData.title}</span>
                    <span className="text-text-muted text-xs font-mono flex-shrink-0">({selectedIssue.issue.pkgName})</span>
                  </div>
                ) : (
                  <span className="text-text-muted">Select a vulnerability...</span>
                )}
                {showIssuePicker ? <ChevronUp size={16} className="flex-shrink-0 ml-2" /> : <ChevronDown size={16} className="flex-shrink-0 ml-2" />}
              </button>

              {showIssuePicker && (
                <div className="absolute top-full left-0 right-0 z-20 mt-1 bg-bg-secondary border border-border rounded-xl shadow-2xl max-h-80 overflow-hidden flex flex-col">
                  <div className="p-2 border-b border-border">
                    <div className="relative">
                      <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-text-muted" />
                      <input
                        type="text"
                        placeholder="Search vulnerabilities..."
                        value={issueSearch}
                        onChange={e => setIssueSearch(e.target.value)}
                        className="input-base pl-9 text-sm py-1.5"
                        autoFocus
                      />
                    </div>
                  </div>
                  <div className="overflow-y-auto">
                    {filteredIssues.length === 0 ? (
                      <p className="p-4 text-text-muted text-sm text-center">No issues found</p>
                    ) : (
                      filteredIssues.map((fi, idx) => (
                        <button
                          key={`${fi.projectId}-${fi.issue.id}-${idx}`}
                          onClick={() => { setLocalSelectedIssue(fi); setShowIssuePicker(false) }}
                          className="w-full flex items-start gap-3 px-4 py-3 hover:bg-bg-tertiary transition-colors text-left border-b border-border/50"
                        >
                          <SeverityBadge severity={fi.issue.issueData.severity} />
                          <div className="flex-1 min-w-0">
                            <p className="text-text-primary text-xs font-medium truncate">{fi.issue.issueData.title}</p>
                            <p className="text-text-muted text-xs mt-0.5 truncate">{fi.projectName} · {fi.issue.pkgName}</p>
                          </div>
                        </button>
                      ))
                    )}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Row 2: Source selection */}
          <div>
            <label className="block text-sm font-medium text-text-secondary mb-2">Source</label>
            <div className="flex gap-2 mb-3">
              <button
                onClick={() => setSource('github')}
                className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-sm transition-colors ${
                  source === 'github'
                    ? 'border-accent-purple bg-accent-purple/10 text-accent-purple'
                    : 'border-border text-text-secondary hover:border-border-light'
                }`}
              >
                <Github size={14} />
                Auto-clone from GitHub
              </button>
              <button
                onClick={() => setSource('local')}
                className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-sm transition-colors ${
                  source === 'local'
                    ? 'border-accent-purple bg-accent-purple/10 text-accent-purple'
                    : 'border-border text-text-secondary hover:border-border-light'
                }`}
              >
                <Folder size={14} />
                Local path
              </button>
            </div>

            {source === 'github' ? (
              <div>
                {!githubToken ? (
                  <div className="flex items-start gap-2 p-3 bg-yellow-950/30 border border-yellow-700/30 rounded-lg text-yellow-400 text-sm">
                    <AlertTriangle size={15} className="flex-shrink-0 mt-0.5" />
                    <div className="flex-1">
                      <p className="font-medium mb-1">GitHub not connected</p>
                      <p className="text-xs text-yellow-400/80 mb-2">Connect your GitHub account to enable automatic repository cloning.</p>
                      <button
                        onClick={() => setView('settings')}
                        className="flex items-center gap-1.5 text-xs bg-yellow-900/30 border border-yellow-700/40 hover:bg-yellow-900/50 px-3 py-1.5 rounded-lg transition-colors"
                      >
                        <Settings size={12} />
                        Open Settings to connect GitHub
                      </button>
                    </div>
                  </div>
                ) : selectedIssue && extractedRepo ? (
                  <div className="flex flex-col gap-1 p-3 bg-bg-tertiary border border-border rounded-lg text-sm text-text-secondary">
                    <div className="flex items-center gap-2">
                      <Github size={14} className="text-accent-green flex-shrink-0" />
                      <span>Will clone</span>
                      <span className="font-mono text-text-primary">{extractedRepo.fullName}</span>
                    </div>
                    <p className="text-xs text-text-muted pl-5">
                      Cached at ~/.snyk-commander/repos/{extractedRepo.owner}/{extractedRepo.repo}/ · pulled fresh if already exists
                    </p>
                  </div>
                ) : selectedIssue ? (
                  <div className="flex items-center gap-2 p-3 bg-yellow-950/20 border border-yellow-700/30 rounded-lg text-sm text-yellow-400/80">
                    <AlertTriangle size={14} className="flex-shrink-0" />
                    Cannot determine GitHub repository from this project — use Local Path instead
                  </div>
                ) : (
                  <div className="flex items-center gap-2 p-3 bg-bg-tertiary border border-border rounded-lg text-sm text-text-muted">
                    <Github size={14} className="flex-shrink-0" />
                    Select a vulnerability to see the repository
                  </div>
                )}
              </div>
            ) : (
              <div className="flex gap-2">
                <input
                  type="text"
                  placeholder="/path/to/your/project"
                  value={codebasePath}
                  onChange={e => setCodebasePath(e.target.value)}
                  className="input-base flex-1 font-mono text-sm"
                />
                <button onClick={handleBrowse} className="btn-secondary flex-shrink-0">
                  <FolderOpen size={16} />
                  Browse
                </button>
              </div>
            )}
          </div>

          {/* Row 3: Ollama model */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-sm font-medium text-text-secondary">Ollama Model</label>
              <button
                onClick={refreshOllama}
                disabled={ollamaLoading}
                className="flex items-center gap-1 text-xs text-text-muted hover:text-text-secondary transition-colors"
              >
                <RefreshCw size={12} className={ollamaLoading ? 'animate-spin' : ''} />
                Refresh
              </button>
            </div>

            <div className="flex items-center gap-2 mb-2">
              {ollamaLoading ? (
                <span className="flex items-center gap-1.5 text-xs text-text-muted">
                  <Loader2 size={11} className="animate-spin" /> Checking Ollama...
                </span>
              ) : ollamaStatus?.available ? (
                <span className="flex items-center gap-1.5 text-xs text-accent-green">
                  <div className="w-1.5 h-1.5 rounded-full bg-accent-green" />
                  Ollama running · {ollamaStatus.models.length} model{ollamaStatus.models.length !== 1 ? 's' : ''} available
                </span>
              ) : (
                <span className="flex items-center gap-1.5 text-xs text-yellow-400">
                  <AlertTriangle size={11} />
                  {ollamaStatus?.error || 'Ollama not detected'} — analysis will use heuristic fallback
                </span>
              )}
            </div>

            {ollamaStatus?.available && ollamaStatus.models.length > 0 ? (
              <select
                value={selectedModel}
                onChange={e => setSelectedModel(e.target.value)}
                className="input-base text-sm font-mono"
              >
                {ollamaStatus.models.map((m: OllamaModel) => (
                  <option key={m.name} value={m.name}>
                    {m.name}{m.details?.parameter_size ? ` (${m.details.parameter_size})` : ''}
                  </option>
                ))}
              </select>
            ) : (
              <input
                type="text"
                placeholder="llama3"
                value={selectedModel}
                onChange={e => setSelectedModel(e.target.value)}
                disabled={!!(ollamaStatus && !ollamaStatus.available)}
                className="input-base font-mono text-sm disabled:opacity-50"
              />
            )}
          </div>

          {/* Row 4: Run / Rescan / Analyze All buttons */}
          <div className="flex gap-3">
            <button
              onClick={handleRun}
              disabled={!canRun}
              className="btn-primary flex-1 justify-center py-3"
            >
              {running ? <Loader2 size={18} className="animate-spin" /> : <Play size={18} />}
              {running ? 'Running Analysis...' : result ? '↺ Re-run Analysis' : '▶ Run Reachability Analysis'}
            </button>
            <button
              onClick={handleAnalyzeAll}
              disabled={batchMode || running || allIssues.length === 0}
              className="btn-secondary justify-center py-3 px-6 whitespace-nowrap"
              title="Analyze all vulnerabilities one by one"
            >
              {batchMode ? <Loader2 size={18} className="animate-spin" /> : <FlaskConical size={18} />}
              {batchMode ? `Analyzing ${batchProgress.current}/${batchProgress.total}...` : 'Analyze All'}
            </button>
          </div>
        </div>

        {/* Progress section */}
        {running && phases.length > 0 && (
          <div className="bg-bg-secondary border border-border rounded-xl p-5 mb-6">
            <div className="mb-4">
              <div className="flex items-center justify-between mb-2">
                <div className="flex items-center gap-2">
                  <Loader2 size={14} className="animate-spin text-accent-purple" />
                  <span className="text-sm font-medium text-text-secondary capitalize">
                    {currentPhaseName || 'Starting...'}
                  </span>
                </div>
                <span className="text-xs text-text-muted font-mono">{currentPct}%</span>
              </div>
              <div className="h-1.5 bg-bg-tertiary rounded-full overflow-hidden">
                <div
                  className="h-full bg-accent-purple transition-all duration-300 rounded-full"
                  style={{ width: `${currentPct}%` }}
                />
              </div>
            </div>

            <div className="space-y-2">
              <p className="text-xs font-medium text-text-muted mb-1">Phase log:</p>
              {phases.map(p => (
                <div key={p.phase} className="flex items-center gap-2">
                  <PhaseIcon status={p.status} />
                  <span className={`text-xs ${
                    p.status === 'active' ? 'text-text-primary' :
                    p.status === 'done' ? 'text-text-secondary' :
                    p.status === 'error' ? 'text-red-400' :
                    'text-text-muted'
                  }`}>
                    <span className="font-medium">{phaseLabel(p.phase)}</span>
                    {p.message ? `: ${p.message}` : ''}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Error */}
        {error && (
          <div className="flex items-start gap-2 p-4 bg-red-950/40 border border-red-800/50 rounded-xl mb-6 text-red-400 text-sm">
            <AlertCircle size={16} className="flex-shrink-0 mt-0.5" />
            <div>
              <p className="font-medium">Analysis Failed</p>
              <p className="mt-0.5 text-red-400/80">{error}</p>
            </div>
          </div>
        )}

        {/* Results */}
        {result && !running && (
          <div className="space-y-5">

            {/* Verdict banner — with ignore button always available */}
            <VerdictBanner
              verdict={result.verdict as 'LIKELY REACHABLE' | 'NOT REACHABLE' | 'LIKELY NOT REACHABLE' | 'INCONCLUSIVE'}
              onIgnore={state.selectedOrg ? () => {
                // Pre-fill ignore notes with LLM reasoning
                if (result.ollama_reasoning) {
                  setIgnoreNotes(`AI Analysis: ${result.ollama_reasoning}`)
                }
                setShowIgnoreModal(true)
              } : undefined}
              ignoreLoading={ignoreLoading}
            />

            {/* Ignore success banner */}
            {ignoreSuccess && (
              <div className="flex items-center gap-3 p-4 bg-green-950/30 border border-green-700/50 rounded-xl text-green-300 text-sm">
                <CheckCircle size={16} className="flex-shrink-0" />
                <span>Vulnerability successfully ignored in Snyk.</span>
              </div>
            )}

            {/* Repo info card */}
            {result.repo_cloned && result.repo_info && (
              <div className="bg-bg-secondary border border-border rounded-xl p-4">
                <div className="flex items-center gap-2 mb-2">
                  <Folder size={15} className="text-accent-purple" />
                  <span className="text-sm font-semibold text-text-primary">Repository</span>
                </div>
                <div className="space-y-1 text-xs text-text-secondary font-mono">
                  <p>github.com/{result.repo_info.owner}/{result.repo_info.repo}</p>
                  {result.repo_info.branch && (
                    <p className="text-text-muted">Branch: <span className="text-text-secondary">{result.repo_info.branch}</span></p>
                  )}
                  {result.repo_path && (
                    <p className="text-text-muted truncate" title={result.repo_path}>
                      Path: <span className="text-text-secondary">{result.repo_path}</span>
                    </p>
                  )}
                </div>
              </div>
            )}

            {/* Summary cards */}
            <div className="grid grid-cols-3 gap-4">
              {[
                { label: 'Import Statements', value: result.import_count, color: 'text-blue-400' },
                { label: 'Function Calls', value: result.func_count, color: 'text-accent-purple' },
                { label: 'Total Matches', value: result.matches.length, color: 'text-accent-green' },
              ].map(card => (
                <div key={card.label} className="bg-bg-secondary border border-border rounded-xl p-4 text-center">
                  <p className={`text-3xl font-bold ${card.color}`}>{card.value}</p>
                  <p className="text-text-muted text-xs mt-1">{card.label}</p>
                </div>
              ))}
            </div>

            {/* Matches table */}
            {result.matches.length > 0 && (
              <div className="bg-bg-secondary border border-border rounded-xl overflow-hidden">
                <div className="px-5 py-3 border-b border-border">
                  <h3 className="text-sm font-semibold text-text-primary">{result.matches.length} Code Matches</h3>
                </div>
                <div className="overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-border bg-bg-tertiary">
                        <th className="px-4 py-2.5 text-left text-text-muted font-medium">File</th>
                        <th className="px-4 py-2.5 text-left text-text-muted font-medium">Line</th>
                        <th className="px-4 py-2.5 text-left text-text-muted font-medium">Type</th>
                        <th className="px-4 py-2.5 text-left text-text-muted font-medium">Code</th>
                      </tr>
                    </thead>
                    <tbody>
                      {result.matches.map((m, i) => {
                        const displayFile = result.repo_path && m.file.startsWith(result.repo_path)
                          ? m.file.slice(result.repo_path.length).replace(/^\//, '')
                          : m.file
                        return (
                          <tr key={i} className="border-b border-border/50 table-row-hover">
                            <td className="px-4 py-2.5 font-mono text-text-secondary max-w-[200px] truncate" title={m.file}>
                              {displayFile}
                            </td>
                            <td className="px-4 py-2.5 font-mono text-accent-purple">{m.line}</td>
                            <td className="px-4 py-2.5">
                              <span className={`px-2 py-0.5 rounded-full border text-xs ${matchTypeColor(m.match_type)}`}>
                                {m.match_type}
                              </span>
                            </td>
                            <td className="px-4 py-2.5 font-mono text-text-primary max-w-xs truncate" title={m.content}>
                              {m.content}
                            </td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {/* AI Reasoning */}
            {result.ollama_reasoning && (
              <div className="bg-bg-secondary border border-border rounded-xl overflow-hidden">
                <div className="flex items-center justify-between px-5 py-3 border-b border-border">
                  <button
                    onClick={() => setReasoningExpanded(v => !v)}
                    className="flex items-center gap-2 flex-1 text-left hover:opacity-80 transition-opacity"
                  >
                    <FlaskConical size={15} className="text-accent-purple" />
                    <span className="text-sm font-semibold text-text-primary">AI Reasoning (Ollama)</span>
                    {reasoningExpanded
                      ? <ChevronUp size={14} className="text-text-muted ml-1" />
                      : <ChevronDown size={14} className="text-text-muted ml-1" />
                    }
                  </button>
                  {reasoningExpanded && (
                    <div className="flex items-center gap-1 ml-4 bg-bg-tertiary border border-border rounded-lg p-0.5 flex-shrink-0">
                      <button
                        onClick={() => setRawMarkdown(false)}
                        className={`px-2.5 py-1 text-xs rounded font-medium transition-colors ${
                          !rawMarkdown ? 'bg-accent-purple text-white' : 'text-text-muted hover:text-text-secondary'
                        }`}
                      >
                        Rendered
                      </button>
                      <button
                        onClick={() => setRawMarkdown(true)}
                        className={`px-2.5 py-1 text-xs rounded font-medium transition-colors ${
                          rawMarkdown ? 'bg-accent-purple text-white' : 'text-text-muted hover:text-text-secondary'
                        }`}
                      >
                        Raw
                      </button>
                    </div>
                  )}
                </div>

                {reasoningExpanded && (
                  <div className="px-5 py-4">
                    {rawMarkdown ? (
                      <pre className="text-text-secondary text-xs leading-relaxed whitespace-pre-wrap font-mono bg-bg-tertiary border border-border rounded-lg p-4 overflow-x-auto">
                        {result.ollama_reasoning}
                      </pre>
                    ) : (
                      <MarkdownRenderer content={result.ollama_reasoning} />
                    )}
                  </div>
                )}
              </div>
            )}

            {/* Error details */}
            {result.error_details && (
              <div className="flex items-start gap-3 p-4 bg-yellow-950/20 border border-yellow-700/30 rounded-xl">
                <AlertTriangle size={15} className="text-yellow-400 flex-shrink-0 mt-0.5" />
                <div>
                  <p className="text-sm font-semibold text-yellow-400 mb-1">⚠ Analysis Note</p>
                  <p className="text-xs text-yellow-300/80 leading-relaxed">{result.error_details}</p>
                </div>
              </div>
            )}
          </div>
        )}

        {/* ── Batch Report ──────────────────────────────────────────────────────── */}
        {showBatchReport && batchComplete && batchResults.length > 0 && (
          <div className="space-y-5 mt-6">
            <div className="bg-bg-secondary border border-border rounded-xl p-5">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h2 className="text-lg font-bold text-text-primary">Batch Analysis Report</h2>
                  <p className="text-text-muted text-sm mt-1">Analyzed {batchResults.length} vulnerabilities</p>
                </div>
                <button
                  onClick={() => setShowBatchReport(false)}
                  className="text-text-muted hover:text-text-secondary transition-colors"
                >
                  <X size={20} />
                </button>
              </div>

              {/* Summary cards */}
              <div className="grid grid-cols-4 gap-3 mb-5">
                {[
                  { 
                    label: 'Total Analyzed', 
                    value: batchResults.length, 
                    color: 'text-text-primary' 
                  },
                  { 
                    label: 'Not Reachable', 
                    value: batchResults.filter(r => r.result && (r.result.verdict === 'NOT REACHABLE' || r.result.verdict === 'LIKELY NOT REACHABLE')).length, 
                    color: 'text-accent-green' 
                  },
                  { 
                    label: 'Reachable', 
                    value: batchResults.filter(r => r.result && (r.result.verdict === 'LIKELY REACHABLE')).length, 
                    color: 'text-red-400' 
                  },
                  { 
                    label: 'Errors', 
                    value: batchResults.filter(r => r.error).length, 
                    color: 'text-yellow-400' 
                  },
                ].map(card => (
                  <div key={card.label} className="bg-bg-tertiary border border-border rounded-lg p-3 text-center">
                    <p className={`text-2xl font-bold ${card.color}`}>{card.value}</p>
                    <p className="text-text-muted text-xs mt-1">{card.label}</p>
                  </div>
                ))}
              </div>

              {/* Ignore all unreachable button */}
              {batchResults.filter(r => r.result && (r.result.verdict === 'NOT REACHABLE' || r.result.verdict === 'LIKELY NOT REACHABLE')).length > 0 && (
                <button
                  onClick={handleIgnoreAllUnreachable}
                  disabled={ignoreLoading || !state.selectedOrg}
                  className="btn-primary w-full justify-center mb-5"
                >
                  {ignoreLoading ? <Loader2 size={16} className="animate-spin" /> : <ShieldOff size={16} />}
                  Ignore All Unreachable ({batchResults.filter(r => r.result && (r.result.verdict === 'NOT REACHABLE' || r.result.verdict === 'LIKELY NOT REACHABLE')).length})
                </button>
              )}

              {/* Results table */}
              <div className="bg-bg-tertiary border border-border rounded-xl overflow-hidden">
                <div className="overflow-x-auto max-h-96 overflow-y-auto">
                  <table className="w-full text-xs">
                    <thead className="sticky top-0 bg-bg-secondary border-b border-border">
                      <tr>
                        <th className="px-4 py-2.5 text-left text-text-muted font-medium">#</th>
                        <th className="px-4 py-2.5 text-left text-text-muted font-medium">Severity</th>
                        <th className="px-4 py-2.5 text-left text-text-muted font-medium">Vulnerability</th>
                        <th className="px-4 py-2.5 text-left text-text-muted font-medium">Package</th>
                        <th className="px-4 py-2.5 text-left text-text-muted font-medium">Project</th>
                        <th className="px-4 py-2.5 text-left text-text-muted font-medium">Verdict</th>
                      </tr>
                    </thead>
                    <tbody>
                      {batchResults.map((item, idx) => {
                        const verdictColor = item.error ? 'text-yellow-400' :
                          item.result?.verdict === 'NOT REACHABLE' ? 'text-accent-green' :
                          item.result?.verdict === 'LIKELY NOT REACHABLE' ? 'text-green-300' :
                          item.result?.verdict === 'LIKELY REACHABLE' ? 'text-red-400' :
                          'text-text-muted'
                        
                        return (
                          <tr key={idx} className="border-b border-border/50 table-row-hover">
                            <td className="px-4 py-2.5 text-text-muted font-mono">{idx + 1}</td>
                            <td className="px-4 py-2.5">
                              <SeverityBadge severity={item.issue.issue.issueData.severity} />
                            </td>
                            <td className="px-4 py-2.5 text-text-primary max-w-xs truncate" title={item.issue.issue.issueData.title}>
                              {item.issue.issue.issueData.title}
                            </td>
                            <td className="px-4 py-2.5 text-text-secondary font-mono">
                              {item.issue.issue.pkgName}
                            </td>
                            <td className="px-4 py-2.5 text-text-secondary max-w-xs truncate" title={item.issue.projectName}>
                              {item.issue.projectName}
                            </td>
                            <td className={`px-4 py-2.5 font-medium ${verdictColor}`}>
                              {item.error ? 'ERROR' : item.result?.verdict || 'UNKNOWN'}
                            </td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>

      {/* ── Ignore Modal ──────────────────────────────────────────────────────── */}
      {showIgnoreModal && selectedIssue && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="bg-bg-secondary border border-border rounded-2xl shadow-2xl w-full max-w-lg">
            {/* Modal header */}
            <div className="flex items-center gap-3 px-6 py-4 border-b border-border">
              <div className="w-8 h-8 bg-green-900/40 border border-green-700/40 rounded-lg flex items-center justify-center">
                <ShieldOff size={16} className="text-green-400" />
              </div>
              <div className="flex-1">
                <h2 className="text-base font-semibold text-text-primary">Ignore in Snyk</h2>
                <p className="text-xs text-text-muted mt-0.5">This vulnerability will be ignored for 90 days</p>
              </div>
              <button
                onClick={() => { setShowIgnoreModal(false); setIgnoreError('') }}
                className="text-text-muted hover:text-text-secondary transition-colors text-xl leading-none"
              >
                ×
              </button>
            </div>

            {/* Vulnerability info */}
            <div className="px-6 py-4 border-b border-border">
              <div className="flex items-start gap-3 p-3 bg-bg-tertiary border border-border rounded-lg">
                <SeverityBadge severity={selectedIssue.issue.issueData.severity} />
                <div className="flex-1 min-w-0">
                  <p className="text-sm font-medium text-text-primary truncate">{selectedIssue.issue.issueData.title}</p>
                  <p className="text-xs text-text-muted mt-0.5">{selectedIssue.issue.pkgName} · {selectedIssue.projectName}</p>
                </div>
              </div>
            </div>

            {/* Notes input */}
            <div className="px-6 py-4">
              <label className="block text-sm font-medium text-text-secondary mb-2">
                Reason / Notes <span className="text-text-muted font-normal">(optional)</span>
              </label>
              <textarea
                value={ignoreNotes}
                onChange={e => setIgnoreNotes(e.target.value)}
                placeholder="Reachability analysis confirmed this vulnerability is not reachable in the codebase."
                rows={4}
                className="input-base w-full text-sm resize-none"
              />
              <p className="text-xs text-text-muted mt-2">
                This note will be saved to the ignore record in Snyk. Leave blank to use the default message.
              </p>
            </div>

            {/* Error */}
            {ignoreError && (
              <div className="mx-6 mb-4 flex items-start gap-2 p-3 bg-red-950/30 border border-red-800/40 rounded-lg text-red-400 text-xs">
                <AlertCircle size={14} className="flex-shrink-0 mt-0.5" />
                {ignoreError}
              </div>
            )}

            {/* Actions */}
            <div className="flex gap-3 px-6 pb-5">
              <button
                onClick={() => { setShowIgnoreModal(false); setIgnoreError('') }}
                className="btn-secondary flex-1 justify-center"
                disabled={ignoreLoading}
              >
                Cancel
              </button>
              <button
                onClick={handleIgnoreConfirm}
                disabled={ignoreLoading || !state.selectedOrg}
                className="flex-1 flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-green-800/60 border border-green-700/60 text-green-300 hover:bg-green-800/90 transition-colors text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {ignoreLoading ? <Loader2 size={15} className="animate-spin" /> : <ShieldOff size={15} />}
                {ignoreLoading ? 'Ignoring...' : 'Confirm Ignore'}
              </button>
            </div>

            {!state.selectedOrg && (
              <p className="px-6 pb-4 text-xs text-yellow-400 text-center">
                No org selected — go back to the dashboard and select an org first.
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
