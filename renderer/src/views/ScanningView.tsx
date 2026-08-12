import React, { useState, useEffect, useRef } from 'react'
import { Shield, X, CheckCircle, AlertCircle, Loader2, Database, Zap } from 'lucide-react'
import { useApp } from '../context/AppContext'
import { scanOrg } from '../api'
import ProgressBar from '../components/ProgressBar'

type ScanPhase = 'idle' | 'listing' | 'scanning' | 'saving' | 'done'

interface ScanProgress {
  phase?: ScanPhase
  project?: string
  status?: 'ok' | 'error'
  done?: number
  total?: number
  vulns?: number
  error?: string
  criticalTotal?: number
  highTotal?: number
  fixableTotal?: number
}

interface LogEntry {
  project: string
  status: 'ok' | 'error'
  time: string
  vulns?: number
  error?: string
}

export default function ScanningView() {
  const { state, setScanResults, setView, setScanning } = useApp()
  const [phase, setPhase] = useState<ScanPhase>('idle')
  const [progress, setProgress] = useState<ScanProgress>({})
  const [log, setLog] = useState<LogEntry[]>([])
  const [error, setError] = useState('')
  const [criticalTotal, setCriticalTotal] = useState(0)
  const [highTotal, setHighTotal] = useState(0)
  const [fixableTotal, setFixableTotal] = useState(0)
  const logRef = useRef<HTMLDivElement>(null)
  const cancelRef = useRef(false)

  // Auto-scroll log
  useEffect(() => {
    if (logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight
    }
  }, [log])

  useEffect(() => {
    if (!state.selectedOrg) return
    cancelRef.current = false
    setScanning(true)
    setPhase('listing')

    const runScan = async () => {
      try {
        const result = await scanOrg(
          state.selectedOrg!,
          state.token,
          (data: unknown) => {
            if (cancelRef.current) return
            const ev = data as { event: string; data: ScanProgress }
            const p: ScanProgress = ev?.data ?? (data as ScanProgress)

            // Update phase
            if (p.phase) setPhase(p.phase as ScanPhase)

            // Update counters
            if (p.criticalTotal !== undefined) setCriticalTotal(p.criticalTotal)
            if (p.highTotal !== undefined) setHighTotal(p.highTotal)
            if (p.fixableTotal !== undefined) setFixableTotal(p.fixableTotal)

            // Update main progress state
            setProgress(prev => ({ ...prev, ...p }))

            // Add to log for scanning phase
            if (p.phase === 'scanning' && p.project && p.status) {
              setLog(prev => {
                const entry: LogEntry = {
                  project: p.project!,
                  status: p.status!,
                  time: new Date().toLocaleTimeString(),
                  vulns: p.vulns,
                  error: p.error,
                }
                return [...prev.slice(-199), entry]
              })
            }
          }
        )

        if (!cancelRef.current) {
          const raw = result as {
            result?: { results?: unknown[]; from_cache?: boolean };
            results?: unknown[];
            from_cache?: boolean;
          }
          const fromCache = raw?.result?.from_cache ?? raw?.from_cache ?? false
          const scanResults = (raw?.result?.results ?? raw?.results ?? []) as Parameters<typeof setScanResults>[0]
          setScanResults(scanResults, new Date().toISOString())
          setScanning(false)

          // If the backend returned cached data, skip the scanning screen and
          // go straight to the dashboard — no progress was shown, nothing to wait for
          if (fromCache) {
            setView('dashboard')
            return
          }

          setView('dashboard')
        }
      } catch (e: unknown) {
        if (!cancelRef.current) {
          const msg = e instanceof Error ? e.message : String(e)
          setError(msg || 'Scan failed')
          setScanning(false)
          setPhase('idle')
        }
      }
    }

    runScan()
    return () => { cancelRef.current = true }
  }, [state.selectedOrg])

  const handleCancel = () => {
    cancelRef.current = true
    setScanning(false)
    setView('org-select')
  }

  const done = progress.done ?? 0
  const total = progress.total ?? 0
  const pct = total > 0 ? Math.round((done / total) * 100) : 0

  const phaseLabel: Record<ScanPhase, string> = {
    idle:     'Initializing...',
    listing:  'Fetching project list...',
    scanning: `Scanning projects (${done.toLocaleString()} / ${total.toLocaleString()})`,
    saving:   'Saving to cache...',
    done:     'Complete',
  }

  const phaseIcon: Record<ScanPhase, React.ReactNode> = {
    idle:     <Loader2 size={18} className="animate-spin text-text-muted" />,
    listing:  <Loader2 size={18} className="animate-spin text-accent-purple" />,
    scanning: <Zap size={18} className="text-accent-purple" />,
    saving:   <Database size={18} className="text-accent-green" />,
    done:     <CheckCircle size={18} className="text-accent-green" />,
  }

  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-bg-primary px-4 py-8">
      <div className="w-full max-w-2xl">

        {/* Header */}
        <div className="text-center mb-6">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-accent-purple/10 border border-accent-purple/30 rounded-2xl mb-4">
            <Shield size={32} className="text-accent-purple animate-pulse" />
          </div>
          <h1 className="text-2xl font-bold text-text-primary">
            Scanning {state.selectedOrg?.name}
          </h1>
          <p className="text-text-muted mt-1 text-sm">Pulling vulnerability data from Snyk API</p>
        </div>

        {/* Error */}
        {error && (
          <div className="flex items-start gap-3 p-4 bg-red-950/40 border border-red-800/50 rounded-xl mb-5 text-red-400">
            <AlertCircle size={20} className="flex-shrink-0 mt-0.5" />
            <div>
              <p className="font-medium">Scan Error</p>
              <p className="text-sm mt-1 opacity-80">{error}</p>
            </div>
          </div>
        )}

        {/* Main progress card */}
        <div className="bg-bg-secondary border border-border rounded-2xl p-6 mb-4">

          {/* Phase + big % */}
          <div className="flex items-end justify-between mb-5">
            <div>
              <span className="text-5xl font-bold text-accent-purple tabular-nums">{pct}%</span>
              <p className="text-text-muted text-sm mt-1">Complete</p>
            </div>
            <div className="text-right">
              <p className="text-2xl font-bold text-text-primary tabular-nums">
                {done.toLocaleString()}
                <span className="text-text-muted font-normal text-lg"> / {total > 0 ? total.toLocaleString() : '…'}</span>
              </p>
              <p className="text-text-muted text-sm">Projects scanned</p>
            </div>
          </div>

          <ProgressBar
            value={done}
            max={total || 1}
            animated={phase === 'scanning'}
            size="lg"
            color="purple"
          />

          {/* Phase status line */}
          <div className="flex items-center gap-2 mt-4 text-sm">
            {phaseIcon[phase]}
            <span className="text-text-secondary">{phaseLabel[phase]}</span>
          </div>

          {/* Current project being scanned */}
          {phase === 'scanning' && progress.project && (
            <div className="mt-2 flex items-center gap-2 text-xs pl-1">
              <div className="w-1.5 h-1.5 rounded-full bg-accent-green animate-pulse flex-shrink-0" />
              <span className="text-text-muted font-mono truncate">{progress.project}</span>
            </div>
          )}
        </div>

        {/* Live stats row */}
        {(phase === 'scanning' || phase === 'saving') && (
          <div className="grid grid-cols-3 gap-3 mb-4">
            <div className="bg-bg-secondary border border-border rounded-xl p-3 text-center">
              <p className="text-2xl font-bold text-red-400 tabular-nums">{criticalTotal.toLocaleString()}</p>
              <p className="text-xs text-text-muted mt-0.5">Critical</p>
            </div>
            <div className="bg-bg-secondary border border-border rounded-xl p-3 text-center">
              <p className="text-2xl font-bold text-orange-400 tabular-nums">{highTotal.toLocaleString()}</p>
              <p className="text-xs text-text-muted mt-0.5">High</p>
            </div>
            <div className="bg-bg-secondary border border-border rounded-xl p-3 text-center">
              <p className="text-2xl font-bold text-accent-green tabular-nums">{fixableTotal.toLocaleString()}</p>
              <p className="text-xs text-text-muted mt-0.5">Fixable</p>
            </div>
          </div>
        )}

        {/* Scan log */}
        <div className="bg-bg-secondary border border-border rounded-xl overflow-hidden mb-4">
          <div className="flex items-center justify-between px-4 py-2.5 border-b border-border">
            <span className="text-xs text-text-muted font-medium uppercase tracking-wider">Scan Log</span>
            <span className="text-xs text-text-muted tabular-nums">{log.length} entries</span>
          </div>
          <div ref={logRef} className="h-52 overflow-y-auto font-mono text-xs p-3 space-y-0.5">
            {log.length === 0 ? (
              <p className="text-text-muted py-2 italic">
                {phase === 'listing' ? 'Fetching project list...' : 'Waiting for first results...'}
              </p>
            ) : (
              log.map((entry, i) => (
                <div key={i} className="flex items-start gap-2 py-0.5">
                  {entry.status === 'ok'
                    ? <CheckCircle size={11} className="text-accent-green flex-shrink-0 mt-0.5" />
                    : <AlertCircle size={11} className="text-red-400 flex-shrink-0 mt-0.5" />
                  }
                  <span className="text-text-muted flex-shrink-0">{entry.time}</span>
                  <span className={`truncate flex-1 ${entry.status === 'ok' ? 'text-text-secondary' : 'text-red-400'}`}>
                    {entry.project}
                  </span>
                  {entry.status === 'ok' && entry.vulns !== undefined && entry.vulns > 0 && (
                    <span className="text-red-400/70 flex-shrink-0 ml-1">{entry.vulns}v</span>
                  )}
                  {entry.status === 'error' && entry.error && (
                    <span className="text-red-400/60 truncate max-w-[120px] flex-shrink-0" title={entry.error}>
                      {entry.error.slice(0, 40)}
                    </span>
                  )}
                </div>
              ))
            )}
          </div>
        </div>

        {/* Cancel */}
        <div className="flex justify-center">
          <button onClick={handleCancel} className="btn-danger">
            <X size={16} />
            Cancel Scan
          </button>
        </div>

      </div>
    </div>
  )
}
