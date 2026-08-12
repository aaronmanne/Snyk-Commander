import React, { useState } from 'react'
import { Ban, Sliders, Play, AlertCircle, CheckCircle, Loader2, FileCode } from 'lucide-react'
import { useApp } from '../context/AppContext'
import { getNonFixable, applyIgnores, generateSnykFiles } from '../api'
import type { IgnoreAnalysis, IgnoreOperation } from '../types'
import SeverityBadge from '../components/SeverityBadge'
import ProgressBar from '../components/ProgressBar'
import Modal from '../components/Modal'
import type { Severity } from '../types'

type Tab = 'api' | 'snyk-files'
type FilterMode = 'all' | 'non_fixable' | 'non_fixable_above_score' | 'fixable_only'

export default function IgnoreManagerView() {
  const { state } = useApp()
  const [tab, setTab] = useState<Tab>('api')

  // API Ignores tab
  const [riskThreshold, setRiskThreshold] = useState(400)
  const [analysis, setAnalysis] = useState<IgnoreAnalysis | null>(null)
  const [analyzing, setAnalyzing] = useState(false)
  const [analyzeError, setAnalyzeError] = useState('')
  const [showConfirm, setShowConfirm] = useState(false)
  const [applying, setApplying] = useState(false)
  const [applyProgress, setApplyProgress] = useState(0)
  const [applyResult, setApplyResult] = useState<{ succeeded: number; failed: number } | null>(null)
  const [applyError, setApplyError] = useState('')

  // Snyk files tab
  const [filterMode, setFilterMode] = useState<FilterMode>('non_fixable')
  const [minScore, setMinScore] = useState(200)
  const [generating, setGenerating] = useState(false)
  const [genResult, setGenResult] = useState<{ files_written: number; total_ignores: number; files: string[] } | null>(null)
  const [genError, setGenError] = useState('')

  const handleAnalyze = async () => {
    if (!state.selectedOrg) return
    setAnalyzing(true)
    setAnalysis(null)
    setAnalyzeError('')
    try {
      const res = await getNonFixable(state.selectedOrg.id, state.scanResults, riskThreshold)
      setAnalysis(res)
    } catch (e: unknown) {
      setAnalyzeError(e instanceof Error ? e.message : String(e))
    } finally {
      setAnalyzing(false)
    }
  }

  const handleApply = async () => {
    if (!state.selectedOrg || !analysis) return
    setApplying(true)
    setApplyError('')
    setApplyResult(null)
    setShowConfirm(false)
    const allOps = [
      ...analysis.to_ignore,
      ...analysis.to_update,
      ...analysis.to_unignore,
    ]
    const total = allOps.length
    let done = 0
    try {
      const res = await applyIgnores(
        state.selectedOrg.id,
        state.token,
        allOps,
        'No known fix available - No upgrade, patch, or pin exists for this vulnerability.',
        new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString(),
        (data: unknown) => {
          done++
          setApplyProgress(total > 0 ? Math.round((done / total) * 100) : 0)
        }
      )
      setApplyResult(res)
    } catch (e: unknown) {
      setApplyError(e instanceof Error ? e.message : String(e))
    } finally {
      setApplying(false)
    }
  }

  const handleGenerate = async () => {
    setGenerating(true)
    setGenResult(null)
    setGenError('')
    try {
      const res = await generateSnykFiles(state.scanResults, filterMode, minScore)
      setGenResult(res)
    } catch (e: unknown) {
      setGenError(e instanceof Error ? e.message : String(e))
    } finally {
      setGenerating(false)
    }
  }

  const OperationsTable = ({
    ops, headerColor, title
  }: {
    ops: IgnoreOperation[], headerColor: string, title: string
  }) => {
    if (ops.length === 0) return null
    return (
      <div className="mb-6">
        <div className={`px-4 py-2 rounded-t-lg font-medium text-sm ${headerColor}`}>
          {title} ({ops.length})
        </div>
        <div className="border border-t-0 border-border rounded-b-lg overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border bg-bg-tertiary">
                <th className="px-4 py-2 text-left text-text-muted font-medium">Issue ID</th>
                <th className="px-4 py-2 text-left text-text-muted font-medium">Title</th>
                <th className="px-4 py-2 text-left text-text-muted font-medium">Severity</th>
                <th className="px-4 py-2 text-left text-text-muted font-medium">Risk Score</th>
              </tr>
            </thead>
            <tbody>
              {ops.map((op, i) => (
                <tr key={i} className="border-b border-border/50 table-row-hover">
                  <td className="px-4 py-2 font-mono text-text-muted">{op.vuln_id || op.issue_id}</td>
                  <td className="px-4 py-2 text-text-primary">{op.title || '—'}</td>
                  <td className="px-4 py-2">
                    {op.severity ? <SeverityBadge severity={op.severity as Severity} /> : '—'}
                  </td>
                  <td className="px-4 py-2 font-mono text-text-secondary">{op.risk_score ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    )
  }

  return (
    <div className="flex-1 overflow-y-auto bg-bg-primary p-6">
      <div className="max-w-5xl mx-auto">
        {/* Header */}
        <div className="flex items-center gap-3 mb-6">
          <div className="w-10 h-10 bg-accent-purple/10 border border-accent-purple/30 rounded-xl flex items-center justify-center">
            <Ban size={20} className="text-accent-purple" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-text-primary">Ignore Manager</h1>
            <p className="text-text-muted text-sm">Manage vulnerability ignores via API or .snyk files</p>
          </div>
        </div>

        {/* Tabs */}
        <div className="flex border-b border-border mb-6">
          {(['api', 'snyk-files'] as Tab[]).map(t => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={`px-5 py-2.5 text-sm font-medium border-b-2 transition-colors -mb-px ${
                tab === t
                  ? 'border-accent-purple text-accent-purple'
                  : 'border-transparent text-text-muted hover:text-text-primary'
              }`}
            >
              {t === 'api' ? '🔗 API Ignores' : '📄 Generate .snyk Files'}
            </button>
          ))}
        </div>

        {tab === 'api' && (
          <div>
            {/* Info banner */}
            <div className="flex items-start gap-3 p-4 bg-accent-blue/10 border border-accent-blue/30 rounded-xl mb-6">
              <AlertCircle size={20} className="text-accent-blue flex-shrink-0 mt-0.5" />
              <div className="text-sm">
                <p className="text-accent-blue font-medium mb-1">Ignoring Vulnerabilities with No Known Fix</p>
                <p className="text-text-secondary">
                  This tool identifies vulnerabilities with <strong>no upgrade, patch, or pinnable fix available</strong> from Snyk.
                  Use the risk score threshold to narrow down to the most critical issues.
                </p>
              </div>
            </div>

            {/* Controls */}
            <div className="bg-bg-secondary border border-border rounded-xl p-5 mb-6">
              <div className="flex items-center gap-4 flex-wrap">
                <div className="flex-1 min-w-64">
                  <label className="block text-sm text-text-secondary mb-2">
                    Minimum Risk Score: <span className="text-accent-purple font-bold">{riskThreshold}</span>
                    {riskThreshold === 0 && <span className="text-text-muted ml-2">(all non-fixable)</span>}
                  </label>
                  <input
                    type="range"
                    min={0}
                    max={1000}
                    step={10}
                    value={riskThreshold}
                    onChange={e => setRiskThreshold(Number(e.target.value))}
                    className="w-full accent-purple-600"
                    style={{ accentColor: '#6c71c4' }}
                  />
                  <div className="flex justify-between text-xs text-text-muted mt-1">
                    <span>0 (all)</span>
                    <span>500</span>
                    <span>1000</span>
                  </div>
                </div>
                <button
                  onClick={handleAnalyze}
                  disabled={analyzing || state.scanResults.length === 0}
                  className="btn-primary self-end"
                >
                  {analyzing ? <Loader2 size={16} className="animate-spin" /> : <Sliders size={16} />}
                  Analyze
                </button>
              </div>
            </div>

            {analyzeError && (
              <div className="flex items-start gap-2 p-3 bg-red-950/40 border border-red-800/50 rounded-lg mb-5 text-red-400 text-sm">
                <AlertCircle size={16} className="flex-shrink-0 mt-0.5" />
                {analyzeError}
              </div>
            )}

            {/* Apply progress */}
            {applying && (
              <div className="bg-bg-secondary border border-border rounded-xl p-5 mb-6">
                <p className="text-sm text-text-secondary mb-3">Applying changes...</p>
                <ProgressBar value={applyProgress} animated color="purple" size="md" showPercent />
              </div>
            )}

            {/* Apply result */}
            {applyResult && !applying && (
              <div className="flex items-start gap-3 p-4 bg-accent-green/10 border border-accent-green/30 rounded-xl mb-6">
                <CheckCircle size={20} className="text-accent-green flex-shrink-0 mt-0.5" />
                <div>
                  <p className="text-accent-green font-medium">Changes Applied</p>
                  <p className="text-text-secondary text-sm mt-0.5">
                    {applyResult.succeeded} succeeded · {applyResult.failed} failed
                  </p>
                </div>
              </div>
            )}

            {applyError && (
              <div className="flex items-start gap-2 p-3 bg-red-950/40 border border-red-800/50 rounded-lg mb-5 text-red-400 text-sm">
                <AlertCircle size={16} className="flex-shrink-0 mt-0.5" />
                {applyError}
              </div>
            )}

            {/* Analysis results */}
            {analysis && (
              <div>
                <div className="bg-bg-secondary border border-border rounded-xl p-4 mb-4">
                  <p className="text-sm text-text-secondary mb-3">
                    Found <strong className="text-text-primary">{analysis.to_ignore.length + analysis.to_update.length}</strong> vulnerabilities 
                    with <strong className="text-accent-orange">no known fix available</strong>
                    {riskThreshold > 0 && <span> and risk score ≥ {riskThreshold}</span>}
                  </p>
                  <div className="flex items-center justify-between">
                    <div className="flex gap-4 text-sm">
                      <span className="text-accent-green">↑ {analysis.to_ignore.length} to ignore</span>
                      <span className="text-accent-yellow">~ {analysis.to_update.length} to update</span>
                      <span className="text-accent-red">↓ {analysis.to_unignore.length} to unignore (fix now available)</span>
                    </div>
                    <button
                      onClick={() => setShowConfirm(true)}
                      disabled={applying}
                      className="btn-primary"
                    >
                      <Play size={16} />
                      Apply Changes
                    </button>
                  </div>
                </div>

                <OperationsTable
                  ops={analysis.to_ignore}
                  title="Will Ignore (no fix available)"
                  headerColor="bg-accent-green/10 text-accent-green border-l-2 border-accent-green"
                />
                <OperationsTable
                  ops={analysis.to_update}
                  title="Will Update Expiry (still no fix)"
                  headerColor="bg-accent-yellow/10 text-accent-yellow border-l-2 border-accent-yellow"
                />
                <OperationsTable
                  ops={analysis.to_unignore}
                  title="Will Unignore (fix now available)"
                  headerColor="bg-accent-red/10 text-accent-red border-l-2 border-accent-red"
                />
              </div>
            )}
          </div>
        )}

        {tab === 'snyk-files' && (
          <div>
            {/* Info banner */}
            <div className="flex items-start gap-3 p-4 bg-accent-cyan/10 border border-accent-cyan/30 rounded-xl mb-6">
              <AlertCircle size={20} className="text-accent-cyan flex-shrink-0 mt-0.5" />
              <div className="text-sm">
                <p className="text-accent-cyan font-medium mb-1">Generate Local .snyk Policy Files</p>
                <p className="text-text-secondary">
                  Creates .snyk files in project folders with ignore rules. "Non-fixable" means no upgrade, patch, or pin is available from Snyk.
                </p>
              </div>
            </div>

            <div className="bg-bg-secondary border border-border rounded-xl p-5 mb-6">
              <div className="flex flex-wrap gap-4 items-end">
                <div className="flex-1 min-w-48">
                  <label className="block text-sm text-text-secondary mb-2">Filter Mode</label>
                  <select
                    value={filterMode}
                    onChange={e => setFilterMode(e.target.value as FilterMode)}
                    className="input-base"
                  >
                    <option value="all">All vulnerabilities</option>
                    <option value="non_fixable">No known fix only</option>
                    <option value="non_fixable_above_score">No known fix above score</option>
                    <option value="fixable_only">Fixable only</option>
                  </select>
                </div>

                {filterMode === 'non_fixable_above_score' && (
                  <div className="w-40">
                    <label className="block text-sm text-text-secondary mb-2">Min Risk Score</label>
                    <input
                      type="number"
                      min={0}
                      max={1000}
                      value={minScore}
                      onChange={e => setMinScore(Number(e.target.value))}
                      className="input-base"
                    />
                  </div>
                )}

                <button
                  onClick={handleGenerate}
                  disabled={generating || state.scanResults.length === 0}
                  className="btn-primary"
                >
                  {generating ? <Loader2 size={16} className="animate-spin" /> : <FileCode size={16} />}
                  Generate
                </button>
              </div>
            </div>

            {genError && (
              <div className="flex items-start gap-2 p-3 bg-red-950/40 border border-red-800/50 rounded-lg mb-5 text-red-400 text-sm">
                <AlertCircle size={16} className="flex-shrink-0 mt-0.5" />
                {genError}
              </div>
            )}

            {genResult && (
              <div>
                <div className="flex items-center gap-3 p-4 bg-accent-green/10 border border-accent-green/30 rounded-xl mb-5">
                  <CheckCircle size={20} className="text-accent-green" />
                  <div>
                    <p className="text-accent-green font-medium">Files Generated</p>
                    <p className="text-text-secondary text-sm">{genResult.files_written} files · {genResult.total_ignores} total ignores</p>
                  </div>
                </div>
                {genResult.files.length > 0 && (
                  <div className="bg-bg-secondary border border-border rounded-xl overflow-hidden">
                    <div className="px-4 py-2.5 border-b border-border">
                      <span className="text-sm text-text-muted">Written files</span>
                    </div>
                    <div className="divide-y divide-border/50">
                      {genResult.files.map((f, i) => (
                        <div key={i} className="px-4 py-2.5 font-mono text-xs text-text-secondary hover:bg-bg-tertiary">
                          {f}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Confirm modal */}
      <Modal
        isOpen={showConfirm}
        onClose={() => setShowConfirm(false)}
        title="Confirm Apply Changes"
        footer={
          <>
            <button onClick={() => setShowConfirm(false)} className="btn-secondary">Cancel</button>
            <button onClick={handleApply} className="btn-primary">Apply Changes</button>
          </>
        }
      >
        <p className="text-text-secondary text-sm mb-2">
          This will apply the following changes to <strong className="text-text-primary">{state.selectedOrg?.name}</strong>:
        </p>
        <p className="text-xs text-text-muted mb-4">
          All changes apply only to vulnerabilities with <strong>no known fix</strong> (no upgrade, patch, or pin available).
        </p>
        <ul className="space-y-2 text-sm">
          <li className="flex items-center gap-2 text-accent-green">
            <span className="w-2 h-2 rounded-full bg-accent-green" />
            {analysis?.to_ignore.length} vulnerabilities will be ignored (no fix available)
          </li>
          <li className="flex items-center gap-2 text-accent-yellow">
            <span className="w-2 h-2 rounded-full bg-accent-yellow" />
            {analysis?.to_update.length} ignore expiries will be updated (still no fix)
          </li>
          <li className="flex items-center gap-2 text-accent-red">
            <span className="w-2 h-2 rounded-full bg-accent-red" />
            {analysis?.to_unignore.length} vulnerabilities will be unignored (fix now available)
          </li>
        </ul>
        <p className="text-xs text-text-muted mt-4">
          All ignores will expire in 90 days and can be reviewed/updated again.
        </p>
      </Modal>
    </div>
  )
}
