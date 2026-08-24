import React, { useState } from 'react'
import { FileText, Loader2, AlertCircle, CheckCircle, Download } from 'lucide-react'
import { useApp } from '../context/AppContext'
import { generateReport } from '../api'

type ReportMode = 'all' | 'non_fixable' | 'non_fixable_above_score'

interface GeneratedReport {
  md_path: string
  csv_path: string
  timestamp: string
  mode: string
}

const reportModes: { mode: ReportMode; label: string; desc: string; icon: string }[] = [
  {
    mode: 'all',
    label: 'All Vulnerabilities',
    desc: 'Include every vulnerability found in the scan',
    icon: '📊',
  },
  {
    mode: 'non_fixable',
    label: 'Non-Fixable Only',
    desc: 'Only vulnerabilities without a known fix',
    icon: '🔒',
  },
  {
    mode: 'non_fixable_above_score',
    label: 'Non-Fixable Above Score',
    desc: 'Non-fixable vulnerabilities above a risk score threshold',
    icon: '⚠️',
  },
]

export default function ReportsView() {
  const { state } = useApp()
  const [selectedMode, setSelectedMode] = useState<ReportMode>('all')
  const [minScore, setMinScore] = useState(400)
  const [generating, setGenerating] = useState(false)
  const [error, setError] = useState('')
  const [reports, setReports] = useState<GeneratedReport[]>([])

  const handleGenerate = async () => {
    if (!state.selectedOrg) return
    setGenerating(true)
    setError('')
    try {
      const res = await generateReport(state.selectedOrg, state.scanResults, state.token, selectedMode, minScore)
      setReports(prev => [{
        ...res,
        timestamp: new Date().toISOString(),
        mode: selectedMode,
      }, ...prev])
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e))
    } finally {
      setGenerating(false)
    }
  }

  return (
    <div className="flex-1 overflow-y-auto bg-bg-primary p-6">
      <div className="max-w-3xl mx-auto">
        {/* Header */}
        <div className="flex items-center gap-3 mb-6">
          <div className="w-10 h-10 bg-accent-purple/10 border border-accent-purple/30 rounded-xl flex items-center justify-center">
            <FileText size={20} className="text-accent-purple" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-text-primary">Reports</h1>
            <p className="text-text-muted text-sm">Generate Markdown & CSV vulnerability reports</p>
          </div>
        </div>

        {/* Mode selector */}
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-6">
          {reportModes.map(rm => (
            <button
              key={rm.mode}
              onClick={() => setSelectedMode(rm.mode)}
              className={`p-4 rounded-xl border-2 text-left transition-all ${
                selectedMode === rm.mode
                  ? 'border-accent-purple bg-accent-purple/10'
                  : 'border-border bg-bg-secondary hover:border-border-light'
              }`}
            >
              <div className="text-2xl mb-2">{rm.icon}</div>
              <p className={`font-semibold text-sm mb-1 ${selectedMode === rm.mode ? 'text-accent-purple' : 'text-text-primary'}`}>
                {rm.label}
              </p>
              <p className="text-xs text-text-muted leading-relaxed">{rm.desc}</p>
            </button>
          ))}
        </div>

        {/* Min score input */}
        {selectedMode === 'non_fixable_above_score' && (
          <div className="bg-bg-secondary border border-border rounded-xl p-4 mb-6">
            <label className="block text-sm text-text-secondary mb-2">
              Minimum Risk Score
            </label>
            <div className="flex gap-3 items-center">
              <input
                type="range"
                min={0}
                max={1000}
                step={10}
                value={minScore}
                onChange={e => setMinScore(Number(e.target.value))}
                className="flex-1"
                style={{ accentColor: '#7c3aed' }}
              />
              <input
                type="number"
                min={0}
                max={1000}
                value={minScore}
                onChange={e => setMinScore(Number(e.target.value))}
                className="input-base w-24"
              />
            </div>
          </div>
        )}

        {/* Error */}
        {error && (
          <div className="flex items-start gap-2 p-3 bg-red-950/40 border border-red-800/50 rounded-lg mb-5 text-red-400 text-sm">
            <AlertCircle size={16} className="flex-shrink-0 mt-0.5" />
            {error}
          </div>
        )}

        {/* Generate button */}
        <button
          onClick={handleGenerate}
          disabled={generating || state.scanResults.length === 0}
          className="btn-primary w-full justify-center py-3 mb-8"
        >
          {generating ? <Loader2 size={18} className="animate-spin" /> : <Download size={18} />}
          {generating ? 'Generating Report...' : 'Generate Report'}
        </button>

        {/* Generated reports */}
        {reports.length > 0 && (
          <div>
            <h2 className="text-sm font-semibold text-text-secondary uppercase tracking-wider mb-3">Generated Reports</h2>
            <div className="space-y-3">
              {reports.map((r, i) => (
                <div key={i} className="bg-bg-secondary border border-accent-green/20 rounded-xl p-4">
                  <div className="flex items-center gap-2 mb-3">
                    <CheckCircle size={16} className="text-accent-green" />
                    <span className="text-accent-green text-sm font-medium">Report Generated</span>
                    <span className="text-text-muted text-xs ml-auto">{new Date(r.timestamp).toLocaleString()}</span>
                  </div>
                  <div className="space-y-2">
                    <div className="flex items-center gap-2 p-2.5 bg-bg-tertiary rounded-lg">
                      <span className="text-xs text-text-muted w-8 flex-shrink-0">MD</span>
                      <span className="font-mono text-xs text-text-secondary flex-1 truncate" title={r.md_path}>{r.md_path}</span>
                    </div>
                    <div className="flex items-center gap-2 p-2.5 bg-bg-tertiary rounded-lg">
                      <span className="text-xs text-text-muted w-8 flex-shrink-0">CSV</span>
                      <span className="font-mono text-xs text-text-secondary flex-1 truncate" title={r.csv_path}>{r.csv_path}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {state.scanResults.length === 0 && (
          <div className="text-center py-8 text-text-muted text-sm">
            <FileText size={32} className="mx-auto mb-2 opacity-30" />
            No scan results available. Run a scan first.
          </div>
        )}
      </div>
    </div>
  )
}
