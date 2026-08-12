import React from 'react'
import { AlertTriangle, CheckCircle, HelpCircle, ShieldOff } from 'lucide-react'

interface VerdictBannerProps {
  verdict: 'LIKELY REACHABLE' | 'LIKELY NOT REACHABLE' | 'NOT REACHABLE' | 'INCONCLUSIVE'
  onIgnore?: () => void
  ignoreLoading?: boolean
}

export default function VerdictBanner({ verdict, onIgnore, ignoreLoading }: VerdictBannerProps) {
  if (verdict === 'LIKELY REACHABLE') {
    return (
      <div className="flex items-center gap-4 p-5 rounded-xl bg-red-950/40 border border-red-700 pulse-red">
        <div className="flex-shrink-0 p-2 bg-red-900/40 rounded-full">
          <AlertTriangle size={28} className="text-red-400" />
        </div>
        <div>
          <p className="text-red-300 font-bold text-xl tracking-wide">LIKELY REACHABLE</p>
          <p className="text-red-400/70 text-sm mt-0.5">This vulnerability may be exploitable in the codebase</p>
        </div>
      </div>
    )
  }

  if (verdict === 'LIKELY NOT REACHABLE' || verdict === 'NOT REACHABLE') {
    return (
      <div className="flex items-center gap-4 p-5 rounded-xl bg-green-950/40 border border-green-700">
        <div className="flex-shrink-0 p-2 bg-green-900/40 rounded-full">
          <CheckCircle size={28} className="text-accent-green" />
        </div>
        <div className="flex-1">
          <p className="text-green-300 font-bold text-xl tracking-wide">NOT REACHABLE</p>
          <p className="text-green-400/70 text-sm mt-0.5">This vulnerability does not appear to be exploitable</p>
        </div>
        {onIgnore && (
          <button
            onClick={onIgnore}
            disabled={ignoreLoading}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-green-900/40 border border-green-700/60 text-green-300 hover:bg-green-900/70 hover:border-green-600 transition-colors text-sm font-medium disabled:opacity-50 disabled:cursor-not-allowed flex-shrink-0"
          >
            <ShieldOff size={15} />
            {ignoreLoading ? 'Ignoring...' : 'Ignore in Snyk'}
          </button>
        )}
      </div>
    )
  }

  return (
    <div className="flex items-center gap-4 p-5 rounded-xl bg-yellow-950/40 border border-yellow-700">
      <div className="flex-shrink-0 p-2 bg-yellow-900/40 rounded-full">
        <HelpCircle size={28} className="text-yellow-400" />
      </div>
      <div>
        <p className="text-yellow-300 font-bold text-xl tracking-wide">INCONCLUSIVE</p>
        <p className="text-yellow-400/70 text-sm mt-0.5">Unable to determine reachability with confidence</p>
      </div>
    </div>
  )
}
