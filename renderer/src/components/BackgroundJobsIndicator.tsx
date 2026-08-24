import React from 'react'
import { Loader2, FlaskConical, CheckCircle, XCircle } from 'lucide-react'
import { useApp } from '../context/AppContext'

export default function BackgroundJobsIndicator() {
  const { state } = useApp()
  
  if (state.backgroundJobs.length === 0) return null
  
  const running = state.backgroundJobs.filter(j => j.status === 'running' || j.status === 'queued')
  const completed = state.backgroundJobs.filter(j => j.status === 'completed')
  const failed = state.backgroundJobs.filter(j => j.status === 'failed')
  
  return (
    <div className="fixed bottom-4 right-4 z-50 max-w-md">
      <div className="bg-bg-secondary border border-border rounded-lg shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="px-4 py-2 bg-accent-purple/10 border-b border-border flex items-center gap-2">
          <FlaskConical size={14} className="text-accent-purple" />
          <span className="text-xs font-semibold text-text-primary">Background Analysis</span>
          <span className="ml-auto text-xs text-text-muted">
            {running.length} running · {completed.length} done · {failed.length} failed
          </span>
        </div>
        
        {/* Job List */}
        <div className="max-h-64 overflow-y-auto">
          {state.backgroundJobs.map(job => (
            <div key={job.jobId} className="px-4 py-3 border-b border-border/50 last:border-b-0">
              <div className="flex items-start gap-2">
                {/* Status Icon */}
                <div className="flex-shrink-0 mt-0.5">
                  {job.status === 'running' || job.status === 'queued' ? (
                    <Loader2 size={14} className="text-accent-purple animate-spin" />
                  ) : job.status === 'completed' ? (
                    <CheckCircle size={14} className="text-accent-green" />
                  ) : (
                    <XCircle size={14} className="text-red-400" />
                  )}
                </div>
                
                {/* Job Info */}
                <div className="flex-1 min-w-0">
                  <p className="text-xs font-medium text-text-primary truncate" title={job.issueName}>
                    {job.issueName}
                  </p>
                  <p className="text-xs text-text-muted truncate" title={job.projectName}>
                    {job.projectName}
                  </p>
                  
                  {/* Progress */}
                  {(job.status === 'running' || job.status === 'queued') && job.progress && (
                    <div className="mt-1">
                      <p className="text-xs text-text-secondary">{job.progress.phase}</p>
                      {job.progress.pct > 0 && (
                        <div className="w-full bg-bg-tertiary rounded-full h-1 mt-1">
                          <div 
                            className="bg-accent-purple h-1 rounded-full transition-all duration-300"
                            style={{ width: `${job.progress.pct}%` }}
                          />
                        </div>
                      )}
                    </div>
                  )}
                  
                  {/* Status Text */}
                  {job.status === 'completed' && (
                    <p className="text-xs text-accent-green mt-1">Analysis complete</p>
                  )}
                  {job.status === 'failed' && (
                    <p className="text-xs text-red-400 mt-1">Analysis failed</p>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
