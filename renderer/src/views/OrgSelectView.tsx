import React, { useState, useEffect, useCallback } from 'react'
import {
  Shield, Play, RefreshCw, CheckCircle, Building2,
  Database, AlertCircle, Clock, Loader2, Zap, Trash2,
  Settings, Key, Eye, EyeOff, ArrowRight
} from 'lucide-react'
import { useApp } from '../context/AppContext'
import { loadOrgCache, deleteOrgCache, verifyToken } from '../api'
import type { Org, ScanResult } from '../types'
import type { OrgCacheEntry } from '../api'

interface OrgCacheMap {
  [orgId: string]: { loading: boolean; entry: OrgCacheEntry | null }
}

export default function OrgSelectView() {
  const { state, setSelectedOrg, setScanResults, setView, setToken, setOrgs } = useApp()

  const [selected, setSelected] = useState<string | null>(
    state.selectedOrg?.id || (state.orgs.length === 1 ? state.orgs[0].id : null)
  )
  const [cacheMap, setCacheMap] = useState<OrgCacheMap>({})
  const [deletingOrgId, setDeletingOrgId] = useState<string | null>(null)

  // Inline token entry (shown when no orgs loaded yet)
  const [tokenInput, setTokenInput] = useState(state.token || '')
  const [showToken, setShowToken] = useState(false)
  const [connectLoading, setConnectLoading] = useState(false)
  const [connectError, setConnectError] = useState('')

  // Auto-connect on mount if token already stored
  useEffect(() => {
    if (state.orgs.length === 0 && state.token) {
      handleConnect(state.token)
    }
  }, [])

  const handleConnect = async (tokenToUse?: string) => {
    const tok = (tokenToUse ?? tokenInput).trim()
    if (!tok) { setConnectError('Please enter your Snyk API token'); return }
    setConnectLoading(true)
    setConnectError('')
    try {
      const res = await verifyToken(tok)
      localStorage.setItem('snyk_token', tok)
      setToken(tok)
      setOrgs(res.orgs)
      if (res.orgs.length === 1) setSelected(res.orgs[0].id)
    } catch (e: unknown) {
      setConnectError(e instanceof Error ? e.message : 'Failed to verify token')
    } finally {
      setConnectLoading(false)
    }
  }

  // Load cache info for every org on mount
  useEffect(() => {
    if (state.orgs.length === 0) return
    const initial: OrgCacheMap = {}
    for (const o of state.orgs) initial[o.id] = { loading: true, entry: null }
    setCacheMap(initial)

    // Fetch in parallel
    Promise.all(
      state.orgs.map(async (o) => {
        try {
          const res = await loadOrgCache(o.id)
          return { id: o.id, loading: false, entry: res.found ? res.entry : null }
        } catch {
          return { id: o.id, loading: false, entry: null }
        }
      })
    ).then(results => {
      const next: OrgCacheMap = {}
      for (const r of results) next[r.id] = { loading: r.loading, entry: r.entry }
      setCacheMap(next)
    })
  }, [state.orgs])

  // ── Use cached data immediately — skip scanning screen
  const handleUseCache = useCallback((org: Org) => {
    const cacheInfo = cacheMap[org.id]
    if (!cacheInfo?.entry) return
    setSelectedOrg(org)
    setScanResults(cacheInfo.entry.results as ScanResult[], cacheInfo.entry.timestamp)
    setView('dashboard')
  }, [cacheMap, setSelectedOrg, setScanResults, setView])

  // ── Fresh scan — go to scanning screen (clears cache first)
  const handleFreshScan = useCallback(async (org: Org) => {
    // Clear cache before scanning
    try {
      await deleteOrgCache(org.id)
      setCacheMap(prev => ({ ...prev, [org.id]: { loading: false, entry: null } }))
    } catch {
      // ignore - will force fresh scan anyway
    }
    setSelectedOrg(org)
    setView('scanning')
  }, [setSelectedOrg, setView])

  // ── Delete cache for an org
  const handleDeleteCache = useCallback(async (org: Org, e: React.MouseEvent) => {
    e.stopPropagation()
    setDeletingOrgId(org.id)
    try {
      await deleteOrgCache(org.id)
      setCacheMap(prev => ({ ...prev, [org.id]: { loading: false, entry: null } }))
    } catch {
      // ignore
    } finally {
      setDeletingOrgId(null)
    }
  }, [])

  // ── Default action for selected org: use cache if available, else scan
  const handleDefault = useCallback(() => {
    if (!selected) return
    const org = state.orgs.find(o => o.id === selected)
    if (!org) return
    const cacheInfo = cacheMap[org.id]
    if (cacheInfo?.entry) {
      handleUseCache(org)
    } else {
      handleFreshScan(org)
    }
  }, [selected, state.orgs, cacheMap, handleUseCache, handleFreshScan])

  if (state.orgs.length === 0) {
    // No orgs loaded — show token entry inline
    return (
      <div className="min-h-screen overflow-y-auto bg-bg-primary px-4 py-8 flex flex-col items-center justify-center">
        <div className="w-full max-w-md">
          {/* Logo */}
          <div className="text-center mb-8">
            <div className="inline-flex items-center justify-center w-16 h-16 bg-accent-purple/10 border border-accent-purple/30 rounded-2xl mb-4">
              <Shield size={32} className="text-accent-purple" />
            </div>
            <h1 className="text-3xl font-bold text-text-primary tracking-tight">
              Snyk <span className="text-accent-purple">Commander</span>
            </h1>
            <p className="text-text-muted mt-2 text-sm">Enter your Snyk API token to get started</p>
          </div>

          <div className="bg-bg-secondary border border-border rounded-2xl p-6 shadow-xl mb-4">
            <div className="flex items-center gap-2 mb-4">
              <Key size={15} className="text-accent-purple" />
              <h2 className="text-sm font-semibold text-text-primary">Snyk API Token</h2>
            </div>

            <div className="relative mb-4">
              <input
                type={showToken ? 'text' : 'password'}
                value={tokenInput}
                onChange={e => { setTokenInput(e.target.value); setConnectError('') }}
                onKeyDown={e => e.key === 'Enter' && handleConnect()}
                placeholder="snyk_token_xxxxxxxxxxxxxxxx"
                className="input-base pr-12 font-mono text-sm"
                autoFocus
              />
              <button
                type="button"
                onClick={() => setShowToken(v => !v)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-secondary"
              >
                {showToken ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>

            {connectError && (
              <div className="flex items-center gap-2 p-2.5 bg-red-950/40 border border-red-800/50 rounded-lg mb-4 text-red-400 text-xs">
                <AlertCircle size={13} /> {connectError}
              </div>
            )}

            <button
              onClick={() => handleConnect()}
              disabled={connectLoading || !tokenInput.trim()}
              className="btn-primary w-full justify-center py-2.5"
            >
              {connectLoading
                ? <><Loader2 size={16} className="animate-spin" />Connecting...</>
                : <>Connect<ArrowRight size={16} /></>
              }
            </button>
          </div>

          <div className="text-center">
            <p className="text-text-muted text-xs mb-2">Need to configure GitHub or OAuth?</p>
            <button onClick={() => setView('settings')} className="btn-secondary text-sm">
              <Settings size={14} />
              Open Settings
            </button>
          </div>
        </div>
      </div>
    )
  }

  const selectedOrg = state.orgs.find(o => o.id === selected) ?? null
  const selectedCache = selected ? cacheMap[selected] : null
  const hasCache = !!selectedCache?.entry
  const cacheLoading = selectedCache?.loading ?? false

  return (
    <div className="min-h-screen overflow-y-auto bg-bg-primary px-4 py-8 flex flex-col items-center">
      <div className="w-full max-w-xl">

        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-accent-purple/10 border border-accent-purple/30 rounded-xl flex items-center justify-center">
              <Shield size={20} className="text-accent-purple" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-text-primary">Select Organization</h1>
              <p className="text-sm text-text-muted">{state.orgs.length} organization{state.orgs.length !== 1 ? 's' : ''} available</p>
            </div>
          </div>
          <button onClick={() => setView('settings')} className="btn-secondary text-sm">
            <Settings size={14} />
            Settings
          </button>
        </div>

        {/* Org list */}
        <div className="bg-bg-secondary border border-border rounded-2xl shadow-xl overflow-hidden mb-4">
          <div className="divide-y divide-border">
            {state.orgs.map((org: Org) => {
              const isSelected = selected === org.id
              const info = cacheMap[org.id]
              const orgHasCache = !!info?.entry
              const orgCacheLoading = info?.loading ?? true

              return (
                <div
                  key={org.id}
                  onClick={() => setSelected(org.id)}
                  className={`flex items-center gap-3 px-4 py-3.5 cursor-pointer transition-colors ${
                    isSelected ? 'bg-accent-purple/10' : 'hover:bg-bg-tertiary'
                  }`}
                >
                  {/* Selection indicator */}
                  <div className={`w-4 h-4 rounded-full border-2 flex-shrink-0 flex items-center justify-center transition-colors ${
                    isSelected ? 'border-accent-purple bg-accent-purple' : 'border-border-light'
                  }`}>
                    {isSelected && <div className="w-1.5 h-1.5 rounded-full bg-white" />}
                  </div>

                  {/* Org icon */}
                  <div className={`w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0 ${
                    isSelected ? 'bg-accent-purple/20' : 'bg-bg-tertiary'
                  }`}>
                    <Building2 size={16} className={isSelected ? 'text-accent-purple' : 'text-text-muted'} />
                  </div>

                  {/* Org info */}
                  <div className="flex-1 min-w-0">
                    <p className={`font-medium truncate text-sm ${isSelected ? 'text-text-primary' : 'text-text-secondary'}`}>
                      {org.name}
                    </p>
                    <p className="text-xs text-text-muted font-mono truncate">{org.slug}</p>
                  </div>

                  {/* Cache badge */}
                  <div className="flex-shrink-0 flex items-center gap-2">
                    {orgCacheLoading ? (
                      <Loader2 size={13} className="text-text-muted animate-spin" />
                    ) : orgHasCache ? (
                      <div className="flex items-center gap-1.5 px-2 py-1 bg-accent-green/10 border border-accent-green/30 rounded-lg">
                        <Database size={11} className="text-accent-green" />
                        <span className="text-xs text-accent-green font-medium">Cached</span>
                      </div>
                    ) : (
                      <div className="flex items-center gap-1.5 px-2 py-1 bg-bg-tertiary border border-border rounded-lg">
                        <AlertCircle size={11} className="text-text-muted" />
                        <span className="text-xs text-text-muted">No cache</span>
                      </div>
                    )}
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Cache details panel — shown when an org with cache is selected */}
        {selectedOrg && !cacheLoading && (
          <div className={`rounded-xl border p-4 mb-4 transition-all ${
            hasCache
              ? 'bg-accent-green/5 border-accent-green/20'
              : 'bg-bg-secondary border-border'
          }`}>
            {hasCache && selectedCache?.entry ? (
              <div className="flex items-start gap-3">
                <Database size={18} className="text-accent-green flex-shrink-0 mt-0.5" />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center justify-between gap-2 mb-2">
                    <p className="text-sm font-semibold text-text-primary">Cached scan available</p>
                    <button
                      onClick={(e) => handleDeleteCache(selectedOrg, e)}
                      disabled={deletingOrgId === selectedOrg.id}
                      className="flex items-center gap-1 text-xs text-text-muted hover:text-red-400 transition-colors p-1 rounded"
                      title="Clear cache"
                    >
                      {deletingOrgId === selectedOrg.id
                        ? <Loader2 size={12} className="animate-spin" />
                        : <Trash2 size={12} />
                      }
                    </button>
                  </div>

                  {/* Stats row */}
                  <div className="grid grid-cols-4 gap-2 mb-3">
                    {[
                      { label: 'Projects', value: selectedCache.entry.project_count },
                      { label: 'Vulns', value: selectedCache.entry.vuln_count, color: selectedCache.entry.vuln_count > 0 ? 'text-yellow-400' : undefined },
                      { label: 'Critical', value: selectedCache.entry.critical_count, color: selectedCache.entry.critical_count > 0 ? 'text-red-400' : undefined },
                      { label: 'Fixable', value: selectedCache.entry.fixable_count, color: selectedCache.entry.fixable_count > 0 ? 'text-accent-green' : undefined },
                    ].map(stat => (
                      <div key={stat.label} className="bg-bg-secondary rounded-lg px-2 py-1.5 text-center">
                        <p className={`text-sm font-bold ${stat.color ?? 'text-text-primary'}`}>{stat.value.toLocaleString()}</p>
                        <p className="text-xs text-text-muted">{stat.label}</p>
                      </div>
                    ))}
                  </div>

                  {/* Timestamp */}
                  <div className="flex items-center gap-1.5 text-xs text-text-muted">
                    <Clock size={11} />
                    <span>Scanned {formatTimestamp(selectedCache.entry.timestamp)}</span>
                  </div>
                </div>
              </div>
            ) : (
              <div className="flex items-center gap-3">
                <AlertCircle size={16} className="text-text-muted flex-shrink-0" />
                <p className="text-sm text-text-secondary">
                  No cached data for <strong className="text-text-primary">{selectedOrg.name}</strong> — a fresh scan is required.
                </p>
              </div>
            )}
          </div>
        )}

        {/* Action buttons */}
        <div className="flex gap-3">
          {/* Use Cache button — only when cache exists */}
          {hasCache && selectedOrg && (
            <button
              onClick={() => handleUseCache(selectedOrg)}
              disabled={cacheLoading}
              className="btn-secondary flex-1 justify-center"
            >
              <Zap size={16} />
              Use Cached Data
            </button>
          )}

          {/* Scan button — always available */}
          <button
            onClick={() => selectedOrg && handleFreshScan(selectedOrg)}
            disabled={!selected || cacheLoading}
            className="btn-primary flex-1 justify-center"
          >
            {hasCache ? <RefreshCw size={16} /> : <Play size={16} />}
            {hasCache ? 'Re-scan' : 'Scan'}
          </button>
        </div>

        {/* Keyboard hint */}
        {selected && (
          <p className="text-center text-text-muted text-xs mt-4">
            {hasCache
              ? 'Use cached data to go straight to the dashboard, or re-scan for fresh results.'
              : 'A fresh scan will pull the latest vulnerability data from Snyk.'}
          </p>
        )}

      </div>
    </div>
  )
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function formatTimestamp(ts: string): string {
  try {
    // Backend stores as "YYYY-MM-DD HH:MM:SS" or ISO string
    const d = new Date(ts.includes('T') ? ts : ts.replace(' ', 'T'))
    const now = new Date()
    const diffMs = now.getTime() - d.getTime()
    const diffMins = Math.floor(diffMs / 60_000)
    const diffHours = Math.floor(diffMs / 3_600_000)
    const diffDays = Math.floor(diffMs / 86_400_000)

    if (diffMins < 1) return 'just now'
    if (diffMins < 60) return `${diffMins}m ago`
    if (diffHours < 24) return `${diffHours}h ago`
    if (diffDays === 1) return 'yesterday'
    if (diffDays < 7) return `${diffDays}d ago`
    return d.toLocaleDateString()
  } catch {
    return ts
  }
}
