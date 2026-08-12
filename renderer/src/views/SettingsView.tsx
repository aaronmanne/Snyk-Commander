import React, { useState, useEffect } from 'react'
import {
  Settings, Shield, Trash2, Eye, EyeOff, AlertCircle, CheckCircle,
  Loader2, Github, Key, Copy, ExternalLink, XCircle, Info, ArrowLeft, Filter
} from 'lucide-react'
import { useApp } from '../context/AppContext'
import {
  verifyToken, deleteAllCache, startSnykOAuth, startGitHubDeviceFlow,
  pollGitHubToken, getStoredTokens, storeToken, clearToken, setGitHubClientId, setGheHost,
  getIncludedOrigins, setIncludedOrigins, getIncludedTypes, setIncludedTypes
} from '../api'
import type { GitHubDeviceFlow } from '../types'
import Modal from '../components/Modal'

export default function SettingsView() {
  const { state, setToken, setOrgs, setGithubToken, setView, logout } = useApp()

  // ── Snyk Token ───────────────────────────────────────────────────────────
  const [tokenInput, setTokenInput] = useState(state.token)
  const [showToken, setShowToken] = useState(false)
  const [reauthing, setReauthing] = useState(false)
  const [reauthError, setReauthError] = useState('')
  const [reauthSuccess, setReauthSuccess] = useState(false)

  // ── Snyk OAuth ────────────────────────────────────────────────────────────
  const [snykOAuthLoading, setSnykOAuthLoading] = useState(false)
  const [snykOAuthMessages, setSnykOAuthMessages] = useState<string[]>([])
  const [snykOAuthError, setSnykOAuthError] = useState('')
  const [snykOAuthSuccess, setSnykOAuthSuccess] = useState('')

  // ── GitHub ────────────────────────────────────────────────────────────────
  const [githubClientId, setGithubClientIdLocal] = useState('')
  const [showClientIdSetup, setShowClientIdSetup] = useState(false)
  const [savingClientId, setSavingClientId] = useState(false)
  const [gheHostInput, setGheHostInput] = useState('')
  const [savingGheHost, setSavingGheHost] = useState(false)
  const [gheHostSaved, setGheHostSaved] = useState(false)
  const [githubLoading, setGithubLoading] = useState(false)
  const [githubDeviceFlow, setGithubDeviceFlow] = useState<GitHubDeviceFlow | null>(null)
  const [githubPollingMsg, setGithubPollingMsg] = useState('')
  const [githubError, setGithubError] = useState('')
  const [storedGithubToken, setStoredGithubToken] = useState<string | null>(state.githubToken || null)
  // Direct PAT entry (for orgs with OAuth App restrictions / SSO)
  const [patInput, setPatInput] = useState('')
  const [showPat, setShowPat] = useState(false)
  const [savingPat, setSavingPat] = useState(false)
  const [patSaved, setPatSaved] = useState(false)

  // ── Cache ─────────────────────────────────────────────────────────────────
  const [clearingCache, setClearingCache] = useState(false)
  const [clearError, setClearError] = useState('')
  const [clearSuccess, setClearSuccess] = useState(false)
  const [showClearConfirm, setShowClearConfirm] = useState(false)

  // ── Project Filters ───────────────────────────────────────────────────────
  const [includedOrigins, setIncludedOriginsLocal] = useState<string[]>([])
  const [includedTypes, setIncludedTypesLocal] = useState<string[]>([])
  const [customOrigin, setCustomOrigin] = useState('')
  const [customType, setCustomType] = useState('')
  const [savingFilters, setSavingFilters] = useState(false)
  const [filtersSaved, setFiltersSaved] = useState(false)
  const [filtersError, setFiltersError] = useState('')

  const commonOrigins = [
    { value: 'github', label: 'GitHub' },
    { value: 'gitlab', label: 'GitLab' },
    { value: 'bitbucket', label: 'Bitbucket' },
    { value: 'azure-repos', label: 'Azure Repos' },
    { value: 'bitbucket-cloud', label: 'Bitbucket Cloud' },
    { value: 'bitbucket-server', label: 'Bitbucket Server' },
    { value: 'azure-repos', label: 'Azure Repos' },
    { value: 'docker-hub', label: 'Docker Hub' },
    { value: 'ecr', label: 'Amazon ECR' },
    { value: 'gcr', label: 'Google GCR' },
    { value: 'acr', label: 'Azure ACR' },
  ]

  const commonTypes = [
    { value: 'npm', label: 'npm (JavaScript)' },
    { value: 'yarn', label: 'Yarn (JavaScript)' },
    { value: 'maven', label: 'Maven (Java)' },
    { value: 'gradle', label: 'Gradle (Java)' },
    { value: 'pip', label: 'pip (Python)' },
    { value: 'poetry', label: 'Poetry (Python)' },
    { value: 'nuget', label: 'NuGet (.NET)' },
    { value: 'rubygems', label: 'RubyGems (Ruby)' },
    { value: 'composer', label: 'Composer (PHP)' },
    { value: 'gomodules', label: 'Go Modules' },
    { value: 'sbt', label: 'sbt (Scala)' },
  ]

  // Load stored tokens and client ID on mount
  useEffect(() => {
    getStoredTokens()
      .then(res => {
        if (res.github) {
          setStoredGithubToken(res.github)
          setGithubToken(res.github)
        }
        if (res.github_client_id) setGithubClientIdLocal(res.github_client_id)
        if (res.ghe_host) setGheHostInput(res.ghe_host)
      })
      .catch(() => {
        const t = localStorage.getItem('github_token')
        if (t) setStoredGithubToken(t)
      })
    
    getIncludedOrigins()
      .then(res => {
        setIncludedOriginsLocal(res.included_origins)
      })
      .catch(() => {})
    
    getIncludedTypes()
      .then(res => {
        setIncludedTypesLocal(res.included_types)
      })
      .catch(() => {})
  }, [])

  // ── Handlers ─────────────────────────────────────────────────────────────

  const handleReauth = async () => {
    if (!tokenInput.trim()) return
    setReauthing(true); setReauthError(''); setReauthSuccess(false)
    try {
      const res = await verifyToken(tokenInput.trim())
      localStorage.setItem('snyk_token', tokenInput.trim())
      setToken(tokenInput.trim())
      setOrgs(res.orgs)
      setReauthSuccess(true)
    } catch (e: unknown) {
      setReauthError(e instanceof Error ? e.message : String(e))
    } finally {
      setReauthing(false)
    }
  }

  const handleSnykOAuth = async () => {
    setSnykOAuthLoading(true); setSnykOAuthMessages([]); setSnykOAuthError(''); setSnykOAuthSuccess('')
    try {
      const res = await startSnykOAuth((msg: string) => {
        setSnykOAuthMessages(prev => [...prev.slice(-2), msg])
      })
      localStorage.setItem('snyk_token', res.token)
      setToken(res.token)
      setOrgs(res.orgs)
      setSnykOAuthSuccess(`Connected to ${res.orgs[0]?.name ?? 'Snyk'} via OAuth`)
    } catch (e: unknown) {
      setSnykOAuthError(e instanceof Error ? e.message : 'OAuth failed')
    } finally {
      setSnykOAuthLoading(false)
    }
  }

  const handleSaveClientId = async () => {
    const id = githubClientId.trim()
    if (!id) return
    setSavingClientId(true)
    try {
      await setGitHubClientId(id)
      setShowClientIdSetup(false)
      setGithubError('')
    } catch (e: unknown) {
      setGithubError(e instanceof Error ? e.message : 'Failed to save client ID')
    } finally {
      setSavingClientId(false)
    }
  }

  const handleSaveGheHost = async () => {
    const host = gheHostInput.trim()
    if (!host) return
    setSavingGheHost(true)
    try {
      await setGheHost(host)
      setGheHostSaved(true)
      setTimeout(() => setGheHostSaved(false), 3000)
    } catch (e: unknown) {
      setGithubError(e instanceof Error ? e.message : 'Failed to save GHE host')
    } finally {
      setSavingGheHost(false)
    }
  }

  const handleGitHubConnect = async () => {
    if (!githubClientId.trim()) {
      setShowClientIdSetup(true)
      setGithubError('A GitHub OAuth App Client ID is required. See setup instructions below.')
      return
    }
    setGithubLoading(true); setGithubDeviceFlow(null); setGithubError(''); setGithubPollingMsg('')
    try {
      const flow = await startGitHubDeviceFlow()
      setGithubDeviceFlow(flow)
      pollGitHubToken(flow.device_code, flow.interval, (msg: string) => {
        setGithubPollingMsg(msg)
      }).then(async (res) => {
        setGithubToken(res.token)
        setStoredGithubToken(res.token)
        setGithubDeviceFlow(null)
        try { await storeToken('github', res.token) } catch { /* ignore */ }
        localStorage.setItem('github_token', res.token)
      }).catch((e: unknown) => {
        setGithubError(e instanceof Error ? e.message : 'GitHub auth failed.')
      }).finally(() => setGithubLoading(false))
    } catch (e: unknown) {
      setGithubError(e instanceof Error ? e.message : 'Failed to start GitHub device flow.')
      setGithubLoading(false)
    }
  }

  const handleSavePat = async () => {
    const tok = patInput.trim()
    if (!tok) return
    setSavingPat(true)
    setGithubError('')
    try {
      await storeToken('github', tok)
      localStorage.setItem('github_token', tok)
      setGithubToken(tok)
      setStoredGithubToken(tok)
      setPatInput('')
      setPatSaved(true)
      setTimeout(() => setPatSaved(false), 3000)
    } catch (e: unknown) {
      setGithubError(e instanceof Error ? e.message : 'Failed to save token')
    } finally {
      setSavingPat(false)
    }
  }

  const handleGitHubDisconnect = async () => {
    setStoredGithubToken(null)
    setGithubToken('')
    localStorage.removeItem('github_token')
    try { await clearToken('github') } catch { /* ignore */ }
  }

  const handleClearCache = async () => {
    setClearingCache(true); setClearError(''); setClearSuccess(false); setShowClearConfirm(false)
    try {
      await deleteAllCache()
      setClearSuccess(true)
    } catch (e: unknown) {
      setClearError(e instanceof Error ? e.message : String(e))
    } finally {
      setClearingCache(false)
    }
  }

  const copyToClipboard = (text: string) => navigator.clipboard.writeText(text).catch(() => {})

  const openUrl = (url: string) => {
    if (window.snykAPI?.openPath) {
      window.snykAPI.openPath(url).catch(() => window.open(url, '_blank'))
    } else {
      window.open(url, '_blank')
    }
  }

  const handleSaveFilters = async () => {
    setSavingFilters(true)
    setFiltersError('')
    setFiltersSaved(false)
    try {
      await Promise.all([
        setIncludedOrigins(includedOrigins),
        setIncludedTypes(includedTypes)
      ])
      setFiltersSaved(true)
      setTimeout(() => setFiltersSaved(false), 3000)
    } catch (e: unknown) {
      setFiltersError(e instanceof Error ? e.message : String(e))
    } finally {
      setSavingFilters(false)
    }
  }

  const toggleOrigin = (origin: string) => {
    setIncludedOriginsLocal(prev => 
      prev.includes(origin) 
        ? prev.filter(o => o !== origin)
        : [...prev, origin]
    )
    setFiltersSaved(false)
  }

  const toggleType = (type: string) => {
    setIncludedTypesLocal(prev => 
      prev.includes(type) 
        ? prev.filter(t => t !== type)
        : [...prev, type]
    )
    setFiltersSaved(false)
  }

  const addCustomOrigin = () => {
    const origin = customOrigin.trim()
    if (origin && !includedOrigins.includes(origin)) {
      setIncludedOriginsLocal(prev => [...prev, origin])
      setCustomOrigin('')
      setFiltersSaved(false)
    }
  }

  const addCustomType = () => {
    const type = customType.trim()
    if (type && !includedTypes.includes(type)) {
      setIncludedTypesLocal(prev => [...prev, type])
      setCustomType('')
      setFiltersSaved(false)
    }
  }

  const removeOrigin = (origin: string) => {
    setIncludedOriginsLocal(prev => prev.filter(o => o !== origin))
    setFiltersSaved(false)
  }

  const removeType = (type: string) => {
    setIncludedTypesLocal(prev => prev.filter(t => t !== type))
    setFiltersSaved(false)
  }

  const isGithubConnected = !!storedGithubToken

  return (
    <div className="flex-1 overflow-y-auto bg-bg-primary p-6">
      <div className="max-w-2xl mx-auto">

        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-accent-purple/10 border border-accent-purple/30 rounded-xl flex items-center justify-center">
              <Settings size={20} className="text-accent-purple" />
            </div>
            <h1 className="text-xl font-bold text-text-primary">Settings</h1>
          </div>
          {state.scanResults.length > 0 && (
            <button onClick={() => setView('dashboard')} className="btn-secondary text-sm">
              <ArrowLeft size={14} />
              Back to Dashboard
            </button>
          )}
        </div>

        {/* ── Snyk API Token ─────────────────────────────────────────────────── */}
        <div className="bg-bg-secondary border border-border rounded-xl p-5 mb-4">
          <div className="flex items-center gap-2 mb-4">
            <Shield size={16} className="text-accent-purple" />
            <h2 className="text-sm font-semibold text-text-primary">Snyk API Token</h2>
          </div>

          <div className="relative mb-3">
            <input
              type={showToken ? 'text' : 'password'}
              value={tokenInput}
              onChange={e => { setTokenInput(e.target.value); setReauthSuccess(false); setReauthError('') }}
              onKeyDown={e => e.key === 'Enter' && handleReauth()}
              className="input-base pr-12 font-mono text-sm"
              placeholder="snyk_token_xxxxxxxxxxxxxxxx"
            />
            <button
              onClick={() => setShowToken(v => !v)}
              className="absolute right-3 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-secondary"
            >
              {showToken ? <EyeOff size={16} /> : <Eye size={16} />}
            </button>
          </div>

          {reauthError && (
            <div className="flex items-center gap-2 p-2.5 bg-red-950/40 border border-red-800/50 rounded-lg mb-3 text-red-400 text-xs">
              <AlertCircle size={13} /> {reauthError}
            </div>
          )}
          {reauthSuccess && (
            <div className="flex items-center gap-2 p-2.5 bg-accent-green/10 border border-accent-green/30 rounded-lg mb-3 text-accent-green text-xs">
              <CheckCircle size={13} /> Token verified — {state.orgs.length} org{state.orgs.length !== 1 ? 's' : ''} loaded
            </div>
          )}

          <div className="flex gap-2">
            <button onClick={handleReauth} disabled={reauthing || !tokenInput.trim()} className="btn-primary">
              {reauthing ? <Loader2 size={15} className="animate-spin" /> : <Shield size={15} />}
              Verify & Save
            </button>
            <button onClick={() => { logout(); setView('org-select') }} className="btn-danger">
              Sign Out
            </button>
          </div>
        </div>

        {/* ── Snyk OAuth ─────────────────────────────────────────────────────── */}
        <div className="bg-bg-secondary border border-border rounded-xl p-5 mb-4">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-sm">🔐</span>
            <h2 className="text-sm font-semibold text-text-primary">Snyk OAuth</h2>
            <span className="text-xs text-text-muted ml-auto">Authorized App</span>
          </div>
          <p className="text-xs text-text-muted mb-4">Connect without exposing your API token</p>

          {snykOAuthSuccess ? (
            <div className="flex items-center gap-2 p-3 bg-green-950/40 border border-green-700/40 rounded-lg text-accent-green text-sm mb-3">
              <CheckCircle size={15} /> {snykOAuthSuccess}
            </div>
          ) : null}

          <button
            onClick={handleSnykOAuth}
            disabled={snykOAuthLoading}
            className="btn-primary mb-3"
          >
            {snykOAuthLoading ? <><Loader2 size={15} className="animate-spin" />Connecting...</> : <>Connect with Snyk OAuth</>}
          </button>

          {snykOAuthMessages.length > 0 && (
            <div className="bg-bg-tertiary border border-border rounded-lg p-3 font-mono text-xs text-text-muted space-y-0.5 mb-2">
              {snykOAuthMessages.map((m, i) => (
                <p key={i} className={i === snykOAuthMessages.length - 1 ? 'text-text-secondary' : ''}>{m}</p>
              ))}
            </div>
          )}
          {snykOAuthError && (
            <div className="flex items-start gap-2 p-2.5 bg-red-950/40 border border-red-800/50 rounded-lg text-red-400 text-xs">
              <XCircle size={13} className="flex-shrink-0 mt-0.5" /> {snykOAuthError}
            </div>
          )}
        </div>

        {/* ── GitHub Connection ───────────────────────────────────────────────── */}
        <div className="bg-bg-secondary border border-border rounded-xl p-5 mb-4">
          <div className="flex items-center gap-2 mb-1">
            <Github size={15} className="text-text-secondary" />
            <h2 className="text-sm font-semibold text-text-primary">GitHub</h2>
            <span className="text-xs text-text-muted ml-auto">for Reachability Analysis</span>
          </div>
          <p className="text-xs text-text-muted mb-4">Auto-clone repos to check if vulnerable code is actually called</p>

          {isGithubConnected ? (
            <div className="flex items-center justify-between p-3 bg-green-950/30 border border-green-700/30 rounded-lg mb-4">
              <div className="flex items-center gap-2 text-accent-green text-sm">
                <CheckCircle size={15} />
                <span>GitHub Connected ✓</span>
                <span className="text-xs text-green-700/60 font-mono ml-1">
                  {storedGithubToken?.startsWith('github_pat_') ? '(Fine-grained PAT)' : storedGithubToken?.startsWith('ghp_') ? '(Classic PAT)' : storedGithubToken?.startsWith('gho_') ? '(OAuth token)' : ''}
                </span>
              </div>
              <button onClick={handleGitHubDisconnect} className="btn-danger text-xs py-1 px-3">
                Disconnect
              </button>
            </div>
          ) : null}

          {/* ── Option 1: Fine-Grained Personal Access Token (recommended) ── */}
          <div className="mb-4 p-3 bg-bg-tertiary border border-border rounded-xl">
            <div className="flex items-center gap-2 mb-2">
              <Key size={13} className="text-accent-green" />
              <span className="text-xs font-semibold text-text-primary">Personal Access Token</span>
              <span className="text-xs text-accent-green bg-accent-green/10 border border-accent-green/20 px-1.5 py-0.5 rounded font-medium">Recommended</span>
            </div>

            {/* Step-by-step instructions */}
            <div className="mb-3 space-y-2">
              <p className="text-xs text-text-secondary font-medium">Create a Fine-Grained PAT — read-only, no write access ever:</p>
              <ol className="space-y-1.5 text-xs text-text-muted">
                <li className="flex gap-2">
                  <span className="text-accent-purple font-bold flex-shrink-0">1.</span>
                  <span>
                    Go to{' '}
                    <button
                      onClick={() => openUrl('https://github.com/settings/personal-access-tokens/new')}
                      className="text-accent-purple hover:underline inline-flex items-center gap-0.5"
                    >
                      github.com/settings/personal-access-tokens/new <ExternalLink size={10} />
                    </button>
                  </span>
                </li>
                <li className="flex gap-2">
                  <span className="text-accent-purple font-bold flex-shrink-0">2.</span>
                  <span>Set <strong className="text-text-secondary">Token name</strong>: <code className="bg-bg-secondary px-1 rounded">Snyk Commander</code></span>
                </li>
                <li className="flex gap-2">
                  <span className="text-accent-purple font-bold flex-shrink-0">3.</span>
                  <span>
                    Set <strong className="text-text-secondary">Resource owner</strong> to your org (e.g. <code className="bg-bg-secondary px-1 rounded">ccsq-eqrs</code>).
                    {' '}If the org doesn't appear, an org admin may need to approve fine-grained PATs first.
                  </span>
                </li>
                <li className="flex gap-2">
                  <span className="text-accent-purple font-bold flex-shrink-0">4.</span>
                  <span>
                    Under <strong className="text-text-secondary">Repository access</strong>, choose{' '}
                    <strong className="text-text-secondary">All repositories</strong> or select specific repos.
                  </span>
                </li>
                <li className="flex gap-2">
                  <span className="text-accent-purple font-bold flex-shrink-0">5.</span>
                  <span>
                    Under <strong className="text-text-secondary">Permissions → Repository permissions</strong>, set only:
                    <span className="block mt-1 ml-1 p-1.5 bg-bg-secondary rounded border border-border">
                      <code className="text-accent-green">Contents</code>
                      <span className="text-text-muted mx-1">→</span>
                      <code className="text-accent-green">Read-only</code>
                      <span className="text-text-muted text-xs ml-2">(needed to clone &amp; pull)</span>
                    </span>
                    <span className="text-text-muted mt-1 block">All other permissions: <strong className="text-text-secondary">No access</strong></span>
                  </span>
                </li>
                <li className="flex gap-2">
                  <span className="text-accent-purple font-bold flex-shrink-0">6.</span>
                  <span>Click <strong className="text-text-secondary">Generate token</strong> and paste it below.</span>
                </li>
              </ol>
              <div className="flex items-start gap-2 p-2 bg-yellow-950/20 border border-yellow-700/20 rounded-lg">
                <span className="text-yellow-400 text-xs flex-shrink-0 mt-0.5">ℹ</span>
                <p className="text-xs text-yellow-400/80">
                  If your org requires SSO and fine-grained PATs are not yet approved, use a{' '}
                  <button
                    onClick={() => openUrl('https://github.com/settings/tokens')}
                    className="underline hover:no-underline inline-flex items-center gap-0.5"
                  >
                    Classic PAT <ExternalLink size={9} />
                  </button>
                  {' '}with <code className="bg-yellow-900/30 px-0.5 rounded">repo</code> scope + Configure SSO instead.
                </p>
              </div>
            </div>

            {/* Token input */}
            <div className="flex gap-2">
              <div className="relative flex-1">
                <input
                  type={showPat ? 'text' : 'password'}
                  placeholder="github_pat_... or ghp_..."
                  value={patInput}
                  onChange={e => { setPatInput(e.target.value); setGithubError('') }}
                  onKeyDown={e => e.key === 'Enter' && handleSavePat()}
                  className="input-base font-mono text-sm pr-10 w-full"
                />
                <button
                  type="button"
                  onClick={() => setShowPat(v => !v)}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-secondary"
                >
                  {showPat ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
              </div>
              <button
                onClick={handleSavePat}
                disabled={!patInput.trim() || savingPat}
                className="btn-primary flex-shrink-0 text-xs px-4"
              >
                {savingPat ? <Loader2 size={13} className="animate-spin" /> : patSaved ? <CheckCircle size={13} /> : 'Save'}
              </button>
            </div>
          </div>

          {/* ── Option 2: OAuth Device Flow ── */}
          <div className="mb-4">
            <div className="flex items-center gap-2 mb-2">
              <Github size={13} className="text-text-muted" />
              <span className="text-xs font-medium text-text-secondary">OAuth Device Flow</span>
              <span className="text-xs text-text-muted">(may be blocked by SSO orgs)</span>
            </div>

            {/* Client ID input */}
            {!isGithubConnected && (
              <div className="mb-3">
                <div className="flex items-center justify-between mb-1.5">
                  <label className="text-xs text-text-muted flex items-center gap-1">
                    <Key size={10} /> OAuth App Client ID
                  </label>
                  <button onClick={() => setShowClientIdSetup(v => !v)} className="text-xs text-accent-purple hover:underline flex items-center gap-1">
                    <Info size={10} /> How to get one
                  </button>
                </div>
                <div className="flex gap-2 mb-1">
                  <input
                    type="text"
                    placeholder="Ov23liXXXXXXXXXXXXXX"
                    value={githubClientId}
                    onChange={e => { setGithubClientIdLocal(e.target.value); setGithubError('') }}
                    className="input-base flex-1 font-mono text-sm"
                  />
                  <button onClick={handleSaveClientId} disabled={!githubClientId.trim() || savingClientId} className="btn-secondary flex-shrink-0 text-xs px-3">
                    {savingClientId ? <Loader2 size={13} className="animate-spin" /> : 'Save'}
                  </button>
                </div>
                {showClientIdSetup && (
                  <div className="mt-2 p-3 bg-bg-secondary border border-border rounded-xl text-xs space-y-1.5">
                    <p className="font-semibold text-text-primary">Create a free GitHub OAuth App:</p>
                    <ol className="space-y-1 text-text-secondary">
                      <li className="flex gap-2"><span className="text-accent-purple font-bold flex-shrink-0">1.</span><span>Go to <button onClick={() => openUrl('https://github.com/settings/developers')} className="text-accent-purple hover:underline inline-flex items-center gap-0.5">github.com/settings/developers <ExternalLink size={9} /></button> → OAuth Apps → New</span></li>
                      <li className="flex gap-2"><span className="text-accent-purple font-bold flex-shrink-0">2.</span><span>Set Homepage URL and callback URL both to <code className="bg-bg-tertiary px-1 rounded">http://localhost</code></span></li>
                      <li className="flex gap-2"><span className="text-accent-purple font-bold flex-shrink-0">3.</span><span>Register and paste the Client ID above. No secret needed.</span></li>
                    </ol>
                  </div>
                )}
              </div>
            )}

            {!isGithubConnected && !githubDeviceFlow && (
              <button onClick={handleGitHubConnect} disabled={githubLoading} className="btn-secondary text-sm">
                {githubLoading ? <><Loader2 size={14} className="animate-spin" />Starting...</> : <><Github size={14} />Connect via Device Flow</>}
              </button>
            )}
          </div>

          {/* GitHub Enterprise Host */}
          <div className="mb-4">
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs font-medium text-text-secondary flex items-center gap-1.5">
                <Key size={11} /> GitHub Enterprise Host
                <span className="text-text-muted font-normal">(optional — only for self-hosted GHE)</span>
              </label>
            </div>
            <div className="flex gap-2">
              <input
                type="text"
                placeholder="github.mycompany.com"
                value={gheHostInput}
                onChange={e => setGheHostInput(e.target.value)}
                className="input-base flex-1 font-mono text-sm"
              />
              <button
                onClick={handleSaveGheHost}
                disabled={!gheHostInput.trim() || savingGheHost}
                className="btn-secondary flex-shrink-0 text-xs px-3"
              >
                {savingGheHost ? <Loader2 size={13} className="animate-spin" /> : gheHostSaved ? <CheckCircle size={13} className="text-accent-green" /> : 'Save'}
              </button>
            </div>
            <p className="text-xs text-text-muted mt-1">
              Only needed for actual self-hosted GitHub Enterprise Server instances. Leave blank for github.com (including SSO orgs).
            </p>
          </div>

          {/* Connect / device flow */}
          {!isGithubConnected && !githubDeviceFlow && (
            <button
              onClick={handleGitHubConnect}
              disabled={githubLoading}
              className="btn-secondary"
            >
              {githubLoading
                ? <><Loader2 size={15} className="animate-spin" />Starting...</>
                : <><Github size={15} />Connect GitHub</>
              }
            </button>
          )}

          {githubDeviceFlow && (
            <div className="space-y-3 mt-3">
              <p className="text-xs text-text-secondary">
                Enter this code at <strong className="text-text-primary">github.com/login/device</strong>:
              </p>
              <div className="flex items-center gap-2">
                <div className="flex-1 bg-bg-tertiary border border-border-light rounded-lg px-4 py-3 font-mono text-xl font-bold text-text-primary tracking-widest text-center">
                  {githubDeviceFlow.user_code}
                </div>
                <button onClick={() => copyToClipboard(githubDeviceFlow.user_code)} className="btn-secondary p-2.5 flex-shrink-0" title="Copy">
                  <Copy size={15} />
                </button>
              </div>
              <button onClick={() => openUrl(githubDeviceFlow.verification_uri)} className="btn-secondary w-full justify-center py-2 text-sm">
                <ExternalLink size={13} /> Open github.com/login/device
              </button>
              {githubPollingMsg && (
                <div className="flex items-center gap-2 text-xs text-text-muted">
                  <Loader2 size={11} className="animate-spin flex-shrink-0" /> {githubPollingMsg}
                </div>
              )}
              <p className="text-xs text-text-muted">Expires in {Math.floor(githubDeviceFlow.expires_in / 60)} minutes</p>
            </div>
          )}

          {githubError && (
            <div className="flex items-start gap-2 p-2.5 bg-red-950/40 border border-red-800/50 rounded-lg mt-3 text-red-400 text-xs">
              <XCircle size={13} className="flex-shrink-0 mt-0.5" /> {githubError}
            </div>
          )}
        </div>

        {/* ── Project Filters ──────────────────────────────────────────────────── */}
        <div className="bg-bg-secondary border border-border rounded-xl p-5 mb-4">
          <div className="flex items-center gap-2 mb-3">
            <Filter size={15} className="text-accent-purple" />
            <h2 className="text-sm font-semibold text-text-primary">Project Filters</h2>
          </div>
          <p className="text-text-muted text-sm mb-4">
            Select which project origins and types to INCLUDE in scans. Leave empty to include all.
            Changes apply to future scans.
          </p>

          {/* Show actual origins and types in current projects */}
          {state.scanResults.length > 0 && (
            <div className="bg-bg-tertiary border border-border rounded-lg p-3 mb-4">
              <p className="text-xs font-semibold text-text-secondary mb-2">Origins in your current projects:</p>
              <div className="flex flex-wrap gap-2 mb-3">
                {Array.from(new Set(state.scanResults.map(r => r.origin))).sort().map(origin => (
                  <span key={origin} className="text-xs px-2 py-1 bg-bg-secondary border border-border rounded font-mono text-text-primary">
                    {origin}
                  </span>
                ))}
              </div>
              <p className="text-xs font-semibold text-text-secondary mb-2 mt-3">Types in your current projects:</p>
              <div className="flex flex-wrap gap-2">
                {Array.from(new Set(state.scanResults.map(r => r.type))).sort().map(type => (
                  <span key={type} className="text-xs px-2 py-1 bg-bg-secondary border border-border rounded font-mono text-text-primary">
                    {type}
                  </span>
                ))}
              </div>
              <p className="text-xs text-text-muted mt-2">
                These are the exact origin and type values from your Snyk projects. Use these when filtering.
              </p>
            </div>
          )}

          {/* Origins Section */}
          <h3 className="text-sm font-semibold text-text-secondary mb-2">Include by Origin</h3>

          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 mb-4">
            {commonOrigins.map(origin => (
              <button
                key={origin.value}
                onClick={() => toggleOrigin(origin.value)}
                className={`flex items-center justify-between px-3 py-2 rounded-lg border text-sm transition-all ${
                  includedOrigins.includes(origin.value)
                    ? 'bg-accent-green/20 border-accent-green/50 text-accent-green'
                    : 'bg-bg-tertiary border-border text-text-secondary hover:border-border-light'
                }`}
              >
                <span>{origin.label}</span>
                {includedOrigins.includes(origin.value) && (
                  <CheckCircle size={14} className="flex-shrink-0 ml-2" />
                )}
              </button>
            ))}
          </div>

          {/* Custom origin input */}
          <div className="mb-4">
            <label className="block text-xs font-medium text-text-muted mb-2">Add Custom Origin</label>
            <div className="flex gap-2">
              <input
                type="text"
                value={customOrigin}
                onChange={e => setCustomOrigin(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && addCustomOrigin()}
                placeholder="e.g., github-enterprise"
                className="input-base flex-1 text-sm font-mono"
              />
              <button
                onClick={addCustomOrigin}
                disabled={!customOrigin.trim()}
                className="btn-secondary"
              >
                Add
              </button>
            </div>
          </div>

          {/* Currently included origins */}
          {includedOrigins.length > 0 && (
            <div className="bg-accent-green/10 border border-accent-green/30 rounded-lg p-3 mb-4">
              <p className="text-xs font-semibold text-accent-green mb-2">Included Origins ({includedOrigins.length}):</p>
              <div className="flex flex-wrap gap-2">
                {includedOrigins.map(origin => (
                  <button
                    key={origin}
                    onClick={() => removeOrigin(origin)}
                    className="flex items-center gap-1.5 px-2 py-1 bg-accent-green/20 border border-accent-green/40 rounded text-xs text-accent-green hover:bg-accent-green/30 transition-colors"
                  >
                    <span className="font-mono">{origin}</span>
                    <XCircle size={12} />
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Types Section */}
          <h3 className="text-sm font-semibold text-text-secondary mb-2 mt-4">Include by Type</h3>
          <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 mb-4">
            {commonTypes.map(type => (
              <button
                key={type.value}
                onClick={() => toggleType(type.value)}
                className={`flex items-center justify-between px-3 py-2 rounded-lg border text-sm transition-all ${
                  includedTypes.includes(type.value)
                    ? 'bg-accent-green/20 border-accent-green/50 text-accent-green'
                    : 'bg-bg-tertiary border-border text-text-secondary hover:border-border-light'
                }`}
              >
                <span>{type.label}</span>
                {includedTypes.includes(type.value) && (
                  <CheckCircle size={14} className="flex-shrink-0 ml-2" />
                )}
              </button>
            ))}
          </div>

          {/* Custom type input */}
          <div className="mb-4">
            <label className="block text-xs font-medium text-text-muted mb-2">Add Custom Type</label>
            <div className="flex gap-2">
              <input
                type="text"
                value={customType}
                onChange={e => setCustomType(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && addCustomType()}
                placeholder="e.g., cargo"
                className="input-base flex-1 text-sm font-mono"
              />
              <button
                onClick={addCustomType}
                disabled={!customType.trim()}
                className="btn-secondary"
              >
                Add
              </button>
            </div>
          </div>

          {/* Currently included types */}
          {includedTypes.length > 0 && (
            <div className="bg-accent-green/10 border border-accent-green/30 rounded-lg p-3 mb-4">
              <p className="text-xs font-semibold text-accent-green mb-2">Included Types ({includedTypes.length}):</p>
              <div className="flex flex-wrap gap-2">
                {includedTypes.map(type => (
                  <button
                    key={type}
                    onClick={() => removeType(type)}
                    className="flex items-center gap-1.5 px-2 py-1 bg-accent-green/20 border border-accent-green/40 rounded text-xs text-accent-green hover:bg-accent-green/30 transition-colors"
                  >
                    <span className="font-mono">{type}</span>
                    <XCircle size={12} />
                  </button>
                ))}
              </div>
            </div>
          )}

          {filtersError && (
            <div className="flex items-center gap-2 p-2.5 bg-red-950/40 border border-red-800/50 rounded-lg mb-3 text-red-400 text-xs">
              <AlertCircle size={13} /> {filtersError}
            </div>
          )}
          {filtersSaved && (
            <div className="flex items-center gap-2 p-2.5 bg-accent-green/10 border border-accent-green/30 rounded-lg mb-3 text-accent-green text-xs">
              <CheckCircle size={13} /> Filters saved. {includedOrigins.length > 0 || includedTypes.length > 0 ? `Only scanning ${includedOrigins.length > 0 ? includedOrigins.length + ' origin(s)' : 'all origins'} and ${includedTypes.length > 0 ? includedTypes.length + ' type(s)' : 'all types'}.` : 'Scanning all projects.'}
            </div>
          )}

          <div className="flex items-start gap-2 p-3 bg-blue-950/20 border border-blue-700/30 rounded-lg mb-4 text-blue-300 text-xs">
            <Info size={13} className="flex-shrink-0 mt-0.5" />
            <div>
              <p className="font-medium mb-1">Tip: Focus on source code only</p>
              <p className="text-blue-300/80">
                To scan only source code repositories, include git origins (github, gitlab, bitbucket, azure-repos) and source code types (npm, maven, pip, etc.). This will skip container images and IaC files.
              </p>
            </div>
          </div>

          <button 
            onClick={handleSaveFilters} 
            disabled={savingFilters} 
            className="btn-primary"
          >
            {savingFilters ? <Loader2 size={15} className="animate-spin" /> : <Filter size={15} />}
            Save Filters
          </button>
        </div>

        {/* ── Cache Management ────────────────────────────────────────────────── */}
        <div className="bg-bg-secondary border border-border rounded-xl p-5 mb-4">
          <div className="flex items-center gap-2 mb-3">
            <Trash2 size={15} className="text-red-400" />
            <h2 className="text-sm font-semibold text-text-primary">Cache Management</h2>
          </div>
          <p className="text-text-muted text-sm mb-4">
            Clear all locally cached scan results. You will need to rescan your organizations.
          </p>

          {clearError && (
            <div className="flex items-center gap-2 p-2.5 bg-red-950/40 border border-red-800/50 rounded-lg mb-3 text-red-400 text-xs">
              <AlertCircle size={13} /> {clearError}
            </div>
          )}
          {clearSuccess && (
            <div className="flex items-center gap-2 p-2.5 bg-accent-green/10 border border-accent-green/30 rounded-lg mb-3 text-accent-green text-xs">
              <CheckCircle size={13} /> Cache cleared successfully
            </div>
          )}

          <button onClick={() => setShowClearConfirm(true)} disabled={clearingCache} className="btn-danger">
            {clearingCache ? <Loader2 size={15} className="animate-spin" /> : <Trash2 size={15} />}
            Clear All Cache
          </button>
        </div>

        {/* ── About ──────────────────────────────────────────────────────────── */}
        <div className="bg-bg-secondary border border-border rounded-xl p-5">
          <div className="flex items-center gap-2 mb-4">
            <Shield size={15} className="text-accent-purple" />
            <h2 className="text-sm font-semibold text-text-primary">About</h2>
          </div>
          <div className="space-y-2 text-sm">
            {[
              ['Application', 'Snyk Commander'],
              ['Version', 'v3.0.0'],
              ['Platform', 'Electron + React + TypeScript'],
            ].map(([label, value]) => (
              <div key={label} className="flex justify-between">
                <span className="text-text-muted">{label}</span>
                <span className={label === 'Version' ? 'text-accent-purple font-mono font-medium' : 'text-text-primary font-medium'}>{value}</span>
              </div>
            ))}
          </div>
        </div>

      </div>

      {/* Clear cache confirm modal */}
      <Modal
        isOpen={showClearConfirm}
        onClose={() => setShowClearConfirm(false)}
        title="Clear All Cache"
        footer={
          <>
            <button onClick={() => setShowClearConfirm(false)} className="btn-secondary">Cancel</button>
            <button onClick={handleClearCache} className="btn-danger">Clear Cache</button>
          </>
        }
      >
        <p className="text-text-secondary text-sm">
          This will delete all cached scan results. You will need to rescan your organizations to view vulnerability data. Are you sure?
        </p>
      </Modal>
    </div>
  )
}
