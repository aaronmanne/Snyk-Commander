// API wrapper around window.snykAPI

import type {
  Org, CachedOrg, ScanResult, IgnoreAnalysis, FixableProject, ReachabilityResult,
  ReachabilityAnalysisResult, OllamaStatus, GitHubDeviceFlow
} from './types'

// Type assertions for the global snykAPI
declare global {
  interface Window {
    snykAPI: {
      invoke(method: string, params: Record<string, unknown>): Promise<unknown>
      stream(
        method: string,
        params: Record<string, unknown>,
        channel: string,
        onProgress: (data: unknown) => void
      ): Promise<unknown>
      removeListener(channel: string): void
      newStreamChannel(): string
      openFolder(): Promise<string | null>
      openPath(filePath: string): Promise<{ ok: boolean }>
    }
  }
}

function api() {
  if (typeof window !== 'undefined' && window.snykAPI) {
    return window.snykAPI
  }
  throw new Error('snykAPI not available')
}

// ── Auth ─────────────────────────────────────────────────────────────────────

export async function verifyToken(token: string): Promise<{ orgs: Org[] }> {
  return api().invoke('auth.verify_token', { token }) as Promise<{ orgs: Org[] }>
}

export async function checkCache(): Promise<{ cached_orgs: CachedOrg[] }> {
  return api().invoke('auth.check_cache', {}) as Promise<{ cached_orgs: CachedOrg[] }>
}

// ── Cache ─────────────────────────────────────────────────────────────────────

export async function deleteAllCache(): Promise<{ ok: boolean }> {
  return api().invoke('cache.delete_all', {}) as Promise<{ ok: boolean }>
}

export async function deleteOrgCache(org_id: string): Promise<{ ok: boolean }> {
  return api().invoke('cache.delete', { org_id }) as Promise<{ ok: boolean }>
}

export interface OrgCacheEntry {
  org: Org
  timestamp: string
  project_count: number
  vuln_count: number
  fixable_count: number
  critical_count: number
  high_count: number
  results: ScanResult[]
}

export async function loadOrgCache(org_id: string): Promise<{ found: boolean; entry: OrgCacheEntry | null }> {
  return api().invoke('cache.load_org', { org_id }) as Promise<{ found: boolean; entry: OrgCacheEntry | null }>
}

// ── Scanner ───────────────────────────────────────────────────────────────────

export async function scanOrg(
  org: Org,
  token: string,
  onProgress: (data: unknown) => void
): Promise<{ result: { org: Org; results: ScanResult[]; from_cache: boolean } }> {
  const channel = api().newStreamChannel()
  try {
    const result = await api().stream('scanner.scan', { org, token }, channel, onProgress)
    return result as { result: { org: Org; results: ScanResult[]; from_cache: boolean } }
  } finally {
    api().removeListener(channel)
  }
}

// ── Ignores ───────────────────────────────────────────────────────────────────

export async function getNonFixable(
  org_id: string,
  results: ScanResult[],
  min_risk_score: number
): Promise<IgnoreAnalysis> {
  return api().invoke('ignores.get_non_fixable', {
    org_id, results, min_risk_score
  }) as Promise<IgnoreAnalysis>
}

export async function applyIgnores(
  org_id: string,
  token: string,
  operations: unknown[],
  reason: string,
  expires: string,
  onProgress: (data: unknown) => void
): Promise<{ succeeded: number; failed: number }> {
  const channel = api().newStreamChannel()
  try {
    const result = await api().stream('ignores.apply', {
      org_id, token, operations, reason, expires
    }, channel, onProgress)
    return result as { succeeded: number; failed: number }
  } finally {
    api().removeListener(channel)
  }
}

export async function ignoreSingleIssue(
  org_id: string,
  token: string,
  project_id: string,
  issue_id: string,
  reason: string
): Promise<{ ok: boolean }> {
  return api().invoke('ignores.ignore_single', {
    org_id, token, project_id, issue_id, reason
  }) as Promise<{ ok: boolean }>
}

export async function generateSnykFiles(
  results: ScanResult[],
  filter_mode: string,
  min_risk_score: number
): Promise<{ files_written: number; total_ignores: number; files: string[] }> {
  return api().invoke('ignores.generate_snyk_files', {
    results, filter_mode, min_risk_score
  }) as Promise<{ files_written: number; total_ignores: number; files: string[] }>
}

// ── Fix PRs ───────────────────────────────────────────────────────────────────

export async function getFixable(
  results: ScanResult[]
): Promise<{ projects: FixableProject[] }> {
  return api().invoke('fix_pr.get_fixable', { results }) as Promise<{ projects: FixableProject[] }>
}

export async function triggerFixPR(
  org_slug: string,
  project_id: string,
  token: string
): Promise<{ ok: boolean; message: string }> {
  return api().invoke('fix_pr.trigger', {
    org_slug, project_id, token
  }) as Promise<{ ok: boolean; message: string }>
}

// ── Reports ───────────────────────────────────────────────────────────────────

export async function generateReport(
  org: Org,
  results: ScanResult[],
  token: string,
  report_mode: string,
  min_risk_score: number
): Promise<{ md_path: string; csv_path: string }> {
  return api().invoke('report.generate', {
    org, results, token, report_mode, min_risk_score
  }) as Promise<{ md_path: string; csv_path: string }>
}

// ── Reachability ──────────────────────────────────────────────────────────────

export async function analyzeReachability(
  issue: unknown,
  project_name: string,
  codebase_path: string,
  ollama_model: string,
  onProgress: (data: unknown) => void
): Promise<{ result: ReachabilityResult }> {
  const channel = api().newStreamChannel()
  try {
    const result = await api().stream('reachability.analyze', {
      issue, project_name, codebase_path, ollama_model
    }, channel, onProgress)
    return result as { result: ReachabilityResult }
  } finally {
    api().removeListener(channel)
  }
}

// ── Native dialogs (Electron) ─────────────────────────────────────────────────

export async function openFolderDialog(): Promise<string | null> {
  return window.snykAPI.openFolder()
}

export async function openPath(filePath: string): Promise<void> {
  await window.snykAPI.openPath(filePath)
}

// ── Token Storage ─────────────────────────────────────────────────────────────

export async function getStoredTokens(): Promise<{ snyk: string | null; github: string | null; github_client_id: string | null; ghe_host: string | null }> {
  return api().invoke('oauth.get_stored_tokens', {}) as Promise<{ snyk: string | null; github: string | null; github_client_id: string | null; ghe_host: string | null }>
}

export async function storeToken(type: 'snyk' | 'github', token: string): Promise<{ ok: boolean }> {
  return api().invoke('oauth.store_token', { type, token }) as Promise<{ ok: boolean }>
}

export async function clearToken(type: 'snyk' | 'github'): Promise<{ ok: boolean }> {
  return api().invoke('oauth.clear_token', { type }) as Promise<{ ok: boolean }>
}

export async function setGheHost(host: string): Promise<{ ok: boolean }> {
  return api().invoke('oauth.set_ghe_host', { host }) as Promise<{ ok: boolean }>
}

export async function setGitHubClientId(client_id: string): Promise<{ ok: boolean }> {
  return api().invoke('oauth.set_github_client_id', { client_id }) as Promise<{ ok: boolean }>
}

// ── Snyk OAuth ────────────────────────────────────────────────────────────────

export async function startSnykOAuth(onProgress: (msg: string) => void): Promise<{ token: string; orgs: Org[] }> {
  const channel = api().newStreamChannel()
  try {
    const result = await api().stream('oauth.start_snyk_oauth', {}, channel, (data: unknown) => {
      const ev = data as { event?: string; data?: { msg?: string } }
      if (ev.event === 'progress' && ev.data?.msg) {
        onProgress(ev.data.msg)
      }
    })
    return result as { token: string; orgs: Org[] }
  } finally {
    api().removeListener(channel)
  }
}

// ── GitHub Device Flow ────────────────────────────────────────────────────────

export async function startGitHubDeviceFlow(): Promise<GitHubDeviceFlow> {
  return api().invoke('oauth.github_device_flow', {}) as Promise<GitHubDeviceFlow>
}

export async function pollGitHubToken(
  device_code: string,
  interval: number,
  onProgress: (msg: string) => void
): Promise<{ token: string }> {
  const channel = api().newStreamChannel()
  try {
    const result = await api().stream('oauth.poll_github', { device_code, interval }, channel, (data: unknown) => {
      const ev = data as { event?: string; data?: { msg?: string } }
      if (ev.event === 'progress' && ev.data?.msg) {
        onProgress(ev.data.msg)
      }
    })
    return result as { token: string }
  } finally {
    api().removeListener(channel)
  }
}

export async function getIncludedOrigins(): Promise<{ included_origins: string[] }> {
  return api().invoke('oauth.get_included_origins', {}) as Promise<{ included_origins: string[] }>
}

export async function setIncludedOrigins(origins: string[]): Promise<{ ok: boolean }> {
  return api().invoke('oauth.set_included_origins', { origins }) as Promise<{ ok: boolean }>
}

export async function getIncludedTypes(): Promise<{ included_types: string[] }> {
  return api().invoke('oauth.get_included_types', {}) as Promise<{ included_types: string[] }>
}

export async function setIncludedTypes(types: string[]): Promise<{ ok: boolean }> {
  return api().invoke('oauth.set_included_types', { types }) as Promise<{ ok: boolean }>
}

// ── Ollama ────────────────────────────────────────────────────────────────────

export async function getOllamaStatus(): Promise<OllamaStatus> {
  return api().invoke('ollama.get_status', {}) as Promise<OllamaStatus>
}

export async function pullOllamaModel(name: string, onProgress: (msg: string) => void): Promise<{ ok: boolean }> {
  const channel = api().newStreamChannel()
  try {
    const result = await api().stream('ollama.pull_model', { name }, channel, (data: unknown) => {
      const ev = data as { event?: string; data?: { msg?: string } }
      if (ev.event === 'progress' && ev.data?.msg) {
        onProgress(ev.data.msg)
      }
    })
    return result as { ok: boolean }
  } finally {
    api().removeListener(channel)
  }
}

// ── Repo Clone ────────────────────────────────────────────────────────────────

export async function cloneRepo(
  project_name: string,
  project_origin: string,
  github_token: string | null,
  onProgress: (msg: string) => void
): Promise<{ path: string; repo: string }> {
  const channel = api().newStreamChannel()
  try {
    const result = await api().stream('github.clone_repo', {
      project_name, project_origin, github_token
    }, channel, (data: unknown) => {
      const ev = data as { event?: string; data?: { msg?: string } }
      if (ev.event === 'progress' && ev.data?.msg) {
        onProgress(ev.data.msg)
      }
    })
    return result as { path: string; repo: string }
  } finally {
    api().removeListener(channel)
  }
}

// ── Full Reachability Analysis ────────────────────────────────────────────────

export async function analyzeReachabilityFull(
  issue: unknown,
  project_name: string,
  project_origin: string,
  github_token: string | null,
  ollama_model: string,
  codebase_path: string | null,
  ghe_host: string | null,
  onProgress: (phase: string, message: string, pct?: number) => void,
  force_reclone = false,
): Promise<{ result: ReachabilityAnalysisResult }> {
  const channel = api().newStreamChannel()
  try {
    const result = await api().stream('reachability.analyze', {
      issue, project_name, project_origin, github_token, ollama_model, codebase_path, ghe_host, force_reclone
    }, channel, (data: unknown) => {
      const ev = data as { event?: string; data?: { phase?: string; msg?: string; message?: string; pct?: number } }
      if (ev.event === 'progress' && ev.data) {
        onProgress(ev.data.phase || '', ev.data.msg || ev.data.message || '', ev.data.pct)
      }
    })
    return result as { result: ReachabilityAnalysisResult }
  } finally {
    api().removeListener(channel)
  }
}

// Start background reachability analysis
export async function analyzeReachabilityBackground(
  org_id: string,
  project_id: string,
  issue_id: string,
  issue: unknown,
  project_name: string,
  project_origin: string,
  github_token: string | null,
  ollama_model: string,
  codebase_path: string | null,
  ghe_host: string | null,
  force_reclone = false,
): Promise<{ jobId: string; background: boolean }> {
  const result = await api().invoke('reachability.analyze', {
    org_id,
    project_id,
    issue_id,
    issue,
    project_name,
    project_origin,
    github_token,
    ollama_model,
    codebase_path,
    ghe_host,
    force_reclone,
    background: true,
  })
  return result as { jobId: string; background: boolean }
}

// Get background job status
export async function getReachabilityJobStatus(jobId: string): Promise<{
  id: string;
  status: 'queued' | 'running' | 'completed' | 'failed';
  progress: { phase: string; message: string; pct: number };
  result?: unknown;
  error?: string;
}> {
  const result = await api().invoke('reachability.get_job_status', { job_id: jobId })
  return result as any
}

// Get stored reachability result
export async function getStoredReachabilityResult(
  org_id: string,
  project_id: string,
  issue_id: string
): Promise<ReachabilityAnalysisResult | null> {
  const result = await api().invoke('reachability.get_stored_result', {
    org_id,
    project_id,
    issue_id,
  })
  return result as ReachabilityAnalysisResult | null
}

// Get all stored reachability results for an org
export async function getAllStoredReachabilityResults(
  org_id: string
): Promise<Record<string, ReachabilityAnalysisResult>> {
  const results = await api().invoke('reachability.get_all_stored_results', { org_id })
  const arr = results as Array<ReachabilityAnalysisResult & { project_id: string; issue_id: string }>
  
  // Convert to map keyed by project_id:issue_id
  const map: Record<string, ReachabilityAnalysisResult> = {}
  arr.forEach(r => {
    const key = `${r.project_id}:${r.issue_id}`
    map[key] = r
  })
  return map
}

