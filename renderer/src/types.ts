// All TypeScript interfaces for Snyk Commander

export interface Org {
  id: string
  name: string
  slug: string
}

export interface CachedOrg {
  org: Org
  timestamp: string
  project_count: number
  fixable_count: number
}

export interface SeverityCounts {
  critical: number
  high: number
  medium: number
  low: number
}

export interface IssueData {
  id: string
  title: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  packageName: string
  description: string
  cvssScore?: number
  functions?: Array<{ functionId?: { functionName: string } } | string>
}

export interface Issue {
  id: string
  issueData: IssueData
  pkgName: string
  pkgVersions: string[]
  isUpgradable: boolean
  isPatchable: boolean
  isPinnable: boolean
  priority?: {
    score: number
    factors: Array<{ name: string; description: string }>
  }
  fixInfo?: {
    isUpgradable: boolean
    isPatchable: boolean
    isFixable?: boolean
    isPinnable?: boolean
  }
  exploitMaturity?: 'mature' | 'proof-of-concept' | 'no-known-exploit' | 'no-data'
  reachability?: 'reachable' | 'no-path' | 'no-info'
  cvss?: {
    version?: string
    score?: number
  }
}

export interface ScanResult {
  id: string
  name: string
  type: string
  origin: string
  severity: SeverityCounts
  fixable: boolean
  total_vulns: number
  risk_score: number | null
  issues: Issue[]
  ignoredIssueIds?: string[]
}

export interface ScanProgress {
  phase?: 'listing' | 'scanning' | 'saving' | 'done'
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

export interface IgnoreOperation {
  vuln_id: string
  issue_id?: string   // alias, some older paths may use this
  project_id?: string
  title?: string
  severity?: string
  risk_score?: number | null
  display_path?: string
  project_name?: string
  action?: 'ignore' | 'unignore'
}

export interface IgnoreAnalysis {
  to_ignore: IgnoreOperation[]
  to_update: IgnoreOperation[]
  to_unignore: IgnoreOperation[]
}

export interface FixableProject {
  id: string
  name: string
  severity: SeverityCounts
}

export interface ReachabilityMatch {
  file: string
  line: number
  content: string
  match_type: string
}

export interface OllamaModel {
  name: string
  size: number
  modified_at: string
  details?: {
    family: string
    parameter_size: string
    quantization_level: string
  }
}

export interface OllamaStatus {
  available: boolean
  version: string | null
  models: OllamaModel[]
  error: string | null
}

export interface GitHubDeviceFlow {
  device_code: string
  user_code: string
  verification_uri: string
  expires_in: number
  interval: number
}

export interface ReachabilityAnalysisResult {
  matches: ReachabilityMatch[]
  import_count: number
  func_count: number
  verdict: string
  ollama_reasoning: string | null
  repo_cloned: boolean
  repo_path: string
  repo_info: { owner: string; repo: string; branch: string | null } | null
  error_details: string | null
}

export type ReachabilityResult = ReachabilityAnalysisResult

export type View =
  | 'auth'
  | 'org-select'
  | 'scanning'
  | 'dashboard'
  | 'vulnerabilities'
  | 'ignore-manager'
  | 'fix-prs'
  | 'reports'
  | 'reachability'
  | 'settings'

export type Severity = 'critical' | 'high' | 'medium' | 'low'

export interface BackgroundJob {
  jobId: string
  projectId: string
  issueId: string
  issueName: string
  projectName: string
  status: 'queued' | 'running' | 'completed' | 'failed'
  progress: { phase: string; message: string; pct: number }
  startedAt: number
}

export interface AppState {
  token: string
  githubToken: string
  orgs: Org[]
  selectedOrg: Org | null
  scanResults: ScanResult[]
  isScanning: boolean
  currentView: View
  scanTimestamp: string | null
  selectedIssue: FlatIssue | null
  reachabilityResults: Record<string, ReachabilityAnalysisResult> // key: project_id:issue_id
  backgroundJobs: BackgroundJob[] // Active background analysis jobs
}

export interface FlatIssue {
  projectId: string
  projectName: string
  projectType: string
  issue: Issue
  riskScore: number | null
}
