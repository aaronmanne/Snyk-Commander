import React, { createContext, useContext, useReducer, useCallback, useEffect } from 'react'
import type { AppState, Org, ScanResult, View, FlatIssue, ReachabilityAnalysisResult, BackgroundJob } from '../types'
import { getAllStoredReachabilityResults } from '../api'

type Action =
  | { type: 'SET_TOKEN'; token: string }
  | { type: 'SET_GITHUB_TOKEN'; token: string }
  | { type: 'SET_ORGS'; orgs: Org[] }
  | { type: 'SET_SELECTED_ORG'; org: Org | null }
  | { type: 'SET_SCAN_RESULTS'; results: ScanResult[]; timestamp: string }
  | { type: 'SET_SCANNING'; isScanning: boolean }
  | { type: 'SET_VIEW'; view: View }
  | { type: 'SET_SELECTED_ISSUE'; issue: FlatIssue | null }
  | { type: 'SET_REACHABILITY_RESULTS'; results: Record<string, ReachabilityAnalysisResult> }
  | { type: 'UPDATE_REACHABILITY_RESULT'; projectId: string; issueId: string; result: ReachabilityAnalysisResult }
  | { type: 'ADD_BACKGROUND_JOB'; job: BackgroundJob }
  | { type: 'UPDATE_BACKGROUND_JOB'; jobId: string; status: string; progress: { phase: string; message: string; pct: number } }
  | { type: 'REMOVE_BACKGROUND_JOB'; jobId: string }
  | { type: 'LOGOUT' }

const initialState: AppState = {
  token: localStorage.getItem('snyk_token') || '',
  githubToken: localStorage.getItem('github_token') || '',
  orgs: [],
  selectedOrg: null,
  scanResults: [],
  isScanning: false,
  currentView: 'org-select',   // Start at org select, not auth
  scanTimestamp: null,
  selectedIssue: null,
  reachabilityResults: {},
  backgroundJobs: [],
}

function reducer(state: AppState, action: Action): AppState {
  switch (action.type) {
    case 'SET_TOKEN':
      return { ...state, token: action.token }
    case 'SET_GITHUB_TOKEN':
      return { ...state, githubToken: action.token }
    case 'SET_ORGS':
      return { ...state, orgs: action.orgs }
    case 'SET_SELECTED_ORG':
      return { ...state, selectedOrg: action.org }
    case 'SET_SCAN_RESULTS':
      return { ...state, scanResults: action.results, scanTimestamp: action.timestamp }
    case 'SET_SCANNING':
      return { ...state, isScanning: action.isScanning }
    case 'SET_VIEW':
      return { ...state, currentView: action.view }
    case 'SET_SELECTED_ISSUE':
      return { ...state, selectedIssue: action.issue }
    case 'SET_REACHABILITY_RESULTS':
      return { ...state, reachabilityResults: action.results }
    case 'UPDATE_REACHABILITY_RESULT':
      return {
        ...state,
        reachabilityResults: {
          ...state.reachabilityResults,
          [`${action.projectId}:${action.issueId}`]: action.result
        }
      }
    case 'ADD_BACKGROUND_JOB':
      return { ...state, backgroundJobs: [...state.backgroundJobs, action.job] }
    case 'UPDATE_BACKGROUND_JOB':
      return {
        ...state,
        backgroundJobs: state.backgroundJobs.map(job =>
          job.jobId === action.jobId
            ? { ...job, status: action.status as any, progress: action.progress }
            : job
        )
      }
    case 'REMOVE_BACKGROUND_JOB':
      return { ...state, backgroundJobs: state.backgroundJobs.filter(job => job.jobId !== action.jobId) }
    case 'LOGOUT':
      localStorage.removeItem('snyk_token')
      localStorage.removeItem('github_token')
      return { ...initialState, token: '', githubToken: '' }
    default:
      return state
  }
}

interface AppContextValue {
  state: AppState
  setToken: (token: string) => void
  setGithubToken: (token: string) => void
  setOrgs: (orgs: Org[]) => void
  setSelectedOrg: (org: Org | null) => void
  setScanResults: (results: ScanResult[], timestamp: string) => void
  setScanning: (isScanning: boolean) => void
  setView: (view: View) => void
  setSelectedIssue: (issue: FlatIssue | null) => void
  setReachabilityResults: (results: Record<string, ReachabilityAnalysisResult>) => void
  updateReachabilityResult: (projectId: string, issueId: string, result: ReachabilityAnalysisResult) => void
  loadReachabilityResults: () => Promise<void>
  addBackgroundJob: (job: BackgroundJob) => void
  updateBackgroundJob: (jobId: string, status: string, progress: { phase: string; message: string; pct: number }) => void
  removeBackgroundJob: (jobId: string) => void
  logout: () => void
}

const AppContext = createContext<AppContextValue | null>(null)

export function AppProvider({ children }: { children: React.ReactNode }) {
  const [state, dispatch] = useReducer(reducer, initialState)

  const setToken = useCallback((token: string) => {
    if (token) localStorage.setItem('snyk_token', token)
    else localStorage.removeItem('snyk_token')
    dispatch({ type: 'SET_TOKEN', token })
  }, [])

  const setGithubToken = useCallback((token: string) => {
    if (token) localStorage.setItem('github_token', token)
    dispatch({ type: 'SET_GITHUB_TOKEN', token })
  }, [])

  const setOrgs = useCallback((orgs: Org[]) => {
    dispatch({ type: 'SET_ORGS', orgs })
  }, [])

  const setSelectedOrg = useCallback((org: Org | null) => {
    dispatch({ type: 'SET_SELECTED_ORG', org })
  }, [])

  const setScanResults = useCallback((results: ScanResult[], timestamp: string) => {
    dispatch({ type: 'SET_SCAN_RESULTS', results, timestamp })
  }, [])

  const setScanning = useCallback((isScanning: boolean) => {
    dispatch({ type: 'SET_SCANNING', isScanning })
  }, [])

  const setView = useCallback((view: View) => {
    dispatch({ type: 'SET_VIEW', view })
  }, [])

  const setSelectedIssue = useCallback((issue: FlatIssue | null) => {
    dispatch({ type: 'SET_SELECTED_ISSUE', issue })
  }, [])

  const setReachabilityResults = useCallback((results: Record<string, ReachabilityAnalysisResult>) => {
    dispatch({ type: 'SET_REACHABILITY_RESULTS', results })
  }, [])

  const updateReachabilityResult = useCallback((projectId: string, issueId: string, result: ReachabilityAnalysisResult) => {
    dispatch({ type: 'UPDATE_REACHABILITY_RESULT', projectId, issueId, result })
  }, [])

  const loadReachabilityResults = useCallback(async () => {
    if (!state.selectedOrg) return
    try {
      const results = await getAllStoredReachabilityResults(state.selectedOrg.id)
      dispatch({ type: 'SET_REACHABILITY_RESULTS', results })
    } catch (err) {
      console.error('[AppContext] Failed to load reachability results:', err)
    }
  }, [state.selectedOrg])

  const addBackgroundJob = useCallback((job: BackgroundJob) => {
    dispatch({ type: 'ADD_BACKGROUND_JOB', job })
  }, [])

  const updateBackgroundJob = useCallback((jobId: string, status: string, progress: { phase: string; message: string; pct: number }) => {
    dispatch({ type: 'UPDATE_BACKGROUND_JOB', jobId, status, progress })
  }, [])

  const removeBackgroundJob = useCallback((jobId: string) => {
    dispatch({ type: 'REMOVE_BACKGROUND_JOB', jobId })
  }, [])

  // Load reachability results when org changes
  useEffect(() => {
    if (state.selectedOrg) {
      loadReachabilityResults()
    }
  }, [state.selectedOrg?.id])

  const logout = useCallback(() => {
    dispatch({ type: 'LOGOUT' })
  }, [])

  return (
    <AppContext.Provider value={{
      state, setToken, setGithubToken, setOrgs, setSelectedOrg,
      setScanResults, setScanning, setView, setSelectedIssue,
      setReachabilityResults, updateReachabilityResult, loadReachabilityResults,
      addBackgroundJob, updateBackgroundJob, removeBackgroundJob,
      logout
    }}>
      {children}
    </AppContext.Provider>
  )
}

export function useApp() {
  const ctx = useContext(AppContext)
  if (!ctx) throw new Error('useApp must be used within AppProvider')
  return ctx
}
