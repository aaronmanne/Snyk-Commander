import React from 'react'
import { useApp } from './context/AppContext'
import Sidebar from './components/Sidebar'
import BackgroundJobsIndicator from './components/BackgroundJobsIndicator'
import AuthView from './views/AuthView'
import OrgSelectView from './views/OrgSelectView'
import ScanningView from './views/ScanningView'
import DashboardView from './views/DashboardView'
import VulnerabilitiesView from './views/VulnerabilitiesView'
import IgnoreManagerView from './views/IgnoreManagerView'
import FixPRsView from './views/FixPRsView'
import ReportsView from './views/ReportsView'
import ReachabilityView from './views/ReachabilityView'
import SettingsView from './views/SettingsView'

const MAIN_VIEWS = ['dashboard', 'vulnerabilities', 'ignore-manager', 'fix-prs', 'reports', 'reachability', 'settings']

function MainContent() {
  const { state } = useApp()
  switch (state.currentView) {
    case 'dashboard': return <DashboardView />
    case 'vulnerabilities': return <VulnerabilitiesView />
    case 'ignore-manager': return <IgnoreManagerView />
    case 'fix-prs': return <FixPRsView />
    case 'reports': return <ReportsView />
    case 'reachability': return <ReachabilityView />
    case 'settings': return <SettingsView />
    default: return <DashboardView />
  }
}

export default function App() {
  const { state } = useApp()
  const { currentView } = state

  // Full-screen flow views (no sidebar)
  // 'auth' is now only shown when explicitly navigated to (from Settings "re-authenticate")
  if (currentView === 'auth') return <AuthView />
  if (currentView === 'org-select') return <OrgSelectView />
  if (currentView === 'scanning') return <ScanningView />

  // Main app layout with sidebar
  if (MAIN_VIEWS.includes(currentView)) {
    return (
      <div className="flex h-screen bg-bg-primary overflow-hidden">
        <Sidebar />
        <main className="flex-1 flex flex-col overflow-hidden">
          <MainContent />
        </main>
        <BackgroundJobsIndicator />
      </div>
    )
  }

  // Default: go straight to org-select (not auth)
  return <OrgSelectView />
}
