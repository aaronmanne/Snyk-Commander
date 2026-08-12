// AuthView is kept as a minimal redirect screen.
// All auth/OAuth configuration has moved to SettingsView.
// This view is only reachable from Settings → "Sign Out" or manual navigation.
import React, { useEffect } from 'react'
import { useApp } from '../context/AppContext'

export default function AuthView() {
  const { setView } = useApp()

  // Auth screen is no longer the entry point — immediately redirect to org-select
  // which handles the unauthenticated state inline.
  useEffect(() => {
    setView('org-select')
  }, [])

  return null
}
