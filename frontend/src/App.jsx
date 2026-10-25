import { useState } from 'react'
import { Navigate, Outlet, Route, Routes, useLocation, useOutletContext } from 'react-router-dom'
import { useAuth } from './auth/AuthContext.jsx'
import { HeaderBar, Sidebar } from './components/DashboardParts.jsx'
import DashboardPage from './pages/DashboardPage.jsx'
import SecurityEventsPage from './pages/SecurityEventsPage.jsx'
import ThreatDetectionPage from './pages/ThreatDetectionPage.jsx'
import RiskAnalysisPage from './pages/RiskAnalysisPage.jsx'
import BackupsPage from './pages/BackupsPage.jsx'
import SystemIsolationPage from './pages/SystemIsolationPage.jsx'
import RecoveryPage from './pages/RecoveryPage.jsx'
import AuditLogsPage from './pages/AuditLogsPage.jsx'
import {
  SettingsAuditMonitoringPage,
  SettingsGeneralPage,
  SettingsLayout,
  SettingsBackupIntegrityPage,
  SettingsIsolationPage,
  SettingsMonitoringPage,
  SettingsNotificationsPage,
  SettingsRecoveryPage,
  SettingsRiskEnginePage,
  SettingsSecurityAccessPage,
  SettingsSystemIntegrationsPage,
} from './pages/SettingsPage.jsx'
import LoginPage from './pages/LoginPage.jsx'
import ChangePasswordPage from './pages/ChangePasswordPage.jsx'
import ProfilePage from './pages/ProfilePage.jsx'
import RegistrationPage from './pages/RegistrationPage.jsx'
import AdminPage from './pages/AdminPage.jsx'
import LandingPage from './pages/LandingPage.jsx'
import './App.css'

function RequireAuth() {
  const { sessionNotice, status, user } = useAuth()
  if (status === 'loading') return <main className="auth-loading" role="status"><span className="loading-spinner" />Verifying secure session…</main>
  if (!user) return <Navigate to="/login" replace state={{ sessionNotice }} />
  return <Outlet />
}

function RootRoute() {
  const { status, user } = useAuth()
  if (status === 'loading') return <main className="auth-loading" role="status"><span className="loading-spinner" />Verifying secure session…</main>
  if (user) return <Navigate to="/dashboard" replace />
  return <LandingPage />
}

function LoginGate() {
  const { status, user } = useAuth()
  if (status === 'loading') return <main className="auth-loading" role="status"><span className="loading-spinner" />Verifying secure session…</main>
  if (user) return <Navigate to="/dashboard" replace />
  return <LoginPage />
}

function DashboardLayout() {
  const location = useLocation()
  const { logout, user } = useAuth()
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false)
  const [notificationsOpen, setNotificationsOpen] = useState(false)
  const [globalSearch, setGlobalSearch] = useState('')
  const pageTitles = {
    '/': 'Home',
    '/dashboard': 'Dashboard',
    '/dashboard/security-events': 'Security Events',
    '/dashboard/threat-detection': 'Threat Detection',
    '/dashboard/risk-analysis': 'Risk Analysis',
    '/dashboard/backups': 'Backups',
    '/dashboard/system-isolation': 'System Isolation',
    '/dashboard/recovery': 'Recovery',
    '/dashboard/audit-logs': 'Audit Logs',
    '/dashboard/settings': 'Settings',
    '/dashboard/settings/general': 'General Settings',
    '/dashboard/settings/monitoring': 'Security Monitoring',
    '/dashboard/settings/risk-engine': 'Risk Engine',
    '/dashboard/settings/backup-integrity': 'Backup & Integrity',
    '/dashboard/settings/isolation': 'Isolation Settings',
    '/dashboard/settings/recovery': 'Recovery Settings',
    '/dashboard/settings/security-access': 'Security & Access',
    '/dashboard/settings/notifications': 'Notifications',
    '/dashboard/settings/system-integrations': 'System & Integrations',
    '/dashboard/settings/audit-monitoring': 'Audit & Monitoring',
    '/dashboard/admin': 'Admin Panel',
    '/dashboard/profile': 'Profile',
    '/dashboard/change-password': 'Change Password',
  }
  const pageTitle = pageTitles[location.pathname] || 'Dashboard'

  return (
    <div className="app-shell">
      <Sidebar collapsed={sidebarCollapsed} onToggle={() => setSidebarCollapsed((current) => !current)} user={user} onLogout={logout} />
      <div className="main-shell">
        <HeaderBar pageTitle={pageTitle} searchValue={globalSearch} onSearch={setGlobalSearch} notificationOpen={notificationsOpen} onToggleNotifications={() => setNotificationsOpen((current) => !current)} />
        <Outlet context={{ globalSearch, setGlobalSearch }} />
      </div>
    </div>
  )
}

function PageContent({ component: PageComponent }) {
  const { globalSearch, setGlobalSearch } = useOutletContext()
  return <PageComponent globalSearch={globalSearch} onGlobalSearchChange={setGlobalSearch} />
}

function LegacySettingsRedirect() {
  const location = useLocation()
  return <Navigate to={`/dashboard${location.pathname}`} replace />
}

function App() {
  return (
    <Routes>
      <Route path="/" element={<RootRoute />} />
      <Route path="/login" element={<LoginGate />} />
      <Route path="/register" element={<RegistrationPage />} />

      {/* Keep legacy URLs working while the dashboard lives under /dashboard. */}
      <Route path="/security-events" element={<Navigate to="/dashboard/security-events" replace />} />
      <Route path="/threat-detection" element={<Navigate to="/dashboard/threat-detection" replace />} />
      <Route path="/risk-analysis" element={<Navigate to="/dashboard/risk-analysis" replace />} />
      <Route path="/backups" element={<Navigate to="/dashboard/backups" replace />} />
      <Route path="/system-isolation" element={<Navigate to="/dashboard/system-isolation" replace />} />
      <Route path="/recovery" element={<Navigate to="/dashboard/recovery" replace />} />
      <Route path="/audit-logs" element={<Navigate to="/dashboard/audit-logs" replace />} />
      <Route path="/admin" element={<Navigate to="/dashboard/admin" replace />} />
      <Route path="/profile" element={<Navigate to="/dashboard/profile" replace />} />
      <Route path="/change-password" element={<Navigate to="/dashboard/change-password" replace />} />
      <Route path="/settings" element={<Navigate to="/dashboard/settings" replace />} />
      <Route path="/settings/*" element={<LegacySettingsRedirect />} />

      <Route element={<RequireAuth />}>
        <Route path="/dashboard" element={<DashboardLayout />}>
          <Route index element={<PageContent component={DashboardPage} />} />
          <Route path="security-events" element={<PageContent component={SecurityEventsPage} />} />
          <Route path="threat-detection" element={<PageContent component={ThreatDetectionPage} />} />
          <Route path="risk-analysis" element={<PageContent component={RiskAnalysisPage} />} />
          <Route path="backups" element={<PageContent component={BackupsPage} />} />
          <Route path="system-isolation" element={<PageContent component={SystemIsolationPage} />} />
          <Route path="recovery" element={<PageContent component={RecoveryPage} />} />
          <Route path="audit-logs" element={<PageContent component={AuditLogsPage} />} />
          <Route path="admin" element={<AdminPage />} />
          <Route path="settings" element={<SettingsLayout />}>
            <Route index element={<Navigate to="general" replace />} />
            <Route path="general" element={<SettingsGeneralPage />} />
            <Route path="monitoring" element={<SettingsMonitoringPage />} />
            <Route path="risk-engine" element={<SettingsRiskEnginePage />} />
            <Route path="backup-integrity" element={<SettingsBackupIntegrityPage />} />
            <Route path="isolation" element={<SettingsIsolationPage />} />
            <Route path="recovery" element={<SettingsRecoveryPage />} />
            <Route path="security-access" element={<SettingsSecurityAccessPage />} />
            <Route path="notifications" element={<SettingsNotificationsPage />} />
            <Route path="system-integrations" element={<SettingsSystemIntegrationsPage />} />
            <Route path="audit-monitoring" element={<SettingsAuditMonitoringPage />} />
          </Route>
          <Route path="profile" element={<PageContent component={ProfilePage} />} />
          <Route path="change-password" element={<ChangePasswordPage />} />
        </Route>
      </Route>

      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}
export default App
