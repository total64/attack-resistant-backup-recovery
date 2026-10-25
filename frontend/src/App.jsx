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
  const pageTitle = {
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
  }[location.pathname] || 'Dashboard'

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

function App() {
  return (
    <Routes>
      <Route path="/" element={<RootRoute />} />
      <Route path="/login" element={<LoginGate />} />
      <Route path="/register" element={<RegistrationPage />} />
      <Route element={<RequireAuth />}>
        <Route element={<DashboardLayout />}>
          <Route path="dashboard" element={<PageContent component={DashboardPage} />} />
          <Route path="dashboard/security-events" element={<PageContent component={SecurityEventsPage} />} />
          <Route path="dashboard/threat-detection" element={<PageContent component={ThreatDetectionPage} />} />
          <Route path="dashboard/risk-analysis" element={<PageContent component={RiskAnalysisPage} />} />
          <Route path="dashboard/backups" element={<PageContent component={BackupsPage} />} />
          <Route path="dashboard/system-isolation" element={<PageContent component={SystemIsolationPage} />} />
          <Route path="dashboard/recovery" element={<PageContent component={RecoveryPage} />} />
          <Route path="dashboard/audit-logs" element={<PageContent component={AuditLogsPage} />} />
          <Route path="dashboard/admin" element={<AdminPage />} />
          <Route path="dashboard/settings" element={<SettingsLayout />}>
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
          <Route path="dashboard/profile" element={<PageContent component={ProfilePage} />} />
          <Route path="dashboard/change-password" element={<ChangePasswordPage />} />
        </Route>
      </Route>
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}

export default App
