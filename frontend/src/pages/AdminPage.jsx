import { useCallback, useEffect, useState, useMemo } from 'react'
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Database,
  ExternalLink,
  Eye,
  Lock,
  RefreshCw,
  Search,
  Server,
  Shield,
  ShieldAlert,
  ShieldCheck,
  UserCheck,
  UserPlus,
  Users,
  X,
} from 'lucide-react'
import { Link } from 'react-router-dom'
import { api } from '../api/client.js'
import { useAuth } from '../auth/AuthContext.jsx'
import './AdminPage.css'

export default function AdminPage() {
  const { user } = useAuth()
  const [activeTab, setActiveTab] = useState('users') // 'users' | 'overview' | 'audit'

  // User Management State
  const [usersList, setUsersList] = useState([])
  const [loadingUsers, setLoadingUsers] = useState(false)
  const [usersError, setUsersError] = useState('')

  // Filters
  const [searchQuery, setSearchQuery] = useState('')
  const [roleFilter, setRoleFilter] = useState('all')
  const [statusFilter, setStatusFilter] = useState('all')

  // Modals
  const [provisionModalOpen, setProvisionModalOpen] = useState(false)
  const [editUserModal, setEditUserModal] = useState(null)
  const [viewUserModal, setViewUserModal] = useState(null)

  // Provision Form
  const [provUsername, setProvUsername] = useState('')
  const [provDisplayName, setProvDisplayName] = useState('')
  const [provRole, setProvRole] = useState('analyst')
  const [provPassword, setProvPassword] = useState('')
  const [provConfirm, setProvConfirm] = useState('')
  const [provError, setProvError] = useState('')
  const [provBusy, setProvBusy] = useState(false)

  // Edit Form
  const [editRole, setEditRole] = useState('')
  const [editActive, setEditActive] = useState(true)
  const [editDisplayName, setEditDisplayName] = useState('')
  const [editError, setEditError] = useState('')
  const [editBusy, setEditBusy] = useState(false)

  // System Overview State
  const [overviewData, setOverviewData] = useState(null)
  const [loadingOverview, setLoadingOverview] = useState(false)
  const [overviewError, setOverviewError] = useState('')

  // Toast / Status Message
  const [successToast, setSuccessToast] = useState('')

  const isAuthorized = user && user.role === 'admin'

  const fetchUsers = useCallback(async () => {
    if (!isAuthorized) return
    setLoadingUsers(true)
    setUsersError('')
    try {
      const data = await api.get('/users')
      setUsersList(Array.isArray(data) ? data : [])
    } catch (err) {
      setUsersError(err.message || 'Failed to retrieve user accounts.')
    } finally {
      setLoadingUsers(false)
    }
  }, [isAuthorized])

  const fetchOverview = useCallback(async () => {
    if (!isAuthorized) return
    setLoadingOverview(true)
    setOverviewError('')
    try {
      const data = await api.get('/admin/overview')
      setOverviewData(data)
    } catch (err) {
      setOverviewError(err.message || 'Failed to retrieve system overview metrics.')
    } finally {
      setLoadingOverview(false)
    }
  }, [isAuthorized])

  useEffect(() => {
    if (isAuthorized) {
      let isMounted = true
      const load = async () => {
        try {
          const [users, overview] = await Promise.all([
            api.get('/users'),
            api.get('/admin/overview'),
          ])
          if (isMounted) {
            setUsersList(Array.isArray(users) ? users : [])
            setOverviewData(overview)
          }
        } catch {
          // Individual fetchers will handle retry and error setting
        }
      }
      load()
      return () => {
        isMounted = false
      }
    }
  }, [isAuthorized])

  const filteredUsers = useMemo(() => {
    return usersList.filter((account) => {
      const query = searchQuery.trim().toLowerCase()
      const matchesSearch =
        !query ||
        account.username.toLowerCase().includes(query) ||
        (account.display_name && account.display_name.toLowerCase().includes(query)) ||
        account.user_id.toLowerCase().includes(query)

      const matchesRole = roleFilter === 'all' || account.role === roleFilter
      const matchesStatus =
        statusFilter === 'all' ||
        (statusFilter === 'active' && account.is_active) ||
        (statusFilter === 'inactive' && !account.is_active)

      return matchesSearch && matchesRole && matchesStatus
    })
  }, [usersList, searchQuery, roleFilter, statusFilter])

  const handleOpenEdit = (account) => {
    setEditUserModal(account)
    setEditRole(account.role)
    setEditActive(account.is_active)
    setEditDisplayName(account.display_name || '')
    setEditError('')
  }

  const handleSaveEdit = async (e) => {
    e.preventDefault()
    if (!editUserModal) return
    setEditBusy(true)
    setEditError('')
    try {
      const payload = {
        role: editRole,
        is_active: editActive,
        display_name: editDisplayName.trim() || undefined,
      }
      await api.patch(`/users/${editUserModal.user_id}`, payload)
      setSuccessToast(`Account '${editUserModal.username}' updated successfully.`)
      setEditUserModal(null)
      fetchUsers()
      fetchOverview()
      setTimeout(() => setSuccessToast(''), 4000)
    } catch (err) {
      setEditError(err.message || 'Failed to update account.')
    } finally {
      setEditBusy(false)
    }
  }

  const handleSaveProvision = async (e) => {
    e.preventDefault()
    setProvError('')
    if (!provUsername.trim()) {
      setProvError('Username is required.')
      return
    }
    if (provPassword.length < 12) {
      setProvError('Initial password must be at least 12 characters long.')
      return
    }
    if (provPassword !== provConfirm) {
      setProvError('Passwords do not match.')
      return
    }

    setProvBusy(true)
    try {
      const payload = {
        username: provUsername.trim(),
        display_name: provDisplayName.trim() || undefined,
        role: provRole,
        initial_password: provPassword,
      }
      await api.post('/users', payload)
      setSuccessToast(`User '${provUsername}' provisioned successfully with ${provRole} role.`)
      setProvisionModalOpen(false)
      setProvUsername('')
      setProvDisplayName('')
      setProvPassword('')
      setProvConfirm('')
      fetchUsers()
      fetchOverview()
      setTimeout(() => setSuccessToast(''), 4000)
    } catch (err) {
      setProvError(err.message || 'Failed to provision user.')
    } finally {
      setProvBusy(false)
    }
  }

  // Unauthorized view
  if (!isAuthorized) {
    return (
      <main className="admin-page">
        <div className="admin-denied">
          <div className="admin-denied-icon">
            <Lock size={26} />
          </div>
          <h2>Administrator Access Required</h2>
          <p>
            You are currently signed in as <strong>{user?.display_name || user?.user_id || 'unauthenticated'}</strong> with role{' '}
            <span className="admin-badge admin-badge--viewer">{user?.role || 'none'}</span>. Administrative actions and user management require authorized administrator credentials.
          </p>
          <Link to="/" className="admin-btn admin-btn--primary">
            Return to Operations Dashboard <ArrowRight size={13} />
          </Link>
        </div>
      </main>
    )
  }

  return (
    <main className="admin-page">
      <div className="api-page-heading">
        <div>
          <h1>System Administration</h1>
          <p>User account provisioning, access governance, system telemetry, and audit monitoring</p>
        </div>
        <div className="api-page-actions">
          <button
            className="admin-btn admin-btn--secondary"
            onClick={() => {
              fetchUsers()
              fetchOverview()
            }}
            disabled={loadingUsers || loadingOverview}
            title="Refresh Administration Data"
          >
            <RefreshCw size={13} className={loadingUsers || loadingOverview ? 'spin' : ''} />
            Refresh
          </button>
          <button
            className="admin-btn admin-btn--primary"
            onClick={() => {
              setProvError('')
              setProvisionModalOpen(true)
            }}
          >
            <UserPlus size={13} /> Provision User
          </button>
        </div>
      </div>

      {successToast && (
        <div className="admin-alert admin-alert--success" role="status">
          <CheckCircle2 size={16} />
          <span>{successToast}</span>
        </div>
      )}

      {/* Navigation Tabs */}
      <nav className="admin-nav-tabs" aria-label="Administration Sections">
        <button
          className={`admin-nav-tab ${activeTab === 'users' ? 'admin-nav-tab--active' : ''}`}
          onClick={() => setActiveTab('users')}
        >
          <Users size={14} /> User Directory ({usersList.length})
        </button>
        <button
          className={`admin-nav-tab ${activeTab === 'overview' ? 'admin-nav-tab--active' : ''}`}
          onClick={() => setActiveTab('overview')}
        >
          <Server size={14} /> System Health &amp; Subsystems
        </button>
        <button
          className={`admin-nav-tab ${activeTab === 'audit' ? 'admin-nav-tab--active' : ''}`}
          onClick={() => setActiveTab('audit')}
        >
          <Shield size={14} /> Audit Trail &amp; Policies
        </button>
      </nav>

      {/* TAB 1: USER MANAGEMENT */}
      {activeTab === 'users' && (
        <section aria-label="User Management">
          {/* Top Metric Cards */}
          <div className="admin-metrics-grid">
            <div className="admin-metric-card">
              <header><span>Total Accounts</span><Users size={13} /></header>
              <div className="admin-metric-value">{usersList.length}</div>
              <div className="admin-metric-footer">
                {usersList.filter((u) => u.source === 'configured').length} configured · {usersList.filter((u) => u.source === 'database').length} database
              </div>
            </div>
            <div className="admin-metric-card">
              <header><span>Active Users</span><UserCheck size={13} /></header>
              <div className="admin-metric-value" style={{ color: '#23c879' }}>
                {usersList.filter((u) => u.is_active).length}
              </div>
              <div className="admin-metric-footer">Authorized operational credentials</div>
            </div>
            <div className="admin-metric-card">
              <header><span>Administrators</span><ShieldCheck size={13} /></header>
              <div className="admin-metric-value" style={{ color: '#06c4d8' }}>
                {usersList.filter((u) => u.role === 'admin' && u.is_active).length}
              </div>
              <div className="admin-metric-footer">Protected from zero-admin lockout</div>
            </div>
            <div className="admin-metric-card">
              <header><span>Deactivated Accounts</span><AlertTriangle size={13} /></header>
              <div className="admin-metric-value" style={{ color: '#ef3e4c' }}>
                {usersList.filter((u) => !u.is_active).length}
              </div>
              <div className="admin-metric-footer">Sessions revoked upon deactivation</div>
            </div>
          </div>

          {/* Search and Filters Toolbar */}
          <div className="admin-toolbar" style={{ marginTop: '12px' }}>
            <div className="admin-toolbar-filters">
              <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
                <Search size={13} style={{ position: 'absolute', left: '8px', color: '#7b889d' }} />
                <input
                  type="text"
                  className="admin-search-input"
                  style={{ paddingLeft: '26px' }}
                  placeholder="Filter by username, name, or ID…"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                />
              </div>

              <select
                className="admin-filter-select"
                value={roleFilter}
                onChange={(e) => setRoleFilter(e.target.value)}
              >
                <option value="all">All Roles</option>
                <option value="admin">Admin</option>
                <option value="analyst">Analyst</option>
                <option value="approver">Approver</option>
                <option value="viewer">Viewer</option>
              </select>

              <select
                className="admin-filter-select"
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
              >
                <option value="all">All Statuses</option>
                <option value="active">Active Only</option>
                <option value="inactive">Inactive Only</option>
              </select>
            </div>

            <div style={{ color: '#8c97a8', fontSize: '10px', fontFamily: 'var(--mono)' }}>
              Showing {filteredUsers.length} of {usersList.length} accounts
            </div>
          </div>

          {usersError && (
            <div className="admin-alert admin-alert--error" style={{ marginTop: '12px' }}>
              <ShieldAlert size={16} />
              <span>{usersError}</span>
            </div>
          )}

          {/* Users Table */}
          <div className="api-table-scroll" style={{ marginTop: '10px', border: '1px solid var(--border)' }}>
            <table className="admin-table">
              <thead>
                <tr>
                  <th>Account / Identity</th>
                  <th>Display Name</th>
                  <th>Role</th>
                  <th>Status</th>
                  <th>Origin</th>
                  <th>Created</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {filteredUsers.length === 0 ? (
                  <tr>
                    <td colSpan={7} style={{ textAlign: 'center', padding: '36px', color: '#8895a7' }}>
                      {loadingUsers ? 'Loading accounts…' : 'No user accounts match the current filter.'}
                    </td>
                  </tr>
                ) : (
                  filteredUsers.map((account) => (
                    <tr key={account.user_id}>
                      <td>
                        <strong style={{ color: '#edf2f9', fontFamily: 'var(--mono)' }}>
                          {account.username}
                        </strong>
                        <div style={{ fontSize: '8px', color: '#68778d' }}>ID: {account.user_id}</div>
                      </td>
                      <td>{account.display_name || <span style={{ color: '#68778d' }}>—</span>}</td>
                      <td>
                        <span className={`admin-badge admin-badge--${account.role}`}>
                          {account.role}
                        </span>
                      </td>
                      <td>
                        <span className={`admin-badge admin-badge--${account.is_active ? 'active' : 'inactive'}`}>
                          {account.is_active ? 'Active' : 'Disabled'}
                        </span>
                      </td>
                      <td>
                        <span className={`admin-badge admin-badge--${account.source}`}>
                          {account.source === 'configured' ? 'Environment' : 'Database'}
                        </span>
                      </td>
                      <td style={{ color: '#9ba7b8', fontFamily: 'var(--mono)', fontSize: '9px' }}>
                        {new Date(account.created_at).toLocaleDateString()}
                      </td>
                      <td style={{ textAlign: 'right' }}>
                        <div style={{ display: 'inline-flex', gap: '6px' }}>
                          <button
                            className="admin-btn admin-btn--secondary"
                            onClick={() => setViewUserModal(account)}
                            title="View Account Details"
                          >
                            <Eye size={12} /> View
                          </button>
                          <button
                            className="admin-btn admin-btn--secondary"
                            onClick={() => handleOpenEdit(account)}
                            title="Modify Account Governance"
                          >
                            Edit
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>
      )}

      {/* TAB 2: SYSTEM OVERVIEW */}
      {activeTab === 'overview' && (
        <section aria-label="System Overview">
          {overviewError && (
            <div className="admin-alert admin-alert--error">
              <ShieldAlert size={16} />
              <span>{overviewError}</span>
            </div>
          )}

          <div className="admin-metrics-grid">
            <div className="admin-metric-card">
              <header><span>System State</span><Activity size={13} /></header>
              <div className="admin-status-indicator" style={{ marginTop: '4px' }}>
                <span
                  className={`admin-status-dot admin-status-dot--${
                    overviewData?.system_health?.status === 'healthy' ? 'green' : 'yellow'
                  }`}
                />
                <span style={{ fontSize: '16px', color: '#edf2f9' }}>
                  {overviewData?.system_health?.status === 'healthy' ? 'Operational' : 'Degraded'}
                </span>
              </div>
              <div className="admin-metric-footer">Defensive core engine active</div>
            </div>

            <div className="admin-metric-card">
              <header><span>Database Engine</span><Database size={13} /></header>
              <div className="admin-status-indicator" style={{ marginTop: '4px' }}>
                <span
                  className={`admin-status-dot admin-status-dot--${
                    overviewData?.system_health?.database?.connected ? 'green' : 'red'
                  }`}
                />
                <span style={{ fontSize: '16px', color: '#edf2f9' }}>
                  {overviewData?.system_health?.database?.connected ? 'Connected' : 'Offline'}
                </span>
              </div>
              <div className="admin-metric-footer">SQLite persistent store</div>
            </div>

            <div className="admin-metric-card">
              <header><span>Wazuh SIEM Ingestion</span><Shield size={13} /></header>
              <div className="admin-status-indicator" style={{ marginTop: '4px' }}>
                <span
                  className={`admin-status-dot admin-status-dot--${
                    overviewData?.system_health?.wazuh_integration?.status === 'configured' ? 'green' : 'gray'
                  }`}
                />
                <span style={{ fontSize: '14px', color: '#edf2f9' }}>
                  {overviewData?.system_health?.wazuh_integration?.status === 'configured'
                    ? 'Connected / Configured'
                    : 'Not Configured'}
                </span>
              </div>
              <div className="admin-metric-footer">
                {overviewData?.system_health?.wazuh_integration?.message || 'External SIEM connector'}
              </div>
            </div>

            <div className="admin-metric-card">
              <header><span>Total Backups Protected</span><Database size={13} /></header>
              <div className="admin-metric-value" style={{ color: '#23c879' }}>
                {overviewData?.backup_recovery_summary?.protected_backups ?? 0}
              </div>
              <div className="admin-metric-footer">
                Out of {overviewData?.backup_recovery_summary?.total_backups ?? 0} registered points
              </div>
            </div>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '12px', marginTop: '16px' }}>
            <div className="admin-metric-card" style={{ padding: '16px' }}>
              <h3 style={{ margin: '0 0 12px', color: '#edf1f8', fontFamily: 'var(--mono)', fontSize: '12px' }}>
                Subsystem Integration Status
              </h3>
              <div style={{ display: 'grid', gap: '10px', fontSize: '10px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
                  <span>Security Event Processor</span>
                  <span className="admin-status-indicator">
                    <span className="admin-status-dot admin-status-dot--green" /> Operational
                  </span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
                  <span>Backup Integrity Verifier</span>
                  <span className="admin-status-indicator">
                    <span className="admin-status-dot admin-status-dot--green" /> Ready ({overviewData?.backup_recovery_summary?.verified_backups ?? 0} verified)
                  </span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
                  <span>Automated Recovery Engine</span>
                  <span className="admin-status-indicator">
                    <span className="admin-status-dot admin-status-dot--green" /> Operational ({overviewData?.backup_recovery_summary?.recovery_jobs ?? 0} jobs)
                  </span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0' }}>
                  <span>System Isolation Agent</span>
                  <span className="admin-status-indicator">
                    <span className="admin-status-dot admin-status-dot--green" /> Standby
                  </span>
                </div>
              </div>
            </div>

            <div className="admin-metric-card" style={{ padding: '16px' }}>
              <h3 style={{ margin: '0 0 12px', color: '#edf1f8', fontFamily: 'var(--mono)', fontSize: '12px' }}>
                Threat &amp; Security Summary
              </h3>
              <div style={{ display: 'grid', gap: '10px', fontSize: '10px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
                  <span>Active Security Threats</span>
                  <strong style={{ color: overviewData?.security_summary?.active_threats ? '#ef3e4c' : '#23c879' }}>
                    {overviewData?.security_summary?.active_threats ?? 0}
                  </strong>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
                  <span>Critical Severity Events</span>
                  <strong style={{ color: overviewData?.security_summary?.critical_events ? '#ef3e4c' : '#aab6c7' }}>
                    {overviewData?.security_summary?.critical_events ?? 0}
                  </strong>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
                  <span>Total Security Events Ingested</span>
                  <strong>{overviewData?.security_summary?.total_events ?? 0}</strong>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0' }}>
                  <span>Total Immutable Audit Logs</span>
                  <strong>{overviewData?.audit_summary?.total_events ?? 0}</strong>
                </div>
              </div>
            </div>
          </div>
        </section>
      )}


          {/* DEMO SECURITY EVENTS — PRESENTATION ONLY */}
          <div className="admin-metric-card" style={{ marginTop: '16px', padding: '16px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', gap: '12px', flexWrap: 'wrap', alignItems: 'center' }}>
              <h3 style={{ margin: 0, color: '#edf1f8', fontFamily: 'var(--mono)', fontSize: '12px' }}>
                Recent Security Events
              </h3>
              <span style={{ color: '#f4bd50', fontSize: '10px', border: '1px solid var(--border)', borderRadius: '4px', padding: '4px 7px' }}>
                DEMO DATA · PRESENTATION ONLY
              </span>
            </div>
            <p style={{ color: '#8c97a8', fontSize: '10px', margin: '8px 0 12px' }}>
              Illustrative examples only — not live Wazuh alerts.
            </p>
            <div style={{ display: 'grid', gap: '8px' }}>
              {[
                { title: 'Suspicious bulk file modifications', detail: 'Multiple files changed in a short period', severity: 'High', color: '#ff6470', bg: 'rgba(239,62,76,0.12)' },
                { title: 'Repeated failed login attempts', detail: 'Several authentication failures', severity: 'Medium', color: '#f4bd50', bg: 'rgba(244,189,80,0.12)' },
                { title: 'Unusual file access activity', detail: 'Access pattern differs from normal usage', severity: 'Low', color: '#70b7ff', bg: 'rgba(112,183,255,0.12)' },
                { title: 'Backup integrity verification failure', detail: 'Sample backup failed verification', severity: 'High', color: '#ff6470', bg: 'rgba(239,62,76,0.12)' },
                { title: 'Unusual outbound network activity', detail: 'Outbound traffic is above the baseline', severity: 'Medium', color: '#f4bd50', bg: 'rgba(244,189,80,0.12)' },
              ].map((event) => (
                <div key={event.title} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '12px', flexWrap: 'wrap', padding: '11px 12px', border: '1px solid var(--border)', borderRadius: '6px' }}>
                  <div style={{ flex: '1 1 230px' }}>
                    <div style={{ color: '#edf1f8', fontSize: '11px', marginBottom: '4px' }}>{event.title}</div>
                    <div style={{ color: '#8c97a8', fontSize: '10px' }}>{event.detail}</div>
                  </div>
                  <span style={{ color: event.color, background: event.bg, border: `1px solid ${event.color}66`, borderRadius: '4px', padding: '4px 9px', fontSize: '10px', fontWeight: 700 }}>
                    {event.severity}
                  </span>
                </div>
              ))}
            </div>
          </div>

      {/* TAB 3: AUDIT & POLICIES */}
      {activeTab === 'audit' && (
        <section aria-label="Audit & Policies">
          <div className="admin-metric-card" style={{ padding: '16px' }}>
            <h3 style={{ margin: '0 0 12px', color: '#edf1f8', fontFamily: 'var(--mono)', fontSize: '12px' }}>
              System Policy Configurations
            </h3>
            <p style={{ margin: '0 0 16px', color: '#8c97a8', fontSize: '10px' }}>
              Manage system policies, risk thresholds, and automation settings through authorized configuration views:
            </p>
            <div className="admin-quick-links-grid">
              <Link to="/settings/general" className="admin-quick-link">
                <strong>General Policies <ExternalLink size={12} /></strong>
                <span>Application environment and branding</span>
              </Link>
              <Link to="/settings/risk-engine" className="admin-quick-link">
                <strong>Risk Engine <ExternalLink size={12} /></strong>
                <span>Scoring weights and threshold bounds</span>
              </Link>
              <Link to="/settings/backup-integrity" className="admin-quick-link">
                <strong>Backup Integrity <ExternalLink size={12} /></strong>
                <span>Verification schedules and retention</span>
              </Link>
              <Link to="/settings/isolation" className="admin-quick-link">
                <strong>System Isolation <ExternalLink size={12} /></strong>
                <span>Network segmentation policy</span>
              </Link>
              <Link to="/settings/recovery" className="admin-quick-link">
                <strong>Recovery Policy <ExternalLink size={12} /></strong>
                <span>Validation checks and automated cutovers</span>
              </Link>
              <Link to="/settings/security-access" className="admin-quick-link">
                <strong>Security &amp; Access <ExternalLink size={12} /></strong>
                <span>Session TTL, origins, and auth policy</span>
              </Link>
            </div>
          </div>

          <div className="admin-metric-card" style={{ marginTop: '16px', padding: '16px' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
              <h3 style={{ margin: 0, color: '#edf1f8', fontFamily: 'var(--mono)', fontSize: '12px' }}>
                Recent Administrative Audit Events
              </h3>
              <Link to="/audit-logs" className="admin-btn admin-btn--secondary">
                View Full Audit Log <ArrowRight size={12} />
              </Link>
            </div>

            <div className="api-table-scroll" style={{ border: '1px solid var(--border)' }}>
              <table className="admin-table">
                <thead>
                  <tr>
                    <th>Action</th>
                    <th>Actor Type</th>
                    <th>Actor ID</th>
                    <th>Result</th>
                    <th>Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {!overviewData?.audit_summary?.recent_events?.length ? (
                    <tr>
                      <td colSpan={5} style={{ textAlign: 'center', padding: '24px', color: '#8c97a8' }}>
                        No audit events recorded yet.
                      </td>
                    </tr>
                  ) : (
                    overviewData.audit_summary.recent_events.map((event) => (
                      <tr key={event.id}>
                        <td>
                          <strong style={{ fontFamily: 'var(--mono)', color: '#06c4d8' }}>
                            {event.action}
                          </strong>
                        </td>
                        <td>{event.actor_type}</td>
                        <td style={{ fontFamily: 'var(--mono)' }}>{event.actor_id}</td>
                        <td>
                          <span
                            className={`admin-badge admin-badge--${
                              event.result_status === 'success' ? 'active' : 'inactive'
                            }`}
                          >
                            {event.result_status}
                          </span>
                        </td>
                        <td style={{ fontFamily: 'var(--mono)', fontSize: '9px', color: '#8c97a8' }}>
                          {new Date(event.occurred_at).toLocaleString()}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </section>
      )}

      {/* PROVISION USER MODAL */}
      {provisionModalOpen && (
        <div className="admin-modal-backdrop" onClick={() => setProvisionModalOpen(false)}>
          <div className="admin-modal" onClick={(e) => e.stopPropagation()}>
            <div className="admin-modal-header">
              <h3>Provision Operator Account</h3>
              <button
                type="button"
                className="admin-modal-close"
                onClick={() => setProvisionModalOpen(false)}
                aria-label="Close"
              >
                <X size={16} />
              </button>
            </div>
            <form onSubmit={handleSaveProvision}>
              <div className="admin-modal-body">
                {provError && (
                  <div className="admin-alert admin-alert--error">
                    <ShieldAlert size={14} />
                    <span>{provError}</span>
                  </div>
                )}

                <div className="admin-field-group">
                  <label htmlFor="prov-username">Username *</label>
                  <input
                    id="prov-username"
                    type="text"
                    required
                    placeholder="e.g. jdoe_ops"
                    value={provUsername}
                    onChange={(e) => setProvUsername(e.target.value)}
                    disabled={provBusy}
                  />
                  <span className="admin-field-hint">3–64 alphanumeric characters, ., -, or _</span>
                </div>

                <div className="admin-field-group">
                  <label htmlFor="prov-display">Display Name</label>
                  <input
                    id="prov-display"
                    type="text"
                    placeholder="Full name or callsign"
                    value={provDisplayName}
                    onChange={(e) => setProvDisplayName(e.target.value)}
                    disabled={provBusy}
                  />
                </div>

                <div className="admin-field-group">
                  <label htmlFor="prov-role">Assigned Role *</label>
                  <select
                    id="prov-role"
                    value={provRole}
                    onChange={(e) => setProvRole(e.target.value)}
                    disabled={provBusy}
                  >
                    <option value="analyst">Analyst (Incident &amp; threat analysis)</option>
                    <option value="approver">Approver (Recovery &amp; isolation approval)</option>
                    <option value="viewer">Viewer (Read-only observation)</option>
                  </select>
                </div>

                <div className="admin-field-group">
                  <label htmlFor="prov-pass">Initial Password *</label>
                  <input
                    id="prov-pass"
                    type="password"
                    required
                    placeholder="Minimum 12 characters"
                    value={provPassword}
                    onChange={(e) => setProvPassword(e.target.value)}
                    disabled={provBusy}
                  />
                </div>

                <div className="admin-field-group">
                  <label htmlFor="prov-confirm">Confirm Password *</label>
                  <input
                    id="prov-confirm"
                    type="password"
                    required
                    placeholder="Re-enter password"
                    value={provConfirm}
                    onChange={(e) => setProvConfirm(e.target.value)}
                    disabled={provBusy}
                  />
                </div>
              </div>
              <div className="admin-modal-footer">
                <button
                  type="button"
                  className="admin-btn admin-btn--secondary"
                  onClick={() => setProvisionModalOpen(false)}
                  disabled={provBusy}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="admin-btn admin-btn--primary"
                  disabled={provBusy}
                >
                  {provBusy ? 'Provisioning…' : 'Create Account'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* EDIT ACCOUNT MODAL */}
      {editUserModal && (
        <div className="admin-modal-backdrop" onClick={() => setEditUserModal(null)}>
          <div className="admin-modal" onClick={(e) => e.stopPropagation()}>
            <div className="admin-modal-header">
              <h3>Govern Account: {editUserModal.username}</h3>
              <button
                type="button"
                className="admin-modal-close"
                onClick={() => setEditUserModal(null)}
                aria-label="Close"
              >
                <X size={16} />
              </button>
            </div>
            <form onSubmit={handleSaveEdit}>
              <div className="admin-modal-body">
                {editUserModal.source === 'configured' && (
                  <div className="admin-alert admin-alert--warning">
                    <AlertTriangle size={14} />
                    <span>
                      This account is defined in system environment configuration. Its properties cannot be modified via API.
                    </span>
                  </div>
                )}

                {editError && (
                  <div className="admin-alert admin-alert--error">
                    <ShieldAlert size={14} />
                    <span>{editError}</span>
                  </div>
                )}

                <div className="admin-field-group">
                  <label>Username</label>
                  <input type="text" value={editUserModal.username} disabled />
                </div>

                <div className="admin-field-group">
                  <label htmlFor="edit-display">Display Name</label>
                  <input
                    id="edit-display"
                    type="text"
                    value={editDisplayName}
                    onChange={(e) => setEditDisplayName(e.target.value)}
                    disabled={editBusy || editUserModal.source === 'configured'}
                  />
                </div>

                <div className="admin-field-group">
                  <label htmlFor="edit-role">Role</label>
                  <select
                    id="edit-role"
                    value={editRole}
                    onChange={(e) => setEditRole(e.target.value)}
                    disabled={editBusy || editUserModal.source === 'configured'}
                  >
                    <option value="admin">Admin (Full administrative privileges)</option>
                    <option value="approver">Approver (Recovery &amp; isolation approval)</option>
                    <option value="analyst">Analyst (Analysis &amp; investigations)</option>
                    <option value="viewer">Viewer (Read-only observation)</option>
                  </select>
                </div>

                <div className="admin-field-group">
                  <label htmlFor="edit-status">Account Status</label>
                  <select
                    id="edit-status"
                    value={editActive ? 'active' : 'inactive'}
                    onChange={(e) => setEditActive(e.target.value === 'active')}
                    disabled={editBusy || editUserModal.source === 'configured'}
                  >
                    <option value="active">Active (Permitted to authenticate)</option>
                    <option value="inactive">Disabled (Authentication blocked)</option>
                  </select>
                </div>

                {editUserModal.role === 'admin' && (
                  <div className="admin-alert admin-alert--warning" style={{ fontSize: '9px' }}>
                    <ShieldCheck size={14} />
                    <span>
                      Governance policy prevents removing or deactivating the last active administrator in the system.
                    </span>
                  </div>
                )}
              </div>
              <div className="admin-modal-footer">
                <button
                  type="button"
                  className="admin-btn admin-btn--secondary"
                  onClick={() => setEditUserModal(null)}
                  disabled={editBusy}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="admin-btn admin-btn--primary"
                  disabled={editBusy || editUserModal.source === 'configured'}
                >
                  {editBusy ? 'Saving Changes…' : 'Save Governance'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* VIEW ACCOUNT DETAILS MODAL */}
      {viewUserModal && (
        <div className="admin-modal-backdrop" onClick={() => setViewUserModal(null)}>
          <div className="admin-modal" onClick={(e) => e.stopPropagation()}>
            <div className="admin-modal-header">
              <h3>Account Record: {viewUserModal.username}</h3>
              <button
                type="button"
                className="admin-modal-close"
                onClick={() => setViewUserModal(null)}
                aria-label="Close"
              >
                <X size={16} />
              </button>
            </div>
            <div className="admin-modal-body">
              <dl style={{ margin: 0, display: 'grid', gap: '8px', fontSize: '10px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
                  <dt style={{ color: '#8c97a8' }}>Stable User ID</dt>
                  <dd style={{ margin: 0, fontFamily: 'var(--mono)' }}>{viewUserModal.user_id}</dd>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
                  <dt style={{ color: '#8c97a8' }}>Username</dt>
                  <dd style={{ margin: 0, fontFamily: 'var(--mono)', fontWeight: 600 }}>{viewUserModal.username}</dd>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
                  <dt style={{ color: '#8c97a8' }}>Display Name</dt>
                  <dd style={{ margin: 0 }}>{viewUserModal.display_name || 'None'}</dd>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
                  <dt style={{ color: '#8c97a8' }}>Assigned Role</dt>
                  <dd style={{ margin: 0 }}>
                    <span className={`admin-badge admin-badge--${viewUserModal.role}`}>
                      {viewUserModal.role}
                    </span>
                  </dd>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
                  <dt style={{ color: '#8c97a8' }}>Status</dt>
                  <dd style={{ margin: 0 }}>
                    <span className={`admin-badge admin-badge--${viewUserModal.is_active ? 'active' : 'inactive'}`}>
                      {viewUserModal.is_active ? 'Active' : 'Disabled'}
                    </span>
                  </dd>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
                  <dt style={{ color: '#8c97a8' }}>Storage Source</dt>
                  <dd style={{ margin: 0 }}>
                    <span className={`admin-badge admin-badge--${viewUserModal.source}`}>
                      {viewUserModal.source === 'configured' ? 'Environment Configuration' : 'Database Storage'}
                    </span>
                  </dd>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
                  <dt style={{ color: '#8c97a8' }}>Provisioned By</dt>
                  <dd style={{ margin: 0, fontFamily: 'var(--mono)' }}>{viewUserModal.created_by_user_id}</dd>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0' }}>
                  <dt style={{ color: '#8c97a8' }}>Created Timestamp</dt>
                  <dd style={{ margin: 0, fontFamily: 'var(--mono)' }}>
                    {new Date(viewUserModal.created_at).toLocaleString()}
                  </dd>
                </div>
              </dl>
              <div className="admin-alert admin-alert--success" style={{ fontSize: '9px', marginTop: '8px' }}>
                <ShieldCheck size={14} />
                <span>Zero-exposure guarantee: Password digests and secrets are excluded from API payloads.</span>
              </div>
            </div>
            <div className="admin-modal-footer">
              <button
                type="button"
                className="admin-btn admin-btn--secondary"
                onClick={() => setViewUserModal(null)}
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </main>
  )
}
