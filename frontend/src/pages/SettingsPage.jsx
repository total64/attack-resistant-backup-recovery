import { useEffect, useMemo, useState } from 'react'
import {
  Activity,
  AlertTriangle,
  Bell,
  ChartNoAxesCombined,
  Check,
  ClipboardList,
  Database,
  KeyRound,
  LockKeyhole,
  RotateCcw,
  Save,
  Settings as SettingsIcon,
  Shield,
  ShieldCheck,
  X,
} from 'lucide-react'
import { Link, NavLink, Outlet, useLocation, useNavigate } from 'react-router-dom'
import { api } from '../api/client.js'
import { displayValue, formatTimestamp } from '../api/formatters.js'
import { ApiState } from '../components/ApiState.jsx'
import { useAuth } from '../auth/AuthContext.jsx'
import './SettingsPage.css'

const settingsPages = [
  { path: '/settings/general', label: 'General', icon: 'settings', description: 'System identity and stored configuration metadata.' },
  { path: '/settings/monitoring', label: 'Security Monitoring', icon: 'activity', description: 'Live service status and backend-reported monitoring coverage.' },
  { path: '/settings/risk-engine', label: 'Risk Engine', icon: 'chart', description: 'Persisted risk bands used when new assessments are classified.' },
  { path: '/settings/backup-integrity', label: 'Backup & Integrity', icon: 'database', description: 'Stored backup policy values; unsupported controls are not fabricated.' },
  { path: '/settings/isolation', label: 'Isolation', icon: 'lock', description: 'Stored isolation policy values and enforced workflow safeguards.' },
  { path: '/settings/recovery', label: 'Recovery', icon: 'rotate', description: 'Stored recovery policy and backend-enforced safety gates.' },
  { path: '/settings/notifications', label: 'Notifications', icon: 'bell', description: 'Stored notification policy; delivery integrations are reported separately.' },
  { path: '/settings/security-access', label: 'Security & Access', icon: 'shield', description: 'Current session and administrator-controlled operations accounts.' },
  { path: '/settings/system-integrations', label: 'System & Integrations', icon: 'integrations', description: 'Live health endpoint and verifiable integration status.' },
  { path: '/settings/audit-monitoring', label: 'Audit & Monitoring', icon: 'audit', description: 'Persisted audit activity and current system risk thresholds.' },
]

const sectionIcons = {
  settings: SettingsIcon,
  activity: Activity,
  chart: ChartNoAxesCombined,
  database: Database,
  lock: LockKeyhole,
  rotate: RotateCcw,
  bell: Bell,
  shield: ShieldCheck,
  integrations: Activity,
  audit: ClipboardList,
}

const roleDescriptions = {
  viewer: 'Read access to authenticated operational data.',
  analyst: 'Read access plus analyst workflow operations, including asset registration.',
  approver: 'Read access plus action-request approval and rejection.',
  admin: 'All human-user operations; system settings and account provisioning are administrator-controlled.',
}
const EMPTY_OBJECT = Object.freeze({})

function useApiResource(path, refreshKey = 0) {
  const requestKey = `${refreshKey}:${path}`
  const [state, setState] = useState({ requestKey: '', data: null, loading: false, error: null })
  useEffect(() => {
    const controller = new AbortController()
    api.get(path, { signal: controller.signal })
      .then((data) => setState({ requestKey, data, loading: false, error: null }))
      .catch((error) => {
        if (error.name !== 'AbortError') setState({ requestKey, data: null, loading: false, error })
      })
    return () => controller.abort()
  }, [path, refreshKey, requestKey])
  return state.requestKey === requestKey ? state : { data: null, loading: true, error: null }
}

function SettingsCard({ title, description, icon: Icon, children }) {
  return (
    <section className="panel settings-card settings-section-card" aria-label={title}>
      <header className="settings-card-heading">
        <span className="settings-card-icon"><Icon size={17} aria-hidden="true" /></span>
        <div><h2>{title}</h2><p className="settings-card-description">{description}</p></div>
      </header>
      <div className="settings-card-content">{children}</div>
    </section>
  )
}

function SettingsValues({ values, emptyMessage = 'No values are configured in the backend response.' }) {
  const entries = Object.entries(values || {})
  if (!entries.length) return <p className="settings-section-empty">{emptyMessage}</p>
  return (
    <dl className="settings-values">
      {entries.map(([key, value]) => <div className="settings-value-row" key={key}><dt>{key.replaceAll('_', ' ')}</dt><dd>{displayValue(value)}</dd></div>)}
    </dl>
  )
}

function SettingsHeader({ eyebrow, title, description, admin, dirty, busy, saveDisabled = false, onCancel, onSave }) {
  return (
    <header className="settings-section-heading">
      <div><span className="eyebrow">{eyebrow}</span><h2>{title}</h2><p>{description}</p></div>
      {admin && <div className="settings-editor-actions">
        <span className={dirty ? 'settings-unsaved-label' : 'settings-saved-label'}>{dirty ? 'Unsaved changes' : 'In sync'}</span>
        <button className="toolbar-button" type="button" disabled={!dirty || busy} onClick={onCancel}><X size={13} />Cancel</button>
        <button className="toolbar-button settings-save-button" type="button" disabled={!dirty || busy || saveDisabled} onClick={onSave}>{busy ? <span className="loading-spinner" /> : <Save size={13} />}{busy ? 'Saving…' : 'Save Changes'}</button>
      </div>}
    </header>
  )
}

function useSettingsDraft(field) {
  const [refresh, setRefresh] = useState(0)
  const { data, loading, error } = useApiResource('/settings', refresh)
  const [draftState, setDraftState] = useState(null)
  const [busy, setBusy] = useState(false)
  const [saveError, setSaveError] = useState(null)
  const [savedMessage, setSavedMessage] = useState('')
  const draft = data
    ? draftState?.field === field && draftState.version === data.version
      ? draftState.value
      : data[field]
    : null
  const setDraft = (update) => {
    if (!data) return
    const current = draft
    const value = typeof update === 'function' ? update(current) : update
    setDraftState({ field, version: data.version, value })
  }
  const dirty = Boolean(data && draft && JSON.stringify(draft) !== JSON.stringify(data[field]))
  const cancel = () => {
    setDraftState(null)
    setSaveError(null)
    setSavedMessage('')
  }
  const save = async (nextValue = draft) => {
    setBusy(true)
    setSaveError(null)
    setSavedMessage('')
    try {
      const updated = await api.put('/settings', { [field]: nextValue })
      setDraftState({ field, version: updated.version, value: structuredClone(updated[field]) })
      setSavedMessage(`Saved as configuration version ${updated.version}.`)
      setRefresh((current) => current + 1)
      return true
    } catch (error) {
      setSaveError(error)
      return false
    } finally {
      setBusy(false)
    }
  }
  return { data, draft, setDraft, loading, error, refresh: () => setRefresh((current) => current + 1), busy, dirty, saveError, savedMessage, cancel, save }
}

function StoredPolicyPage({ field, title, description, runtimeNote }) {
  const state = useApiResource('/settings')
  return (
    <section className="panel settings-form-panel">
      <header className="settings-section-heading"><div><span className="eyebrow">System configuration</span><h2>{title}</h2><p>{description}</p></div></header>
      <ApiState loading={state.loading} error={state.error} onRetry={state.refresh}>
        {state.data && <SettingsValues values={state.data[field]} emptyMessage="No policy values are configured in the backend." />}
      </ApiState>
      <p className="settings-policy-caveat"><AlertTriangle size={13} />{runtimeNote}</p>
    </section>
  )
}

const thresholdFields = [
  ['low_min', 'Low minimum'], ['low_max', 'Low maximum'],
  ['medium_min', 'Medium minimum'], ['medium_max', 'Medium maximum'],
  ['high_min', 'High minimum'], ['high_max', 'High maximum'],
  ['critical_min', 'Critical minimum'], ['critical_max', 'Critical maximum'],
]

function RiskEnginePage() {
  const { user } = useAuth()
  const admin = user?.role === 'admin'
  const state = useSettingsDraft('risk_thresholds')
  const draft = state.draft || EMPTY_OBJECT
  const validationMessage = useMemo(() => {
    if (!state.dirty || !admin) return ''
    const rawValues = thresholdFields.map(([key]) => draft[key])
    if (rawValues.some((value) => value === '' || value === null || value === undefined)) return 'All threshold values are required.'
    const values = rawValues.map(Number)
    if (values.some((value) => !Number.isInteger(value) || value < 0 || value > 100)) return 'Enter whole-number thresholds from 0 through 100.'
    const [lowMin, lowMax, mediumMin, mediumMax, highMin, highMax, criticalMin, criticalMax] = values
    if (lowMin !== 0 || criticalMax !== 100 || lowMax + 1 !== mediumMin || mediumMax + 1 !== highMin || highMax + 1 !== criticalMin || !(lowMax < mediumMin && mediumMax < highMin && highMax < criticalMin)) return 'Risk bands must be ordered, contiguous, and cover the full 0–100 range.'
    return ''
  }, [admin, draft, state.dirty])

  return (
    <section className="panel settings-form-panel">
      <SettingsHeader eyebrow="System configuration" title="Risk Engine" description="These persisted thresholds are applied when the backend classifies new risk assessments. Existing assessments are not rewritten." admin={admin} dirty={state.dirty} busy={state.busy} saveDisabled={Boolean(validationMessage)} onCancel={state.cancel} onSave={() => state.save(Object.fromEntries(thresholdFields.map(([key]) => [key, Number(draft[key])] )))} />
      <ApiState loading={state.loading} error={state.error} onRetry={state.refresh}>
        {state.data && <>
          <div className="settings-fields settings-fields--thresholds">
            {thresholdFields.map(([key, label]) => <label className="setting-row setting-row--input" key={key}><span className="setting-copy"><strong>{label}</strong><span>Valid range: 0–100</span></span>{admin ? <span className="setting-number-wrap"><input aria-label={label} type="number" min="0" max="100" step="1" value={draft[key] ?? ''} onChange={(event) => state.setDraft((current) => ({ ...current, [key]: event.target.value === '' ? '' : Number(event.target.value) }))} /><small>/ 100</small></span> : <span className="settings-readonly-value">{state.data.risk_thresholds[key]}</span>}</label>)}
          </div>
          <p className="settings-policy-caveat"><Shield size={13} />Threshold changes affect future risk assessments only. Risk-based containment and recovery still require their existing workflow, authorization, and verification gates.</p>
          {validationMessage && <p className="settings-inline-error" role="alert">{validationMessage}</p>}
          {state.saveError && <ApiState error={state.saveError} />}
          {state.savedMessage && <p className="settings-save-success" role="status"><Check size={14} />{state.savedMessage}</p>}
        </>}
      </ApiState>
    </section>
  )
}

function MonitoringPage() {
  const health = useApiResource('/health')
  const dashboard = useApiResource('/dashboard/summary')
  const assets = useApiResource('/assets?page=1&page_size=1')
  return (
    <div className="settings-sections-grid">
      <SettingsCard title="Backend service" description="Live response from the health endpoint." icon={Activity}>
        <ApiState loading={health.loading} error={health.error} onRetry={health.refresh}>
          {health.data && <div className="settings-live-state"><i className={`status-dot ${health.data.status === 'ok' ? 'status-dot--green' : ''}`} /><strong>{health.data.status === 'ok' ? 'Connected' : `Health status: ${health.data.status}`}</strong></div>}
        </ApiState>
      </SettingsCard>
      <SettingsCard title="Persisted monitoring data" description="Counts returned by authenticated backend endpoints; no invented coverage states." icon={ChartNoAxesCombined}>
        <ApiState loading={dashboard.loading || assets.loading} error={dashboard.error || assets.error}>
          {dashboard.data && assets.data && <dl className="settings-values">
            <div className="settings-value-row"><dt>Security events</dt><dd>{dashboard.data.total_security_events}</dd></div>
            <div className="settings-value-row"><dt>Active threats</dt><dd>{dashboard.data.active_threats}</dd></div>
            <div className="settings-value-row"><dt>Registered assets</dt><dd>{assets.data.total}</dd></div>
          </dl>}
        </ApiState>
        <p className="settings-policy-caveat"><AlertTriangle size={13} />The API does not expose configurable source toggles or Wazuh health. No editable controls are shown for unimplemented integrations.</p>
      </SettingsCard>
    </div>
  )
}

function GeneralSettingsPage() {
  const state = useApiResource('/settings')
  return (
    <div className="settings-sections-grid">
      <SettingsCard title="Application" description="Identity and version metadata returned by the backend." icon={SettingsIcon}>
        <dl className="settings-values"><div className="settings-value-row"><dt>Application</dt><dd>Attack-Resistant Backup &amp; Recovery</dd></div></dl>
        <ApiState loading={state.loading} error={state.error} onRetry={state.refresh}>
          {state.data && <dl className="settings-values"><div className="settings-value-row"><dt>Configuration version</dt><dd>{state.data.version}</dd></div><div className="settings-value-row"><dt>Last updated</dt><dd>{formatTimestamp(state.data.updated_at)}</dd></div></dl>}
        </ApiState>
      </SettingsCard>
      <SettingsCard title="Console behavior" description="The active frontend supports a fixed dark console presentation." icon={Activity}>
        <div className="settings-readonly-explainer"><strong>No appearance preferences are configured.</strong><p>Theme, time-zone, refresh interval, and environment selectors are not part of the current settings API, so the interface does not offer controls that would not persist.</p></div>
      </SettingsCard>
    </div>
  )
}

export function AdminUserManagement() {
  const [refresh, setRefresh] = useState(0)
  const { data, loading, error } = useApiResource('/users', refresh)
  const [selectedAccount, setSelectedAccount] = useState(null)
  const [form, setForm] = useState({ username: '', display_name: '', role: 'viewer', initial_password: '', confirm_password: '' })
  const [busy, setBusy] = useState(false)
  const [formError, setFormError] = useState('')
  const [success, setSuccess] = useState('')
  const update = (key, value) => setForm((current) => ({ ...current, [key]: value }))

  const submit = async (event) => {
    event.preventDefault()
    setFormError('')
    setSuccess('')
    if (form.initial_password !== form.confirm_password) {
      setFormError('The initial password and confirmation do not match.')
      return
    }
    setBusy(true)
    try {
      const result = await api.post('/users', {
        username: form.username.trim(),
        display_name: form.display_name.trim() || null,
        role: form.role,
        initial_password: form.initial_password,
      })
      setSuccess(`Account ${result.username} was created with the ${result.role} role.`)
      setForm({ username: '', display_name: '', role: 'viewer', initial_password: '', confirm_password: '' })
      setRefresh((current) => current + 1)
    } catch (error) {
      setFormError(error.message || 'The account could not be created.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="settings-sections-grid settings-access-grid">
      <SettingsCard title="Provision an operations account" description="Administrator-only account creation. Public self-registration and administrator-role creation are disabled." icon={KeyRound}>
        <form className="settings-provision-form" onSubmit={submit}>
          <label>Username<input autoComplete="off" required minLength={3} maxLength={64} pattern="[A-Za-z0-9][A-Za-z0-9._-]{2,63}" value={form.username} onChange={(event) => update('username', event.target.value)} placeholder="e.g. ops.analyst" /></label>
          <label>Display name <span>(optional)</span><input autoComplete="off" maxLength={255} value={form.display_name} onChange={(event) => update('display_name', event.target.value)} placeholder="Operations analyst" /></label>
          <label>Assigned role<select value={form.role} onChange={(event) => update('role', event.target.value)}><option value="viewer">Viewer</option><option value="analyst">Analyst</option><option value="approver">Approver</option></select></label>
          <label>Initial password<input type="password" autoComplete="new-password" required minLength={12} maxLength={1024} value={form.initial_password} onChange={(event) => update('initial_password', event.target.value)} /></label>
          <label>Confirm initial password<input type="password" autoComplete="new-password" required minLength={12} maxLength={1024} value={form.confirm_password} onChange={(event) => update('confirm_password', event.target.value)} /></label>
          {formError && <p className="settings-inline-error" role="alert">{formError}</p>}
          {success && <p className="settings-save-success" role="status"><Check size={14} />{success}</p>}
          <button className="toolbar-button settings-save-button" type="submit" disabled={busy}>{busy ? <span className="loading-spinner" /> : <Shield size={14} />}{busy ? 'Creating account…' : 'Create account'}</button>
          <p className="settings-readonly-note">The server hashes passwords, assigns a unique account ID, rejects duplicate usernames, and audits creation. Share the initial password only through an approved private channel.</p>
        </form>
      </SettingsCard>
      <section className="panel settings-provisioned-list">
        <header className="settings-section-heading"><div><span className="eyebrow">Account registry</span><h2>Provisioned accounts</h2><p>Database-managed identities created by administrators. Passwords and hashes are never returned.</p></div><button className="toolbar-button" type="button" onClick={() => setRefresh((current) => current + 1)} disabled={loading}><RotateCcw size={13} />Refresh</button></header>
        <ApiState loading={loading} error={error} onRetry={() => setRefresh((current) => current + 1)} empty={data && data.length === 0 ? 'No database-provisioned accounts yet.' : null}>
          {data?.length > 0 && <div className="settings-account-table-wrap"><table className="settings-account-table"><thead><tr><th>Username</th><th>Display name</th><th>Role</th><th>Created by</th><th>Created</th><th>Details</th></tr></thead><tbody>{data.map((account) => <tr key={account.user_id}><td>{account.username}</td><td>{account.display_name || '—'}</td><td>{account.role}</td><td>{account.created_by_user_id}</td><td>{formatTimestamp(account.created_at)}</td><td><button className="row-action" type="button" onClick={() => setSelectedAccount(account)}>View</button></td></tr>)}</tbody></table></div>}
        </ApiState>
        {selectedAccount && <section className="settings-account-details" aria-labelledby="provisioned-user-details"><header><div><span className="eyebrow">Provisioned user</span><h3 id="provisioned-user-details">{selectedAccount.display_name || selectedAccount.username}</h3></div><button className="icon-button" type="button" aria-label="Close account details" onClick={() => setSelectedAccount(null)}><X size={15} /></button></header><dl className="settings-values"><div className="settings-value-row"><dt>Account ID</dt><dd>{selectedAccount.user_id}</dd></div><div className="settings-value-row"><dt>Username</dt><dd>{selectedAccount.username}</dd></div><div className="settings-value-row"><dt>Display name</dt><dd>{selectedAccount.display_name || 'Not set'}</dd></div><div className="settings-value-row"><dt>Role</dt><dd>{selectedAccount.role}</dd></div><div className="settings-value-row"><dt>Created by</dt><dd>{selectedAccount.created_by_user_id}</dd></div><div className="settings-value-row"><dt>Created at</dt><dd>{formatTimestamp(selectedAccount.created_at)}</dd></div></dl><p className="settings-readonly-note">Credential values and password hashes are never returned by the account API.</p></section>}
      </section>
    </div>
  )
}

export function SettingsLayout() {
  const location = useLocation()
  const navigate = useNavigate()
  const { user, logout } = useAuth()
  const signOut = async () => {
    if (!window.confirm('Sign out of this account on this browser?')) return
    await logout()
    navigate('/login', { replace: true })
  }
  return (
    <main className="settings-main">
      <section className="settings-page-heading"><div><h1>System Settings</h1><p>Configure persisted policy, review service status, and administer authorized operations accounts.</p></div></section>
      <div className="settings-workspace">
        <nav className="panel settings-nav-panel" aria-label="Settings categories"><span className="settings-nav-label">Configuration</span>{settingsPages.map((item) => {
          const Icon = sectionIcons[item.icon]
          return <NavLink key={item.path} to={item.path} className={({ isActive }) => `settings-nav-item ${isActive ? 'settings-nav-item--active' : ''}`} aria-current={location.pathname === item.path ? 'page' : undefined}><Icon size={14} /><span>{item.label}</span>{location.pathname === item.path && <span className="settings-nav-marker" />}</NavLink>
        })}<div className="settings-nav-footer"><i className="status-dot status-dot--green" />Settings API protected · {user?.role || 'unknown role'}</div></nav>
        <section className="settings-content"><Outlet /></section>
      </div>
      <section className="panel settings-danger-zone" aria-labelledby="settings-danger-title"><header><div><span className="eyebrow">Account controls</span><h2 id="settings-danger-title">Danger Zone</h2><p>Only supported account actions are offered here. Configuration and stored operational data are not deleted from this screen.</p></div><AlertTriangle size={16} /></header><div className="settings-danger-actions"><div><strong>Change Password</strong><span>Verify the current password; active sessions are revoked after update.</span><Link className="settings-danger-button" to="/change-password">Change password</Link></div><div><strong>End Current Session</strong><span>Revoke this browser session through the protected logout endpoint.</span><button className="settings-danger-button" type="button" onClick={signOut}>Sign out</button></div><div><strong>Account Recovery</strong><span>Operations accounts are created by an administrator; contact your system administrator if access is needed.</span><span className="settings-readonly-value">Administrator-managed</span></div></div>
      </section>
      <footer className="settings-page-footer"><span><i className="status-dot status-dot--green" />Settings values from authenticated backend APIs</span><span>Database-managed policies · role-controlled changes</span></footer>
    </main>
  )
}

export function SettingsGeneralPage() { return <GeneralSettingsPage /> }
export function SettingsMonitoringPage() { return <MonitoringPage /> }
export function SettingsRiskEnginePage() { return <RiskEnginePage /> }
export function SettingsBackupIntegrityPage() { return <StoredPolicyPage field="backup_policy" title="Backup & Integrity" description="Backend-stored policy values; backup and verification outcomes remain component-reported." runtimeNote="The current backend does not consume arbitrary backup-policy keys to schedule or change backup execution. These values are read-only here." /> }
export function SettingsIsolationPage() { return <StoredPolicyPage field="isolation_policy" title="Isolation" description="Backend-stored policy values; confirmed isolation remains component-reported." runtimeNote="Isolation requests still require the existing role, approval, and trusted component workflow. No unimplemented automatic-isolation switches are shown." /> }
export function SettingsRecoveryPage() { return <StoredPolicyPage field="recovery_policy" title="Recovery" description="Backend-stored policy values alongside enforced recovery safety gates." runtimeNote="Recovery completion and release remain governed by the backend state machine and trusted component results. Stored policy keys do not override those safeguards." /> }
export function SettingsNotificationsPage() { return <StoredPolicyPage field="notification_policy" title="Notifications" description="Backend-stored notification policy values; delivery health is not exposed by a notification service." runtimeNote="No notification delivery integration is currently connected. No switches imply that alerts are being delivered." /> }
export function SettingsSecurityAccessPage() {
  const { user } = useAuth()
  return <div className="settings-sections-grid settings-access-grid">
    <SettingsCard title="Authenticated account" description="Identity and authorization details from the active session." icon={ShieldCheck}>
      <dl className="settings-values">
        <div className="settings-value-row"><dt>Account ID</dt><dd>{displayValue(user?.user_id)}</dd></div>
        <div className="settings-value-row"><dt>Display name</dt><dd>{user?.display_name || 'Not set'}</dd></div>
        <div className="settings-value-row"><dt>Role</dt><dd>{user?.role || '—'}</dd></div>
        <div className="settings-value-row"><dt>Permissions</dt><dd>{roleDescriptions[user?.role] || '—'}</dd></div>
      </dl>
      <p className="settings-readonly-note">Environment-managed identities remain provisioned through the protected server environment and are not modified by this form.</p>
      <Link className="toolbar-button settings-password-link" to="/change-password"><KeyRound size={14} />Change password</Link>
    </SettingsCard>
    {user?.role === 'admin' ? <SettingsCard title="Administrator tools" description="User registry and account provisioning are available in the protected Admin Panel." icon={LockKeyhole}><div className="settings-readonly-explainer"><strong>Manage operations accounts</strong><p>Create viewer, analyst, and approver accounts, or inspect administrator-provisioned account details.</p></div><Link className="toolbar-button settings-password-link" to="/admin"><ShieldCheck size={14} />Open Admin Panel</Link></SettingsCard> : <SettingsCard title="Operations account access" description="This restricted system does not allow public self-registration." icon={LockKeyhole}><div className="settings-readonly-explainer"><strong>Administrator-managed access</strong><p>Contact an authorized system administrator to request an operations account. Viewers and operators cannot enumerate users or create accounts.</p></div></SettingsCard>}
  </div>
}

export function SettingsSystemIntegrationsPage() {
  const [refresh, setRefresh] = useState(0)
  const health = useApiResource('/health', refresh)
  return <div className="settings-sections-grid">
    <SettingsCard title="Backend API" description="Connection status from the live health endpoint." icon={Activity}>
      <div className="settings-health-row"><ApiState loading={health.loading} error={health.error} onRetry={() => setRefresh((value) => value + 1)}>{health.data && <span className={`settings-inline-status ${health.data.status === 'ok' ? 'settings-inline-status--ok' : 'settings-inline-status--error'}`}>{health.data.status === 'ok' ? 'Connected' : 'Health check reported'} · {displayValue(health.data.status)}</span>}</ApiState><button className="toolbar-button" type="button" onClick={() => setRefresh((value) => value + 1)} disabled={health.loading}><RotateCcw size={14} />Check again</button></div>
    </SettingsCard>
    <SettingsCard title="External integrations" description="Only status verified by an available endpoint is shown." icon={ShieldCheck}>
      <dl className="settings-values"><div className="settings-value-row"><dt>Wazuh</dt><dd>Unverified — no integration health endpoint</dd></div><div className="settings-value-row"><dt>Backup/recovery workers</dt><dd>Unknown — worker health is not exposed</dd></div></dl>
    </SettingsCard>
  </div>
}

export function SettingsAuditMonitoringPage() {
  const [refresh, setRefresh] = useState(0)
  const audit = useApiResource('/audit-logs?page=1&page_size=100', refresh)
  const config = useApiResource('/settings', refresh)
  return <div className="settings-sections-grid">
    <SettingsCard title="Audit records" description="Record totals and actual outcomes returned by the audit API." icon={ClipboardList}>
      <ApiState loading={audit.loading} error={audit.error} onRetry={() => setRefresh((value) => value + 1)}>{audit.data && <dl className="settings-values"><div className="settings-value-row"><dt>Matching records</dt><dd>{audit.data.total}</dd></div><div className="settings-value-row"><dt>Inspected records</dt><dd>{audit.data.items.length}</dd></div><div className="settings-value-row"><dt>Rejected outcomes in loaded page</dt><dd>{audit.data.items.filter((event) => event.result_status === 'rejected').length}</dd></div></dl>}</ApiState><Link className="toolbar-button settings-password-link" to="/audit-logs">View audit log</Link>
    </SettingsCard>
    <SettingsCard title="Risk thresholds" description="Active thresholds used for future risk classification." icon={ChartNoAxesCombined}>
      <ApiState loading={config.loading} error={config.error} onRetry={() => setRefresh((value) => value + 1)}>{config.data && <SettingsValues values={config.data.risk_thresholds} />}</ApiState><Link className="toolbar-button settings-password-link" to="/settings/risk-engine">Configure risk bands</Link>
    </SettingsCard>
  </div>
}
