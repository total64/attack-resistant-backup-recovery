import { useState } from 'react'
import { Activity, Clock3, KeyRound, LogOut, ShieldCheck, UserRound } from 'lucide-react'
import { Link, Navigate, useNavigate } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext.jsx'

const roleDescriptions = {
  viewer: 'Read access to authenticated operational data.',
  analyst: 'Read access plus analyst workflow operations, including asset registration.',
  approver: 'Read access plus action-request approval and rejection.',
  admin: 'All human-user operations; system settings remain read-only.',
}

function initialsFor(value) {
  return value.split(/[\s_-]+/).filter(Boolean).slice(0, 2).map((part) => part[0]).join('').toUpperCase() || 'AR'
}

export default function ProfilePage() {
  const { user, logout } = useAuth()
  const navigate = useNavigate()
  const [signingOut, setSigningOut] = useState(false)

  if (!user) return <Navigate to="/login" replace />

  const accountLabel = user.display_name || user.user_id || 'Authenticated account'
  const signOut = async () => {
    if (!window.confirm('Sign out of this account on this browser?')) return
    setSigningOut(true)
    await logout()
    navigate('/login', { replace: true })
  }

  return (
    <main className="dashboard-main profile-main">
      <section className="api-page-heading">
        <div><h1>Profile</h1><p>Authenticated account details and session controls.</p></div>
      </section>

      <section className="panel profile-hero" aria-label="Account summary">
        <div className="profile-avatar" aria-hidden="true">{initialsFor(accountLabel)}</div>
        <div className="profile-hero-copy">
          <h2>{accountLabel}</h2>
          <p>{user.display_name ? `Account ID: ${user.user_id}` : 'Account identifier supplied by the authentication API'}</p>
          <span className="profile-role-badge">{user.role || 'Unknown role'}</span>
        </div>
      </section>

      <div className="profile-grid">
        <section className="panel profile-card" aria-labelledby="profile-account-heading">
          <header className="profile-card-heading">
            <span className="profile-info-icon"><UserRound size={19} /></span>
            <div><h2 id="profile-account-heading">Account information</h2><p>Identity fields returned by the current authenticated session.</p></div>
          </header>
          <div className="profile-card-content">
            <dl className="profile-details">
              <dt>Account ID</dt><dd>{user.user_id || '—'}</dd>
              <dt>Display name</dt><dd>{user.display_name || 'Not set'}</dd>
              <dt>Username</dt><dd>Not exposed by the authenticated-user API</dd>
              <dt>Assigned role</dt><dd>{user.role || '—'}</dd>
              <dt>Role permissions</dt><dd>{roleDescriptions[user.role] || 'Permission details are not available for this role.'}</dd>
            </dl>
          </div>
        </section>

        <section className="panel profile-card" aria-labelledby="profile-session-heading">
          <header className="profile-card-heading">
            <span className="profile-info-icon"><Activity size={19} /></span>
            <div><h2 id="profile-session-heading">Session &amp; access</h2><p>Current browser authentication state.</p></div>
          </header>
          <div className="profile-card-content">
            <dl className="profile-details">
              <dt>Session status</dt><dd>Authenticated</dd>
              <dt>Authentication</dt><dd>Secure, cookie-based browser session</dd>
              <dt>Session expiry</dt><dd>Time-limited; enforced by the server</dd>
              <dt>CSRF protection</dt><dd>Enabled for state-changing requests</dd>
            </dl>
            <p className="profile-note">Session identifiers are held in an HttpOnly cookie. The interface does not display tokens or credential data.</p>
          </div>
        </section>

        <section className="panel profile-card" aria-labelledby="profile-password-heading">
          <header className="profile-card-heading">
            <span className="profile-info-icon"><ShieldCheck size={19} /></span>
            <div><h2 id="profile-password-heading">Password &amp; security</h2><p>Password changes are verified and saved by the backend.</p></div>
          </header>
          <div className="profile-card-content">
            <p className="profile-note">Changing your password requires the current password and signs out all active sessions after the API confirms the update.</p>
            <div className="profile-actions">
              <Link className="toolbar-button profile-password-link" to="/change-password"><KeyRound size={15} /> Change password</Link>
            </div>
          </div>
        </section>

        <section className="panel profile-card" aria-labelledby="profile-controls-heading">
          <header className="profile-card-heading">
            <span className="profile-info-icon"><Clock3 size={19} /></span>
            <div><h2 id="profile-controls-heading">Account controls</h2><p>End the current browser session.</p></div>
          </header>
          <div className="profile-card-content">
            <p className="profile-note">Signing out revokes this session through the authenticated API when available.</p>
            <div className="profile-actions">
              <button className="toolbar-button profile-danger-button" type="button" onClick={signOut} disabled={signingOut}>
                <LogOut size={15} /> {signingOut ? 'Signing out…' : 'Sign out'}
              </button>
            </div>
          </div>
        </section>
      </div>
    </main>
  )
}
