import { useState } from 'react'
import {
  Activity,
  ArrowRight,
  CheckCircle2,
  Eye,
  EyeOff,
  Fingerprint,
  LockKeyhole,
  Shield,
  ShieldCheck,
  UserPlus,
} from 'lucide-react'
import { Link, Navigate, useNavigate } from 'react-router-dom'
import { api } from '../api/client.js'
import { useAuth } from '../auth/AuthContext.jsx'
import './LoginPage.css'

export default function RegistrationPage() {
  const { status, user } = useAuth()
  const navigate = useNavigate()

  const [username, setUsername] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [password, setPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [passwordVisible, setPasswordVisible] = useState(false)
  const [confirmVisible, setConfirmVisible] = useState(false)

  const [validationError, setValidationError] = useState('')
  const [apiError, setApiError] = useState('')
  const [successMessage, setSuccessMessage] = useState('')
  const [busy, setBusy] = useState(false)

  if (status === 'loading') {
    return (
      <main className="auth-loading" role="status">
        <span className="loading-spinner" />
        Verifying secure session…
      </main>
    )
  }
  if (user) return <Navigate to="/dashboard" replace />

  const validate = () => {
    const trimmedUsername = username.trim()
    if (!trimmedUsername) {
      return 'Username is required.'
    }
    if (!/^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$/.test(trimmedUsername)) {
      return 'Username must be 3–64 characters long and start with an alphanumeric character (letters, numbers, ., -, _ allowed).'
    }
    if (password.length < 12) {
      return 'Password must be at least 12 characters long.'
    }
    if (password !== confirmPassword) {
      return 'Passwords do not match.'
    }
    return ''
  }

  const submit = async (event) => {
    event.preventDefault()
    setApiError('')
    setSuccessMessage('')

    const clientError = validate()
    if (clientError) {
      setValidationError(clientError)
      return
    }
    setValidationError('')
    setBusy(true)

    try {
      const payload = {
        username: username.trim(),
        password,
        display_name: displayName.trim() || undefined,
      }
      await api.post('/auth/register', payload)
      setSuccessMessage('Account registered successfully with viewer permissions. You may now sign in.')
      setPassword('')
      setConfirmPassword('')
    } catch (err) {
      setApiError(err.message || 'Registration failed. Please check your information and try again.')
    } finally {
      setBusy(false)
    }
  }

  return (
    <main className="login-page">
      <div className="login-grid" aria-hidden="true" />
      <section className="login-showcase" aria-label="System overview">
        <div className="login-brand">
          <span className="login-brand-mark"><Shield size={20} strokeWidth={2.2} /></span>
          <span>ARBR <i>SECURE OPERATIONS</i></span>
        </div>
        <div className="login-showcase-copy">
          <span className="login-eyebrow"><span className="live-indicator" /> DEFENSIVE OPERATIONS PLATFORM</span>
          <h1>Zero-Trust<br />Identity <em>Enforcement.</em></h1>
          <p>Public registrations are assigned the least-privileged viewer role by default. Elevated administrative roles require authorized operator provisioning.</p>
        </div>
        <div className="login-status-card">
          <div className="login-status-icon"><Activity size={17} /></div>
          <div><span>PROVISIONING POLICY</span><strong>Least-Privilege Role Default</strong></div>
          <ShieldCheck className="login-status-check" size={19} />
        </div>
        <div className="login-showcase-footer">
          <span>ROLE-BASED ACCESS CONTROL</span>
          <span>ARBR · UNIVERSITY MVP</span>
        </div>
      </section>

      <section className="login-panel-wrap">
        <div className="login-panel">
          <div className="login-panel-heading">
            <span className="login-mobile-mark"><Shield size={17} /></span>
            <span className="login-eyebrow">OPERATIONS REGISTRATION</span>
            <h2>Create Account</h2>
            <p>Register for access to view backup and recovery metrics.</p>
          </div>

          {validationError && (
            <div className="login-message login-message--error" role="alert">
              <Fingerprint size={16} />
              <span>{validationError}</span>
            </div>
          )}
          {apiError && (
            <div className="login-message login-message--error" role="alert">
              <Fingerprint size={16} />
              <span>{apiError}</span>
            </div>
          )}
          {successMessage && (
            <div className="login-message login-message--success" role="status">
              <CheckCircle2 size={16} />
              <div>
                <strong>Registration complete!</strong>
                <p style={{ margin: '4px 0 0' }}>{successMessage}</p>
              </div>
            </div>
          )}

          {successMessage ? (
            <div style={{ display: 'grid', gap: '12px', marginTop: '16px' }}>
              <button
                className="login-submit"
                type="button"
                onClick={() => navigate('/login')}
              >
                Proceed to Sign In <ArrowRight size={16} />
              </button>
            </div>
          ) : (
            <form className="login-form" onSubmit={submit}>
              <label htmlFor="reg-username">Username *</label>
              <input
                id="reg-username"
                name="username"
                type="text"
                autoComplete="username"
                autoCapitalize="none"
                spellCheck="false"
                maxLength={64}
                value={username}
                onChange={(event) => {
                  setUsername(event.target.value)
                  if (validationError) setValidationError('')
                }}
                placeholder="Choose a username (3–64 chars)"
                required
                disabled={busy}
              />

              <label htmlFor="reg-display-name">Display Name (Optional)</label>
              <input
                id="reg-display-name"
                name="displayName"
                type="text"
                autoComplete="name"
                maxLength={255}
                value={displayName}
                onChange={(event) => setDisplayName(event.target.value)}
                placeholder="Your full name or callsign"
                disabled={busy}
              />

              <label htmlFor="reg-password">Password (Minimum 12 characters) *</label>
              <div className="login-password-field">
                <input
                  id="reg-password"
                  name="password"
                  type={passwordVisible ? 'text' : 'password'}
                  autoComplete="new-password"
                  maxLength={1024}
                  value={password}
                  onChange={(event) => {
                    setPassword(event.target.value)
                    if (validationError) setValidationError('')
                  }}
                  placeholder="At least 12 characters"
                  required
                  disabled={busy}
                />
                <button
                  type="button"
                  className="password-visibility"
                  onClick={() => setPasswordVisible((v) => !v)}
                  aria-label={passwordVisible ? 'Hide password' : 'Show password'}
                >
                  {passwordVisible ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>

              <label htmlFor="reg-confirm-password">Confirm Password *</label>
              <div className="login-password-field">
                <input
                  id="reg-confirm-password"
                  name="confirmPassword"
                  type={confirmVisible ? 'text' : 'password'}
                  autoComplete="new-password"
                  maxLength={1024}
                  value={confirmPassword}
                  onChange={(event) => {
                    setConfirmPassword(event.target.value)
                    if (validationError) setValidationError('')
                  }}
                  placeholder="Re-enter password"
                  required
                  disabled={busy}
                />
                <button
                  type="button"
                  className="password-visibility"
                  onClick={() => setConfirmVisible((v) => !v)}
                  aria-label={confirmVisible ? 'Hide password' : 'Show password'}
                >
                  {confirmVisible ? <EyeOff size={16} /> : <Eye size={16} />}
                </button>
              </div>

              <button
                className="login-submit"
                type="submit"
                disabled={busy || !username.trim() || !password || !confirmPassword}
              >
                {busy ? (
                  <>
                    <span className="loading-spinner" /> Creating account…
                  </>
                ) : (
                  <>
                    Complete Registration <UserPlus size={16} />
                  </>
                )}
              </button>
            </form>
          )}

          <div className="login-register-prompt">
            <span>Already have an operations account?</span>
            <Link to="/login" className="login-register-link">
              Sign in <ArrowRight size={13} />
            </Link>
          </div>

          <div className="login-assurance">
            <LockKeyhole size={13} />
            <span>Passphrases hashed securely with PBKDF2-SHA256.</span>
          </div>
          <footer className="login-panel-footer">
            Public accounts receive least-privileged Viewer permissions.
          </footer>
        </div>
      </section>
    </main>
  )
}
