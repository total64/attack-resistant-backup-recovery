import { useState } from 'react'
import { Activity, ArrowRight, Eye, EyeOff, Fingerprint, LockKeyhole, Shield, ShieldCheck } from 'lucide-react'
import { Link, Navigate, useNavigate } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext.jsx'
import './LoginPage.css'

export default function LoginPage() {
  const { login, sessionNotice, status, user } = useAuth()
  const navigate = useNavigate()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [passwordVisible, setPasswordVisible] = useState(false)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  if (status === 'loading') return <main className="auth-loading" role="status"><span className="loading-spinner" />Verifying secure session…</main>
  if (user) return <Navigate to="/dashboard" replace />

  const submit = async (event) => {
    event.preventDefault()
    setError('')
    setBusy(true)
    try {
      await login({ username: username.trim(), password })
      setPassword('')
      navigate('/dashboard', { replace: true })
    } catch (loginError) {
      setError(loginError.message || 'Unable to sign in. Check your connection and try again.')
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
          <h1>Resilience starts<br />with <em>visibility.</em></h1>
          <p>Securely monitor threats, validate recovery points, and coordinate response across your infrastructure.</p>
        </div>
        <div className="login-status-card">
          <div className="login-status-icon"><Activity size={17} /></div>
          <div><span>OPERATIONAL STATUS</span><strong>Protected workspace</strong></div>
          <ShieldCheck className="login-status-check" size={19} />
        </div>
        <div className="login-showcase-footer"><span>AUTHENTICATED ACCESS ONLY</span><span>ARBR · UNIVERSITY MVP</span></div>
      </section>

      <section className="login-panel-wrap">
        <div className="login-panel">
          <div className="login-panel-heading">
            <span className="login-mobile-mark"><Shield size={17} /></span>
            <span className="login-eyebrow">SECURE SIGN-IN</span>
            <h2>Welcome back</h2>
            <p>Sign in with your assigned operations account.</p>
          </div>

          {sessionNotice && <div className="login-message login-message--notice" role="status"><LockKeyhole size={16} /><span>{sessionNotice}</span></div>}
          {error && <div className="login-message login-message--error" role="alert"><Fingerprint size={16} /><span>{error}</span></div>}

          <form className="login-form" onSubmit={submit}>
            <label htmlFor="login-username">Username</label>
            <input
              id="login-username"
              name="username"
              type="text"
              autoComplete="username"
              autoCapitalize="none"
              spellCheck="false"
              maxLength={128}
              value={username}
              onChange={(event) => setUsername(event.target.value)}
              placeholder="Enter your username"
              required
              disabled={busy}
            />
            <label htmlFor="login-password">Password</label>
            <div className="login-password-field">
              <input
                id="login-password"
                name="password"
                type={passwordVisible ? 'text' : 'password'}
                autoComplete="current-password"
                maxLength={1024}
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="Enter your password"
                required
                disabled={busy}
              />
              <button type="button" className="password-visibility" onClick={() => setPasswordVisible((visible) => !visible)} aria-label={passwordVisible ? 'Hide password' : 'Show password'}>
                {passwordVisible ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
            <button className="login-submit" type="submit" disabled={busy || !username.trim() || !password}>
              {busy ? <><span className="loading-spinner" /> Verifying credentials…</> : <>Sign in securely <ArrowRight size={16} /></>}
            </button>
          </form>

          <div className="login-register-prompt">
            <span>Don't have an operations account?</span>
            <Link to="/register" className="login-register-link">
              Create an account <ArrowRight size={13} />
            </Link>
          </div>

          <div className="login-assurance"><LockKeyhole size={13} /><span>Protected with encrypted, time-limited session access.</span></div>
          <footer className="login-panel-footer">Access is monitored and governed by your assigned role.</footer>
        </div>
      </section>
    </main>
  )
}
