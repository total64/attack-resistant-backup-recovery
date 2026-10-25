import {
  Activity,
  AlertTriangle,
  ArrowDownRight,
  ArrowUpRight,
  Bell,
  ChartNoAxesCombined,
  ChevronRight,
  CircleHelp,
  Database,
  FileText,
  Fingerprint,
  LayoutDashboard,
  LogOut,
  LockKeyhole,
  Menu,
  RotateCcw,
  Search,
  Settings,
  Shield,
  ShieldCheck,
} from 'lucide-react'
import { Link, NavLink } from 'react-router-dom'
import { navigationItems } from '../data/dashboardData.js'

const iconMap = {
  dashboard: LayoutDashboard,
  activity: Activity,
  shield: Shield,
  chart: ChartNoAxesCombined,
  database: Database,
  rotate: RotateCcw,
  lock: LockKeyhole,
  file: FileText,
  settings: Settings,
  'shield-check': ShieldCheck,
  alert: AlertTriangle,
  fingerprint: Fingerprint,
}

export function Sidebar({ collapsed, onToggle, user, onLogout }) {
  const userLabel = user?.display_name || user?.user_id || 'Signed-in user'
  const initials = userLabel.split(/[\s_-]+/).filter(Boolean).slice(0, 2).map((part) => part[0]).join('').toUpperCase() || 'AR'
  const paths = {
    Dashboard: '/',
    'Security Events': '/security-events',
    'Threat Detection': '/threat-detection',
    'Risk Analysis': '/risk-analysis',
    Backups: '/backups',
    Recovery: '/recovery',
    'System Isolation': '/system-isolation',
    'Audit Logs': '/audit-logs',
    Settings: '/settings',
    'Admin Panel': '/admin',
    Profile: '/profile',
  }
  return (
    <aside className={`sidebar ${collapsed ? 'sidebar--collapsed' : ''}`}>
      <div className="brand">
        <div className="brand-mark"><Shield size={16} strokeWidth={2.3} /></div>
        <div className="brand-name">Attack-Resistant<br />Backup &amp; Recovery</div>
        <button className="icon-button sidebar-toggle" aria-label="Toggle sidebar" onClick={onToggle}>
          <Menu size={15} />
        </button>
      </div>
      <nav className="side-nav" aria-label="Main navigation">
        {navigationItems.filter(({ label }) => label !== 'Admin Panel' || user?.role === 'admin').map(({ label, icon }) => {
          const Icon = iconMap[icon]
          const path = paths[label]
          const contents = (active) => <><Icon size={14} strokeWidth={1.8} /><span>{label}</span>{active && <ChevronRight className="nav-chevron" size={12} />}</>
          return path
            ? <NavLink className={({ isActive }) => `nav-link ${isActive ? 'nav-link--active' : ''}`} key={label} to={path} end={path === '/'} aria-label={label} title={label}>{({ isActive }) => contents(isActive)}</NavLink>
            : <button className="nav-link" key={label} type="button" aria-label={label} title={label}>{contents(false)}</button>
        })}
      </nav>
      <div className="sidebar-user">
        <Link className="sidebar-profile-link" to={paths.Profile} aria-label="View profile" title="Profile">
          <div className="user-avatar" aria-hidden="true">{initials}</div>
          <div className="user-copy"><strong title={userLabel}>{userLabel}</strong><span>{user?.role || 'Authenticated'}</span></div>
        </Link>
        <button className="logout-button" type="button" onClick={() => { if (window.confirm('Sign out of this account on this browser?')) onLogout() }} aria-label="Sign out" title="Sign out"><LogOut size={14} /></button>
      </div>
      <Link className="sidebar-password-link" to="/profile">Profile &amp; password</Link>
    </aside>
  )
}

export function HeaderBar({ pageTitle = 'Threat Detection', searchValue = '', onSearch, notificationOpen, onToggleNotifications }) {
  return (
    <header className="topbar">
      <div className="breadcrumbs">
        <LayoutDashboard size={13} />
        <span>Dashboard</span>
        <ChevronRight size={12} />
        <Shield size={13} />
        <strong>{pageTitle}</strong>
      </div>
      <div className="topbar-tools">
        <label className="search-box">
          <Search size={13} />
          <input type="search" placeholder="Search threats, systems..." value={searchValue} onChange={(event) => onSearch?.(event.target.value)} />
          <kbd>/</kbd>
        </label>
        <button className={`icon-button notification-button ${notificationOpen ? 'is-active' : ''}`} aria-label="Notifications" onClick={onToggleNotifications}>
          <Bell size={15} />
          <span className="notification-dot" />
        </button>
        {notificationOpen && (
          <div className="notification-popover">
            <strong>Notifications</strong>
            <span>No notification feed is configured for this deployment.</span>
          </div>
        )}
      </div>
    </header>
  )
}

export function MetricCard({ metric }) {
  const Icon = iconMap[metric.icon]
  return (
    <article className="metric-card">
      <div className="metric-copy">
        <span className="eyebrow">{metric.label}</span>
        <strong className="metric-value">{metric.value}</strong>
        {metric.trend && (
          <span className={`metric-trend metric-trend--${metric.trendTone}`}>
            {metric.trendTone === 'good' ? <ArrowDownRight size={12} /> : <ArrowUpRight size={12} />}
            <b>{metric.trend}</b><span>vs last 24h</span>
          </span>
        )}
      </div>
      <div className={`metric-icon metric-icon--${metric.icon}`}><Icon size={18} strokeWidth={1.8} /></div>
    </article>
  )
}

export function EventsTable({ events, onViewAll }) {
  return (
    <section className="panel events-panel" aria-labelledby="events-heading">
      <div className="events-heading">
        <div><h2 id="events-heading">Recent Security Events</h2><p>Latest records returned by the backend</p></div>
        <button className="text-button" onClick={onViewAll}>View All Events <ChevronRight size={13} /></button>
      </div>
      <div className="table-scroll">
        <table>
          <thead><tr><th>Event ID</th><th>Occurred At</th><th>Source</th><th>Event Type</th><th>Severity</th><th>Processing Status</th></tr></thead>
          <tbody>{events.map((event) => (
            <tr key={event.id}>
              <td className="event-id">{event.id}</td><td className="event-time">{event.time}</td><td>{event.source}</td><td>{event.category}</td>
              <td><span className={`severity severity--${event.severity.toLowerCase()}`}>{event.severity}</span></td>
              <td className={`event-status event-status--${event.status.toLowerCase()}`}>{event.status}</td>
            </tr>
          ))}</tbody>
        </table>
        {events.length === 0 && <div className="empty-table"><CircleHelp size={16} /> No matching security events</div>}
      </div>
    </section>
  )
}
