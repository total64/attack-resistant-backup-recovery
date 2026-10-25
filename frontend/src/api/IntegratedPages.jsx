import { useEffect, useMemo, useState } from 'react'
import { Activity, AlertTriangle, CalendarDays, Clock3, Database, Download, Fingerprint, ShieldCheck } from 'lucide-react'
import { CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { useNavigate } from 'react-router-dom'
import { api, queryString } from './client.js'
import { displayValue, formatBytes, formatTimestamp, statusClass } from './formatters.js'
import { ApiDetail, ApiState } from '../components/ApiState.jsx'
import { EventsTable, MetricCard } from '../components/DashboardParts.jsx'
import '../pages/SecurityEventsPage.css'
import '../pages/ThreatDetectionPage.css'
import '../pages/RiskAnalysisPage.css'
import '../pages/BackupsPage.css'
import '../pages/SystemIsolationPage.css'
import '../pages/RecoveryPage.css'
import '../pages/AuditLogsPage.css'
function useApiResource(path, refreshKey = 0) {
  const requestKey = `${refreshKey}:${path || ''}`
  const [state, setState] = useState({ requestKey: '', data: null, loading: false, error: null })
  useEffect(() => {
    if (!path) return undefined
    const controller = new AbortController()
    api.get(path, { signal: controller.signal })
      .then((data) => setState({ requestKey, data, loading: false, error: null }))
      .catch((error) => {
        if (error.name !== 'AbortError') setState({ requestKey, data: null, loading: false, error })
      })
    return () => controller.abort()
  }, [path, refreshKey, requestKey])
  if (!path) return { data: null, loading: false, error: null }
  return state.requestKey === requestKey ? state : { data: null, loading: true, error: null }
}
function PageHeading({ title, description, actions }) {
  return <section className="api-page-heading"><div><h1>{title}</h1><p>{description}</p></div>{actions && <div className="api-page-actions">{actions}</div>}</section>
}

function ApiTable({ headings, children, className = '' }) {
  return <div className={`api-table-scroll ${className}`}><table><thead><tr>{headings.map((heading) => <th key={heading}>{heading}</th>)}</tr></thead><tbody>{children}</tbody></table></div>
}

function ValueBadge({ value, className = 'event-status-badge' }) {
  return <span className={`${className} ${className}--${statusClass(value)}`}>{displayValue(value)}</span>
}

function ActionRequestApprovalPanel({ actionTypes, refresh, onChanged }) {
  const [actionError, setActionError] = useState(null)
  const { data, loading, error } = useApiResource('/action-requests?page=1&page_size=100', refresh)
  const requests = (data?.items || []).filter((item) => actionTypes.includes(item.action_type))
  const decide = async (request, approve) => {
    setActionError(null)
    try {
      if (request.approval_status === 'pending') {
        await api.post(`/action-requests/${encodeURIComponent(request.id)}/${approve ? 'approve' : 'reject'}`, approve ? {} : { reason: 'Rejected by an authorized approver through the frontend.' })
      } else if (approve && request.action_type === 'recover' && request.approval_status === 'approved') {
        await api.post('/recovery-jobs', {
          action_request_id: request.id,
          asset_id: request.asset_id,
          incident_id: request.incident_id,
          backup_id: request.backup_id,
          verification_id: request.verification_id,
          correlation_id: request.correlation_id,
        })
      }
      onChanged()
    } catch (requestError) { setActionError(requestError) }
  }
  return <section className="panel"><header className="panel-heading"><div><h2>Pending Action Requests</h2><p>Backend approval status; the backend enforces role authorization and requester/approver separation.</p></div></header>
    {actionError && <ApiState error={actionError} />}
    <ApiState loading={loading} error={error} empty={!loading && !error && requests.length === 0 ? 'No matching action requests.' : null}>{requests.length > 0 && <ApiTable headings={['Request ID', 'Action', 'Asset ID', 'Incident ID', 'Backup ID', 'Requested By', 'Approval', 'Execution', 'Operation']}>
      {requests.map((request) => <tr key={request.id}><td>{request.id}</td><td>{request.action_type}</td><td>{displayValue(request.asset_id)}</td><td>{displayValue(request.incident_id)}</td><td>{displayValue(request.backup_id)}</td><td>{displayValue(request.requested_by_id)}</td><td>{request.approval_status}</td><td>{request.execution_status}</td><td>{request.approval_status === 'pending' ? <><button className="toolbar-button" onClick={() => decide(request, true)}>Approve</button><button className="toolbar-button" onClick={() => decide(request, false)}>Reject</button></> : request.action_type === 'recover' && request.approval_status === 'approved' && request.execution_status === 'not_started' ? <button className="toolbar-button" onClick={() => decide(request, true)}>Create Recovery Job</button> : 'No frontend operation'}</td></tr>)}
    </ApiTable>}</ApiState>
  </section>
}

function Metric({ label, value, icon = 'activity', support }) {
  return <MetricCard metric={{ label, value: displayValue(value), icon, ...(support ? { trend: support, trendTone: 'good' } : {}) }} />
}

const eventPeriods = [
  { value: '1h', label: '1H' },
  { value: '6h', label: '6H' },
  { value: '24h', label: '24H' },
  { value: '7d', label: '7D' },
]

function EventActivityChart({ points, period }) {
  const formatBucket = (value) => {
    const date = new Date(value)
    return period === '7d'
      ? date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' })
      : date.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
  }
  return <ResponsiveContainer width="100%" height="100%"><LineChart data={points} margin={{ top: 10, right: 8, bottom: 0, left: -12 }}>
    <CartesianGrid vertical={false} stroke="#30343d" strokeDasharray="2 5" />
    <XAxis dataKey="bucket_start" axisLine={false} tickLine={false} tickFormatter={formatBucket} tick={{ fill: '#9298a4', fontSize: 9, fontFamily: 'ui-monospace, monospace' }} dy={8} />
    <YAxis allowDecimals={false} axisLine={false} tickLine={false} tick={{ fill: '#9298a4', fontSize: 9, fontFamily: 'ui-monospace, monospace' }} />
    <Tooltip labelFormatter={(value) => formatBucket(value)} contentStyle={{ border: '1px solid #384253', borderRadius: 2, color: '#dce3ec', background: '#131e33', fontSize: 9 }} />
    <Line type="monotone" dataKey="events" name="All events" stroke="#09c7d8" strokeWidth={1.7} dot={false} activeDot={{ r: 3, fill: '#09c7d8', stroke: '#101a34', strokeWidth: 2 }} />
    <Line type="monotone" dataKey="critical_events" name="Critical events" stroke="#f03c4b" strokeWidth={1.5} dot={false} activeDot={{ r: 3, fill: '#f03c4b', stroke: '#101a34', strokeWidth: 2 }} />
  </LineChart></ResponsiveContainer>
}

function exportSecurityEvents(events) {
  const columns = [
    ['Event ID', 'id'],
    ['Occurred At', 'occurred_at'],
    ['Source', 'source'],
    ['Event Type', 'event_type'],
    ['Severity', 'event_severity'],
    ['Processing Status', 'processing_status'],
    ['Summary', 'summary'],
  ]
  const quote = (value) => `"${String(value ?? '').replaceAll('"', '""')}"`
  const csv = [columns.map(([label]) => quote(label)), ...events.map((event) => columns.map(([, key]) => quote(event[key])))].map((row) => row.join(',')).join('\n')
  const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }))
  const link = document.createElement('a')
  link.href = url
  link.download = 'security-events.csv'
  link.click()
  window.setTimeout(() => URL.revokeObjectURL(url), 0)
}

export function DashboardPage({ globalSearch }) {
  const navigate = useNavigate()
  const { data, loading, error } = useApiResource('/dashboard/summary')
  const { data: activity, loading: activityLoading, error: activityError } = useApiResource('/security-events/summary?period=24h')
  const events = useMemo(() => (data?.recent_events || []).map((event) => ({
    id: event.id,
    time: formatTimestamp(event.occurred_at),
    source: event.source,
    category: event.event_type,
    severity: event.event_severity,
    status: event.processing_status,
  })).filter((event) => !globalSearch?.trim() || Object.values(event).some((value) => String(value).toLowerCase().includes(globalSearch.trim().toLowerCase()))), [data, globalSearch])
  const riskRows = Object.entries(data?.risk_distribution || {})
  return <main className="dashboard-main">
    <PageHeading title="Operational Overview" description="Backend-provided system summary and recent security events." />
    <ApiState loading={loading} error={error} empty={!data && !loading && !error ? 'Dashboard summary is not available.' : null}>
      {data && <>
        <section className="metric-grid" aria-label="System security metrics">
          <Metric label="Total Security Events" value={data.total_security_events} icon="activity" />
          <Metric label="Active Threats" value={data.active_threats} icon="alert" />
          <Metric label="High-Risk Incidents" value={data.high_risk_incidents} icon="fingerprint" />
          <Metric label="Critical-Risk Incidents" value={data.critical_risk_incidents} icon="database" />
        </section>
        <div className="dashboard-grid">
          <section className="panel chart-panel"><div className="chart-heading"><div><h2>Security Event Activity</h2><p>Event and critical-event counts from persisted records over the last 24 hours.</p></div><div className="chart-legend"><span><i className="legend-dot" />All events</span><span><i className="legend-dot legend-dot--threat" />Critical</span></div></div><div className="chart-area"><ApiState loading={activityLoading} error={activityError} empty={activity && activity.total_events === 0 ? 'No security events were recorded in the last 24 hours.' : null}>{activity && <EventActivityChart points={activity.activity} period="24h" />}</ApiState></div></section>
          <section className="panel action-panel"><div className="panel-heading"><div><h2>Current Risk Distribution</h2><p>Current incident counts returned by the API.</p></div></div><div className="api-distribution">{riskRows.map(([level, count]) => <div key={level}><span>{level}</span><strong>{count}</strong></div>)}</div></section>
        </div>
        <EventsTable events={events} onViewAll={() => navigate('/security-events')} />
      </>}
    </ApiState>
    <footer className="status-footer"><span>Metrics and activity are calculated from persisted backend records.</span></footer>
  </main>
}

function SecurityEventDrawer({ eventId, onClose }) {
  const { data, loading, error } = useApiResource(eventId ? `/security-events/${encodeURIComponent(eventId)}` : null)
  return <div className="event-drawer-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose() }}><aside className="event-details-drawer" role="dialog" aria-modal="true" aria-labelledby="security-event-detail-title">
    <header className="event-drawer-header"><div><span className="eyebrow">Backend security-event record</span><h2 id="security-event-detail-title">Event Details</h2></div><button className="icon-button" onClick={onClose} aria-label="Close details">×</button></header>
    <ApiState loading={loading} error={error} empty={!data && !loading && !error ? 'Event details are unavailable.' : null}>
      {data && <><section className="detail-section"><dl className="event-detail-grid">
        <ApiDetail label="Event ID" value={data.id} /><ApiDetail label="Source" value={data.source} /><ApiDetail label="Source event ID" value={data.source_event_id} /><ApiDetail label="Asset ID" value={data.asset_id} /><ApiDetail label="Incident ID" value={data.incident_id} /><ApiDetail label="Occurred at" value={formatTimestamp(data.occurred_at)} /><ApiDetail label="Received at" value={formatTimestamp(data.received_at)} /><ApiDetail label="Event type" value={data.event_type} /><ApiDetail label="Severity" value={data.event_severity} /><ApiDetail label="Processing status" value={data.processing_status} /><ApiDetail label="Source component" value={data.source_component} /><ApiDetail label="Correlation ID" value={data.correlation_id} /><ApiDetail label="Summary" value={data.summary} /><ApiDetail label="Indicators" value={data.indicators} /><ApiDetail label="Evidence" value={data.evidence} />
      </dl></section><p className="api-note">Security-event processing is distinct from incident lifecycle; this record has no resolve action.</p></>}
    </ApiState>
  </aside></div>
}

export function SecurityEventsPage({ globalSearch, onGlobalSearchChange }) {
  const [filters, setFilters] = useState({ event_severity: '', event_type: '', processing_status: '', source: '', asset_id: '', incident_id: '', from: '', to: '' })
  const [period, setPeriod] = useState('24h')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(25)
  const [selectedId, setSelectedId] = useState(null)
  const [refresh, setRefresh] = useState(0)
  const path = `/security-events${queryString({ page, page_size: pageSize, ...filters })}`
  const { data, loading, error } = useApiResource(path, refresh)
  const { data: summary, loading: summaryLoading, error: summaryError } = useApiResource(`/security-events/summary${queryString({ period, ...filters })}`, refresh)
  const items = data?.items || []
  const visible = items.filter((event) => !globalSearch?.trim() || [event.id, event.source, event.source_event_id, event.asset_id, event.incident_id, event.event_type, event.summary, event.correlation_id].some((value) => String(value || '').toLowerCase().includes(globalSearch.trim().toLowerCase())))
  const updateFilter = (name, value) => { setFilters((current) => ({ ...current, [name]: value })); setPage(1) }
  const selectPeriod = (value) => {
    const durationMs = { '1h': 60 * 60 * 1000, '6h': 6 * 60 * 60 * 1000, '24h': 24 * 60 * 60 * 1000, '7d': 7 * 24 * 60 * 60 * 1000 }[value]
    const end = new Date()
    const start = new Date(end.getTime() - durationMs)
    setPeriod(value)
    setFilters((current) => ({ ...current, from: start.toISOString(), to: end.toISOString() }))
    setPage(1)
  }
  return <main className="security-events-main">
    <PageHeading title="Security Events" description="Normalized security telemetry and database-derived activity." actions={<div className="event-page-toolbar"><div className="period-selector" aria-label="Activity period">{eventPeriods.map(({ value, label }) => <button key={value} type="button" className={period === value ? 'selected' : ''} aria-pressed={period === value} onClick={() => selectPeriod(value)}>{label}</button>)}</div><button className="toolbar-button" type="button" onClick={() => exportSecurityEvents(visible)} disabled={!visible.length}><Download size={13} />Export page</button></div>} />
    <ApiState loading={summaryLoading} error={summaryError} onRetry={() => setRefresh((value) => value + 1)}>
      {summary && <section className="event-summary-grid" aria-label="Security event summary">
        {[
          ['Total Events', summary.total_events, `${period.toUpperCase()} · all matching API filters`, Activity, 'cyan'],
          ['Critical Events', summary.critical_events, 'Critical severity in selected period', AlertTriangle, 'red'],
          ['Pending Processing', summary.pending_processing_events, 'Received or normalized records', Clock3, 'amber'],
          ['Events Today', summary.events_today, 'UTC calendar day', CalendarDays, 'green'],
          ['Monitored Assets', summary.monitored_assets, 'Assets with a reported monitoring state', Database, 'cyan'],
        ].map(([label, value, support, Icon, tone]) => <article className={`event-summary-card event-summary-card--${tone}`} key={label}><div className="event-summary-copy"><span className="eyebrow">{label}</span><strong>{value.toLocaleString()}</strong><span className="event-summary-support">{support}</span></div><div className="event-summary-icon"><Icon size={17} strokeWidth={1.8} /></div></article>)}
      </section>}
    </ApiState>
    <section className="panel event-activity-panel"><header className="event-activity-heading"><div><h2>Event Activity</h2><p>Persisted event counts grouped across the selected period.</p></div><div className="chart-legend"><span><i className="legend-dot" />All Events</span><span><i className="legend-dot legend-dot--threat" />Critical</span></div></header><div className="event-activity-chart"><ApiState loading={summaryLoading} error={summaryError} onRetry={() => setRefresh((value) => value + 1)} empty={summary && summary.total_events === 0 ? 'No security events were recorded in the selected period.' : null}>{summary && <EventActivityChart points={summary.activity} period={period} />}</ApiState></div></section>
    <section className="panel security-log-panel"><header className="security-log-heading"><div><h2>Security Event Log</h2><p>Fields and processing states returned by the API.</p></div></header>
      <div className="event-filter-bar"><label className="event-search"><span>Search</span><input type="search" value={globalSearch || ''} onChange={(event) => { onGlobalSearchChange?.(event.target.value); setPage(1) }} placeholder="Search returned fields" /></label>
        <div className="event-select-filters">
          <label className="event-select"><span className="sr-only">Severity</span><select value={filters.event_severity} onChange={(event) => updateFilter('event_severity', event.target.value)}><option value="">All severities</option>{['info', 'low', 'medium', 'high', 'critical'].map((value) => <option key={value}>{value}</option>)}</select></label>
          <label className="event-select"><span className="sr-only">Processing status</span><select value={filters.processing_status} onChange={(event) => updateFilter('processing_status', event.target.value)}><option value="">All processing statuses</option>{['received', 'normalized', 'processed', 'rejected'].map((value) => <option key={value}>{value}</option>)}</select></label>
          <label className="event-select"><span className="sr-only">Event type</span><input value={filters.event_type} onChange={(event) => updateFilter('event_type', event.target.value)} placeholder="Exact event type" /></label>
          <label className="event-select"><span className="sr-only">Source</span><input value={filters.source} onChange={(event) => updateFilter('source', event.target.value)} placeholder="Exact source" /></label>
          <label className="event-select"><span className="sr-only">Asset ID</span><input value={filters.asset_id} onChange={(event) => updateFilter('asset_id', event.target.value)} placeholder="Asset ID" /></label>
          <label className="event-select"><span className="sr-only">Incident ID</span><input value={filters.incident_id} onChange={(event) => updateFilter('incident_id', event.target.value)} placeholder="Incident ID" /></label>
          <label className="event-select"><span className="sr-only">From</span><input type="datetime-local" value={filters.from ? new Date(filters.from).toISOString().slice(0, 16) : ''} onChange={(event) => updateFilter('from', event.target.value ? new Date(event.target.value).toISOString() : '')} /></label>
          <label className="event-select"><span className="sr-only">To</span><input type="datetime-local" value={filters.to ? new Date(filters.to).toISOString().slice(0, 16) : ''} onChange={(event) => updateFilter('to', event.target.value ? new Date(event.target.value).toISOString() : '')} /></label>
        </div>
        <button className="event-clear-button" onClick={() => { setFilters({ event_severity: '', event_type: '', processing_status: '', source: '', asset_id: '', incident_id: '', from: '', to: '' }); setPeriod('24h'); onGlobalSearchChange?.(''); setPage(1) }}>Clear filters</button>
      </div>
      <ApiState loading={loading} error={error} onRetry={() => setRefresh((value) => value + 1)} empty={!loading && !error && visible.length === 0 ? 'No security events match the current search and filters.' : null}>
        {visible.length > 0 && <><ApiTable headings={['Event ID', 'Occurred At', 'Source', 'Event Type', 'Severity', 'Processing Status', 'Correlation ID', 'Details']} className="security-event-table-scroll">{visible.map((event) => <tr key={event.id}><td className="event-id">{event.id}</td><td>{formatTimestamp(event.occurred_at)}</td><td>{event.source}</td><td>{event.event_type}</td><td><ValueBadge value={event.event_severity} className="severity" /></td><td>{event.processing_status}</td><td>{event.correlation_id}</td><td><button className="row-action" onClick={() => setSelectedId(event.id)}>View</button></td></tr>)}</ApiTable>
          <div className="event-pagination"><span>Page {data.page} · {data.total} matching records</span><label>Rows per page <select value={pageSize} onChange={(event) => { setPageSize(Number(event.target.value)); setPage(1) }}>{[10, 25, 50, 100].map((size) => <option key={size}>{size}</option>)}</select></label><button disabled={page <= 1} onClick={() => setPage(page - 1)}>Previous</button><button disabled={page * pageSize >= data.total} onClick={() => setPage(page + 1)}>Next</button></div>
        </>}
      </ApiState>
    </section>
    {selectedId && <SecurityEventDrawer eventId={selectedId} onClose={() => setSelectedId(null)} />}
  </main>
}

function ThreatDrawer({ id, refreshKey, onClose, onTransition, transitionError, busy }) {
  const { data, loading, error } = useApiResource(id ? `/threats/${encodeURIComponent(id)}` : null, refreshKey)
  const transitions = data ? [
    ...(data.lifecycle_status === 'new' ? [['triage', 'Triage']] : []),
    ...(data.lifecycle_status === 'triaged' ? [['investigate', 'Investigate']] : []),
    ...(['new', 'triaged', 'investigating'].includes(data.lifecycle_status) ? [['false-positive', 'Mark false positive']] : []),
    ...(data.lifecycle_status === 'recovered' ? [['resolve', 'Resolve recovered incident']] : []),
  ] : []
  return <div className="event-drawer-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose() }}><aside className="event-details-drawer" role="dialog" aria-modal="true" aria-labelledby="threat-detail-title"><header className="event-drawer-header"><div><span className="eyebrow">Threat incident</span><h2 id="threat-detail-title">Threat Details</h2></div><button className="icon-button" onClick={onClose} aria-label="Close details">×</button></header>
    <ApiState loading={loading} error={error} empty={!data && !loading && !error ? 'Threat details are unavailable.' : null}>{data && <><section className="detail-section"><dl className="event-detail-grid"><ApiDetail label="Incident ID" value={data.id} /><ApiDetail label="Title" value={data.title} /><ApiDetail label="Threat type" value={data.threat_type} /><ApiDetail label="Primary asset" value={data.asset_id} /><ApiDetail label="Affected assets" value={data.affected_asset_ids} /><ApiDetail label="Detection source" value={data.detection_source} /><ApiDetail label="Detected at" value={formatTimestamp(data.detected_at)} /><ApiDetail label="Lifecycle status" value={data.lifecycle_status} /><ApiDetail label="Current risk assessment ID" value={data.current_risk_assessment_id} /><ApiDetail label="Correlation ID" value={data.correlation_id} /><ApiDetail label="Resolved at" value={formatTimestamp(data.resolved_at)} /><ApiDetail label="Description" value={data.description} /><ApiDetail label="Indicators" value={data.indicators} /></dl></section>
      <div className="event-drawer-actions">{transitions.map(([operation, label]) => <button className="toolbar-button" key={operation} disabled={busy} onClick={() => onTransition(data.id, operation)}>{label}</button>)}</div>
      {transitionError && <ApiState error={transitionError} />}
      <p className="api-note">Resolution is available only when backend lifecycle status is recovered. Containment is confirmed through the isolation workflow.</p>
    </>}</ApiState>
  </aside></div>
}

export function ThreatDetectionPage({ globalSearch, onGlobalSearchChange }) {
  const [filters, setFilters] = useState({ lifecycle_status: '', threat_type: '' })
  const [page, setPage] = useState(1)
  const [selectedId, setSelectedId] = useState(null)
  const [refresh, setRefresh] = useState(0)
  const { data: summary, loading: summaryLoading, error: summaryError } = useApiResource('/threats/summary', refresh)
  const [transitionError, setTransitionError] = useState(null)
  const [busy, setBusy] = useState(false)
  const path = `/threats${queryString({ page, page_size: 25, ...filters })}`
  const { data, loading, error } = useApiResource(path, refresh)
  const items = (data?.items || []).filter((item) => !globalSearch?.trim() || [item.id, item.title, item.threat_type, item.asset_id, item.description, item.detection_source, item.lifecycle_status].some((value) => String(value || '').toLowerCase().includes(globalSearch.trim().toLowerCase())))
  const transition = async (id, operation) => {
    setBusy(true); setTransitionError(null)
    try {
      await api.post(`/threats/${encodeURIComponent(id)}/${operation}`, {})
      setRefresh((value) => value + 1)
    } catch (requestError) { setTransitionError(requestError) } finally { setBusy(false) }
  }
  return <main className="threat-detection-main"><PageHeading title="Threat Detection" description="Threat incidents, current risk, and lifecycle counts from persisted backend records." />
    <ApiState loading={summaryLoading} error={summaryError} onRetry={() => setRefresh((value) => value + 1)}>{summary && <section className="threat-summary-grid" aria-label="Threat summary">
      {[
        ['Total Incidents', summary.total_incidents, 'All persisted incidents', AlertTriangle, 'cyan'],
        ['Active Threats', summary.active_threats, 'Not in a terminal lifecycle state', Activity, 'amber'],
        ['Critical-Risk Incidents', summary.critical_risk_incidents, 'Current risk assessment is critical', Fingerprint, 'red'],
        ['Resolved Incidents', summary.resolved_incidents, 'Resolved, false positive, or closed', ShieldCheck, 'green'],
      ].map(([label, value, support, Icon, tone]) => <article className={`threat-summary-card threat-summary-card--${tone}`} key={label}><div className="threat-summary-copy"><span className="eyebrow">{label}</span><strong>{value.toLocaleString()}</strong><span className="threat-summary-support">{support}</span></div><div className="threat-summary-icon"><Icon size={17} strokeWidth={1.8} /></div></article>)}
    </section>}</ApiState>
    <section className="panel threat-log-panel"><header className="threat-log-heading"><div><h2>Threat Incidents</h2><p>Lifecycle status uses the backend's incident state machine.</p></div></header>
      <div className="threat-filter-bar"><label className="event-search"><input type="search" value={globalSearch || ''} onChange={(event) => onGlobalSearchChange?.(event.target.value)} placeholder="Search returned fields" /></label><div className="event-select-filters"><label className="event-select"><span className="sr-only">Lifecycle status</span><select value={filters.lifecycle_status} onChange={(event) => { setFilters((v) => ({ ...v, lifecycle_status: event.target.value })); setPage(1) }}><option value="">All lifecycle statuses</option>{['new', 'triaged', 'investigating', 'contained', 'recovery_in_progress', 'recovered', 'resolved', 'false_positive', 'closed'].map((value) => <option key={value}>{value}</option>)}</select></label><label className="event-select"><span className="sr-only">Threat type</span><input value={filters.threat_type} onChange={(event) => { setFilters((v) => ({ ...v, threat_type: event.target.value })); setPage(1) }} placeholder="Exact threat type" /></label></div></div>
      <ApiState loading={loading} error={error} onRetry={() => setRefresh((value) => value + 1)} empty={!loading && !error && items.length === 0 ? 'No threat incidents match the current filters.' : null}>{items.length > 0 && <><ApiTable headings={['Incident', 'Threat Type', 'Asset', 'Affected Asset IDs', 'Detected At', 'Lifecycle Status', 'Details']} className="threat-table-scroll">{items.map((item) => <tr key={item.id}><td><strong>{item.title}</strong><small className="threat-id">{item.id}</small></td><td>{item.threat_type}</td><td>{item.asset_id}</td><td>{item.affected_asset_ids.join(', ')}</td><td>{formatTimestamp(item.detected_at)}</td><td>{item.lifecycle_status}</td><td><button className="row-action" onClick={() => { setSelectedId(item.id); setTransitionError(null) }}>View</button></td></tr>)}</ApiTable><div className="event-pagination"><span>Page {data.page} · {data.total} incidents</span><button disabled={page <= 1} onClick={() => setPage(page - 1)}>Previous</button><button disabled={page * data.page_size >= data.total} onClick={() => setPage(page + 1)}>Next</button></div></>}</ApiState>
    </section>
    {selectedId && <ThreatDrawer id={selectedId} refreshKey={refresh} onClose={() => setSelectedId(null)} onTransition={transition} transitionError={transitionError} busy={busy} />}
  </main>
}

function riskLevelTone(level) {
  const value = String(level || '').toLowerCase()
  if (value === 'critical' || value === 'high') return 'red'
  if (value === 'medium') return 'amber'
  if (value === 'low' || value === 'info') return 'green'
  return 'cyan'
}

export function RiskAnalysisPage({ globalSearch = '', onGlobalSearchChange }) {
  const [refresh, setRefresh] = useState(0)
  const { data, loading, error } = useApiResource('/risk-assessments?page=1&page_size=100', refresh)
  const rows = data?.items || []
  const visible = rows.filter((row) => !globalSearch.trim() || [row.id, row.incident_id, row.asset_id, row.score, row.risk_level, row.status, row.factors, row.correlation_id].some((value) => String(value || '').toLowerCase().includes(globalSearch.trim().toLowerCase())))
  const latest = rows[0]
  const history = [...rows].reverse().map((row) => ({ time: formatTimestamp(row.assessed_at), score: row.score }))
  const assets = [...new Set(rows.map((row) => row.asset_id))]
  const retry = () => setRefresh((value) => value + 1)
  return <main className="risk-analysis-main"><PageHeading title="Risk Analysis" description="Risk assessments and contributing factors as actually returned by the API." />
    <ApiState loading={loading} error={error} onRetry={retry}>
      {data && <>
        <section className="risk-summary-grid" aria-label="Risk assessment summary">
          {[
            ['Latest Risk Score', latest ? `${latest.score} / 100` : 'No records', latest?.risk_level || 'No assessments returned', AlertTriangle, riskLevelTone(latest?.risk_level)],
            ['Assessments', data.total ?? '—', 'Total returned by API', Activity, 'cyan'],
            ['Latest Assessment', latest ? formatTimestamp(latest.assessed_at) : 'No records', 'Backend assessment timestamp', CalendarDays, 'amber'],
            ['Assets Represented', assets.length || '—', 'In the loaded assessment page only', Database, 'green'],
          ].map(([label, value, support, Icon, tone]) => <article className={`risk-summary-card risk-summary-card--${tone}`} key={label}><div className="risk-summary-copy"><span className="eyebrow">{label}</span><strong>{value}</strong><span className="risk-summary-support">{support}</span></div><div className="risk-summary-icon"><Icon size={17} strokeWidth={1.8} /></div></article>)}
        </section>
        <div className="risk-overview-grid">
          <section className="panel risk-history-panel"><header className="risk-section-heading"><div><h2>Risk Assessment History</h2><p>Scores from the loaded API page, ordered by assessment time.</p></div><div className="chart-legend"><span><i className="legend-dot" />Score</span></div></header>{history.length > 1 ? <div className="risk-history-chart"><ResponsiveContainer width="100%" height="100%"><LineChart data={history} margin={{ top: 10, right: 8, bottom: 0, left: -12 }}><CartesianGrid vertical={false} stroke="#30343d" strokeDasharray="2 5" /><XAxis dataKey="time" axisLine={false} tickLine={false} tick={{ fill: '#9298a4', fontSize: 9, fontFamily: 'ui-monospace, monospace' }} dy={8} /><YAxis domain={[0, 100]} allowDecimals={false} axisLine={false} tickLine={false} tick={{ fill: '#9298a4', fontSize: 9, fontFamily: 'ui-monospace, monospace' }} /><Tooltip contentStyle={{ border: '1px solid #384253', borderRadius: 2, color: '#dce3ec', background: '#131e33', fontSize: 9 }} /><Line type="monotone" dataKey="score" name="Score" stroke="#09c7d8" strokeWidth={1.7} dot={false} activeDot={{ r: 3, fill: '#09c7d8', stroke: '#101a34', strokeWidth: 2 }} /></LineChart></ResponsiveContainer></div> : <div className="api-unavailable">At least two assessments are required for a history chart.</div>}</section>
          <section className="panel risk-score-panel"><header className="risk-section-heading"><div><h2>Latest Risk Assessment</h2><p>One backend assessment; no aggregate score is inferred.</p></div>{latest && <span className={`severity severity--${statusClass(latest.risk_level)}`}>{latest.risk_level}</span>}</header><div className="api-risk-latest">{latest ? <><strong>{latest.score}</strong><span>/ 100 · assessment {latest.id}</span><dl className="event-detail-grid"><ApiDetail label="Incident ID" value={latest.incident_id} /><ApiDetail label="Asset ID" value={latest.asset_id} /><ApiDetail label="Confidence" value={latest.confidence} /><ApiDetail label="Status" value={latest.status} /><ApiDetail label="Model version" value={latest.model_version} /><ApiDetail label="Policy version" value={latest.policy_version} /></dl></> : <div className="api-unavailable">No assessment records returned.</div>}</div></section>
        </div>
        <section className="panel risk-table-panel"><header className="risk-section-heading"><div><h2>Risk Assessments</h2><p>Factors are displayed in the form supplied by the backend.</p></div></header>
          <div className="risk-filter-bar"><label className="event-search"><span className="sr-only">Search</span><input type="search" value={globalSearch || ''} onChange={(event) => onGlobalSearchChange?.(event.target.value)} placeholder="Search returned fields" /></label></div>
          <ApiState empty={visible.length === 0 ? 'No risk assessments match the current search.' : null}>{visible.length > 0 && <ApiTable headings={['Assessment ID', 'Incident ID', 'Asset ID', 'Score', 'Risk Level', 'Status', 'Assessed At', 'Factors', 'Correlation ID']} className="risk-table-scroll">{visible.map((row) => <tr key={row.id}><td className="event-id">{row.id}</td><td>{row.incident_id}</td><td>{row.asset_id}</td><td>{row.score}</td><td><ValueBadge value={row.risk_level} className="severity" /></td><td>{row.status}</td><td>{formatTimestamp(row.assessed_at)}</td><td>{row.factors.length ? displayValue(row.factors) : 'None provided'}</td><td>{row.correlation_id}</td></tr>)}</ApiTable>}</ApiState>
        </section>
        <section className="panel recommended-response"><header className="risk-section-heading"><div><h2>Recommended Response</h2><p>Recommendations are not part of the RiskAssessment response schema.</p></div></header></section>
      </>}
    </ApiState>
    <footer className="status-footer"><span>Risk scores and factors are taken from persisted backend assessments.</span></footer>
  </main>
}

function BackupDetails({ backupId, onClose }) {
  const [refresh, setRefresh] = useState(0)
  const requestKey = `${backupId}:${refresh}`
  const [state, setState] = useState({ requestKey: '', data: null, loading: false, error: null })
  useEffect(() => {
    if (!backupId) return undefined
    const controller = new AbortController()
    Promise.all([
      api.get(`/backups/${encodeURIComponent(backupId)}`, { signal: controller.signal }),
      api.get(`/backups/${encodeURIComponent(backupId)}/recovery-eligibility`, { signal: controller.signal }),
    ]).then(async ([backup, eligibility]) => {
      const points = await api.get(`/assets/${encodeURIComponent(backup.asset_id)}/recovery-points?page=1&page_size=20`, { signal: controller.signal })
      setState({ requestKey, data: { backup, eligibility, points }, loading: false, error: null })
    }).catch((error) => { if (error.name !== 'AbortError') setState({ requestKey, data: null, loading: false, error }) })
    return () => controller.abort()
  }, [backupId, refresh, requestKey])
  const currentState = state.requestKey === requestKey ? state : { data: null, loading: true, error: null }
  const data = currentState.data
  return <div className="event-drawer-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose() }}><aside className="event-details-drawer" role="dialog" aria-modal="true" aria-labelledby="backup-details-title"><header className="event-drawer-header"><div><span className="eyebrow">Backend recovery point</span><h2 id="backup-details-title">Backup Details</h2></div><button className="icon-button" onClick={onClose} aria-label="Close details">×</button></header>
    <ApiState loading={currentState.loading} error={currentState.error} onRetry={() => setRefresh((value) => value + 1)}>{data && <><section className="detail-section"><dl className="event-detail-grid"><ApiDetail label="Backup ID" value={data.backup.backup_id} /><ApiDetail label="Asset ID" value={data.backup.asset_id} /><ApiDetail label="External backup ID" value={data.backup.external_backup_id} /><ApiDetail label="Created by component" value={data.backup.created_by_component} /><ApiDetail label="Created at" value={formatTimestamp(data.backup.created_at)} /><ApiDetail label="Backup type" value={data.backup.backup_type} /><ApiDetail label="Size" value={formatBytes(data.backup.size_bytes)} /><ApiDetail label="Lifecycle status" value={data.backup.lifecycle_status} /><ApiDetail label="Protection status" value={data.backup.protection_status} /><ApiDetail label="Encryption status" value={data.backup.encryption_status} /><ApiDetail label="Verified" value={data.backup.verified} /><ApiDetail label="Recovery eligible" value={data.eligibility.eligible} /><ApiDetail label="Eligibility reasons" value={data.eligibility.reasons} /><ApiDetail label="Correlation ID" value={data.backup.correlation_id} /></dl></section>
      <section className="detail-section"><h3>Recovery points for asset</h3><p>{data.points.total} points returned; eligibility is backend-confirmed per record.</p>{data.points.items.map((point) => <p key={point.backup_id}>{point.backup_id} · eligible: {String(point.recovery_eligible)} · {point.eligibility_reasons.join(', ') || 'no reasons returned'}</p>)}</section></>}</ApiState>
  </aside></div>
}

export function BackupsPage({ globalSearch = '' }) {
  const [refresh, setRefresh] = useState(0)
  const [selectedId, setSelectedId] = useState(null)
  const [actionState, setActionState] = useState({ busy: false, error: null, message: '' })
  const { data, loading, error } = useApiResource('/backups?page=1&page_size=100', refresh)
  const items = data?.items || []
  const filtered = items.filter((item) => !globalSearch.trim() || [item.backup_id, item.asset_id, item.external_backup_id, item.backup_type, item.lifecycle_status, item.protection_status, item.eligibility_reasons].some((value) => String(value || '').toLowerCase().includes(globalSearch.trim().toLowerCase())))
  const requestVerification = async (backupId) => {
    setActionState({ busy: true, error: null, message: '' })
    try {
      const result = await api.post(`/backups/${encodeURIComponent(backupId)}/integrity-verifications`, {})
      setActionState({ busy: false, error: null, message: `Verification request recorded with backend status: ${result.result_status}.` })
      setRefresh((value) => value + 1)
    } catch (requestError) { setActionState({ busy: false, error: requestError, message: '' }) }
  }
  const count = (predicate) => items.filter(predicate).length
  return <main className="backups-main"><PageHeading title="Backups" description="Backend backup metadata, verification state, and recovery eligibility." actions={<button className="toolbar-button" onClick={() => setRefresh((value) => value + 1)}>Refresh</button>} />
    <section className="backup-summary-grid"><article className="backup-summary-card"><div className="backup-summary-copy"><span className="eyebrow">Total Backups</span><strong>{data?.total ?? '—'}</strong><span>Backend total</span></div></article><article className="backup-summary-card"><div className="backup-summary-copy"><span className="eyebrow">Verified In Loaded Page</span><strong>{count((item) => item.verified)}</strong><span>Backend eligibility assessment</span></div></article><article className="backup-summary-card"><div className="backup-summary-copy"><span className="eyebrow">Recovery Eligible In Loaded Page</span><strong>{count((item) => item.recovery_eligible)}</strong><span>Backend-confirmed</span></div></article><article className="backup-summary-card"><div className="backup-summary-copy"><span className="eyebrow">Not Recovery Eligible · Loaded Page</span><strong>{count((item) => !item.recovery_eligible)}</strong><span>Backend eligibility assessment</span></div></article></section>
    <ActionRequestApprovalPanel actionTypes={['protect_backup']} refresh={refresh} onChanged={() => setRefresh((value) => value + 1)} />
    <section className="panel backup-repository-panel"><header className="backup-section-heading"><div><h2>Backup Repository</h2><p>Actual backend lifecycle, protection, verification, and eligibility fields.</p></div></header>{actionState.message && <p className="api-note" role="status">{actionState.message}</p>}{actionState.error && <ApiState error={actionState.error} />}
      <ApiState loading={loading} error={error} onRetry={() => setRefresh((value) => value + 1)} empty={!loading && !error && filtered.length === 0 ? 'No backups match the current search.' : null}>{filtered.length > 0 && <ApiTable headings={['Backup ID', 'Asset ID', 'Type', 'Size', 'Created', 'Lifecycle', 'Protection', 'Verified', 'Recovery Eligible', 'Actions']} className="backup-table-scroll">{filtered.map((item) => <tr key={item.backup_id}><td className="backup-id">{item.backup_id}</td><td>{item.asset_id}</td><td>{displayValue(item.backup_type)}</td><td>{formatBytes(item.size_bytes)}</td><td>{formatTimestamp(item.created_at)}</td><td>{item.lifecycle_status}</td><td>{item.protection_status}</td><td>{String(item.verified)}</td><td>{String(item.recovery_eligible)}{item.eligibility_reasons.length > 0 && <small>{item.eligibility_reasons.join('; ')}</small>}</td><td><button className="row-action" onClick={() => setSelectedId(item.backup_id)}>Details</button> <button className="backup-verify-row" disabled={actionState.busy} onClick={() => requestVerification(item.backup_id)}>Request verification</button></td></tr>)}</ApiTable>}</ApiState>
      <footer className="backup-table-footer">Showing {items.length} loaded of {data?.total ?? 0} backups. Verification is requested through the backend; only a component report can complete it.</footer>
    </section>
    {selectedId && <BackupDetails backupId={selectedId} onClose={() => setSelectedId(null)} />}
  </main>
}

function IsolationAssetDetails({ asset, onClose }) {
  const { data, loading, error } = useApiResource(asset ? `/assets/${encodeURIComponent(asset.id)}/isolation` : null)
  return <div className="event-drawer-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose() }}><aside className="event-details-drawer" role="dialog" aria-modal="true" aria-labelledby="isolation-details-title"><header className="event-drawer-header"><div><span className="eyebrow">Backend-derived asset state</span><h2 id="isolation-details-title">Isolation Details</h2></div><button className="icon-button" onClick={onClose} aria-label="Close details">×</button></header><section className="detail-section"><dl className="event-detail-grid"><ApiDetail label="Asset ID" value={asset.id} /><ApiDetail label="Hostname" value={asset.hostname} /><ApiDetail label="Asset type" value={asset.asset_type} /><ApiDetail label="Environment" value={asset.environment} /><ApiDetail label="Network segment" value={asset.network_segment} /></dl></section><ApiState loading={loading} error={error}>{data && <section className="detail-section"><h3>Confirmed isolation state</h3><dl className="event-detail-grid"><ApiDetail label="Isolation state" value={data.isolation_state} /><ApiDetail label="Active action ID" value={data.active_isolation_action_id} /><ApiDetail label="Execution status" value={data.execution_status} /><ApiDetail label="Network state" value={data.network_state} /><ApiDetail label="Isolation mode" value={data.isolation_mode} /><ApiDetail label="Requested at" value={formatTimestamp(data.requested_at)} /><ApiDetail label="Acknowledged at" value={formatTimestamp(data.acknowledged_at)} /><ApiDetail label="Component reference" value={data.component_reference} /></dl></section>}</ApiState></aside></div>
}

function IsolationAssetRow({ asset, busy, onSelect, onRequestIsolation, onRequestRelease }) {
  const { data, loading, error } = useApiResource(`/assets/${encodeURIComponent(asset.id)}/isolation`)
  const state = data?.isolation_state
  const mayRequestIsolation = state === 'not_isolated'
  const mayRequestRelease = state === 'isolated' && data.active_isolation_action_id
  return <tr>
    <td>{asset.hostname}</td><td>{asset.id}</td><td>{displayValue(asset.asset_type)}</td><td>{displayValue(asset.network_segment)}</td>
    <td>{loading ? 'Loading…' : error ? 'Unavailable' : state || 'No state returned'}{data?.execution_status ? ` · ${data.execution_status}` : ''}</td>
    <td>{data?.active_isolation_action_id || 'None'}</td>
    <td><button className="row-action" onClick={() => onSelect(asset)}>Details</button>{mayRequestIsolation && <button className="isolation-row-action" disabled={busy} onClick={() => onRequestIsolation(asset)}>Request isolation</button>}{mayRequestRelease && <button className="isolation-row-action" disabled={busy} onClick={() => onRequestRelease(data.active_isolation_action_id)}>Request release</button>}{!error && !loading && !mayRequestIsolation && !mayRequestRelease && <span>Request in progress / no action</span>}</td>
  </tr>
}

export function SystemIsolationPage({ globalSearch = '' }) {
  const [refresh, setRefresh] = useState(0)
  const [selectedAsset, setSelectedAsset] = useState(null)
  const [mode, setMode] = useState('network')
  const [actionState, setActionState] = useState({ busy: false, error: null, message: '' })
  const { data, loading, error } = useApiResource(`/assets?page=1&page_size=100`, refresh)
  const { data: isolationData, loading: isolationLoading, error: isolationError } = useApiResource('/isolation?page=1&page_size=100', refresh)
  const assets = data?.items || []
  const actions = isolationData?.items || []
  const pendingActions = actions.filter((action) => ['requested', 'awaiting_approval', 'approved', 'executing', 'release_requested'].includes(action.execution_status)).length
  const filtered = assets.filter((asset) => !globalSearch.trim() || [asset.id, asset.hostname, asset.asset_type, asset.environment, asset.network_segment].some((value) => String(value || '').toLowerCase().includes(globalSearch.trim().toLowerCase())))
  const requestIsolation = async (asset) => {
    setActionState({ busy: true, error: null, message: '' })
    try {
      const actionRequest = await api.post('/action-requests', { action_type: 'isolate', asset_id: asset.id, isolation_mode: mode, request_reason: 'Isolation request submitted from the frontend.' })
      const result = await api.post('/isolation-requests', { action_request_id: actionRequest.id, asset_id: asset.id, isolation_mode: mode, correlation_id: actionRequest.correlation_id })
      setActionState({ busy: false, error: null, message: `Backend isolation request status: ${result.execution_status}. Approval and component execution remain required.` })
      setRefresh((value) => value + 1)
    } catch (requestError) { setActionState({ busy: false, error: requestError, message: '' }) }
  }
  const requestRelease = async (actionId) => {
    setActionState({ busy: true, error: null, message: '' })
    try {
      const result = await api.post(`/isolation-requests/${encodeURIComponent(actionId)}/release`, { reason: 'Release requested from the frontend.' })
      setActionState({ busy: false, error: null, message: `Backend release request status: ${result.execution_status}. Approval and component confirmation remain required.` })
      setRefresh((value) => value + 1)
    } catch (requestError) { setActionState({ busy: false, error: requestError, message: '' }) }
  }
  return <main className="system-isolation-main"><PageHeading title="System Isolation" description="Asset state is read from backend isolation records; requests do not imply execution or success." actions={<><label>Request mode <select value={mode} onChange={(event) => setMode(event.target.value)}>{['network', 'host', 'full'].map((value) => <option key={value}>{value}</option>)}</select></label><button className="toolbar-button" onClick={() => setRefresh((value) => value + 1)}>Refresh</button></>} />
    {actionState.message && <p className="api-note" role="status">{actionState.message}</p>}{actionState.error && <ApiState error={actionState.error} />}
    <section className="isolation-summary-grid">{[['Assets loaded', data?.total ?? '—'], ['Isolation actions loaded', isolationData?.total ?? '—'], ['Pending actions · loaded page', pendingActions], ['Confirmed state', 'Read per asset']].map(([label, value]) => <article className="isolation-summary-card" key={label}><div className="isolation-summary-copy"><span className="eyebrow">{label}</span><strong>{value}</strong></div></article>)}</section>
    <section className="panel isolation-table-panel"><header className="isolation-section-heading"><div><h2>Assets &amp; Isolation Actions</h2><p>Current isolation state comes from each asset's backend state endpoint.</p></div></header><ApiState loading={loading} error={error} onRetry={() => setRefresh((value) => value + 1)} empty={!loading && !error && filtered.length === 0 ? 'No assets match the current search.' : null}>{filtered.length > 0 && <ApiTable headings={['Asset', 'Asset ID', 'Type', 'Network Segment', 'Confirmed Isolation State', 'Action ID', 'Actions']} className="isolation-table-scroll">{filtered.map((asset) => <IsolationAssetRow key={asset.id} asset={asset} busy={actionState.busy} onSelect={setSelectedAsset} onRequestIsolation={requestIsolation} onRequestRelease={requestRelease} />)}</ApiTable>}</ApiState><footer className="isolation-table-footer">Requests enter backend approval/execution workflow. Only component results change confirmed isolation state.</footer></section>
    <section className="panel isolation-activity-panel"><header className="isolation-section-heading"><div><h2>Recent Isolation Actions</h2><p>Backend actions only; no synthetic activity records.</p></div></header><ApiState loading={isolationLoading} error={isolationError} onRetry={() => setRefresh((value) => value + 1)} empty={!isolationLoading && !isolationError && actions.length === 0 ? 'No isolation actions returned.' : null}>{actions.length > 0 && <ApiTable headings={['Action ID', 'Asset ID', 'Operation', 'Execution Status', 'Network State', 'Requested At', 'Correlation ID']}>{actions.map((action) => <tr key={action.isolation_action_id}><td>{action.isolation_action_id}</td><td>{action.asset_id}</td><td>{action.operation}</td><td>{action.execution_status}</td><td>{displayValue(action.network_state)}</td><td>{formatTimestamp(action.requested_at)}</td><td>{action.correlation_id}</td></tr>)}</ApiTable>}</ApiState></section>
    <ActionRequestApprovalPanel actionTypes={['isolate', 'release_isolation']} refresh={refresh} onChanged={() => setRefresh((value) => value + 1)} />
    {selectedAsset && <IsolationAssetDetails asset={selectedAsset} onClose={() => setSelectedAsset(null)} />}
  </main>
}

function RecoveryJobDetails({ jobId, onClose }) {
  const { data, loading, error } = useApiResource(jobId ? `/recovery-jobs/${encodeURIComponent(jobId)}` : null)
  return <div className="event-drawer-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose() }}><aside className="event-details-drawer" role="dialog" aria-modal="true" aria-labelledby="recovery-job-title"><header className="event-drawer-header"><div><span className="eyebrow">Backend recovery job</span><h2 id="recovery-job-title">Recovery Details</h2></div><button className="icon-button" onClick={onClose} aria-label="Close details">×</button></header><ApiState loading={loading} error={error}>{data && <section className="detail-section"><dl className="event-detail-grid"><ApiDetail label="Job ID" value={data.id} /><ApiDetail label="Action request ID" value={data.action_request_id} /><ApiDetail label="Asset ID" value={data.asset_id} /><ApiDetail label="Incident ID" value={data.incident_id} /><ApiDetail label="Backup ID" value={data.backup_id} /><ApiDetail label="Verification ID" value={data.verification_id} /><ApiDetail label="Recovery environment" value={data.recovery_environment} /><ApiDetail label="Job status" value={data.job_status} /><ApiDetail label="Cutover status" value={data.cutover_status} /><ApiDetail label="Malware scan status" value={data.malware_scan_status} /><ApiDetail label="Security validation status" value={data.security_validation_status} /><ApiDetail label="Started at" value={formatTimestamp(data.started_at)} /><ApiDetail label="Completed at" value={formatTimestamp(data.completed_at)} /><ApiDetail label="Outcome" value={data.outcome} /><ApiDetail label="Failure reason" value={data.failure_reason} /><ApiDetail label="Correlation ID" value={data.correlation_id} /></dl><p className="api-note">Job completion and validation are reported by the trusted component; this interface does not synthesize results.</p></section>}</ApiState></aside></div>
}

export function RecoveryPage({ globalSearch = '' }) {
  const [refresh, setRefresh] = useState(0)
  const [selectedJob, setSelectedJob] = useState(null)
  const [requestState, setRequestState] = useState({ busy: false, error: null, message: '' })
  const [dispatchState, setDispatchState] = useState({ busyId: '', error: null })
  const { data: jobs, loading: jobsLoading, error: jobsError } = useApiResource('/recovery-jobs?page=1&page_size=100', refresh)
  const { data: backups, loading: backupsLoading, error: backupsError } = useApiResource('/backups?page=1&page_size=100', refresh)
  const jobItems = (jobs?.items || []).filter((job) => !globalSearch.trim() || [job.id, job.asset_id, job.incident_id, job.backup_id, job.job_status, job.correlation_id].some((value) => String(value || '').toLowerCase().includes(globalSearch.trim().toLowerCase())))
  const backupItems = (backups?.items || []).filter((backup) => !globalSearch.trim() || [backup.backup_id, backup.asset_id, backup.lifecycle_status, backup.eligibility_reasons].some((value) => String(value || '').toLowerCase().includes(globalSearch.trim().toLowerCase())))
  const inProgressJobs = (jobs?.items || []).filter((job) => ['queued', 'restoring', 'scanning', 'cutover_in_progress'].includes(job.job_status)).length
  const [incidents, setIncidents] = useState([])
  const [assets, setAssets] = useState([])
  const [selectedIncident, setSelectedIncident] = useState('')
  const [selectedBackup, setSelectedBackup] = useState('')
  const [selectedVerification, setSelectedVerification] = useState('')
  const { data: verificationPage, loading: verificationLoading, error: verificationError } = useApiResource(selectedBackup ? `/integrity-verifications?backup_id=${encodeURIComponent(selectedBackup.backup_id)}&page=1&page_size=100` : null, refresh)
  const passedVerifications = (verificationPage?.items || []).filter((verification) => verification.result_status === 'passed')
  const { data: isolationState, loading: isolationStateLoading, error: isolationStateError } = useApiResource(selectedBackup ? `/assets/${encodeURIComponent(selectedBackup.asset_id)}/isolation` : null, refresh)
  useEffect(() => {
    const controller = new AbortController()
    Promise.all([api.get('/threats?page=1&page_size=100', { signal: controller.signal }), api.get('/assets?page=1&page_size=100', { signal: controller.signal })])
      .then(([incidentPage, assetPage]) => { setIncidents(incidentPage.items); setAssets(assetPage.items) })
      .catch((loadError) => { if (loadError.name !== 'AbortError') setRequestState((current) => ({ ...current, error: loadError })) })
    return () => controller.abort()
  }, [refresh])
  const incidentMatchesSelectedBackup = incidents.some((incident) => incident.id === selectedIncident && (incident.asset_id === selectedBackup?.asset_id || incident.affected_asset_ids?.includes(selectedBackup?.asset_id)))
  const requestRecovery = async () => {
    const asset = assets.find((item) => item.id === selectedBackup?.asset_id)
    if (!selectedIncident || !selectedBackup || !selectedVerification || !asset || !incidentMatchesSelectedBackup) return
    setRequestState({ busy: true, error: null, message: '' })
    try {
      const request = await api.post('/action-requests', { action_type: 'recover', asset_id: asset.id, incident_id: selectedIncident, backup_id: selectedBackup.backup_id, verification_id: selectedVerification })
      setRequestState({ busy: false, error: null, message: `ActionRequest recorded with backend approval status: ${request.approval_status}. An authorized approver must approve it before RecoveryJob creation.` })
      setRefresh((value) => value + 1)
    } catch (requestError) { setRequestState({ busy: false, error: requestError, message: '' }) }
  }
  const dispatchRecovery = async (jobId) => {
    setDispatchState({ busyId: jobId, error: null })
    try {
      const result = await api.post(`/recovery-jobs/${encodeURIComponent(jobId)}/dispatch`, {})
      setRequestState({ busy: false, error: null, message: `Backend dispatch accepted with job status: ${result.job_status}. The trusted component must still claim and report results.` })
      setRefresh((value) => value + 1)
    } catch (dispatchError) {
      setDispatchState({ busyId: '', error: dispatchError })
    } finally {
      setDispatchState((current) => ({ ...current, busyId: '' }))
    }
  }
  return <main className="recovery-main"><PageHeading title="Recovery" description="Recovery jobs and backend-confirmed backup eligibility; execution remains component-controlled." actions={<button className="toolbar-button" onClick={() => setRefresh((value) => value + 1)}>Refresh</button>} />
    <section className="recovery-summary-grid"><article className="recovery-summary-card"><div className="recovery-summary-copy"><span className="eyebrow">Recovery Jobs</span><strong>{jobs?.total ?? '—'}</strong><span>Backend total</span></div></article><article className="recovery-summary-card"><div className="recovery-summary-copy"><span className="eyebrow">Eligible Backups Loaded</span><strong>{backupItems.filter((item) => item.recovery_eligible).length}</strong><span>Backend-confirmed only</span></div></article><article className="recovery-summary-card"><div className="recovery-summary-copy"><span className="eyebrow">Jobs In Progress · Loaded Page</span><strong>{inProgressJobs}</strong><span>Queued or component processing</span></div></article></section>
    <section className="panel recovery-plan-panel"><header className="recovery-section-heading"><div><h2>Recovery Workflow</h2><p>ActionRequest → approval → validation → RecoveryJob → dispatch → trusted component result.</p></div></header><p className="api-note">Recovery completion, scan results, and cutover status are never set by the frontend.</p><div className="api-recovery-request"><label>Incident<select value={selectedIncident} onChange={(event) => setSelectedIncident(event.target.value)}><option value="">Select incident</option>{(selectedBackup ? incidents.filter((incident) => incident.asset_id === selectedBackup.asset_id || incident.affected_asset_ids?.includes(selectedBackup.asset_id)) : incidents).map((incident) => <option key={incident.id} value={incident.id}>{incident.title} · {incident.lifecycle_status}</option>)}</select></label><label>Eligible backup<select value={selectedBackup?.backup_id || ''} onChange={(event) => { const backup = backupItems.find((item) => item.backup_id === event.target.value); setSelectedBackup(backup || null); setSelectedVerification(''); setSelectedIncident((current) => { const incident = incidents.find((item) => item.id === current); return incident && (incident.asset_id === backup?.asset_id || incident.affected_asset_ids?.includes(backup?.asset_id)) ? current : '' })
      }}><option value="">Select recovery-eligible backup</option>{backupItems.filter((backup) => backup.recovery_eligible).map((backup) => <option key={backup.backup_id} value={backup.backup_id}>{backup.backup_id} · asset {backup.asset_id}</option>)}</select></label><label>Passed verification<select value={selectedVerification} onChange={(event) => setSelectedVerification(event.target.value)}><option value="">Select verification</option>{passedVerifications.map((verification) => <option key={verification.verification_id} value={verification.verification_id}>{verification.verification_id} · completed {formatTimestamp(verification.completed_at)}</option>)}</select></label><button className="toolbar-button" disabled={requestState.busy || verificationLoading || isolationStateLoading || isolationState?.isolation_state !== 'isolated' || !selectedIncident || !selectedBackup || !selectedVerification || !incidentMatchesSelectedBackup} onClick={requestRecovery}>Create recovery request</button></div>{selectedBackup && <p className="api-note">Selected asset isolation state: {isolationStateLoading ? 'Loading…' : isolationStateError ? 'Unavailable' : isolationState?.isolation_state || 'No state returned'}. Backend validates current confirmed isolation again at the recovery gates.</p>}{verificationLoading && <ApiState loading />}{verificationError && <ApiState error={verificationError} />}{isolationStateError && <ApiState error={isolationStateError} />}{requestState.message && <p className="api-note" role="status">{requestState.message}</p>}{requestState.error && <ApiState error={requestState.error} />}</section>
    <ActionRequestApprovalPanel actionTypes={['recover']} refresh={refresh} onChanged={() => setRefresh((value) => value + 1)} />
    <section className="panel recovery-jobs-panel"><header className="recovery-section-heading"><div><h2>Recovery Jobs</h2><p>Backend job lifecycle values.</p></div></header><ApiState loading={jobsLoading} error={jobsError} onRetry={() => setRefresh((value) => value + 1)} empty={!jobsLoading && !jobsError && jobItems.length === 0 ? 'No recovery jobs returned.' : null}>{jobItems.length > 0 && <ApiTable headings={['Job ID', 'Asset ID', 'Incident ID', 'Backup ID', 'Verification ID', 'Job Status', 'Cutover Status', 'Scan', 'Security Validation', 'Details']} className="restore-points-table-scroll">{jobItems.map((job) => <tr key={job.id}><td>{job.id}</td><td>{job.asset_id}</td><td>{job.incident_id}</td><td>{job.backup_id}</td><td>{job.verification_id}</td><td>{job.job_status}</td><td>{job.cutover_status}</td><td>{job.malware_scan_status}</td><td>{job.security_validation_status}</td><td><button className="row-action" onClick={() => setSelectedJob(job.id)}>Details</button></td></tr>)}</ApiTable>}</ApiState></section>
    {dispatchState.error && <ApiState error={dispatchState.error} />}
    <section className="panel recovery-plan-panel"><header className="recovery-section-heading"><div><h2>Approved Jobs Ready for Dispatch</h2><p>Dispatch rechecks backend prerequisites; this only queues work for a trusted component.</p></div></header>{jobItems.filter((job) => job.job_status === 'approved').length ? <ApiTable headings={['Job ID', 'Asset ID', 'Incident ID', 'Backup ID', 'Status', 'Dispatch']}>
      {jobItems.filter((job) => job.job_status === 'approved').map((job) => <tr key={job.id}><td>{job.id}</td><td>{job.asset_id}</td><td>{job.incident_id}</td><td>{job.backup_id}</td><td>{job.job_status}</td><td><button className="toolbar-button" disabled={dispatchState.busyId === job.id} onClick={() => dispatchRecovery(job.id)}>Dispatch</button></td></tr>)}
    </ApiTable> : <div className="api-state">No approved RecoveryJobs are currently available for dispatch.</div>}</section>
    <section className="panel restore-points-panel"><header className="recovery-section-heading"><div><h2>Backup Recovery Eligibility</h2><p>Eligibility and reasons are supplied by the backend.</p></div></header><ApiState loading={backupsLoading} error={backupsError} onRetry={() => setRefresh((value) => value + 1)} empty={!backupsLoading && !backupsError && backupItems.length === 0 ? 'No backup records returned.' : null}>{backupItems.length > 0 && <ApiTable headings={['Backup ID', 'Asset ID', 'Lifecycle', 'Verified', 'Recovery Eligible', 'Eligibility Reasons']} className="restore-points-table-scroll">{backupItems.map((backup) => <tr key={backup.backup_id}><td>{backup.backup_id}</td><td>{backup.asset_id}</td><td>{backup.lifecycle_status}</td><td>{String(backup.verified)}</td><td>{String(backup.recovery_eligible)}</td><td>{backup.eligibility_reasons.join('; ') || 'No reasons returned'}</td></tr>)}</ApiTable>}</ApiState><footer className="recovery-table-footer">Showing {backupItems.length} loaded of {backups?.total ?? 0} backup candidates.</footer></section>
    {selectedJob && <RecoveryJobDetails jobId={selectedJob} onClose={() => setSelectedJob(null)} />}
  </main>
}

function AuditDetails({ eventId, onClose }) {
  const { data, loading, error } = useApiResource(eventId ? `/audit-logs/${encodeURIComponent(eventId)}` : null)
  return <div className="event-drawer-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose() }}><aside className="event-details-drawer" role="dialog" aria-modal="true" aria-labelledby="audit-details-title"><header className="event-drawer-header"><div><span className="eyebrow">Audit record</span><h2 id="audit-details-title">Audit Event Details</h2></div><button className="icon-button" onClick={onClose} aria-label="Close details">×</button></header><ApiState loading={loading} error={error}>{data && <section className="detail-section"><dl className="event-detail-grid"><ApiDetail label="Event ID" value={data.id} /><ApiDetail label="Occurred at" value={formatTimestamp(data.occurred_at)} /><ApiDetail label="Actor type" value={data.actor_type} /><ApiDetail label="Actor ID" value={data.actor_id} /><ApiDetail label="Action" value={data.action} /><ApiDetail label="Result status" value={data.result_status} /><ApiDetail label="Resource type" value={data.resource_type} /><ApiDetail label="Resource ID" value={data.resource_id} /><ApiDetail label="Asset ID" value={data.asset_id} /><ApiDetail label="Incident ID" value={data.incident_id} /><ApiDetail label="Source component" value={data.source_component} /><ApiDetail label="Reason" value={data.reason} /><ApiDetail label="Safe metadata" value={data.safe_metadata} /><ApiDetail label="Correlation ID" value={data.correlation_id} /></dl></section>}</ApiState></aside></div>
}

export function AuditLogsPage({ globalSearch = '', onGlobalSearchChange }) {
  const [page, setPage] = useState(1)
  const [filters, setFilters] = useState({ actor_type: '', action: '', result_status: '', correlation_id: '' })
  const [selectedId, setSelectedId] = useState(null)
  const path = `/audit-logs${queryString({ page, page_size: 25, ...filters })}`
  const { data, loading, error } = useApiResource(path)
  const items = (data?.items || []).filter((event) => !globalSearch.trim() || [event.id, event.actor_type, event.actor_id, event.action, event.result_status, event.resource_type, event.resource_id, event.correlation_id].some((value) => String(value || '').toLowerCase().includes(globalSearch.trim().toLowerCase())))
  const updateFilter = (key, value) => { setFilters((current) => ({ ...current, [key]: value })); setPage(1) }
  return (
    <main className="audit-logs-main"><PageHeading title="Audit Logs" description="Append-oriented audit records using fields exposed by the API." />
    <section className="audit-summary-grid"><article className="audit-summary-card"><div className="audit-summary-copy"><span className="eyebrow">Total matching records</span><strong>{data?.total ?? '—'}</strong><span>Backend pagination total</span></div></article><article className="audit-summary-card"><div className="audit-summary-copy"><span className="eyebrow">Rejected · Loaded Page</span><strong>{items.filter((event) => event.result_status === 'rejected').length}</strong><span>From returned result statuses</span></div></article><article className="audit-summary-card"><div className="audit-summary-copy"><span className="eyebrow">Actor Types · Loaded Page</span><strong>{new Set(items.map((event) => event.actor_type)).size}</strong><span>Distinct values in current page</span></div></article></section>
    <section className="panel audit-log-panel"><header className="audit-section-heading"><div><h2>Audit Log</h2><p>Correlation IDs are preserved where present.</p></div></header><div className="audit-filter-bar"><label className="event-search"><input type="search" value={globalSearch} onChange={(event) => { onGlobalSearchChange?.(event.target.value); setPage(1) }} placeholder="Search loaded audit fields" /></label><div className="event-select-filters"><label className="event-select"><input value={filters.actor_type} onChange={(event) => updateFilter('actor_type', event.target.value)} placeholder="Exact actor type" /></label><label className="event-select"><input value={filters.action} onChange={(event) => updateFilter('action', event.target.value)} placeholder="Action contains" /></label><label className="event-select"><input value={filters.result_status} onChange={(event) => updateFilter('result_status', event.target.value)} placeholder="Exact result status" /></label><label className="event-select"><input value={filters.correlation_id} onChange={(event) => updateFilter('correlation_id', event.target.value)} placeholder="Correlation ID" /></label></div></div>
      <ApiState loading={loading} error={error} empty={!loading && !error && items.length === 0 ? 'No audit events match the current search and filters.' : null}>{items.length > 0 && <><ApiTable headings={['Occurred At', 'Event ID', 'Actor Type', 'Actor ID', 'Action', 'Result Status', 'Resource', 'Correlation ID', 'Details']} className="audit-table-scroll">{items.map((event) => <tr key={event.id}><td>{formatTimestamp(event.occurred_at)}</td><td>{event.id}</td><td>{event.actor_type}</td><td>{displayValue(event.actor_id)}</td><td>{event.action}</td><td>{event.result_status}</td><td>{displayValue(event.resource_type)} · {displayValue(event.resource_id)}</td><td>{event.correlation_id}</td><td><button className="row-action" onClick={() => setSelectedId(event.id)}>View</button></td></tr>)}</ApiTable><div className="event-pagination"><span>Page {data.page} · {data.total} events</span><button disabled={page <= 1} onClick={() => setPage(page - 1)}>Previous</button><button disabled={page * data.page_size >= data.total} onClick={() => setPage(page + 1)}>Next</button></div></>}</ApiState>
    </section>{selectedId && <AuditDetails eventId={selectedId} onClose={() => setSelectedId(null)} />}
    </main>
  )
}

