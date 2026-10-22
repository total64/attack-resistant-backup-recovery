import os
from fastapi import APIRouter, Depends
from sqlalchemy import func, text
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models import AuditEvent, Backup, IntegrityVerification, IsolationAction, RecoveryJob, SecurityEvent, ThreatIncident, UserAccount
from app.schemas import AdminOverviewRead
from app.services.user_auth import (
    UserPrincipal,
    UserRole,
    get_configured_credentials,
    get_current_user,
    require_role,
)

router = APIRouter(prefix="/api/admin", tags=["Admin operations"], dependencies=[Depends(get_current_user)])


@router.get("/overview", response_model=AdminOverviewRead)
def get_admin_overview(
    _admin: UserPrincipal = Depends(require_role(UserRole.ADMIN)),
    db: Session = Depends(get_db),
):
    """Provide aggregated administration metrics, system health, and audit summary."""
    # 1. User counts
    configured = get_configured_credentials()
    db_accounts = db.query(UserAccount).all()

    total_users = len(configured) + len(db_accounts)
    active_users = len(configured) + sum(1 for a in db_accounts if a.is_active)
    inactive_users = sum(1 for a in db_accounts if not a.is_active)

    roles = {"admin": 0, "analyst": 0, "approver": 0, "viewer": 0}
    for item in configured:
        roles[item["role"]] = roles.get(item["role"], 0) + 1
    for a in db_accounts:
        roles[a.role] = roles.get(a.role, 0) + 1

    user_counts = {
        "total": total_users,
        "active": active_users,
        "inactive": inactive_users,
        "admins": roles.get("admin", 0),
        "analysts": roles.get("analyst", 0),
        "approvers": roles.get("approver", 0),
        "viewers": roles.get("viewer", 0),
    }

    # 2. System Health
    db_ok = True
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        db_ok = False

    wazuh_url = os.getenv("WAZUH_API_URL")
    wazuh_status = "configured" if wazuh_url else "unavailable"

    system_health = {
        "status": "healthy" if db_ok else "degraded",
        "database": {"connected": db_ok, "engine": "sqlite"},
        "wazuh_integration": {
            "status": wazuh_status,
            "url": wazuh_url or None,
            "message": "Configured for security event ingestion" if wazuh_url else "Wazuh integration endpoint not configured",
        },
        "backup_subsystem": {"status": "component_worker_managed"},
        "recovery_subsystem": {"status": "component_worker_managed"},
        "isolation_subsystem": {"status": "component_worker_managed"},
    }

    # 3. Security summary
    terminal_statuses = ("resolved", "false_positive", "closed")
    active_threats = (
        db.query(func.count(ThreatIncident.id))
        .filter(ThreatIncident.lifecycle_status.notin_(terminal_statuses))
        .scalar()
        or 0
    )
    total_events = db.query(func.count(SecurityEvent.id)).scalar() or 0
    critical_events = (
        db.query(func.count(SecurityEvent.id))
        .filter(SecurityEvent.event_severity == "critical")
        .scalar()
        or 0
    )
    pending_events = (
        db.query(func.count(SecurityEvent.id))
        .filter(SecurityEvent.processing_status.in_(("received", "normalized")))
        .scalar()
        or 0
    )
    active_isolation_operations = (
        db.query(func.count(IsolationAction.id))
        .filter(IsolationAction.execution_status.in_(
            ("requested", "awaiting_approval", "approved", "executing", "isolated", "release_requested")
        ))
        .scalar()
        or 0
    )
    system_health["isolation_subsystem"]["active_operations"] = active_isolation_operations

    security_summary = {
        "total_events": total_events,
        "active_threats": active_threats,
        "critical_events": critical_events,
        "pending_events": pending_events,
    }

    # 4. Backup & Recovery summary
    total_backups = db.query(func.count(Backup.id)).scalar() or 0
    protected_backups = (
        db.query(func.count(Backup.id))
        .filter(Backup.protection_status == "protected")
        .scalar()
        or 0
    )
    verified_backups = (
        db.query(func.count(IntegrityVerification.id))
        .filter(IntegrityVerification.result_status == "passed")
        .scalar()
        or 0
    )
    recovery_jobs = db.query(func.count(RecoveryJob.id)).scalar() or 0

    backup_recovery_summary = {
        "total_backups": total_backups,
        "protected_backups": protected_backups,
        "verified_backups": verified_backups,
        "recovery_jobs": recovery_jobs,
    }

    # 5. Audit summary
    total_audit_events = db.query(func.count(AuditEvent.id)).scalar() or 0
    recent_admin_events = (
        db.query(AuditEvent)
        .order_by(AuditEvent.occurred_at.desc())
        .limit(5)
        .all()
    )

    audit_summary = {
        "total_events": total_audit_events,
        "recent_events": [
            {
                "id": event.id,
                "action": event.action,
                "actor_type": event.actor_type,
                "actor_id": event.actor_id,
                "result_status": event.result_status,
                "occurred_at": event.occurred_at.isoformat(),
            }
            for event in recent_admin_events
        ],
    }

    return AdminOverviewRead(
        user_counts=user_counts,
        system_health=system_health,
        security_summary=security_summary,
        backup_recovery_summary=backup_recovery_summary,
        audit_summary=audit_summary,
    )
