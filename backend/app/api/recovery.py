from datetime import datetime, timezone
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from app.api.common import as_utc, get_or_404, paginate
from app.database.session import get_db
from app.enums import ActionType, RecoveryJobStatus
from app.models import ActionRequest, AuditEvent, RecoveryJob
from app.schemas import (
    AuditEventCreate,
    Page,
    RecoveryComponentClaim,
    RecoveryComponentResult,
    RecoveryJobCancel,
    RecoveryJobCreate,
    RecoveryJobRead,
)
from app.services.audit import record_audit_event
from app.services.internal_auth import ComponentPrincipal, ComponentScope, require_component_scope
from app.services.recovery_validation import validate_recovery_prerequisites
from app.services.user_auth import UserPrincipal, UserRole, get_current_user, require_role

router = APIRouter(
    prefix="/api/recovery-jobs",
    tags=["recovery"],
    dependencies=[Depends(get_current_user)],
)
internal_router = APIRouter(prefix="/api/internal/recovery-jobs", tags=["Internal Recovery Component"])
recovery_component = require_component_scope(ComponentScope.RECOVERY_WRITE)


@internal_router.get("/queue", dependencies=[Depends(recovery_component)])
def list_queued_recovery_work(
    db: Session = Depends(get_db),
    _component: ComponentPrincipal = Depends(recovery_component),
):
    """List queued jobs; claim still revalidates approval, isolation and backup state."""
    return [
        {
            "recovery_job_id": job.id,
            "action_request_id": job.action_request_id,
            "asset_id": job.asset_id,
            "incident_id": job.incident_id,
            "backup_id": job.backup_id,
            "verification_id": job.verification_id,
            "correlation_id": job.correlation_id,
        }
        for job in db.query(RecoveryJob)
        .filter(RecoveryJob.job_status == RecoveryJobStatus.QUEUED.value)
        .order_by(RecoveryJob.created_at.asc())
        .all()
    ]

TERMINAL_STATUSES = {RecoveryJobStatus.COMPLETED.value, RecoveryJobStatus.FAILED.value, RecoveryJobStatus.CANCELLED.value}


def _audit(
    db: Session,
    *,
    action: str,
    result_status: str,
    recovery_job: RecoveryJob | None = None,
    action_request: ActionRequest | None = None,
    reason: str | None = None,
    actor_type: str = "system",
    actor_id: str | None = None,
    source_component: str = "api",
    correlation_id: UUID | str | None = None,
    safe_metadata: dict | None = None,
) -> AuditEvent:
    job = recovery_job
    request = action_request or (job.action_request if job else None)
    return record_audit_event(
        db,
        AuditEventCreate(
            actor_type=actor_type,
            actor_id=actor_id,
            action=action,
            result_status=result_status,
            resource_type="recovery_job" if job else "action_request",
            resource_id=job.id if job else (request.id if request else None),
            asset_id=job.asset_id if job else (request.asset_id if request else None),
            incident_id=job.incident_id if job else (request.incident_id if request else None),
            decision_id=request.decision_id if request else None,
            action_request_id=request.id if request else None,
            backup_id=job.backup_id if job else (request.backup_id if request else None),
            verification_id=job.verification_id if job else (request.verification_id if request else None),
            recovery_job_id=job.id if job else None,
            source_component=source_component,
            reason=reason,
            safe_metadata=safe_metadata or {},
            correlation_id=correlation_id or (job.correlation_id if job else request.correlation_id if request else None),
        ),
    )


def _reject(
    db: Session,
    code: str,
    message: str,
    *,
    status_code: int = 409,
    recovery_job=None,
    action_request=None,
    audit_action: str | None = None,
):
    _audit(
        db,
        action=audit_action or ("recovery.component_result_rejected" if recovery_job else "recovery.request_rejected"),
        result_status="rejected",
        recovery_job=recovery_job,
        action_request=action_request,
        reason=code,
    )
    db.commit()
    raise HTTPException(status_code=status_code, detail={"code": code, "message": message})


def _validate_job(db: Session, job: RecoveryJob):
    action_request = job.action_request
    if action_request is None:
        _reject(db, "action_request_invalid", "Recovery job has no ActionRequest", recovery_job=job)
    if job.correlation_id != action_request.correlation_id:
        _reject(db, "correlation_mismatch", "RecoveryJob correlation does not match its ActionRequest", recovery_job=job)
    try:
        return validate_recovery_prerequisites(
            db,
            asset_id=job.asset_id,
            incident_id=job.incident_id,
            backup_id=job.backup_id,
            verification_id=job.verification_id,
            decision_id=action_request.decision_id,
            action_request=action_request,
        )
    except HTTPException as exc:
        detail = exc.detail if isinstance(exc.detail, dict) else {"code": "recovery_validation_failed", "message": str(exc.detail)}
        _reject(
            db,
            detail.get("code", "recovery_validation_failed"),
            detail.get("message", "Recovery validation failed"),
            status_code=exc.status_code,
            recovery_job=job,
            audit_action="recovery.validation_rejected",
        )


@router.get("", response_model=Page[RecoveryJobRead])
def list_recovery_jobs(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    asset_id: UUID | None = None,
    incident_id: UUID | None = None,
    status: RecoveryJobStatus | None = None,
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(RecoveryJob)
    if asset_id:
        query = query.filter(RecoveryJob.asset_id == str(asset_id))
    if incident_id:
        query = query.filter(RecoveryJob.incident_id == str(incident_id))
    if status:
        query = query.filter(RecoveryJob.job_status == status.value)
    if from_:
        query = query.filter(RecoveryJob.started_at >= as_utc(from_))
    if to:
        query = query.filter(RecoveryJob.started_at <= as_utc(to))
    return paginate(query.order_by(RecoveryJob.started_at.desc()), page, page_size)


@router.get("/{recovery_job_id}", response_model=RecoveryJobRead)
def get_recovery_job(recovery_job_id: UUID, db: Session = Depends(get_db)):
    return get_or_404(db, RecoveryJob, str(recovery_job_id), "Recovery job")


@router.post("", response_model=RecoveryJobRead, status_code=status.HTTP_201_CREATED)
def create_recovery_job(
    payload: RecoveryJobCreate,
    response: Response,
    db: Session = Depends(get_db),
    _current_user: UserPrincipal = Depends(require_role(UserRole.ANALYST)),
):
    action_request = db.get(ActionRequest, str(payload.action_request_id))
    if action_request is None:
        _reject(db, "action_request_not_found", "ActionRequest not found", status_code=404)
    if action_request.action_type != ActionType.RECOVER.value:
        _reject(db, "action_request_invalid", "ActionRequest must be a recovery request", action_request=action_request)
    if action_request.recovery_job is not None:
        existing = action_request.recovery_job
        if (
            existing.asset_id == str(payload.asset_id)
            and existing.incident_id == str(payload.incident_id)
            and existing.backup_id == str(payload.backup_id)
            and existing.verification_id == str(payload.verification_id)
            and existing.correlation_id == action_request.correlation_id
        ):
            response.status_code = status.HTTP_200_OK
            return existing
        _reject(db, "recovery_job_exists", "ActionRequest already has a RecoveryJob", action_request=action_request)
    if payload.correlation_id is not None and str(payload.correlation_id) != action_request.correlation_id:
        _reject(db, "correlation_mismatch", "Correlation ID must match the recovery ActionRequest", action_request=action_request)

    try:
        validate_recovery_prerequisites(
            db,
            asset_id=payload.asset_id,
            incident_id=payload.incident_id,
            backup_id=payload.backup_id,
            verification_id=payload.verification_id,
            decision_id=action_request.decision_id,
            action_request=action_request,
        )
    except HTTPException as exc:
        detail = exc.detail if isinstance(exc.detail, dict) else {"code": "recovery_validation_failed", "message": str(exc.detail)}
        _reject(
            db,
            detail.get("code", "recovery_validation_failed"),
            detail.get("message", "Recovery validation failed"),
            status_code=exc.status_code,
            action_request=action_request,
        )

    job = RecoveryJob(
        action_request_id=action_request.id,
        asset_id=str(payload.asset_id),
        incident_id=str(payload.incident_id),
        backup_id=str(payload.backup_id),
        verification_id=str(payload.verification_id),
        recovery_environment=payload.recovery_environment,
        job_status=(
            RecoveryJobStatus.APPROVED.value
            if action_request.approval_status == "approved"
            else RecoveryJobStatus.AWAITING_APPROVAL.value
        ),
        correlation_id=action_request.correlation_id,
    )
    db.add(job)
    db.flush()
    _audit(
        db,
        action="recovery.job_created",
        result_status="success",
        recovery_job=job,
        actor_type="user",
        actor_id=action_request.requested_by_id,
        reason="RecoveryJob created; no execution has started",
    )
    db.commit()
    db.refresh(job)
    return job


@router.post("/{recovery_job_id}/dispatch", response_model=RecoveryJobRead)
def dispatch_recovery_job(
    recovery_job_id: UUID,
    db: Session = Depends(get_db),
    current_user: UserPrincipal = Depends(require_role(UserRole.ANALYST)),
):
    job = get_or_404(db, RecoveryJob, str(recovery_job_id), "Recovery job")
    if job.job_status == RecoveryJobStatus.QUEUED.value:
        return job
    if job.job_status != RecoveryJobStatus.APPROVED.value:
        _reject(
            db,
            "invalid_state_transition",
            "Only an approved recovery job can be dispatched",
            recovery_job=job,
            audit_action="recovery.dispatch_rejected",
        )
    _validate_job(db, job)
    job.job_status = RecoveryJobStatus.QUEUED.value
    job.action_request.execution_status = "queued"
    _audit(
        db,
        action="recovery.dispatched",
        result_status="queued",
        recovery_job=job,
        actor_type="user",
        actor_id=current_user.user_id,
    )
    db.commit()
    db.refresh(job)
    return job


@router.post("/{recovery_job_id}/cancel", response_model=RecoveryJobRead)
def cancel_recovery_job(
    recovery_job_id: UUID,
    payload: RecoveryJobCancel,
    db: Session = Depends(get_db),
    current_user: UserPrincipal = Depends(require_role(UserRole.ANALYST)),
):
    job = get_or_404(db, RecoveryJob, str(recovery_job_id), "Recovery job")
    if job.job_status not in {RecoveryJobStatus.APPROVED.value, RecoveryJobStatus.QUEUED.value}:
        _reject(db, "invalid_state_transition", "Recovery can only be cancelled before component execution", recovery_job=job)
    if job.job_status == RecoveryJobStatus.QUEUED.value:
        _reject(db, "invalid_state_transition", "A queued job may already have been claimed and cannot be cancelled safely", recovery_job=job)
    job.job_status = RecoveryJobStatus.CANCELLED.value
    job.completed_at = datetime.now(timezone.utc)
    job.failure_reason = payload.reason
    job.action_request.execution_status = "cancelled"
    job.action_request.completed_at = job.completed_at
    _audit(
        db,
        action="recovery.cancelled",
        result_status="cancelled",
        recovery_job=job,
        actor_type="user",
        actor_id=current_user.user_id,
        reason=payload.reason,
    )
    db.commit()
    db.refresh(job)
    return job


@internal_router.post(
    "/{recovery_job_id}/claim",
    response_model=RecoveryJobRead,
    dependencies=[Depends(recovery_component)],
)
def claim_recovery_job(
    recovery_job_id: UUID,
    payload: RecoveryComponentClaim,
    db: Session = Depends(get_db),
    component: ComponentPrincipal = Depends(recovery_component),
):
    job = get_or_404(db, RecoveryJob, str(recovery_job_id), "Recovery job")
    if str(payload.correlation_id) != job.correlation_id:
        _reject(db, "correlation_mismatch", "Correlation ID does not match the recovery job", recovery_job=job)
    if job.job_status != RecoveryJobStatus.QUEUED.value:
        if job.component_reference == payload.component_reference and job.job_status in {
            RecoveryJobStatus.RESTORING.value,
            RecoveryJobStatus.SCANNING.value,
        }:
            return job
        _reject(db, "invalid_state_transition", "Only queued jobs can be claimed", recovery_job=job)
    if job.component_reference and job.component_reference != payload.component_reference:
        _reject(db, "component_reference_mismatch", "Recovery job has already been claimed by another component", recovery_job=job)
    _validate_job(db, job)
    now = datetime.now(timezone.utc)
    job.component_reference = payload.component_reference
    job.job_status = RecoveryJobStatus.RESTORING.value
    job.action_request.execution_status = "executing"
    job.started_at = job.started_at or now
    job.action_request.started_at = job.action_request.started_at or now
    _audit(
        db,
        action="recovery.restoring",
        result_status="started",
        recovery_job=job,
        actor_type="internal_component",
        actor_id=component.component_id,
        source_component=component.component_id,
    )
    db.commit()
    db.refresh(job)
    return job


@internal_router.post(
    "/{recovery_job_id}/result",
    response_model=RecoveryJobRead,
    dependencies=[Depends(recovery_component)],
)
def report_recovery_result(
    recovery_job_id: UUID,
    payload: RecoveryComponentResult,
    db: Session = Depends(get_db),
    component: ComponentPrincipal = Depends(recovery_component),
):
    job = get_or_404(db, RecoveryJob, str(recovery_job_id), "Recovery job")
    if (
        str(payload.asset_id) != job.asset_id
        or str(payload.incident_id) != job.incident_id
        or str(payload.backup_id) != job.backup_id
        or str(payload.verification_id) != job.verification_id
    ):
        _reject(db, "recovery_reference_mismatch", "Component result references do not match the RecoveryJob", recovery_job=job)
    if str(payload.correlation_id) != job.correlation_id:
        _reject(db, "correlation_mismatch", "Correlation ID does not match the RecoveryJob", recovery_job=job)
    if job.component_reference != payload.component_reference:
        _reject(db, "component_reference_mismatch", "Component reference does not match the claimed worker", recovery_job=job)

    duplicate = (
        job.job_status == payload.job_status
        and job.malware_scan_status == payload.malware_scan_status
        and job.security_validation_status == payload.security_validation_status
        and job.outcome == payload.outcome
        and job.failure_reason == payload.failure_reason
        and job.result_evidence_reference == payload.result_evidence_reference
    )
    if duplicate:
        return job
    if job.job_status in TERMINAL_STATUSES:
        _reject(db, "invalid_state_transition", "Terminal recovery result cannot be overwritten", recovery_job=job)

    current = job.job_status
    target = payload.job_status
    allowed = {
        RecoveryJobStatus.RESTORING.value: {
            RecoveryJobStatus.SCANNING.value,
            RecoveryJobStatus.FAILED.value,
        },
        RecoveryJobStatus.SCANNING.value: {
            RecoveryJobStatus.COMPLETED.value,
            RecoveryJobStatus.FAILED.value,
        },
    }
    if target not in allowed.get(current, set()):
        _reject(db, "invalid_state_transition", f"Cannot transition recovery job from {current} to {target}", recovery_job=job)

    if current not in {RecoveryJobStatus.RESTORING.value, RecoveryJobStatus.SCANNING.value}:
        _reject(db, "invalid_state_transition", "Recovery component must claim the job before reporting results", recovery_job=job)
    job.job_status = target
    job.malware_scan_status = payload.malware_scan_status
    job.security_validation_status = payload.security_validation_status
    job.outcome = payload.outcome
    job.failure_reason = payload.failure_reason
    job.result_evidence_reference = payload.result_evidence_reference
    job.action_request.component_result = {
        "job_status": target,
        "malware_scan_status": payload.malware_scan_status,
        "security_validation_status": payload.security_validation_status,
        "component_reference": payload.component_reference,
        "result_evidence_reference": payload.result_evidence_reference,
    }
    terminal = target in TERMINAL_STATUSES
    if terminal:
        job.completed_at = datetime.now(timezone.utc)
        job.action_request.completed_at = job.completed_at
        job.action_request.execution_status = "succeeded" if target == RecoveryJobStatus.COMPLETED.value else "failed"
    action_name = {
        RecoveryJobStatus.SCANNING.value: "recovery.scanning",
        RecoveryJobStatus.COMPLETED.value: "recovery.completed",
        RecoveryJobStatus.FAILED.value: "recovery.failed",
    }[target]
    _audit(
        db,
        action=action_name,
        result_status="success" if target == RecoveryJobStatus.COMPLETED.value else target,
        recovery_job=job,
        actor_type="internal_component",
        actor_id=component.component_id,
        source_component=component.component_id,
        reason=payload.failure_reason,
        safe_metadata={
            "malware_scan_status": payload.malware_scan_status,
            "security_validation_status": payload.security_validation_status,
        },
    )
    db.commit()
    db.refresh(job)
    return job