from datetime import datetime, timezone
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.common import as_utc, get_or_404, paginate
from app.database.session import get_db
from app.enums import ActionExecutionStatus, ActionType, VerificationStatus
from app.models import ActionRequest, Backup, IntegrityVerification
from app.schemas import (
    AuditEventCreate,
    IntegrityVerificationCreate,
    IntegrityVerificationClaim,
    IntegrityVerificationClaimRead,
    IntegrityVerificationRead,
    IntegrityVerificationRequested,
    IntegrityVerificationResult,
    Page,
    BackupRead,
)
from app.services.audit import record_audit_event, record_phase2_audit
from app.services.internal_auth import ComponentPrincipal, ComponentScope, require_component_scope
from app.services.user_auth import UserPrincipal, UserRole, get_current_user, require_role

router = APIRouter(
    prefix="/api/integrity-verifications",
    tags=["Integrity Verification"],
    dependencies=[Depends(get_current_user)],
)
backup_router = APIRouter(
    prefix="/api/backups",
    tags=["Integrity Verification"],
    dependencies=[Depends(get_current_user)],
)
internal_router = APIRouter(
    prefix="/api/internal/integrity-verifications",
    tags=["Internal Integrity Component"],
)
verification_component = require_component_scope(ComponentScope.VERIFICATION_WRITE)


@internal_router.get("/queue", dependencies=[Depends(verification_component)])
def list_approved_integrity_work(
    db: Session = Depends(get_db),
    _component: ComponentPrincipal = Depends(verification_component),
):
    """List approved queued verifications for the scoped verifier worker."""
    return [
        {
            "verification_id": verification.id,
            "backup_id": verification.backup_id,
            "correlation_id": verification.correlation_id,
            "action_request_id": action_request.id,
        }
        for verification, action_request in db.query(IntegrityVerification, ActionRequest)
        .join(ActionRequest, ActionRequest.verification_id == IntegrityVerification.id)
        .filter(
            IntegrityVerification.result_status == VerificationStatus.QUEUED.value,
            ActionRequest.action_type == ActionType.VERIFY_BACKUP.value,
            ActionRequest.approval_status == "approved",
            ActionRequest.execution_status == "not_started",
        )
        .order_by(IntegrityVerification.created_at.asc())
        .all()
    ]


@backup_router.post(
    "/{backup_id}/integrity-verifications",
    response_model=IntegrityVerificationRequested,
    status_code=status.HTTP_201_CREATED,
)
def request_integrity_verification(
    backup_id: UUID,
    payload: IntegrityVerificationCreate,
    db: Session = Depends(get_db),
    current_user: UserPrincipal = Depends(require_role(UserRole.ANALYST)),
):
    backup = get_or_404(db, Backup, str(backup_id), "Backup")
    correlation_id = payload.correlation_id or uuid4()
    verification = IntegrityVerification(
        backup_id=backup.id,
        result_status=VerificationStatus.QUEUED.value,
        correlation_id=str(correlation_id),
    )
    db.add(verification)
    db.flush()
    action_request = ActionRequest(
        action_type=ActionType.VERIFY_BACKUP.value,
        asset_id=backup.asset_id,
        backup_id=backup.id,
        verification_id=verification.id,
        requested_by_type="user",
        requested_by_id=current_user.user_id,
        request_reason=payload.reason,
        approval_status="pending",
        execution_status="not_started",
        correlation_id=str(correlation_id),
    )
    db.add(action_request)
    db.flush()
    record_audit_event(
        db,
        AuditEventCreate(
            actor_type="user",
            actor_id=current_user.user_id,
            action="integrity_verification.requested",
            result_status="success",
            resource_type="integrity_verification",
            resource_id=verification.id,
            action_request_id=action_request.id,
            backup_id=backup.id,
            verification_id=verification.id,
            asset_id=backup.asset_id,
            source_component="api",
            reason=payload.reason,
            correlation_id=correlation_id,
        ),
    )
    db.commit()
    db.refresh(verification)
    return IntegrityVerificationRequested(
        verification_id=UUID(verification.id),
        backup_id=UUID(backup.id),
        result_status=VerificationStatus.QUEUED,
        requested_at=as_utc(verification.created_at),
        correlation_id=correlation_id,
    )


@internal_router.post(
    "/{verification_id}/claim",
    response_model=IntegrityVerificationClaimRead,
    dependencies=[Depends(verification_component)],
)
def claim_integrity_verification(
    verification_id: UUID,
    payload: IntegrityVerificationClaim,
    db: Session = Depends(get_db),
    component: ComponentPrincipal = Depends(verification_component),
):
    verification = get_or_404(db, IntegrityVerification, str(verification_id), "Integrity verification")
    action_request = db.query(ActionRequest).filter(ActionRequest.verification_id == verification.id).first()
    if action_request is None or action_request.action_type != ActionType.VERIFY_BACKUP.value:
        raise HTTPException(status_code=409, detail="Verification has no authorized verify_backup ActionRequest")
    if action_request.approval_status != "approved":
        raise HTTPException(status_code=409, detail="Verification ActionRequest must be approved before execution")
    existing_reference = action_request.component_result.get("component_reference")
    if verification.result_status == VerificationStatus.RUNNING.value:
        if existing_reference == payload.component_reference:
            return IntegrityVerificationClaimRead(
                verification=IntegrityVerificationRead.model_validate(verification),
                backup=BackupRead.model_validate(get_or_404(db, Backup, verification.backup_id, "Backup")),
            )
        raise HTTPException(status_code=409, detail="Verification is already claimed by another component reference")
    if verification.result_status != VerificationStatus.QUEUED.value or action_request.execution_status != "not_started":
        raise HTTPException(status_code=409, detail="Only a queued verification can be claimed")

    now = datetime.now(timezone.utc)
    verification.result_status = VerificationStatus.RUNNING.value
    verification.verifier_component = component.component_id
    verification.started_at = now
    action_request.execution_status = ActionExecutionStatus.EXECUTING.value
    action_request.started_at = now
    action_request.component_result = {"component_reference": payload.component_reference}
    record_phase2_audit(
        db,
        action="integrity_verification.started",
        result_status="started",
        resource_type="integrity_verification",
        resource_id=verification.id,
        backup_id=verification.backup_id,
        verification_id=verification.id,
        action_request_id=action_request.id,
        asset_id=action_request.asset_id,
        correlation_id=verification.correlation_id,
        actor_id=component.component_id,
        source_component=component.component_id,
        safe_metadata={"component_reference": payload.component_reference},
    )
    db.commit()
    db.refresh(verification)
    return IntegrityVerificationClaimRead(
        verification=IntegrityVerificationRead.model_validate(verification),
        backup=BackupRead.model_validate(get_or_404(db, Backup, verification.backup_id, "Backup")),
    )


@internal_router.post(
    "/{verification_id}/result",
    response_model=IntegrityVerificationRead,
    dependencies=[Depends(verification_component)],
)
def report_integrity_result(
    verification_id: UUID,
    payload: IntegrityVerificationResult,
    db: Session = Depends(get_db),
    component: ComponentPrincipal = Depends(verification_component),
):
    verification = get_or_404(db, IntegrityVerification, str(verification_id), "Integrity verification")
    backup = get_or_404(db, Backup, verification.backup_id, "Backup")
    terminal_statuses = {
        VerificationStatus.PASSED.value,
        VerificationStatus.FAILED.value,
        VerificationStatus.INCONCLUSIVE.value,
        VerificationStatus.CANCELLED.value,
        VerificationStatus.ERROR.value,
    }
    if verification.result_status in terminal_statuses:
        raise HTTPException(status_code=409, detail="A completed verification result is immutable")

    if payload.correlation_id and str(payload.correlation_id) != verification.correlation_id:
        raise HTTPException(status_code=409, detail="Correlation ID does not match the verification request")
    trusted_manifest_reference = payload.trusted_manifest_reference or backup.manifest_reference
    if payload.result_status == VerificationStatus.PASSED and not (
        payload.expected_digest or trusted_manifest_reference
    ):
        raise HTTPException(
            status_code=422,
            detail="A passed result requires an expected digest or the backup's trusted manifest reference",
        )

    verification.result_status = payload.result_status
    verification.algorithm = payload.algorithm
    verification.expected_digest = payload.expected_digest
    verification.trusted_manifest_reference = trusted_manifest_reference
    verification.observed_digest = payload.observed_digest
    verification.verification_evidence_reference = payload.verification_evidence_reference
    verification.verifier_component = component.component_id
    verification.verifier_version = payload.verifier_version
    verification.started_at = (
        as_utc(payload.started_at) if payload.started_at else verification.started_at
    )
    if payload.result_status == VerificationStatus.RUNNING:
        verification.started_at = verification.started_at or datetime.now(timezone.utc)
        verification.completed_at = None
    else:
        verification.started_at = verification.started_at or datetime.now(timezone.utc)
        verification.completed_at = as_utc(payload.completed_at) if payload.completed_at else datetime.now(timezone.utc)
    verification.failure_reason = payload.failure_reason

    action_request = (
        db.query(ActionRequest)
        .filter(ActionRequest.verification_id == verification.id)
        .order_by(ActionRequest.created_at.desc())
        .first()
    )
    if action_request is None or action_request.action_type != ActionType.VERIFY_BACKUP.value:
        raise HTTPException(status_code=409, detail="Verification has no authorized verify_backup ActionRequest")
    if action_request.approval_status != "approved":
        raise HTTPException(status_code=409, detail="Verification ActionRequest must be approved before component results")
    if action_request.execution_status != ActionExecutionStatus.EXECUTING.value:
        raise HTTPException(status_code=409, detail="Verification must be claimed before reporting a component result")
    if action_request.component_result.get("component_reference") != payload.component_reference:
        raise HTTPException(status_code=409, detail="Verifier component reference does not match the claim")
    if payload.result_status == VerificationStatus.PASSED and payload.expected_digest and payload.observed_digest:
        if payload.expected_digest.lower() != payload.observed_digest.lower():
            raise HTTPException(status_code=409, detail="A passed integrity result must match the trusted expected digest")
    if action_request is not None:
        if payload.result_status == VerificationStatus.RUNNING:
            action_request.execution_status = "executing"
            action_request.started_at = verification.started_at
        elif payload.result_status == VerificationStatus.CANCELLED:
            action_request.execution_status = "cancelled"
            action_request.completed_at = verification.completed_at
        elif payload.result_status in {
            VerificationStatus.FAILED,
            VerificationStatus.INCONCLUSIVE,
            VerificationStatus.ERROR,
        }:
            action_request.execution_status = "failed"
            action_request.completed_at = verification.completed_at
        else:
            action_request.execution_status = "succeeded"
            action_request.completed_at = verification.completed_at
        action_request.failure_reason = payload.failure_reason
        action_request.component_result = {"verification_result": payload.result_status}

    action_names = {
        VerificationStatus.RUNNING: ("integrity_verification.started", "started"),
        VerificationStatus.PASSED: ("integrity_verification.passed", "success"),
        VerificationStatus.FAILED: ("integrity_verification.failed", "failed"),
        VerificationStatus.INCONCLUSIVE: ("integrity_verification.inconclusive", "inconclusive"),
        VerificationStatus.CANCELLED: ("integrity_verification.cancelled", "cancelled"),
        VerificationStatus.ERROR: ("integrity_verification.errored", "error"),
    }
    action, result_status = action_names[payload.result_status]
    record_phase2_audit(
        db,
        action=action,
        result_status=result_status,
        resource_type="integrity_verification",
        resource_id=verification.id,
        backup_id=backup.id,
        verification_id=verification.id,
        action_request_id=action_request.id if action_request else None,
        asset_id=backup.asset_id,
        correlation_id=verification.correlation_id,
        actor_id=component.component_id,
        source_component=component.component_id,
        reason=payload.failure_reason,
        safe_metadata={"verifier_version": payload.verifier_version} if payload.verifier_version else {},
    )
    db.commit()
    db.refresh(verification)
    return verification


@router.get("", response_model=Page[IntegrityVerificationRead])
def list_integrity_verifications(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    backup_id: UUID | None = None,
    status: VerificationStatus | None = None,
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(IntegrityVerification)
    if backup_id:
        query = query.filter(IntegrityVerification.backup_id == str(backup_id))
    if status:
        query = query.filter(IntegrityVerification.result_status == status.value)
    if from_:
        query = query.filter(IntegrityVerification.created_at >= as_utc(from_))
    if to:
        query = query.filter(IntegrityVerification.created_at <= as_utc(to))
    return paginate(query.order_by(IntegrityVerification.created_at.desc()), page, page_size)


@router.get("/{verification_id}", response_model=IntegrityVerificationRead)
def get_integrity_verification(verification_id: UUID, db: Session = Depends(get_db)):
    return get_or_404(db, IntegrityVerification, str(verification_id), "Integrity verification")