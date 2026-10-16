from datetime import datetime, timezone
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.api.common import as_utc, get_or_404, paginate
from app.database.session import get_db
from app.enums import ActionExecutionStatus, ActionType, ApprovalStatus, BackupLifecycleStatus, BackupProtectionStatus
from app.models import ActionRequest, Asset, Backup
from app.schemas import (
    BackupCandidateRead,
    BackupCreate,
    BackupCreationResult,
    BackupCreationResultRead,
    BackupProtectionResult,
    BackupProtectionResultRead,
    BackupRead,
    ActionRequestRead,
    BackupWorkerClaim,
    Page,
    RecoveryEligibilityRead,
)
from app.services.audit import record_phase2_audit
from app.services.backup_readiness import assess_recovery_eligibility
from app.services.internal_auth import ComponentPrincipal, ComponentScope, require_component_scope
from app.services.user_auth import UserPrincipal, UserRole, get_current_user, require_role

router = APIRouter(prefix="/api/backups", tags=["Backups"], dependencies=[Depends(get_current_user)])
recovery_points_router = APIRouter(prefix="/api/assets", tags=["Backups"], dependencies=[Depends(get_current_user)])
internal_router = APIRouter(prefix="/api/internal/backups", tags=["Internal Backup Component"])
backup_component = require_component_scope(ComponentScope.BACKUPS_WRITE)


@internal_router.get("/queue", dependencies=[Depends(backup_component)])
def list_approved_backup_work(
    db: Session = Depends(get_db),
    _component: ComponentPrincipal = Depends(backup_component),
):
    """List approved create/protect requests for this scoped backup worker."""
    return [
        {
            "action_request_id": request.id,
            "action_type": request.action_type,
            "asset_id": request.asset_id,
            "backup_id": request.backup_id,
            "correlation_id": request.correlation_id,
            "request_reason": request.request_reason,
        }
        for request in db.query(ActionRequest)
        .filter(
            ActionRequest.action_type.in_((ActionType.CREATE_BACKUP.value, ActionType.PROTECT_BACKUP.value)),
            ActionRequest.approval_status == ApprovalStatus.APPROVED.value,
            ActionRequest.execution_status == ActionExecutionStatus.NOT_STARTED.value,
        )
        .order_by(ActionRequest.created_at.asc())
        .all()
    ]


@internal_router.post(
    "/action-requests/{action_request_id}/claim",
    response_model=ActionRequestRead,
    dependencies=[Depends(backup_component)],
)
def claim_backup_action(
    action_request_id: UUID,
    payload: BackupWorkerClaim,
    db: Session = Depends(get_db),
    component: ComponentPrincipal = Depends(backup_component),
):
    action_request = get_or_404(db, ActionRequest, str(action_request_id), "Action request")
    if action_request.action_type not in {ActionType.CREATE_BACKUP.value, ActionType.PROTECT_BACKUP.value}:
        raise HTTPException(status_code=409, detail="ActionRequest is not a backup creation or protection request")
    if action_request.approval_status != ApprovalStatus.APPROVED.value:
        raise HTTPException(status_code=409, detail="Backup operation requires explicit approver authorization")
    if str(payload.correlation_id) != action_request.correlation_id:
        raise HTTPException(status_code=409, detail="Correlation ID does not match the ActionRequest")
    previous_reference = action_request.component_result.get("component_reference")
    if action_request.execution_status == ActionExecutionStatus.EXECUTING.value:
        if previous_reference == payload.component_reference:
            return action_request
        raise HTTPException(status_code=409, detail="Backup operation is already claimed by another worker")
    if action_request.execution_status != ActionExecutionStatus.NOT_STARTED.value:
        raise HTTPException(status_code=409, detail="Only an unstarted backup operation can be claimed")
    if action_request.action_type == ActionType.CREATE_BACKUP.value and not action_request.asset_id:
        raise HTTPException(status_code=409, detail="Backup creation request is missing its asset")
    if action_request.action_type == ActionType.PROTECT_BACKUP.value and not action_request.backup_id:
        raise HTTPException(status_code=409, detail="Backup protection request is missing its backup")

    now = datetime.now(timezone.utc)
    action_request.execution_status = ActionExecutionStatus.EXECUTING.value
    action_request.started_at = now
    action_request.component_result = {
        "component_reference": payload.component_reference,
        "operation": action_request.action_type,
    }
    action = "backup.creation.started" if action_request.action_type == ActionType.CREATE_BACKUP.value else "backup.protection.started"
    record_phase2_audit(
        db,
        action=action,
        result_status="started",
        resource_type="action_request",
        resource_id=action_request.id,
        action_request_id=action_request.id,
        backup_id=action_request.backup_id,
        asset_id=action_request.asset_id,
        incident_id=action_request.incident_id,
        decision_id=action_request.decision_id,
        correlation_id=action_request.correlation_id,
        actor_id=component.component_id,
        source_component=component.component_id,
        safe_metadata={"component_reference": payload.component_reference},
    )
    db.commit()
    db.refresh(action_request)
    return action_request


@internal_router.post(
    "/action-requests/{action_request_id}/creation-result",
    response_model=BackupCreationResultRead,
    dependencies=[Depends(backup_component)],
)
def report_backup_creation_result(
    action_request_id: UUID,
    payload: BackupCreationResult,
    db: Session = Depends(get_db),
    component: ComponentPrincipal = Depends(backup_component),
):
    action_request = get_or_404(db, ActionRequest, str(action_request_id), "Action request")
    if action_request.action_type != ActionType.CREATE_BACKUP.value:
        raise HTTPException(status_code=409, detail="ActionRequest is not a backup creation request")
    if action_request.approval_status != ApprovalStatus.APPROVED.value:
        raise HTTPException(status_code=409, detail="Backup creation requires explicit approver authorization")
    if str(payload.correlation_id) != action_request.correlation_id:
        raise HTTPException(status_code=409, detail="Correlation ID does not match the ActionRequest")
    if action_request.execution_status != ActionExecutionStatus.EXECUTING.value:
        # Exact duplicate reports are idempotent, but a worker cannot skip its claim.
        previous = action_request.component_result
        if previous.get("component_reference") == payload.component_reference and previous.get("execution_status") == str(payload.execution_status):
            backup = db.get(Backup, previous.get("backup_id")) if previous.get("backup_id") else None
            return BackupCreationResultRead(
                backup=BackupRead.model_validate(backup) if backup else None,
                action_request_id=UUID(action_request.id),
                execution_status=payload.execution_status,
                correlation_id=UUID(action_request.correlation_id),
            )
        raise HTTPException(status_code=409, detail="Backup creation must be claimed before reporting its result")
    claim_reference = action_request.component_result.get("component_reference")
    if claim_reference != payload.component_reference:
        raise HTTPException(status_code=409, detail="Component reference does not match the backup claim")

    backup = None
    if payload.execution_status == ActionExecutionStatus.SUCCEEDED:
        existing = db.query(Backup).filter(
            Backup.source_component == component.component_id,
            Backup.external_backup_id == payload.external_backup_id,
        ).first()
        if existing is not None:
            raise HTTPException(status_code=409, detail="Backup identity already exists for this component")
        backup = Backup(
            asset_id=action_request.asset_id,
            source_component=component.component_id,
            external_backup_id=payload.external_backup_id,
            backup_created_at=as_utc(payload.created_at),
            backup_type=payload.backup_type,
            size_bytes=payload.size_bytes,
            storage_reference=payload.storage_reference,
            manifest_reference=payload.manifest_reference,
            lifecycle_status=BackupLifecycleStatus.AVAILABLE.value,
            protection_status=BackupProtectionStatus.NOT_PROTECTED.value,
            encryption_status=payload.encryption_status,
            correlation_id=action_request.correlation_id,
        )
        db.add(backup)
        db.flush()
        action_request.backup_id = backup.id
        action_request.execution_status = ActionExecutionStatus.SUCCEEDED.value
        action_request.completed_at = as_utc(payload.created_at)
        action_request.component_result = {
            **action_request.component_result,
            "execution_status": str(payload.execution_status),
            "backup_id": backup.id,
            "manifest_reference": payload.manifest_reference,
            "encryption_status": payload.encryption_status,
        }
        action = "backup.creation.succeeded"
        result_status = "success"
    else:
        action_request.execution_status = ActionExecutionStatus.FAILED.value
        action_request.completed_at = as_utc(payload.created_at) if payload.created_at else datetime.now(timezone.utc)
        action_request.failure_reason = payload.failure_reason
        action_request.component_result = {
            **action_request.component_result,
            "execution_status": str(payload.execution_status),
        }
        action = "backup.creation.failed"
        result_status = "failed"
    record_phase2_audit(
        db,
        action=action,
        result_status=result_status,
        resource_type="backup" if backup else "action_request",
        resource_id=backup.id if backup else action_request.id,
        action_request_id=action_request.id,
        backup_id=backup.id if backup else None,
        asset_id=action_request.asset_id,
        incident_id=action_request.incident_id,
        decision_id=action_request.decision_id,
        correlation_id=action_request.correlation_id,
        actor_id=component.component_id,
        source_component=component.component_id,
        reason=payload.failure_reason,
        safe_metadata={"execution_status": str(payload.execution_status)},
    )
    db.commit()
    if backup is not None:
        db.refresh(backup)
    return BackupCreationResultRead(
        backup=BackupRead.model_validate(backup) if backup else None,
        action_request_id=UUID(action_request.id),
        execution_status=payload.execution_status,
        correlation_id=UUID(action_request.correlation_id),
    )


def _candidate(db: Session, backup: Backup) -> BackupCandidateRead:
    eligibility = assess_recovery_eligibility(db, backup)
    safe_metadata = BackupRead.model_validate(backup).model_dump()
    return BackupCandidateRead(
        **safe_metadata,
        verified=eligibility.verified,
        recovery_eligible=eligibility.eligible,
        eligibility_reasons=eligibility.reasons,
    )


@internal_router.post(
    "",
    response_model=BackupRead,
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(backup_component)],
)
def register_backup(
    payload: BackupCreate,
    response: Response,
    db: Session = Depends(get_db),
    component: ComponentPrincipal = Depends(backup_component),
):
    correlation_id = payload.correlation_id or uuid4()
    asset = db.get(Asset, str(payload.asset_id))
    if asset is None:
        record_phase2_audit(
            db,
            action="backup.registration_rejected",
            result_status="rejected",
            resource_type="backup",
            asset_id=payload.asset_id,
            correlation_id=correlation_id,
            actor_id=component.component_id,
            source_component=component.component_id,
            reason="Asset not found",
        )
        db.commit()
        raise HTTPException(status_code=404, detail="Asset not found")

    existing = (
        db.query(Backup)
        .filter(
            Backup.source_component == payload.created_by_component,
            Backup.external_backup_id == payload.external_backup_id,
        )
        .first()
    )
    if existing is not None:
        record_phase2_audit(
            db,
            action="backup.registered",
            result_status="duplicate",
            resource_type="backup",
            resource_id=existing.id,
            backup_id=existing.id,
            asset_id=existing.asset_id,
            correlation_id=existing.correlation_id,
            actor_id=component.component_id,
            source_component=component.component_id,
            reason="Existing producer identity returned unchanged",
        )
        db.commit()
        response.status_code = status.HTTP_200_OK
        return existing

    backup = Backup(
        asset_id=asset.id,
        source_component=payload.created_by_component,
        external_backup_id=payload.external_backup_id,
        backup_created_at=as_utc(payload.created_at),
        backup_type=payload.backup_type,
        size_bytes=payload.size_bytes,
        storage_reference=payload.storage_reference,
        manifest_reference=payload.manifest_reference,
        protection_status=payload.protection_status,
        lifecycle_status=payload.lifecycle_status,
        encryption_status=payload.encryption_status,
        correlation_id=str(correlation_id),
    )
    db.add(backup)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        existing = (
            db.query(Backup)
            .filter(
                Backup.source_component == payload.created_by_component,
                Backup.external_backup_id == payload.external_backup_id,
            )
            .first()
        )
        if existing is None:
            raise HTTPException(status_code=409, detail="Backup identity conflicts with an existing record") from exc
        record_phase2_audit(
            db,
            action="backup.registered",
            result_status="duplicate",
            resource_type="backup",
            resource_id=existing.id,
            backup_id=existing.id,
            asset_id=existing.asset_id,
            correlation_id=existing.correlation_id,
            actor_id=component.component_id,
            source_component=component.component_id,
            reason="Concurrent duplicate producer identity returned unchanged",
        )
        db.commit()
        response.status_code = status.HTTP_200_OK
        return existing

    record_phase2_audit(
        db,
        action="backup.registered",
        result_status="success",
        resource_type="backup",
        resource_id=backup.id,
        backup_id=backup.id,
        asset_id=asset.id,
        correlation_id=correlation_id,
        actor_id=component.component_id,
        source_component=component.component_id,
    )
    db.commit()
    db.refresh(backup)
    return backup


@internal_router.post(
    "/{backup_id}/protection-result",
    response_model=BackupProtectionResultRead,
    dependencies=[Depends(backup_component)],
)
def report_protection_result(
    backup_id: UUID,
    payload: BackupProtectionResult,
    db: Session = Depends(get_db),
    component: ComponentPrincipal = Depends(backup_component),
):
    backup = get_or_404(db, Backup, str(backup_id), "Backup")
    action_request = None
    if payload.action_request_id is not None:
        action_request = db.get(ActionRequest, str(payload.action_request_id))
        if action_request is None:
            raise HTTPException(status_code=404, detail="Action request not found")
        if action_request.action_type != "protect_backup" or action_request.backup_id != backup.id:
            raise HTTPException(status_code=409, detail="Action request does not target this backup protection operation")
        if action_request.asset_id != backup.asset_id:
            raise HTTPException(status_code=409, detail="Action request asset does not match the backup")
        if action_request.correlation_id and payload.correlation_id and action_request.correlation_id != str(payload.correlation_id):
            raise HTTPException(status_code=409, detail="Correlation ID does not match the action request")
        if action_request.approval_status != ApprovalStatus.APPROVED.value:
            raise HTTPException(status_code=409, detail="Backup protection requires explicit approval")
        if action_request.execution_status != ActionExecutionStatus.EXECUTING.value:
            raise HTTPException(status_code=409, detail="Backup protection must be claimed before reporting a result")
        if action_request.component_result.get("component_reference") != payload.component_reference:
            raise HTTPException(status_code=409, detail="Component reference does not match the protection claim")
        if action_request.component_result.get("operation") != ActionType.PROTECT_BACKUP.value:
            raise HTTPException(status_code=409, detail="ActionRequest was not claimed for backup protection")
    elif payload.action_request_id is None:
        raise HTTPException(status_code=422, detail="Protection results require the authorized ActionRequest ID")

    correlation_id = (
        payload.correlation_id
        or (UUID(action_request.correlation_id) if action_request else UUID(backup.correlation_id))
    )
    backup.protection_status = payload.protection_status
    if action_request is not None:
        action_request.execution_status = payload.execution_status
        action_request.started_at = action_request.started_at or datetime.now(timezone.utc)
        if payload.execution_status != ActionExecutionStatus.EXECUTING:
            action_request.completed_at = as_utc(payload.completed_at) if payload.completed_at else datetime.now(timezone.utc)
        action_request.failure_reason = payload.failure_reason
        action_request.component_result = {
            **action_request.component_result,
            "component_reference": payload.component_reference,
            "protection_status": payload.protection_status,
            "execution_status": str(payload.execution_status),
        }
    if payload.execution_status == ActionExecutionStatus.EXECUTING:
        action = "backup.protection.started"
        result = "started"
    elif payload.execution_status == ActionExecutionStatus.SUCCEEDED:
        action = "backup.protection.succeeded"
        result = "success"
    else:
        action = "backup.protection.failed"
        result = "failed"
    record_phase2_audit(
        db,
        action=action,
        result_status=result,
        resource_type="backup",
        resource_id=backup.id,
        backup_id=backup.id,
        asset_id=backup.asset_id,
        action_request_id=action_request.id if action_request else None,
        correlation_id=correlation_id,
        actor_id=component.component_id,
        source_component=component.component_id,
        reason=payload.failure_reason,
        safe_metadata={"execution_status": payload.execution_status},
    )
    db.commit()
    db.refresh(backup)
    return BackupProtectionResultRead(
        backup=BackupRead.model_validate(backup),
        action_request_id=UUID(action_request.id) if action_request else None,
        execution_status=payload.execution_status,
        correlation_id=correlation_id,
    )


@router.get("", response_model=Page[BackupCandidateRead])
def list_backups(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    asset_id: UUID | None = None,
    lifecycle_status: BackupLifecycleStatus | None = None,
    protection_status: BackupProtectionStatus | None = None,
    backup_type: str | None = None,
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(Backup)
    if asset_id:
        query = query.filter(Backup.asset_id == str(asset_id))
    if lifecycle_status:
        query = query.filter(Backup.lifecycle_status == lifecycle_status.value)
    if protection_status:
        query = query.filter(Backup.protection_status == protection_status.value)
    if backup_type:
        query = query.filter(Backup.backup_type == backup_type)
    if from_:
        query = query.filter(Backup.backup_created_at >= as_utc(from_))
    if to:
        query = query.filter(Backup.backup_created_at <= as_utc(to))
    page_result = paginate(query.order_by(Backup.backup_created_at.desc()), page, page_size)
    return Page[BackupCandidateRead](
        items=[_candidate(db, backup) for backup in page_result.items],
        page=page_result.page,
        page_size=page_result.page_size,
        total=page_result.total,
    )


@router.get("/{backup_id}/recovery-eligibility", response_model=RecoveryEligibilityRead)
def get_recovery_eligibility(backup_id: UUID, db: Session = Depends(get_db)):
    backup = get_or_404(db, Backup, str(backup_id), "Backup")
    eligibility = assess_recovery_eligibility(db, backup)
    record_phase2_audit(
        db,
        action=("recovery.eligibility_check_passed" if eligibility.eligible else "recovery.eligibility_check_failed"),
        result_status=("success" if eligibility.eligible else "failed"),
        resource_type="backup",
        resource_id=backup.id,
        backup_id=backup.id,
        asset_id=backup.asset_id,
        correlation_id=backup.correlation_id,
        source_component="api",
        actor_type="system",
        reason=", ".join(eligibility.reasons) if eligibility.reasons else None,
    )
    db.commit()
    return RecoveryEligibilityRead(
        eligible=eligibility.eligible,
        backup_id=backup.id,
        reasons=eligibility.reasons,
    )


@router.post("/{backup_id}/select-for-recovery", response_model=RecoveryEligibilityRead)
def select_backup_for_recovery(
    backup_id: UUID,
    db: Session = Depends(get_db),
    current_user: UserPrincipal = Depends(require_role(UserRole.ANALYST)),
):
    """Record a readiness-checked selection only; this does not execute recovery."""
    backup = get_or_404(db, Backup, str(backup_id), "Backup")
    eligibility = assess_recovery_eligibility(db, backup)
    if not eligibility.eligible:
        record_phase2_audit(
            db,
            action="backup.selected_for_recovery",
            result_status="rejected",
            resource_type="backup",
            resource_id=backup.id,
            backup_id=backup.id,
            asset_id=backup.asset_id,
            correlation_id=backup.correlation_id,
            actor_type="user",
            actor_id=current_user.user_id,
            source_component="api",
            reason=", ".join(eligibility.reasons),
        )
        db.commit()
        raise HTTPException(status_code=409, detail={"eligible": False, "reasons": eligibility.reasons})
    record_phase2_audit(
        db,
        action="backup.selected_for_recovery",
        result_status="success",
        resource_type="backup",
        resource_id=backup.id,
        backup_id=backup.id,
        asset_id=backup.asset_id,
        correlation_id=backup.correlation_id,
        actor_type="user",
        actor_id=current_user.user_id,
        source_component="api",
    )
    db.commit()
    return RecoveryEligibilityRead(eligible=True, backup_id=backup.id, reasons=[])


@recovery_points_router.get("/{asset_id}/recovery-points", response_model=Page[BackupCandidateRead])
def list_asset_recovery_points(
    asset_id: UUID,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    if db.get(Asset, str(asset_id)) is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    query = db.query(Backup).filter(Backup.asset_id == str(asset_id))
    page_result = paginate(query.order_by(Backup.backup_created_at.desc()), page, page_size)
    return Page[BackupCandidateRead](
        items=[_candidate(db, backup) for backup in page_result.items],
        page=page_result.page,
        page_size=page_result.page_size,
        total=page_result.total,
    )


@router.get("/{backup_id}", response_model=BackupCandidateRead)
def get_backup(backup_id: UUID, db: Session = Depends(get_db)):
    return _candidate(db, get_or_404(db, Backup, str(backup_id), "Backup"))