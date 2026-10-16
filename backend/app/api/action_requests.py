from datetime import datetime, timezone
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.common import as_utc, get_or_404, paginate
from app.database.session import get_db
from app.enums import ActionExecutionStatus, ActionType, ApprovalStatus, IsolationExecutionStatus
from app.models import ActionRequest, Asset, Backup, Decision, IntegrityVerification, ThreatIncident
from app.schemas import (
    ActionRequestApproval,
    ActionRequestCreate,
    ActionRequestRead,
    ActionRequestRejection,
    AuditEventCreate,
    Page,
)
from app.services.audit import record_audit_event
from app.services.recovery_validation import validate_recovery_prerequisites
from app.services.user_auth import UserPrincipal, UserRole, get_current_user, require_role

router = APIRouter(
    prefix="/api/action-requests",
    tags=["Action Requests"],
    dependencies=[Depends(get_current_user)],
)


def _create_action_request(payload: ActionRequestCreate, db: Session, current_user: UserPrincipal) -> ActionRequest:
    if payload.action_type not in (
        ActionType.CREATE_BACKUP.value,
        ActionType.PROTECT_BACKUP.value,
        ActionType.VERIFY_BACKUP.value,
        ActionType.VERIFY_BACKUP.value,
        ActionType.ISOLATE.value,
        ActionType.RECOVER.value,
    ):
        raise HTTPException(status_code=422, detail="This action type must use its dedicated workflow endpoint")

    backup = db.get(Backup, str(payload.backup_id)) if payload.backup_id else None
    verification = db.get(IntegrityVerification, str(payload.verification_id)) if payload.verification_id else None
    decision = db.get(Decision, str(payload.decision_id)) if payload.decision_id else None
    incident = db.get(ThreatIncident, str(payload.incident_id)) if payload.incident_id else None
    if decision is not None and incident is None:
        incident = db.get(ThreatIncident, decision.incident_id)
    if payload.backup_id and backup is None:
        raise HTTPException(status_code=404, detail="Backup not found")
    if payload.verification_id and verification is None:
        raise HTTPException(status_code=404, detail="Integrity verification not found")
    if payload.decision_id and decision is None:
        raise HTTPException(status_code=404, detail="Decision not found")
    if payload.incident_id and incident is None:
        raise HTTPException(status_code=404, detail="Threat incident not found")
    asset = db.get(Asset, str(payload.asset_id)) if payload.asset_id else None
    if payload.asset_id and asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")

    if payload.action_type == ActionType.PROTECT_BACKUP.value and backup is None:
        raise HTTPException(status_code=422, detail="protect_backup requires backup_id")
    if payload.action_type == ActionType.CREATE_BACKUP.value and asset is None:
        raise HTTPException(status_code=422, detail="create_backup requires an existing asset_id")
    if payload.action_type == ActionType.VERIFY_BACKUP.value:
        if verification is None or backup is None:
            raise HTTPException(status_code=422, detail="verify_backup requires backup_id and verification_id")
        if verification.backup_id != backup.id:
            raise HTTPException(status_code=409, detail="Verification does not belong to the referenced backup")

    if payload.action_type == ActionType.ISOLATE.value and asset is None:
        raise HTTPException(status_code=422, detail="isolate requests require an existing asset_id")
    if payload.action_type == ActionType.RECOVER.value and not all(
        (asset, incident, backup, verification)
    ):
        raise HTTPException(
            status_code=422,
            detail="recover requests require asset_id, incident_id, backup_id, and verification_id",
        )

    asset_id = str(payload.asset_id) if payload.asset_id else (backup.asset_id if backup else verification.asset_id if verification else None)
    if backup and backup.asset_id != asset_id:
        raise HTTPException(status_code=409, detail="Action asset does not match backup asset")
    if verification and verification.asset_id != asset_id:
        raise HTTPException(status_code=409, detail="Action asset does not match verification asset")
    if backup and verification and verification.backup_id != backup.id:
        raise HTTPException(status_code=409, detail="Verification does not belong to the referenced backup")
    if decision:
        if decision.asset_id != asset_id or (incident and decision.incident_id != incident.id):
            raise HTTPException(status_code=409, detail="Decision does not match action asset or incident")
        if payload.action_type not in decision.recommended_actions:
            raise HTTPException(status_code=409, detail="Decision does not recommend the requested backup action")
        if payload.correlation_id and str(payload.correlation_id) != decision.correlation_id:
            raise HTTPException(status_code=409, detail="Correlation ID must preserve the decision correlation")
    if incident:
        affected_asset_ids = {incident.asset_id, *(item.id for item in incident.affected_assets)}
        if asset_id not in affected_asset_ids:
            raise HTTPException(status_code=409, detail="Action asset is not affected by the incident")
    if payload.action_type == ActionType.RECOVER.value:
        # A request may be recorded while awaiting approval or containment, but
        # all entity/link/backup-verification gates are checked here and again
        # at job creation and immediately before dispatch.
        validate_recovery_prerequisites(
            db,
            asset_id=asset_id,
            incident_id=incident.id,
            backup_id=backup.id,
            verification_id=verification.id,
            decision_id=decision.id if decision else None,
            require_isolation=False,
        )
    if decision and decision.approval_required and payload.action_type == ActionType.ISOLATE.value:
        approval_status = "pending"
    elif decision and payload.action_type == ActionType.ISOLATE.value:
        approval_status = "not_required"
    else:
        approval_status = "pending"

    correlation_id = (
        payload.correlation_id
        or (UUID(decision.correlation_id) if decision else None)
        or (UUID(incident.correlation_id) if payload.action_type == ActionType.RECOVER.value and incident else None)
        or (UUID(verification.correlation_id) if verification else None)
        or (UUID(incident.correlation_id) if incident else None)
        or uuid4()
    )
    if incident and not decision and payload.correlation_id and str(payload.correlation_id) != incident.correlation_id:
        raise HTTPException(status_code=409, detail="Correlation ID must preserve the incident correlation")
    action_request = ActionRequest(
        action_type=payload.action_type,
        decision_id=decision.id if decision else None,
        incident_id=incident.id if incident else None,
        asset_id=asset_id,
        backup_id=backup.id if backup else None,
        verification_id=verification.id if verification else None,
        isolation_mode=payload.isolation_mode if payload.isolation_mode else None,
        requested_by_type="user",
        requested_by_id=current_user.user_id,
        request_reason=payload.request_reason,
        approval_status=approval_status,
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
            action=(
                "backup.creation.requested"
                if payload.action_type == ActionType.CREATE_BACKUP.value
                else "backup.protection.requested"
                if backup and payload.action_type == ActionType.PROTECT_BACKUP.value
                else "isolation.requested"
                if payload.action_type == ActionType.ISOLATE.value
                else "recovery.requested"
                if payload.action_type == ActionType.RECOVER.value
                else "integrity_verification.action_requested"
            ),
            result_status="success",
            resource_type="action_request",
            resource_id=action_request.id,
            action_request_id=action_request.id,
            decision_id=decision.id if decision else None,
            backup_id=backup.id if backup else None,
            verification_id=verification.id if verification else None,
            asset_id=asset_id,
            incident_id=incident.id if incident else None,
            source_component="api",
            reason=payload.request_reason,
            correlation_id=correlation_id,
        ),
    )
    if payload.action_type == ActionType.ISOLATE.value and approval_status == "pending":
        record_audit_event(
            db,
            AuditEventCreate(
                actor_type="user",
                actor_id=current_user.user_id,
                action="isolation.approval_requested",
                result_status="pending",
                resource_type="action_request",
                resource_id=action_request.id,
                action_request_id=action_request.id,
                asset_id=asset_id,
                incident_id=incident.id if incident else None,
                decision_id=decision.id if decision else None,
                source_component="api",
                reason=payload.request_reason,
                correlation_id=correlation_id,
            ),
        )
    db.commit()
    db.refresh(action_request)
    return action_request


@router.post("", response_model=ActionRequestRead, status_code=status.HTTP_201_CREATED)
def create_action_request(
    payload: ActionRequestCreate,
    db: Session = Depends(get_db),
    current_user: UserPrincipal = Depends(require_role(UserRole.ANALYST)),
):
    try:
        return _create_action_request(payload, db, current_user)
    except HTTPException as exc:
        if payload.action_type == ActionType.RECOVER:
            record_audit_event(
                db,
                AuditEventCreate(
                    actor_type="user",
                    actor_id=current_user.user_id,
                    action="recovery.request_rejected",
                    result_status="rejected",
                    resource_type="action_request",
                    source_component="api",
                    reason=(exc.detail.get("code") if isinstance(exc.detail, dict) else str(exc.detail)),
                    correlation_id=payload.correlation_id,
                ),
            )
            db.commit()
        raise


@router.post("/{action_request_id}/approve", response_model=ActionRequestRead)
def approve_action_request(
    action_request_id: UUID,
    payload: ActionRequestApproval,
    db: Session = Depends(get_db),
    current_user: UserPrincipal = Depends(require_role(UserRole.APPROVER)),
):
    action_request = get_or_404(db, ActionRequest, str(action_request_id), "Action request")
    approvable_types = {
        ActionType.CREATE_BACKUP.value,
        ActionType.PROTECT_BACKUP.value,
        ActionType.VERIFY_BACKUP.value,
        ActionType.ISOLATE.value,
        ActionType.RELEASE_ISOLATION.value,
        ActionType.RECOVER.value,
    }
    if action_request.action_type not in approvable_types:
        raise HTTPException(status_code=409, detail="This action type does not use the approval transition")
    if action_request.requested_by_id == current_user.user_id:
        record_audit_event(
            db,
            AuditEventCreate(
                actor_type="user",
                actor_id=current_user.user_id,
                action="action_request.self_approval_rejected",
                result_status="rejected",
                resource_type="action_request",
                resource_id=action_request.id,
                action_request_id=action_request.id,
                asset_id=action_request.asset_id,
                incident_id=action_request.incident_id,
                correlation_id=action_request.correlation_id,
                source_component="api",
                reason="Requester and approver must be different users",
            ),
        )
        db.commit()
        raise HTTPException(
            status_code=409,
            detail={"code": "requester_cannot_approve", "message": "A requester cannot approve their own ActionRequest"},
        )
    if action_request.approval_status != "pending":
        raise HTTPException(status_code=409, detail="Action request is not awaiting approval")
    action_request.approval_status = "approved"
    action_request.approved_by_id = current_user.user_id
    action_request.approved_at = datetime.now(timezone.utc)
    isolation_action = action_request.isolation_action
    if isolation_action is not None and isolation_action.execution_status in {
        IsolationExecutionStatus.AWAITING_APPROVAL.value,
        IsolationExecutionStatus.RELEASE_REQUESTED.value,
    }:
        isolation_action.execution_status = IsolationExecutionStatus.APPROVED.value
    record_audit_event(
        db,
        AuditEventCreate(
            actor_type="user",
            actor_id=current_user.user_id,
            action=(
                "isolation.release.approved"
                if action_request.action_type == ActionType.RELEASE_ISOLATION.value
                else "isolation.approved"
                if action_request.action_type == ActionType.ISOLATE.value
                else "recovery.approved"
                if action_request.action_type == ActionType.RECOVER.value
                else "backup.creation.approved"
                if action_request.action_type == ActionType.CREATE_BACKUP.value
                else "integrity_verification.approved"
                if action_request.action_type == ActionType.VERIFY_BACKUP.value
                else "backup.protection.approved"
            ),
            result_status="success",
            resource_type="action_request",
            resource_id=action_request.id,
            action_request_id=action_request.id,
            isolation_action_id=isolation_action.id if isolation_action else None,
            decision_id=action_request.decision_id,
            backup_id=action_request.backup_id,
            asset_id=action_request.asset_id,
            incident_id=action_request.incident_id,
            source_component="api",
            correlation_id=action_request.correlation_id,
        ),
    )
    db.commit()
    db.refresh(action_request)
    return action_request


@router.post("/{action_request_id}/reject", response_model=ActionRequestRead)
def reject_action_request(
    action_request_id: UUID,
    payload: ActionRequestRejection,
    db: Session = Depends(get_db),
    current_user: UserPrincipal = Depends(require_role(UserRole.APPROVER)),
):
    action_request = get_or_404(db, ActionRequest, str(action_request_id), "Action request")
    if action_request.action_type not in {
        ActionType.CREATE_BACKUP.value,
        ActionType.ISOLATE.value,
        ActionType.VERIFY_BACKUP.value,
        ActionType.RELEASE_ISOLATION.value,
        ActionType.RECOVER.value,
        ActionType.PROTECT_BACKUP.value,
    }:
        raise HTTPException(status_code=409, detail="This action type does not use the rejection transition")
    if action_request.requested_by_id == current_user.user_id:
        record_audit_event(
            db,
            AuditEventCreate(
                actor_type="user",
                actor_id=current_user.user_id,
                action="action_request.self_rejection_rejected",
                result_status="rejected",
                resource_type="action_request",
                resource_id=action_request.id,
                action_request_id=action_request.id,
                asset_id=action_request.asset_id,
                incident_id=action_request.incident_id,
                correlation_id=action_request.correlation_id,
                source_component="api",
                reason="Requester and approver must be different users",
            ),
        )
        db.commit()
        raise HTTPException(
            status_code=409,
            detail={"code": "requester_cannot_approve", "message": "A requester cannot reject their own ActionRequest"},
        )
    if action_request.approval_status != "pending":
        raise HTTPException(status_code=409, detail="Action request is not awaiting approval")
    action_request.approval_status = "rejected"
    isolation_action = action_request.isolation_action
    if isolation_action is not None and isolation_action.execution_status in {
        IsolationExecutionStatus.AWAITING_APPROVAL.value,
        IsolationExecutionStatus.RELEASE_REQUESTED.value,
        IsolationExecutionStatus.APPROVED.value,
    }:
        isolation_action.execution_status = IsolationExecutionStatus.CANCELLED.value
        isolation_action.completed_at = datetime.now(timezone.utc)
    record_audit_event(
        db,
        AuditEventCreate(
            actor_type="user",
            actor_id=current_user.user_id,
            action=(
                "isolation.release.rejected"
                if action_request.action_type == ActionType.RELEASE_ISOLATION.value
                else "recovery.rejected"
                if action_request.action_type == ActionType.RECOVER.value
                else "backup.creation.rejected"
                if action_request.action_type == ActionType.CREATE_BACKUP.value
                else "integrity_verification.rejected"
                if action_request.action_type == ActionType.VERIFY_BACKUP.value
                else "isolation.rejected"
            ),
            result_status="rejected",
            resource_type="isolation_action" if isolation_action else "action_request",
            resource_id=isolation_action.id if isolation_action else action_request.id,
            action_request_id=action_request.id,
            isolation_action_id=isolation_action.id if isolation_action else None,
            asset_id=action_request.asset_id,
            incident_id=action_request.incident_id,
            decision_id=action_request.decision_id,
            source_component="api",
            reason=payload.reason,
            correlation_id=action_request.correlation_id,
        ),
    )
    db.commit()
    db.refresh(action_request)
    return action_request


@router.get("", response_model=Page[ActionRequestRead])
def list_action_requests(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    asset_id: UUID | None = None,
    incident_id: UUID | None = None,
    action_type: ActionType | None = None,
    approval_status: ApprovalStatus | None = None,
    execution_status: ActionExecutionStatus | None = None,
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(ActionRequest)
    if asset_id:
        query = query.filter(ActionRequest.asset_id == str(asset_id))
    if incident_id:
        query = query.filter(ActionRequest.incident_id == str(incident_id))
    if action_type:
        query = query.filter(ActionRequest.action_type == action_type.value)
    if approval_status:
        query = query.filter(ActionRequest.approval_status == approval_status.value)
    if execution_status:
        query = query.filter(ActionRequest.execution_status == execution_status.value)
    if from_:
        query = query.filter(ActionRequest.created_at >= as_utc(from_))
    if to:
        query = query.filter(ActionRequest.created_at <= as_utc(to))
    return paginate(query.order_by(ActionRequest.created_at.desc()), page, page_size)


@router.get("/{action_request_id}", response_model=ActionRequestRead)
def get_action_request(action_request_id: UUID, db: Session = Depends(get_db)):
    return get_or_404(db, ActionRequest, str(action_request_id), "Action request")