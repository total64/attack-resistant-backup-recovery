from datetime import datetime, timezone
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.common import as_utc, get_or_404, paginate
from app.database.session import get_db
from app.enums import ActionType, IsolationExecutionStatus, IsolationMode, IsolationNetworkState
from app.models import (
    ActionRequest,
    Asset,
    AuditEvent,
    Decision,
    IsolationAction,
    RecoveryJob,
    ThreatIncident,
)
from app.schemas import (
    AssetIsolationRead,
    AuditEventCreate,
    IsolationActionCreate,
    IsolationActionRead,
    IsolationComponentResult,
    IsolationReleaseCreate,
    Page,
)
from app.services.audit import record_audit_event
from app.services.internal_auth import ComponentPrincipal, ComponentScope, require_component_scope
from app.services.isolation_state import ACTIVE_ISOLATION_STATUSES, get_asset_isolation_state
from app.services.user_auth import UserPrincipal, UserRole, get_current_user, require_role

router = APIRouter(prefix="/api/isolation", tags=["Isolation"], dependencies=[Depends(get_current_user)])
request_router = APIRouter(
    prefix="/api/isolation-requests",
    tags=["Isolation"],
    dependencies=[Depends(get_current_user)],
)
asset_router = APIRouter(prefix="/api/assets", tags=["Isolation"], dependencies=[Depends(get_current_user)])
internal_router = APIRouter(prefix="/api/internal/isolation", tags=["Internal Isolation Component"])
isolation_component = require_component_scope(ComponentScope.ISOLATION_WRITE)


@internal_router.get("/queue", dependencies=[Depends(isolation_component)])
def list_approved_isolation_work(
    db: Session = Depends(get_db),
    _component: ComponentPrincipal = Depends(isolation_component),
):
    """List only approved or explicitly not-required isolation operations."""
    return [
        {
            "isolation_action_id": action.id,
            "action_request_id": action.action_request_id,
            "operation": action.action_request.action_type,
            "asset_id": action.asset_id,
            "incident_id": action.incident_id,
            "isolation_mode": action.isolation_mode,
            "execution_status": action.execution_status,
            "correlation_id": action.correlation_id,
        }
        for action in db.query(IsolationAction)
        .join(ActionRequest, ActionRequest.id == IsolationAction.action_request_id)
        .filter(
            ActionRequest.approval_status.in_(("approved", "not_required")),
            ActionRequest.execution_status == "not_started",
            IsolationAction.execution_status.in_(("requested", "approved", "release_requested")),
        )
        .order_by(IsolationAction.requested_at.asc())
        .all()
    ]

ACTIVE_INCIDENT_STATES = {"new", "triaged", "investigating", "contained", "recovery_in_progress"}
TERMINAL_ISOLATION_STATUSES = {
    IsolationExecutionStatus.ISOLATED.value,
    IsolationExecutionStatus.RELEASED.value,
    IsolationExecutionStatus.FAILED.value,
    IsolationExecutionStatus.CANCELLED.value,
}


def _audit(
    db: Session,
    *,
    action: str,
    result_status: str,
    isolation_action: IsolationAction | None = None,
    action_request: ActionRequest | None = None,
    asset_id: str | None = None,
    incident_id: str | None = None,
    decision_id: str | None = None,
    correlation_id: UUID | str | None = None,
    actor_type: str = "system",
    actor_id: str | None = None,
    source_component: str = "api",
    reason: str | None = None,
    safe_metadata: dict | None = None,
) -> AuditEvent:
    resolved_asset_id = asset_id or (isolation_action.asset_id if isolation_action else None)
    resolved_incident_id = incident_id or (isolation_action.incident_id if isolation_action else None)
    resolved_decision_id = decision_id or (isolation_action.decision_id if isolation_action else None)
    resolved_request_id = action_request.id if action_request else (
        isolation_action.action_request_id if isolation_action else None
    )
    resolved_correlation = correlation_id or (
        isolation_action.correlation_id if isolation_action else None
    ) or (action_request.correlation_id if action_request else None) or uuid4()
    return record_audit_event(
        db,
        AuditEventCreate(
            actor_type=actor_type,
            actor_id=actor_id,
            action=action,
            result_status=result_status,
            resource_type="isolation_action" if isolation_action else "action_request",
            resource_id=isolation_action.id if isolation_action else (action_request.id if action_request else None),
            asset_id=resolved_asset_id,
            incident_id=resolved_incident_id,
            decision_id=resolved_decision_id,
            action_request_id=resolved_request_id,
            isolation_action_id=isolation_action.id if isolation_action else None,
            source_component=source_component,
            reason=reason,
            safe_metadata=safe_metadata or {},
            correlation_id=resolved_correlation,
        ),
    )


def _reject(
    db: Session,
    *,
    code: str,
    message: str,
    status_code: int,
    action: str = "isolation.rejected",
    isolation_action: IsolationAction | None = None,
    action_request: ActionRequest | None = None,
    asset_id: str | None = None,
    incident_id: str | None = None,
    decision_id: str | None = None,
    correlation_id: UUID | str | None = None,
):
    _audit(
        db,
        action=action,
        result_status="rejected",
        isolation_action=isolation_action,
        action_request=action_request,
        asset_id=asset_id,
        incident_id=incident_id,
        decision_id=decision_id,
        correlation_id=correlation_id,
        actor_type="system",
        reason=code,
    )
    db.commit()
    raise HTTPException(status_code=status_code, detail={"code": code, "message": message})


def _active_isolation_for_asset(db: Session, asset_id: str) -> IsolationAction | None:
    state = get_asset_isolation_state(db, asset_id)
    return state.current_action if state.isolation_state != "not_isolated" else None


@request_router.post("", response_model=IsolationActionRead, status_code=status.HTTP_201_CREATED)
def create_isolation_action(
    payload: IsolationActionCreate,
    response: Response,
    db: Session = Depends(get_db),
    _current_user: UserPrincipal = Depends(require_role(UserRole.ANALYST)),
):
    asset = db.get(Asset, str(payload.asset_id))
    if asset is None:
        _reject(db, code="asset_not_found", message="Asset not found", status_code=404, asset_id=str(payload.asset_id))

    action_request = db.get(ActionRequest, str(payload.action_request_id))
    if action_request is None:
        _reject(db, code="action_request_invalid", message="Action request not found", status_code=404)
    if action_request.action_type != ActionType.ISOLATE.value or action_request.asset_id != asset.id:
        _reject(
            db,
            code="action_request_invalid",
            message="Action request must be an isolate request for the same asset",
            status_code=409,
            action_request=action_request,
            asset_id=asset.id,
        )
    if action_request.approval_status in {"rejected", "revoked"}:
        _reject(
            db,
            code="action_request_invalid",
            message="Rejected or revoked isolation requests cannot be dispatched",
            status_code=409,
            action_request=action_request,
        )
    incident_id = str(payload.incident_id) if payload.incident_id else action_request.incident_id
    decision_id = str(payload.decision_id) if payload.decision_id else action_request.decision_id
    if payload.incident_id and action_request.incident_id != str(payload.incident_id):
        _reject(db, code="action_request_invalid", message="Incident does not match the action request", status_code=409, action_request=action_request)
    if payload.decision_id and action_request.decision_id != str(payload.decision_id):
        _reject(db, code="decision_asset_mismatch", message="Decision does not match the action request", status_code=409, action_request=action_request)
    incident = db.get(ThreatIncident, incident_id) if incident_id else None
    if incident_id and incident is None:
        _reject(db, code="incident_not_found", message="Incident not found", status_code=404, action_request=action_request)
    if incident:
        affected_asset_ids = {incident.asset_id, *(item.id for item in incident.affected_assets)}
        if asset.id not in affected_asset_ids:
            _reject(
                db,
                code="incident_asset_mismatch",
                message="Incident is not associated with the requested asset",
                status_code=409,
                action_request=action_request,
                asset_id=asset.id,
                incident_id=incident.id,
            )

    decision = db.get(Decision, decision_id) if decision_id else None
    if decision_id and decision is None:
        _reject(db, code="decision_asset_mismatch", message="Decision not found", status_code=404, action_request=action_request)
    if decision:
        if decision.asset_id != asset.id or (incident and decision.incident_id != incident.id):
            _reject(
                db,
                code="decision_asset_mismatch",
                message="Decision does not match the requested asset and incident",
                status_code=409,
                action_request=action_request,
                asset_id=asset.id,
                incident_id=incident.id if incident else None,
                decision_id=decision.id,
            )
        if ActionType.ISOLATE not in decision.recommended_actions:
            _reject(
                db,
                code="action_request_invalid",
                message="Decision does not recommend isolation",
                status_code=409,
                action_request=action_request,
                decision_id=decision.id,
            )

    if payload.isolation_mode != action_request.isolation_mode:
        _reject(
            db,
            code="action_request_invalid",
            message="Isolation mode must match the ActionRequest",
            status_code=409,
            action_request=action_request,
        )
    if payload.correlation_id and str(payload.correlation_id) != action_request.correlation_id:
        _reject(
            db,
            code="action_request_invalid",
            message="Correlation ID must match the ActionRequest",
            status_code=409,
            action_request=action_request,
        )

    if action_request.isolation_action is not None:
        response.status_code = status.HTTP_200_OK
        return action_request.isolation_action

    active_action = _active_isolation_for_asset(db, asset.id)
    if active_action is not None:
        _reject(
            db,
            code="isolation_already_active",
            message="An active isolation operation already exists for this asset",
            status_code=409,
            isolation_action=active_action,
            action_request=action_request,
            asset_id=asset.id,
            incident_id=incident_id,
            decision_id=decision_id,
        )
    if action_request.execution_status != "not_started":
        _reject(
            db,
            code="action_request_invalid",
            message="Isolation ActionRequest is already executing or terminal",
            status_code=409,
            action_request=action_request,
        )

    if action_request.approval_status == "pending":
        execution_status = IsolationExecutionStatus.AWAITING_APPROVAL.value
    elif action_request.approval_status in {"approved", "not_required"}:
        execution_status = (
            IsolationExecutionStatus.APPROVED.value
            if action_request.approval_status == "approved"
            else IsolationExecutionStatus.REQUESTED.value
        )
    else:
        _reject(
            db,
            code="action_request_invalid",
            message="Isolation ActionRequest is not authorized for dispatch",
            status_code=409,
            action_request=action_request,
        )

    isolation_action = IsolationAction(
        action_request_id=action_request.id,
        asset_id=asset.id,
        incident_id=incident.id if incident else None,
        decision_id=decision.id if decision else None,
        isolation_mode=action_request.isolation_mode,
        network_state=IsolationNetworkState.UNKNOWN.value,
        execution_status=execution_status,
        correlation_id=action_request.correlation_id,
    )
    db.add(isolation_action)
    db.flush()
    _audit(
        db,
        action="isolation.dispatch_requested",
        result_status="awaiting_approval" if execution_status == IsolationExecutionStatus.AWAITING_APPROVAL.value else "requested",
        isolation_action=isolation_action,
        action_request=action_request,
        actor_type=action_request.requested_by_type,
        actor_id=action_request.requested_by_id,
        reason=payload.reason or action_request.request_reason,
    )
    db.commit()
    db.refresh(isolation_action)
    return isolation_action


def _release_policy_review(db: Session, isolation_action: IsolationAction) -> list[str]:
    reasons: list[str] = []
    incident = isolation_action.incident
    if incident is not None and incident.lifecycle_status in ACTIVE_INCIDENT_STATES:
        reasons.append("active_incident_requires_review")
    if incident is not None and incident.lifecycle_status in {"false_positive", "resolved", "closed"}:
        reasons.append("incident_state_requires_review")
    pending_recovery = db.scalar(
        select(RecoveryJob.id)
        .where(
            RecoveryJob.asset_id == isolation_action.asset_id,
            RecoveryJob.job_status.not_in(("completed", "failed", "cancelled")),
        )
        .limit(1)
    )
    if pending_recovery is not None:
        reasons.append("recovery_state_requires_review")
    return reasons


@request_router.post("/{isolation_action_id}/release", response_model=IsolationActionRead, status_code=status.HTTP_201_CREATED)
def request_isolation_release(
    isolation_action_id: UUID,
    payload: IsolationReleaseCreate,
    response: Response,
    db: Session = Depends(get_db),
    current_user: UserPrincipal = Depends(require_role(UserRole.ANALYST)),
):
    original = get_or_404(db, IsolationAction, str(isolation_action_id), "Isolation action")
    if original.action_request.action_type != ActionType.ISOLATE.value or original.execution_status != IsolationExecutionStatus.ISOLATED.value:
        _reject(
            db,
            code="release_not_allowed",
            message="Only a currently confirmed isolation can be released",
            status_code=409,
            isolation_action=original,
            action="isolation.release.rejected",
        )
    existing_release = db.scalar(
        select(IsolationAction)
        .where(
            IsolationAction.parent_isolation_action_id == original.id,
            IsolationAction.execution_status.in_(ACTIVE_ISOLATION_STATUSES),
        )
        .limit(1)
    )
    if existing_release is not None:
        response.status_code = status.HTTP_200_OK
        return existing_release
    current_state = get_asset_isolation_state(db, original.asset_id)
    if current_state.isolation_state != "isolated" or current_state.current_action is None or current_state.current_action.id != original.id:
        _reject(
            db,
            code="release_not_allowed",
            message="This is not the asset's current confirmed isolation",
            status_code=409,
            isolation_action=original,
            action="isolation.release.rejected",
        )
    review_reasons = _release_policy_review(db, original)
    if review_reasons:
        _reject(
            db,
            code="policy_requires_review",
            message="Release requires policy review before an ActionRequest can be created",
            status_code=409,
            isolation_action=original,
            action="isolation.release.rejected",
        )
    correlation_id = payload.correlation_id or uuid4()
    action_request = ActionRequest(
        action_type=ActionType.RELEASE_ISOLATION.value,
        decision_id=original.decision_id,
        incident_id=original.incident_id,
        asset_id=original.asset_id,
        requested_by_type="user",
        requested_by_id=current_user.user_id,
        request_reason=payload.reason,
        approval_status="pending",
        execution_status="not_started",
        correlation_id=str(correlation_id),
    )
    db.add(action_request)
    db.flush()
    release_action = IsolationAction(
        action_request_id=action_request.id,
        parent_isolation_action_id=original.id,
        asset_id=original.asset_id,
        incident_id=original.incident_id,
        decision_id=original.decision_id,
        isolation_mode=original.isolation_mode,
        network_state=IsolationNetworkState.ISOLATED.value,
        execution_status=IsolationExecutionStatus.RELEASE_REQUESTED.value,
        correlation_id=str(correlation_id),
    )
    db.add(release_action)
    db.flush()
    _audit(
        db,
        action="isolation.release.requested",
        result_status="pending_approval",
        isolation_action=release_action,
        action_request=action_request,
        actor_type="user",
        actor_id=current_user.user_id,
        reason=payload.reason,
    )
    _audit(
        db,
        action="isolation.release.approval_requested",
        result_status="pending",
        isolation_action=release_action,
        action_request=action_request,
        actor_type="user",
        actor_id=current_user.user_id,
        reason=payload.reason,
    )
    db.commit()
    db.refresh(release_action)
    return release_action


@internal_router.post(
    "/{isolation_action_id}/result",
    response_model=IsolationActionRead,
    dependencies=[Depends(isolation_component)],
)
def report_isolation_result(
    isolation_action_id: UUID,
    payload: IsolationComponentResult,
    db: Session = Depends(get_db),
    component: ComponentPrincipal = Depends(isolation_component),
):
    isolation_action = get_or_404(db, IsolationAction, str(isolation_action_id), "Isolation action")
    action_request = isolation_action.action_request
    operation = action_request.action_type
    if str(payload.correlation_id) != isolation_action.correlation_id:
        _reject(
            db,
            code="invalid_state_transition",
            message="Correlation ID does not match the isolation ActionRequest",
            status_code=409,
            isolation_action=isolation_action,
            action_request=action_request,
        )

    duplicate = (
        isolation_action.component_reference == payload.component_reference
        and isolation_action.execution_status == payload.execution_status
        and isolation_action.network_state == payload.network_state
        and isolation_action.failure_reason == payload.failure_reason
    )
    if duplicate:
        return isolation_action
    if isolation_action.execution_status in TERMINAL_ISOLATION_STATUSES:
        _reject(
            db,
            code="invalid_state_transition",
            message="Isolation operation is terminal and cannot be overwritten",
            status_code=409,
            isolation_action=isolation_action,
            action_request=action_request,
        )
    if isolation_action.component_reference and isolation_action.component_reference != payload.component_reference:
        _reject(
            db,
            code="invalid_state_transition",
            message="Component reference cannot change during an isolation operation",
            status_code=409,
            isolation_action=isolation_action,
            action_request=action_request,
        )
    reused_reference = db.scalar(
        select(IsolationAction.id)
        .where(
            IsolationAction.component_reference == payload.component_reference,
            IsolationAction.id != isolation_action.id,
        )
        .limit(1)
    )
    if reused_reference is not None:
        _reject(
            db,
            code="invalid_state_transition",
            message="Component reference is already associated with another isolation operation",
            status_code=409,
            isolation_action=isolation_action,
            action_request=action_request,
        )

    approved = action_request.approval_status in {"approved", "not_required"}
    current_status = isolation_action.execution_status
    if operation == ActionType.ISOLATE.value:
        if not approved:
            _reject(
                db,
                code="action_request_not_approved",
                message="Isolation ActionRequest must be approved before component execution",
                status_code=409,
                isolation_action=isolation_action,
                action_request=action_request,
            )
        if payload.execution_status == IsolationExecutionStatus.EXECUTING and payload.network_state not in {
            IsolationNetworkState.ISOLATING,
            IsolationNetworkState.UNKNOWN,
        }:
            _reject(
                db,
                code="invalid_state_transition",
                message="Isolation execution requires network_state=isolating or unknown",
                status_code=409,
                isolation_action=isolation_action,
                action_request=action_request,
            )
        if payload.execution_status == IsolationExecutionStatus.FAILED and payload.network_state == IsolationNetworkState.ISOLATED:
            _reject(
                db,
                code="invalid_state_transition",
                message="Failed isolation cannot report network_state=isolated",
                status_code=409,
                isolation_action=isolation_action,
                action_request=action_request,
            )
        allowed = {
            IsolationExecutionStatus.EXECUTING: {
                IsolationExecutionStatus.REQUESTED.value,
                IsolationExecutionStatus.APPROVED.value,
                IsolationExecutionStatus.EXECUTING.value,
            },
            IsolationExecutionStatus.ISOLATED: {IsolationExecutionStatus.EXECUTING.value},
            IsolationExecutionStatus.FAILED: {
                IsolationExecutionStatus.REQUESTED.value,
                IsolationExecutionStatus.APPROVED.value,
                IsolationExecutionStatus.EXECUTING.value,
            },
            IsolationExecutionStatus.CANCELLED: {
                IsolationExecutionStatus.REQUESTED.value,
                IsolationExecutionStatus.AWAITING_APPROVAL.value,
                IsolationExecutionStatus.APPROVED.value,
                IsolationExecutionStatus.EXECUTING.value,
            },
        }
    elif operation == ActionType.RELEASE_ISOLATION.value:
        if not approved:
            _reject(
                db,
                code="action_request_not_approved",
                message="Release ActionRequest must be approved before component execution",
                status_code=409,
                isolation_action=isolation_action,
                action_request=action_request,
                action="isolation.release.rejected",
            )
        if payload.execution_status == IsolationExecutionStatus.FAILED and payload.network_state == IsolationNetworkState.CONNECTED:
            _reject(
                db,
                code="invalid_state_transition",
                message="Failed release cannot report network_state=connected",
                status_code=409,
                isolation_action=isolation_action,
                action_request=action_request,
                action="isolation.release.rejected",
            )
        allowed = {
            IsolationExecutionStatus.EXECUTING: {
                IsolationExecutionStatus.RELEASE_REQUESTED.value,
                IsolationExecutionStatus.APPROVED.value,
                IsolationExecutionStatus.EXECUTING.value,
            },
            IsolationExecutionStatus.RELEASED: {IsolationExecutionStatus.EXECUTING.value},
            IsolationExecutionStatus.FAILED: {
                IsolationExecutionStatus.RELEASE_REQUESTED.value,
                IsolationExecutionStatus.APPROVED.value,
                IsolationExecutionStatus.EXECUTING.value,
            },
            IsolationExecutionStatus.CANCELLED: {
                IsolationExecutionStatus.RELEASE_REQUESTED.value,
                IsolationExecutionStatus.APPROVED.value,
                IsolationExecutionStatus.EXECUTING.value,
            },
        }
    else:
        _reject(
            db,
            code="action_request_invalid",
            message="IsolationAction must reference isolate or release_isolation",
            status_code=409,
            isolation_action=isolation_action,
            action_request=action_request,
        )

    valid_predecessors = allowed.get(payload.execution_status)
    if valid_predecessors is None or current_status not in valid_predecessors:
        _reject(
            db,
            code="invalid_state_transition",
            message=f"Cannot transition {operation} from {current_status} to {payload.execution_status}",
            status_code=409,
            isolation_action=isolation_action,
            action_request=action_request,
        )
    if operation == ActionType.RELEASE_ISOLATION.value and payload.execution_status == IsolationExecutionStatus.RELEASED:
        if payload.network_state != IsolationNetworkState.CONNECTED:
            _reject(
                db,
                code="invalid_state_transition",
                message="Confirmed release requires network_state=connected",
                status_code=409,
                isolation_action=isolation_action,
                action_request=action_request,
                action="isolation.release.rejected",
            )
    if operation == ActionType.RELEASE_ISOLATION.value and payload.execution_status == IsolationExecutionStatus.EXECUTING:
        if payload.network_state not in {IsolationNetworkState.RELEASING, IsolationNetworkState.UNKNOWN}:
            _reject(
                db,
                code="invalid_state_transition",
                message="Release execution requires network_state=releasing or unknown",
                status_code=409,
                isolation_action=isolation_action,
                action_request=action_request,
                action="isolation.release.rejected",
            )

    isolation_action.execution_status = payload.execution_status
    isolation_action.network_state = payload.network_state
    isolation_action.component_reference = payload.component_reference
    isolation_action.failure_reason = payload.failure_reason
    action_request.component_result = {
        "execution_status": payload.execution_status,
        "network_state": payload.network_state,
        "component_reference": payload.component_reference,
    }
    isolation_action.acknowledged_at = (
        as_utc(payload.acknowledged_at)
        if payload.acknowledged_at
        else isolation_action.acknowledged_at or datetime.now(timezone.utc)
    )
    if payload.execution_status in TERMINAL_ISOLATION_STATUSES:
        isolation_action.completed_at = as_utc(payload.completed_at) if payload.completed_at else datetime.now(timezone.utc)
    if operation == ActionType.RELEASE_ISOLATION.value and payload.execution_status == IsolationExecutionStatus.RELEASED:
        isolation_action.released_at = isolation_action.completed_at

    if payload.execution_status == IsolationExecutionStatus.EXECUTING:
        action_request.execution_status = "executing"
        action_request.started_at = action_request.started_at or isolation_action.acknowledged_at
        action = "isolation.release.started" if operation == ActionType.RELEASE_ISOLATION.value else "isolation.started"
        outcome = "executing"
    elif payload.execution_status == IsolationExecutionStatus.ISOLATED:
        action_request.execution_status = "succeeded"
        action_request.completed_at = isolation_action.completed_at
        action = "isolation.succeeded"
        outcome = "isolated"
    elif payload.execution_status == IsolationExecutionStatus.RELEASED:
        action_request.execution_status = "succeeded"
        action_request.completed_at = isolation_action.completed_at
        action = "isolation.released"
        outcome = "released"
    elif payload.execution_status == IsolationExecutionStatus.FAILED:
        action_request.execution_status = "failed"
        action_request.completed_at = isolation_action.completed_at
        action_request.failure_reason = payload.failure_reason
        action = "isolation.release.failed" if operation == ActionType.RELEASE_ISOLATION.value else "isolation.failed"
        outcome = "failed"
    else:
        action_request.execution_status = "cancelled"
        action_request.completed_at = isolation_action.completed_at
        action_request.failure_reason = payload.failure_reason
        action = "isolation.cancelled"
        outcome = "cancelled"
    record_audit_event(
        db,
        AuditEventCreate(
            actor_type="internal_component",
            actor_id=component.component_id,
            action=action,
            result_status=outcome,
            resource_type="isolation_action",
            resource_id=isolation_action.id,
            asset_id=isolation_action.asset_id,
            incident_id=isolation_action.incident_id,
            decision_id=isolation_action.decision_id,
            action_request_id=action_request.id,
            isolation_action_id=isolation_action.id,
            source_component=component.component_id,
            reason=payload.failure_reason,
            safe_metadata={"execution_status": payload.execution_status, "network_state": payload.network_state},
            correlation_id=isolation_action.correlation_id,
        ),
    )

    if operation == ActionType.ISOLATE.value and payload.execution_status == IsolationExecutionStatus.ISOLATED:
        _maybe_mark_incident_contained(db, isolation_action)
    db.commit()
    db.refresh(isolation_action)
    return isolation_action


def _maybe_mark_incident_contained(db: Session, isolation_action: IsolationAction) -> None:
    if isolation_action.incident_id is None:
        return
    incident = db.get(ThreatIncident, isolation_action.incident_id)
    if incident is None or incident.lifecycle_status not in {"new", "triaged", "investigating"}:
        return
    affected_asset_ids = {incident.asset_id, *(asset.id for asset in incident.affected_assets)}
    if not all(get_asset_isolation_state(db, asset_id).isolation_state == "isolated" for asset_id in affected_asset_ids):
        return
    previous_status = incident.lifecycle_status
    incident.lifecycle_status = "contained"
    db.flush()
    record_audit_event(
        db,
        AuditEventCreate(
            actor_type="system",
            action="threat_incident.lifecycle_change",
            result_status="success",
            resource_type="threat_incident",
            resource_id=incident.id,
            incident_id=incident.id,
            asset_id=incident.asset_id,
            decision_id=isolation_action.decision_id,
            action_request_id=isolation_action.action_request_id,
            isolation_action_id=isolation_action.id,
            source_component="isolation_workflow",
            reason="All assets affected by the incident have confirmed isolation",
            safe_metadata={"from": previous_status, "to": "contained"},
            correlation_id=isolation_action.correlation_id,
        ),
    )


def _asset_isolation_response(db: Session, asset: Asset) -> AssetIsolationRead:
    state = get_asset_isolation_state(db, asset.id)
    action = state.current_action
    if action is None:
        return AssetIsolationRead(
            asset_id=asset.id,
            isolation_state=state.isolation_state,
            active_isolation_action_id=None,
            execution_status=None,
            network_state=None,
            isolation_mode=None,
            requested_at=None,
            acknowledged_at=None,
            component_reference=None,
        )
    return AssetIsolationRead(
        asset_id=asset.id,
        isolation_state=state.isolation_state,
        active_isolation_action_id=action.id,
        execution_status=action.execution_status,
        network_state=action.network_state,
        isolation_mode=action.isolation_mode,
        requested_at=action.requested_at,
        acknowledged_at=action.acknowledged_at,
        component_reference=action.component_reference,
    )


@asset_router.get("/{asset_id}/isolation", response_model=AssetIsolationRead)
def get_asset_isolation(asset_id: UUID, db: Session = Depends(get_db)):
    asset = get_or_404(db, Asset, str(asset_id), "Asset")
    return _asset_isolation_response(db, asset)


@router.get("", response_model=Page[IsolationActionRead])
def list_isolation_actions(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    asset_id: UUID | None = None,
    incident_id: UUID | None = None,
    execution_status: IsolationExecutionStatus | None = None,
    isolation_mode: IsolationMode | None = None,
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(IsolationAction)
    if asset_id:
        query = query.filter(IsolationAction.asset_id == str(asset_id))
    if incident_id:
        query = query.filter(IsolationAction.incident_id == str(incident_id))
    if execution_status:
        query = query.filter(IsolationAction.execution_status == execution_status.value)
    if isolation_mode:
        query = query.filter(IsolationAction.isolation_mode == isolation_mode.value)
    if from_:
        query = query.filter(IsolationAction.requested_at >= as_utc(from_))
    if to:
        query = query.filter(IsolationAction.requested_at <= as_utc(to))
    return paginate(
        query.order_by(IsolationAction.requested_at.desc()), page, page_size
    )


@router.get("/{isolation_action_id}", response_model=IsolationActionRead)
def get_isolation_action(isolation_action_id: UUID, db: Session = Depends(get_db)):
    return get_or_404(db, IsolationAction, str(isolation_action_id), "Isolation action")