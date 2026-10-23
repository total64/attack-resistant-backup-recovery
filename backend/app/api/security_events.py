from datetime import datetime, timedelta, timezone
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy import case, func
from sqlalchemy.orm import Session

from app.api.common import as_utc, get_or_404, paginate
from app.database.session import get_db
from app.enums import EventProcessingStatus, EventSeverity
from app.models import Asset, SecurityEvent
from app.schemas import (
    Page,
    SecurityEventActivityPoint,
    SecurityEventCreate,
    SecurityEventIngestResponse,
    SecurityEventRead,
    SecurityEventSummary,
)
from app.services.asset_resolution import resolve_asset
from app.services.audit import record_phase2_audit
from app.services.internal_auth import ComponentPrincipal, ComponentScope, require_component_scope
from app.services.user_auth import get_current_user

router = APIRouter(prefix="/api/security-events", tags=["security-events"], dependencies=[Depends(get_current_user)])
security_event_component = require_component_scope(ComponentScope.SECURITY_EVENTS_WRITE)
internal_router = APIRouter(
    prefix="/api/internal/security-events",
    tags=["internal-security-events"],
    dependencies=[Depends(security_event_component)],
)


@internal_router.post("", response_model=SecurityEventIngestResponse, status_code=status.HTTP_201_CREATED)
def ingest_security_event(
    payload: SecurityEventCreate,
    response: Response,
    db: Session = Depends(get_db),
    component: ComponentPrincipal = Depends(security_event_component),
):
    correlation_id = payload.correlation_id or uuid4()
    existing = (
        db.query(SecurityEvent)
        .filter(SecurityEvent.source == payload.source, SecurityEvent.source_event_id == payload.source_event_id)
        .first()
    )
    if existing is not None:
        record_phase2_audit(
            db,
            action="security_event.duplicate",
            result_status="duplicate",
            resource_type="security_event",
            resource_id=existing.id,
            event_id=existing.id,
            asset_id=existing.asset_id,
            correlation_id=existing.correlation_id,
            actor_id=component.component_id,
            source_component=component.component_id,
            safe_metadata={"source_event_id": payload.source_event_id},
        )
        db.commit()
        response.status_code = status.HTTP_200_OK
        if existing.processing_status in {"received", "normalized"}:
            from app.services.event_pipeline import process_security_event

            try:
                process_security_event(db, existing)
            except Exception:
                db.rollback()
                existing = db.get(SecurityEvent, existing.id)
                existing.processing_status = "normalized"
                record_phase2_audit(
                    db,
                    action="security_event.processing_failed",
                    result_status="failed",
                    resource_type="security_event",
                    resource_id=existing.id,
                    event_id=existing.id,
                    asset_id=existing.asset_id,
                    correlation_id=existing.correlation_id,
                    actor_id=component.component_id,
                    source_component=component.component_id,
                    reason="Event pipeline failed; event remains available for retry",
                )
                db.commit()
        return SecurityEventIngestResponse(event=existing, duplicate=True, correlation_id=existing.correlation_id)

    try:
        asset = resolve_asset(db, payload.asset_id, payload.asset_external_ref)
        if payload.incident_id is not None:
            from app.models import ThreatIncident

            incident = db.get(ThreatIncident, str(payload.incident_id))
            if incident is None:
                raise HTTPException(status_code=404, detail="Threat incident not found")
            affected_asset_ids = {incident.asset_id, *(item.id for item in incident.affected_assets)}
            if asset.id not in affected_asset_ids:
                raise HTTPException(status_code=409, detail="Asset is not affected by the referenced incident")
    except HTTPException as exc:
        record_phase2_audit(
            db,
            action="security_event.received",
            result_status="rejected",
            resource_type="security_event",
            correlation_id=correlation_id,
            actor_id=component.component_id,
            source_component=component.component_id,
            reason=exc.detail,
        )
        db.commit()
        raise

    event = SecurityEvent(
        source=payload.source,
        source_event_id=payload.source_event_id,
        asset_id=asset.id,
        incident_id=str(payload.incident_id) if payload.incident_id else None,
        occurred_at=as_utc(payload.occurred_at),
        event_type=payload.event_type,
        event_severity=payload.event_severity,
        summary=payload.summary,
        indicators=payload.indicators,
        evidence=payload.evidence,
        source_component=component.component_id,
        correlation_id=str(correlation_id),
    )
    db.add(event)
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        existing = (
            db.query(SecurityEvent)
            .filter(SecurityEvent.source == payload.source, SecurityEvent.source_event_id == payload.source_event_id)
            .first()
        )
        if existing is None:
            raise HTTPException(status_code=409, detail="Security event conflicts with an existing record") from exc
        record_phase2_audit(
            db,
            action="security_event.duplicate",
            result_status="duplicate",
            resource_type="security_event",
            resource_id=existing.id,
            event_id=existing.id,
            asset_id=existing.asset_id,
            correlation_id=existing.correlation_id,
            actor_id=component.component_id,
            source_component=component.component_id,
            safe_metadata={"source_event_id": payload.source_event_id},
        )
        db.commit()
        response.status_code = status.HTTP_200_OK
        return SecurityEventIngestResponse(event=existing, duplicate=True, correlation_id=existing.correlation_id)

    record_phase2_audit(
        db,
        action="security_event.received",
        result_status="success",
        resource_type="security_event",
        resource_id=event.id,
        event_id=event.id,
        asset_id=asset.id,
        correlation_id=correlation_id,
        actor_id=component.component_id,
        source_component=component.component_id,
        safe_metadata={"source_event_id": payload.source_event_id},
    )
    db.commit()
    db.refresh(event)
    from app.services.event_pipeline import process_security_event

    try:
        process_security_event(db, event)
    except Exception:
        db.rollback()
        event = db.get(SecurityEvent, event.id)
        event.processing_status = "normalized"
        record_phase2_audit(
            db,
            action="security_event.processing_failed",
            result_status="failed",
            resource_type="security_event",
            resource_id=event.id,
            event_id=event.id,
            asset_id=event.asset_id,
            correlation_id=event.correlation_id,
            actor_id=component.component_id,
            source_component=component.component_id,
            reason="Event pipeline failed; event remains available for retry",
        )
        db.commit()
        db.refresh(event)
    return SecurityEventIngestResponse(event=event, duplicate=False, correlation_id=correlation_id)


@router.get("", response_model=Page[SecurityEventRead])
def list_security_events(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    asset_id: UUID | None = None,
    source: str | None = None,
    event_type: str | None = None,
    event_severity: EventSeverity | None = None,
    processing_status: EventProcessingStatus | None = None,
    incident_id: UUID | None = None,
    status: EventProcessingStatus | None = None,
    severity: EventSeverity | None = None,
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = None,
    db: Session = Depends(get_db),
):
    query = db.query(SecurityEvent)
    if asset_id:
        query = query.filter(SecurityEvent.asset_id == str(asset_id))
    if source:
        query = query.filter(SecurityEvent.source == source)
    if event_type:
        query = query.filter(SecurityEvent.event_type == event_type)
    selected_status = processing_status or status
    if selected_status:
        query = query.filter(SecurityEvent.processing_status == selected_status.value)
    selected_severity = event_severity or severity
    if selected_severity:
        query = query.filter(SecurityEvent.event_severity == selected_severity.value)
    if incident_id:
        query = query.filter(SecurityEvent.incident_id == str(incident_id))
    if from_:
        query = query.filter(SecurityEvent.occurred_at >= as_utc(from_))
    if to:
        query = query.filter(SecurityEvent.occurred_at <= as_utc(to))
    return paginate(query.order_by(SecurityEvent.occurred_at.desc()), page, page_size)


@router.get("/summary", response_model=SecurityEventSummary)
def security_event_summary(
    period: str = Query(default="24h", pattern="^(1h|6h|24h|7d)$"),
    asset_id: UUID | None = None,
    source: str | None = None,
    event_type: str | None = None,
    event_severity: EventSeverity | None = None,
    processing_status: EventProcessingStatus | None = None,
    incident_id: UUID | None = None,
    from_: datetime | None = Query(default=None, alias="from"),
    to: datetime | None = None,
    db: Session = Depends(get_db),
):
    """Return database-derived security-event counts and a bounded activity series."""
    period_durations = {
        "1h": timedelta(hours=1),
        "6h": timedelta(hours=6),
        "24h": timedelta(hours=24),
        "7d": timedelta(days=7),
    }
    now = datetime.now(timezone.utc)
    start = now - period_durations[period]
    end = now
    if from_ is not None:
        start = max(start, as_utc(from_))
    if to is not None:
        end = min(end, as_utc(to))
    bucket_count = 12
    bucket_seconds = period_durations[period].total_seconds() / bucket_count

    def filtered_events_query():
        query = db.query(SecurityEvent)
        if asset_id:
            query = query.filter(SecurityEvent.asset_id == str(asset_id))
        if source:
            query = query.filter(SecurityEvent.source == source)
        if event_type:
            query = query.filter(SecurityEvent.event_type == event_type)
        if event_severity:
            query = query.filter(SecurityEvent.event_severity == event_severity.value)
        if processing_status:
            query = query.filter(SecurityEvent.processing_status == processing_status.value)
        if incident_id:
            query = query.filter(SecurityEvent.incident_id == str(incident_id))
        return query

    events_query = filtered_events_query().filter(
        SecurityEvent.occurred_at >= start,
        SecurityEvent.occurred_at <= end,
    )
    buckets = [{"events": 0, "critical_events": 0} for _ in range(bucket_count)]
    bucket_case = case(
        *(
            (SecurityEvent.occurred_at < start + timedelta(seconds=bucket_seconds * index), index - 1)
            for index in range(1, bucket_count)
        ),
        else_=bucket_count - 1,
    )
    grouped_activity = events_query.with_entities(
        bucket_case.label("bucket_index"),
        func.count(SecurityEvent.id).label("event_count"),
        func.sum(case((SecurityEvent.event_severity == "critical", 1), else_=0)).label("critical_count"),
    ).group_by(bucket_case).all()
    for bucket_index, event_count, critical_count in grouped_activity:
        buckets[bucket_index]["events"] = event_count
        buckets[bucket_index]["critical_events"] = critical_count

    utc_midnight = now.replace(hour=0, minute=0, second=0, microsecond=0)
    today_start = max(utc_midnight, as_utc(from_)) if from_ is not None else utc_midnight
    today_end = min(now, as_utc(to)) if to is not None else now
    return SecurityEventSummary(
        total_events=events_query.count(),
        critical_events=events_query.filter(SecurityEvent.event_severity == "critical").count(),
        pending_processing_events=events_query.filter(
            SecurityEvent.processing_status.in_(("received", "normalized"))
        ).count(),
        events_today=filtered_events_query().filter(
            SecurityEvent.occurred_at >= today_start,
            SecurityEvent.occurred_at <= today_end,
        ).count(),
        monitored_assets=db.query(Asset).filter(Asset.monitoring_status != "unknown").count(),
        activity=[
            SecurityEventActivityPoint(
                bucket_start=start + timedelta(seconds=bucket_seconds * index),
                **bucket,
            )
            for index, bucket in enumerate(buckets)
        ],
    )


@router.get("/{event_id}", response_model=SecurityEventRead)
def get_security_event(event_id: UUID, db: Session = Depends(get_db)):
    return get_or_404(db, SecurityEvent, str(event_id), "Security event")
