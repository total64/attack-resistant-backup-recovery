from datetime import datetime, timezone
import json
from uuid import UUID, uuid4

import pytest
from fastapi import HTTPException, Response
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.dashboard import dashboard_summary
from app.api.decisions import create_decision
from app.api.health import health_check
from app.api.risk_assessments import create_risk_assessment
from app.api.security_events import ingest_security_event
from app.api.threats import create_threat, triage_threat
from app.database.session import get_db
from app.main import app, root
from app.models import (
    ActionRequest,
    Asset,
    AuditEvent,
    Base,
    Decision,
    RiskAssessment,
    SecurityEvent,
    SystemSettings,
    ThreatIncident,
)
from app.schemas import (
    AssetExternalReference,
    DecisionCreate,
    DecisionRead,
    RiskAssessmentCreate,
    RiskAssessmentRead,
    SecurityEventCreate,
    SecurityEventRead,
    ThreatIncidentCreate,
    ThreatIncidentRead,
)
from app.services.internal_auth import ComponentPrincipal
from app.services.user_auth import UserPrincipal, UserRole


@pytest.fixture
def db():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    with Session(engine, expire_on_commit=False) as session:
        yield session
    engine.dispose()


def test_phase2_end_to_end_workflow_and_audit(db: Session, monkeypatch):
    # This test exercises the original manually staged Phase 2 API contract.
    # A separate HTTP integration test below exercises the automatic pipeline.
    from app.services import event_pipeline

    monkeypatch.setattr(event_pipeline, "process_security_event", lambda _db, _event: None)
    correlation_id = uuid4()
    asset = Asset(hostname="phase2-test-host", external_source="test", external_id="host-001")
    db.add(asset)
    db.commit()

    event_payload = SecurityEventCreate(
        source="test-monitor",
        source_event_id="event-001",
        asset_external_ref=AssetExternalReference(external_source="test", external_id="host-001"),
        occurred_at=datetime.now(timezone.utc),
        event_type="suspicious_process",
        event_severity="high",
        summary="Suspicious process activity detected",
        indicators=[{"kind": "process", "value": "sample.exe"}],
        evidence={"process_name": "sample.exe"},
        correlation_id=correlation_id,
    )
    detector = ComponentPrincipal("phase2-test-monitor", frozenset({"security_events:write"}))
    first = ingest_security_event(event_payload, Response(), db, detector)
    assert first.duplicate is False
    assert first.event.asset_id == UUID(asset.id)
    assert first.correlation_id == correlation_id
    assert SecurityEventRead.model_validate(first.event).correlation_id == correlation_id

    duplicate = ingest_security_event(event_payload, Response(), db, detector)
    assert duplicate.duplicate is True
    assert duplicate.event.id == first.event.id
    assert db.scalar(select(func.count(SecurityEvent.id))) == 1

    other_source_event = SecurityEventCreate(
        **{**event_payload.model_dump(), "source": "another-monitor"}
    )
    distinct_source = ingest_security_event(other_source_event, Response(), db, detector)
    assert distinct_source.duplicate is False

    incident_payload = ThreatIncidentCreate(
        title="Suspicious execution",
        threat_type="endpoint_activity",
        asset_id=UUID(asset.id),
        event_ids=[first.event.id],
        indicators=[{"kind": "process", "value": "sample.exe"}],
        description="Test incident",
        detection_source="test-monitor",
        detected_at=datetime.now(timezone.utc),
    )
    threat_component = ComponentPrincipal("phase2-test-threat", frozenset({"threats:write"}))
    risk_component = ComponentPrincipal("phase2-test-risk", frozenset({"risk_assessments:write"}))
    decision_engine = ComponentPrincipal("phase2-test-decision", frozenset({"decisions:write"}))
    incident = create_threat(incident_payload, db, threat_component)
    assert incident.lifecycle_status == "new"
    assert incident.correlation_id == str(correlation_id)
    assert incident.security_events[0].id == str(first.event.id)
    assert incident.affected_asset_ids == [asset.id]
    assert ThreatIncidentRead.model_validate(incident).affected_asset_ids == [UUID(asset.id)]

    assessment_78 = create_risk_assessment(
        RiskAssessmentCreate(incident_id=UUID(incident.id), asset_id=UUID(asset.id), score=78), db, risk_component
    )
    assessment_85 = create_risk_assessment(
        RiskAssessmentCreate(incident_id=UUID(incident.id), asset_id=UUID(asset.id), score=85), db, risk_component
    )
    assert assessment_78.risk_level == "HIGH"
    assert assessment_85.risk_level == "CRITICAL"
    assert incident.current_risk_assessment_id == assessment_85.id
    assert assessment_78.correlation_id == incident.correlation_id
    assert RiskAssessmentRead.model_validate(assessment_78).risk_level == "HIGH"

    decision = create_decision(
        DecisionCreate(
            incident_id=UUID(incident.id),
            assessment_id=UUID(assessment_85.id),
            asset_id=UUID(asset.id),
            recommended_actions=["isolate"],
            rationale="Recommendation only",
            decision_engine_version="test-engine-1",
        ),
        db,
        decision_engine,
    )
    assert decision.decision_status == "proposed"
    assert decision.correlation_id == assessment_85.correlation_id
    assert DecisionRead.model_validate(decision).decision_engine_version == "test-engine-1"
    assert db.scalar(select(func.count(ActionRequest.id))) == 0

    with pytest.raises(HTTPException) as mismatched_decision:
        create_decision(
            DecisionCreate(
                incident_id=UUID(incident.id),
                assessment_id=uuid4(),
                asset_id=UUID(asset.id),
                recommended_actions=["isolate"],
                rationale="Must reject an unknown assessment",
            ),
            db,
            decision_engine,
        )
    assert mismatched_decision.value.status_code == 404

    analyst = UserPrincipal(user_id="phase2-analyst", role=UserRole.ANALYST)
    triaged = triage_threat(UUID(incident.id), db, analyst)
    assert triaged.lifecycle_status == "triaged"
    with pytest.raises(HTTPException) as invalid_transition:
        triage_threat(UUID(incident.id), db, analyst)
    assert invalid_transition.value.status_code == 409

    summary = dashboard_summary(db)
    assert summary.total_security_events == 2
    assert summary.active_threats == 1
    assert summary.critical_risk_incidents == 1
    assert summary.risk_distribution["CRITICAL"] == 1

    assert db.scalar(select(func.count(AuditEvent.id))) >= 7
    successful_actions = {row.action for row in db.scalars(select(AuditEvent)).all()}
    assert {
        "security_event.received",
        "security_event.duplicate",
        "threat_incident.create",
        "risk_assessment.create",
        "decision.create",
        "threat_incident.lifecycle_change",
    } <= successful_actions


def test_detector_payload_runs_authenticated_persisted_pipeline(db: Session, monkeypatch):
    from detector.converter import detection_to_payload
    from detector.schema import Detection

    asset = Asset(hostname="detector-host", external_source="wazuh", external_id="agent-001")
    db.add(asset)
    db.commit()
    monkeypatch.setenv(
        "MVP_COMPONENT_TOKENS",
        json.dumps([{
            "component_id": "detector",
            "token": "integration-test-only-token",
            "scopes": ["security_events:write"],
        }]),
    )

    def override_db():
        yield db

    app.dependency_overrides[get_db] = override_db
    try:
        client = TestClient(app)
        payload = detection_to_payload(Detection(
            agent_id="agent-001",
            agent_name="agent-001",
            host="detector-host",
            detection_type="ransomware_confirmed",
            severity="critical",
            raw_alert_id="wazuh-alert-42",
            evidence={"backup_deletion": True},
        ))
        headers = {"X-Internal-Component-Token": "integration-test-only-token"}
        first = client.post("/api/internal/security-events", json=payload, headers=headers)
        duplicate = client.post("/api/internal/security-events", json=payload, headers=headers)
    finally:
        app.dependency_overrides.pop(get_db, None)

    assert first.status_code == 201, first.text
    assert duplicate.status_code == 200
    assert duplicate.json()["duplicate"] is True
    event_data = first.json()["event"]
    assert event_data["processing_status"] == "processed"
    event = db.get(SecurityEvent, event_data["id"])
    assert event is not None and event.incident_id is not None
    incident = db.get(ThreatIncident, event.incident_id)
    assert incident is not None and incident.security_events[0].id == event.id
    assessment = db.get(RiskAssessment, incident.current_risk_assessment_id)
    assert assessment is not None and assessment.score == 100
    decision = db.scalar(select(Decision).where(Decision.assessment_id == assessment.id))
    assert decision is not None
    assert decision.recommended_actions == ["isolate"]
    assert decision.approval_required is True
    assert db.scalar(select(func.count(ActionRequest.id))) == 0


def test_invalid_references_scores_and_correlations(db: Session):
    with pytest.raises(HTTPException) as missing_incident:
        create_risk_assessment(
            RiskAssessmentCreate(incident_id=uuid4(), asset_id=uuid4(), score=78),
            db,
            ComponentPrincipal("phase2-test-risk", frozenset({"risk_assessments:write"})),
        )
    assert missing_incident.value.status_code == 404
    assert db.scalar(select(func.count(AuditEvent.id))) == 1

    for invalid_score in (-1, 101):
        with pytest.raises(ValidationError):
            RiskAssessmentCreate(incident_id=uuid4(), asset_id=uuid4(), score=invalid_score)

    with pytest.raises(ValidationError):
        SecurityEventCreate(
            source="test",
            source_event_id="credential-event",
            asset_id=uuid4(),
            occurred_at=datetime.now(timezone.utc),
            event_type="test",
            event_severity="high",
            summary="credential capture",
            evidence={"message": "password=do-not-store"},
        )

    asset = Asset(hostname="valid-test-host")
    db.add(asset)
    db.commit()
    with pytest.raises(HTTPException) as missing_event:
        create_threat(
            ThreatIncidentCreate(
                title="Invalid reference",
                threat_type="test",
                asset_id=UUID(asset.id),
                event_ids=[uuid4()],
                detected_at=datetime.now(timezone.utc),
            ),
            db,
            ComponentPrincipal("phase2-test-threat", frozenset({"threats:write"})),
        )
    assert missing_event.value.status_code == 404
    assert db.scalar(select(func.count(ThreatIncident.id))) == 0


def test_saved_risk_thresholds_classify_future_assessments(db: Session):
    asset = Asset(hostname="configured-risk-threshold-host")
    settings = SystemSettings(
        is_singleton=True,
        risk_thresholds={
            "low_min": 0,
            "low_max": 9,
            "medium_min": 10,
            "medium_max": 29,
            "high_min": 30,
            "high_max": 69,
            "critical_min": 70,
            "critical_max": 100,
        },
        isolation_policy={},
        backup_policy={},
        recovery_policy={},
        notification_policy={},
    )
    db.add_all([asset, settings])
    db.flush()
    incident = ThreatIncident(
        title="Configured threshold incident",
        threat_type="test",
        asset_id=asset.id,
        detected_at=datetime.now(timezone.utc),
    )
    db.add(incident)
    db.commit()

    result = create_risk_assessment(
        RiskAssessmentCreate(incident_id=UUID(incident.id), asset_id=UUID(asset.id), score=75),
        db,
        ComponentPrincipal("phase2-test-risk", frozenset({"risk_assessments:write"})),
    )

    assert result.risk_level == "CRITICAL"


def test_root_health_and_openapi_routes():
    assert "running" in root()["message"]
    assert health_check() == {"status": "ok"}
    paths = app.openapi()["paths"]
    assert "/api/internal/security-events" in paths
    assert "/api/internal/threats" in paths
    assert "/api/internal/risk-assessments" in paths
    assert "/api/internal/decisions" in paths
    assert "/docs" not in paths  # FastAPI serves docs separately from the OpenAPI path table.
