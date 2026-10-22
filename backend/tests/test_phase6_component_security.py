from datetime import datetime, timezone
import json
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database.session import get_db
from app.main import app
from app.models import (
    ActionRequest,
    Asset,
    AuditEvent,
    Backup,
    Base,
    IntegrityVerification,
    IsolationAction,
    RecoveryJob,
    ThreatIncident,
)


COMPONENTS = {
    "security-event-ingestor": {"token": "phase6-test-security-event-token", "scopes": ["security_events:write"]},
    "threat-ingestor": {"token": "phase6-test-threat-token", "scopes": ["threats:write"]},
    "risk-assessor": {"token": "phase6-test-risk-token", "scopes": ["risk_assessments:write"]},
    "decision-engine": {"token": "phase6-test-decision-token", "scopes": ["decisions:write"]},
    "backup-agent": {"token": "phase6-test-backup-token", "scopes": ["backups:write"]},
    "integrity-verifier": {"token": "phase6-test-verification-token", "scopes": ["verification:write"]},
    "isolation-agent": {"token": "phase6-test-isolation-token", "scopes": ["isolation:write"]},
    "recovery-agent": {"token": "phase6-test-recovery-token", "scopes": ["recovery:write"]},
}
USER_TOKEN = "phase6-test-human-bearer-token"


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


@pytest.fixture
def client(db: Session, monkeypatch):
    configured = [
        {"component_id": component_id, **config}
        for component_id, config in COMPONENTS.items()
    ]
    monkeypatch.setenv("MVP_COMPONENT_TOKENS", json.dumps(configured))
    monkeypatch.delenv("BACKUP_COMPONENT_TOKEN", raising=False)
    monkeypatch.setenv(
        "MVP_USER_TOKENS",
        json.dumps([{"token": USER_TOKEN, "user_id": "human-1", "role": "admin"}]),
    )

    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _component_auth(component_id: str) -> dict[str, str]:
    return {"X-Internal-Component-Token": COMPONENTS[component_id]["token"]}


def _asset(db: Session) -> Asset:
    asset = Asset(hostname=f"phase6-component-{uuid4().hex[:8]}")
    db.add(asset)
    db.commit()
    return asset


def _security_event_payload(asset_id: str) -> dict:
    return {
        "source": "telemetry-monitor",
        "source_event_id": str(uuid4()),
        "asset_id": asset_id,
        "occurred_at": datetime.now(timezone.utc).isoformat(),
        "event_type": "suspicious_process",
        "event_severity": "high",
        "summary": "Suspicious process activity",
        "source_component": "spoofed-component-label",
    }


def test_startup_public_routes_and_openapi_component_header(client: TestClient):
    assert client.get("/").status_code == 200
    assert client.get("/api/health").json() == {"status": "ok"}
    assert client.get("/docs").status_code == 200
    schema_response = client.get("/openapi.json")
    assert schema_response.status_code == 200
    parameters = schema_response.json()["paths"]["/api/internal/security-events"]["post"]["parameters"]
    assert any(item["name"] == "X-Internal-Component-Token" for item in parameters)


def test_event_ingestion_requires_component_credentials_and_scoped_identity(client: TestClient, db: Session):
    asset = _asset(db)
    payload = _security_event_payload(asset.id)
    missing = client.post("/api/internal/security-events", json=payload)
    invalid = client.post(
        "/api/internal/security-events",
        headers={"X-Internal-Component-Token": "wrong-phase6-secret"},
        json=payload,
    )
    assert missing.status_code == 401
    assert invalid.status_code == 401
    assert COMPONENTS["security-event-ingestor"]["token"] not in missing.text + invalid.text
    assert "wrong-phase6-secret" not in missing.text + invalid.text

    accepted = client.post(
        "/api/internal/security-events",
        headers=_component_auth("security-event-ingestor"),
        json=payload,
    )
    assert accepted.status_code == 201, accepted.text
    event = accepted.json()["event"]
    assert event["source_component"] == "security-event-ingestor"
    audit = db.scalar(
        select(AuditEvent).where(
            AuditEvent.action == "security_event.received",
            AuditEvent.event_id == event["id"],
        )
    )
    assert audit.actor_id == "security-event-ingestor"
    assert audit.source_component == "security-event-ingestor"
    assert audit.correlation_id == event["correlation_id"]


def test_component_scope_denial_is_audited_without_secrets(client: TestClient, db: Session):
    job_id = str(uuid4())
    token = COMPONENTS["security-event-ingestor"]["token"]
    denied = client.post(
        f"/api/internal/recovery-jobs/{job_id}/result",
        headers=_component_auth("security-event-ingestor"),
        json={},
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["code"] == "insufficient_component_scope"
    assert token not in denied.text
    denial = db.scalar(
        select(AuditEvent).where(
            AuditEvent.action == "recovery.component_request_rejected",
            AuditEvent.actor_id == "security-event-ingestor",
        )
    )
    assert denial is not None
    assert denial.safe_metadata["required_scope"] == "recovery:write"
    assert token not in json.dumps(denial.safe_metadata)
    assert denial.reason == "Component does not have the required scope"


def test_recovery_component_cannot_ingest_threats(client: TestClient, db: Session):
    asset = _asset(db)
    payload = {
        "title": "Component scope boundary",
        "threat_type": "endpoint_activity",
        "asset_id": asset.id,
        "detected_at": datetime.now(timezone.utc).isoformat(),
        "detection_source": "spoofed-detector",
    }
    denied = client.post(
        "/api/internal/threats",
        headers=_component_auth("recovery-agent"),
        json=payload,
    )
    assert denied.status_code == 403
    assert denied.json()["detail"]["code"] == "insufficient_component_scope"


def test_threat_risk_and_decision_components_use_distinct_scopes_and_audits(client: TestClient, db: Session):
    asset = _asset(db)
    incident_response = client.post(
        "/api/internal/threats",
        headers=_component_auth("threat-ingestor"),
        json={
            "title": "Scoped threat intake",
            "threat_type": "endpoint_activity",
            "asset_id": asset.id,
            "detected_at": datetime.now(timezone.utc).isoformat(),
            "detection_source": "monitor-reported-source",
        },
    )
    assert incident_response.status_code == 201, incident_response.text
    incident_id = incident_response.json()["id"]

    assessment_response = client.post(
        "/api/internal/risk-assessments",
        headers=_component_auth("risk-assessor"),
        json={"incident_id": incident_id, "asset_id": asset.id, "score": 88, "model_version": "spoofed-model"},
    )
    assert assessment_response.status_code == 201, assessment_response.text
    assessment_id = assessment_response.json()["id"]

    decision_response = client.post(
        "/api/internal/decisions",
        headers=_component_auth("decision-engine"),
        json={
            "incident_id": incident_id,
            "assessment_id": assessment_id,
            "asset_id": asset.id,
            "recommended_actions": ["isolate"],
            "rationale": "Recommendation only",
            "decision_engine_version": "spoofed-engine-label",
        },
    )
    assert decision_response.status_code == 201, decision_response.text

    for action, resource_id, component_id in (
        ("threat_incident.create", incident_id, "threat-ingestor"),
        ("risk_assessment.create", assessment_id, "risk-assessor"),
        ("decision.create", decision_response.json()["id"], "decision-engine"),
    ):
        audit = db.scalar(
            select(AuditEvent).where(AuditEvent.action == action, AuditEvent.resource_id == resource_id)
        )
        assert audit is not None
        assert audit.actor_id == component_id
        assert audit.source_component == component_id


def test_backup_component_scoped_registration_and_audit_identity(client: TestClient, db: Session):
    asset = _asset(db)
    token = COMPONENTS["backup-agent"]["token"]
    payload = {
        "asset_id": asset.id,
        "created_by_component": "client-supplied-spoofed-backup-agent",
        "external_backup_id": "scoped-backup-001",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "backup_type": "full",
        "size_bytes": 1024,
        "protection_status": "unknown",
        "lifecycle_status": "available",
        "encryption_status": "encrypted",
    }
    registered = client.post(
        "/api/internal/backups",
        headers=_component_auth("backup-agent"),
        json=payload,
    )
    assert registered.status_code == 201, registered.text
    # The provider label remains backup metadata; authenticated identity is the audit actor.
    assert registered.json()["created_by_component"] == "client-supplied-spoofed-backup-agent"
    audit = db.scalar(
        select(AuditEvent).where(
            AuditEvent.action == "backup.registered",
            AuditEvent.backup_id == registered.json()["backup_id"],
        )
    )
    assert audit.actor_id == "backup-agent"
    assert audit.source_component == "backup-agent"
    assert token not in json.dumps(audit.safe_metadata)
    assert client.post(
        "/api/internal/backups",
        headers=_component_auth("security-event-ingestor"),
        json={**payload, "external_backup_id": "scope-denied-backup"},
    ).status_code == 403


def test_integrity_verifier_identity_is_server_derived(client: TestClient, db: Session):
    asset = _asset(db)
    backup = Backup(
        asset_id=asset.id,
        source_component="backup-agent",
        external_backup_id="verification-backup-1",
        lifecycle_status="available",
        protection_status="protected",
        encryption_status="encrypted",
        correlation_id=str(uuid4()),
    )
    db.add(backup)
    db.flush()
    verification = IntegrityVerification(
        backup_id=backup.id,
        result_status="queued",
        correlation_id=backup.correlation_id,
    )
    db.add(verification)
    db.flush()
    verification_request = ActionRequest(
        action_type="verify_backup",
        asset_id=asset.id,
        backup_id=backup.id,
        verification_id=verification.id,
        requested_by_type="user",
        requested_by_id="verification-requester",
        approval_status="approved",
        execution_status="executing",
        component_result={"component_reference": "verify-claim-1"},
        correlation_id=verification.correlation_id,
    )
    db.add(verification_request)
    db.commit()

    result = client.post(
        f"/api/internal/integrity-verifications/{verification.id}/result",
        headers=_component_auth("integrity-verifier"),
        json={
            "result_status": "passed",
            "expected_digest": "a" * 64,
            "observed_digest": "a" * 64,
            "verifier_component": "spoofed-verifier",
            "component_reference": "verify-claim-1",
            "correlation_id": verification.correlation_id,
        },
    )
    assert result.status_code == 200, result.text
    assert result.json()["verifier_component"] == "integrity-verifier"
    audit = db.scalar(
        select(AuditEvent).where(
            AuditEvent.action == "integrity_verification.passed",
            AuditEvent.verification_id == verification.id,
        )
    )
    assert audit.actor_id == "integrity-verifier"
    assert audit.source_component == "integrity-verifier"


def test_isolation_component_scope_and_audit_identity(client: TestClient, db: Session):
    asset = _asset(db)
    request = ActionRequest(
        action_type="isolate",
        asset_id=asset.id,
        requested_by_type="user",
        approval_status="approved",
        execution_status="not_started",
        correlation_id=str(uuid4()),
    )
    db.add(request)
    db.flush()
    isolation = IsolationAction(
        action_request_id=request.id,
        asset_id=asset.id,
        execution_status="approved",
        network_state="unknown",
        correlation_id=request.correlation_id,
    )
    db.add(isolation)
    db.commit()

    result = client.post(
        f"/api/internal/isolation/{isolation.id}/result",
        headers=_component_auth("isolation-agent"),
        json={
            "execution_status": "executing",
            "network_state": "isolating",
            "component_reference": "isolation-operation-42",
            "correlation_id": isolation.correlation_id,
        },
    )
    assert result.status_code == 200, result.text
    audit = db.scalar(
        select(AuditEvent).where(
            AuditEvent.action == "isolation.started",
            AuditEvent.isolation_action_id == isolation.id,
        )
    )
    assert audit.actor_id == "isolation-agent"
    assert audit.source_component == "isolation-agent"
    assert audit.correlation_id == isolation.correlation_id


def test_recovery_component_scope_and_audit_identity(client: TestClient, db: Session):
    asset = _asset(db)
    incident = ThreatIncident(
        title="Recovery component test",
        threat_type="endpoint_activity",
        asset_id=asset.id,
        detected_at=datetime.now(timezone.utc),
        lifecycle_status="contained",
        correlation_id=str(uuid4()),
    )
    db.add(incident)
    db.flush()
    backup = Backup(
        asset_id=asset.id,
        source_component="backup-agent",
        external_backup_id="recovery-backup-1",
        lifecycle_status="available",
        protection_status="protected",
        encryption_status="encrypted",
        correlation_id=incident.correlation_id,
    )
    db.add(backup)
    db.flush()
    verification = IntegrityVerification(
        backup_id=backup.id,
        result_status="passed",
        completed_at=datetime.now(timezone.utc),
        correlation_id=incident.correlation_id,
    )
    db.add(verification)
    db.flush()
    action_request = ActionRequest(
        action_type="recover",
        incident_id=incident.id,
        asset_id=asset.id,
        backup_id=backup.id,
        verification_id=verification.id,
        requested_by_type="user",
        approval_status="approved",
        execution_status="executing",
        correlation_id=incident.correlation_id,
    )
    db.add(action_request)
    db.flush()
    job = RecoveryJob(
        action_request_id=action_request.id,
        asset_id=asset.id,
        incident_id=incident.id,
        backup_id=backup.id,
        verification_id=verification.id,
        job_status="restoring",
        component_reference="recovery-worker-17",
        correlation_id=incident.correlation_id,
    )
    db.add(job)
    db.commit()

    result = client.post(
        f"/api/internal/recovery-jobs/{job.id}/result",
        headers=_component_auth("recovery-agent"),
        json={
            "job_status": "scanning",
            "asset_id": asset.id,
            "incident_id": incident.id,
            "backup_id": backup.id,
            "verification_id": verification.id,
            "correlation_id": job.correlation_id,
            "component_reference": "recovery-worker-17",
            "malware_scan_status": "running",
            "security_validation_status": "running",
        },
    )
    assert result.status_code == 200, result.text
    audit = db.scalar(
        select(AuditEvent).where(
            AuditEvent.action == "recovery.scanning",
            AuditEvent.recovery_job_id == job.id,
        )
    )
    assert audit.actor_id == "recovery-agent"
    assert audit.source_component == "recovery-agent"


def test_human_bearer_does_not_authenticate_internal_component_route(client: TestClient, db: Session):
    asset = _asset(db)
    response = client.post(
        "/api/internal/security-events",
        headers={"Authorization": f"Bearer {USER_TOKEN}"},
        json=_security_event_payload(asset.id),
    )
    assert response.status_code == 401
    assert USER_TOKEN not in response.text


def test_authentication_tokens_are_never_audited(client: TestClient, db: Session):
    asset = _asset(db)
    payload = _security_event_payload(asset.id)
    invalid_secret = "phase6-invalid-secret-must-not-be-recorded"
    client.post(
        "/api/internal/security-events",
        headers={"X-Internal-Component-Token": invalid_secret},
        json=payload,
    )
    client.post(
        "/api/internal/security-events",
        headers=_component_auth("security-event-ingestor"),
        json=payload,
    )
    audits = db.scalars(select(AuditEvent)).all()
    serialized = " ".join(
        f"{item.actor_id} {item.source_component} {item.reason} {json.dumps(item.safe_metadata)}"
        for item in audits
    )
    assert invalid_secret not in serialized
    assert all(config["token"] not in serialized for config in COMPONENTS.values())
