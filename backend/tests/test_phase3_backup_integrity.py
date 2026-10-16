from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.database.session import get_db
from app.main import app
from app.models import ActionRequest, Asset, AuditEvent, Base, Backup, IntegrityVerification


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
    monkeypatch.setenv("BACKUP_COMPONENT_TOKEN", "phase3-test-component-token")
    monkeypatch.setenv(
        "MVP_USER_TOKENS",
        '[{"token":"phase6-viewer-test-token","user_id":"phase6-viewer","role":"viewer"},'
        '{"token":"phase6-analyst-test-token","user_id":"phase6-analyst","role":"analyst"},'
        '{"token":"phase6-approver-test-token","user_id":"phase6-approver","role":"approver"},'
        '{"token":"phase6-same-user-approver-test-token","user_id":"phase6-analyst","role":"approver"},'
        '{"token":"phase6-admin-test-token","user_id":"phase6-admin","role":"admin"}]',
    )

    def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        test_client.headers["Authorization"] = "Bearer phase6-analyst-test-token"
        yield test_client
    app.dependency_overrides.clear()


def _register_backup(client: TestClient, asset_id: str, ext_id: str, **overrides):
    body = {
        "asset_id": asset_id,
        "created_by_component": "backup-agent-a",
        "external_backup_id": ext_id,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "backup_type": "full",
        "size_bytes": 8192,
        "storage_reference": "vault://opaque-reference",
        "manifest_reference": "manifest://trusted/backup-manifest",
        "protection_status": "not_protected",
        "lifecycle_status": "available",
        "encryption_status": "encrypted",
        "correlation_id": str(uuid4()),
    }
    body.update(overrides)
    return client.post(
        "/api/internal/backups",
        headers={"X-Internal-Component-Token": "phase3-test-component-token"},
        json=body,
    )


def test_phase3_backup_protection_verification_and_readiness(client: TestClient, db: Session):
    asset = Asset(hostname="phase3-host")
    db.add(asset)
    db.commit()

    payload = {
        "asset_id": asset.id,
        "created_by_component": "backup-agent-a",
        "external_backup_id": "ext-001",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "backup_type": "full",
        "size_bytes": 8192,
        "storage_reference": "vault://opaque-reference",
        "manifest_reference": "manifest://trusted/backup-manifest",
        "protection_status": "pending",
        "lifecycle_status": "available",
        "encryption_status": "encrypted",
        "correlation_id": str(uuid4()),
    }
    unauthorized = client.post("/api/internal/backups", json=payload)
    assert unauthorized.status_code == 401

    registered = _register_backup(client, asset.id, "ext-001", **{
        key: value for key, value in payload.items() if key not in {"asset_id", "created_by_component", "external_backup_id"}
    })
    assert registered.status_code == 201
    backup = registered.json()
    backup_id = backup["backup_id"]
    correlation_id = backup["correlation_id"]
    assert backup["asset_id"] == asset.id
    assert "contents" not in backup and "password" not in backup

    duplicate = _register_backup(
        client,
        asset.id,
        "ext-001",
        protection_status="protected",
        correlation_id=str(uuid4()),
    )
    assert duplicate.status_code == 200
    assert duplicate.json()["backup_id"] == backup_id
    assert duplicate.json()["protection_status"] == "pending"
    assert client.get("/api/backups", params={"asset_id": asset.id}).json()["total"] == 1
    assert client.get(f"/api/backups/{backup_id}").json()["backup_id"] == backup_id

    request = client.post(
        "/api/action-requests",
        json={
            "action_type": "protect_backup",
            "asset_id": asset.id,
            "backup_id": backup_id,
            "requested_by_type": "user",
            "requested_by_id": "operator-1",
            "request_reason": "Apply backup protection",
            "correlation_id": correlation_id,
        },
    )
    assert request.status_code == 201
    action_request = request.json()
    assert action_request["approval_status"] == "pending"
    assert action_request["execution_status"] == "not_started"
    approved = client.post(
        f"/api/action-requests/{action_request['id']}/approve",
        headers={"Authorization": "Bearer phase6-approver-test-token"},
        json={"approved_by_id": "spoofed-approver-id"},
    )
    assert approved.status_code == 200
    assert approved.json()["approval_status"] == "approved"
    assert approved.json()["execution_status"] == "not_started"
    failed_claim = client.post(
        f"/api/internal/backups/action-requests/{action_request['id']}/claim",
        headers={"X-Internal-Component-Token": "phase3-test-component-token"},
        json={"component_reference": "provider-job-failed", "correlation_id": correlation_id},
    )
    assert failed_claim.status_code == 200

    failed_protection = client.post(
        f"/api/internal/backups/{backup_id}/protection-result",
        headers={"X-Internal-Component-Token": "phase3-test-component-token"},
        json={
            "protection_status": "failed",
            "execution_status": "failed",
            "failure_reason": "Provider rejected protection request",
            "component_reference": "provider-job-failed",
            "action_request_id": action_request["id"],
            "correlation_id": correlation_id,
        },
    )
    assert failed_protection.status_code == 200
    assert failed_protection.json()["backup"]["protection_status"] == "failed"
    assert failed_protection.json()["execution_status"] == "failed"

    passed_protection_request = client.post(
        "/api/action-requests",
        json={
            "action_type": "protect_backup",
            "asset_id": asset.id,
            "backup_id": backup_id,
            "requested_by_type": "user",
            "request_reason": "Retry after external correction",
        },
    ).json()
    approved_retry = client.post(
        f"/api/action-requests/{passed_protection_request['id']}/approve",
        headers={"Authorization": "Bearer phase6-approver-test-token"},
        json={},
    )
    assert approved_retry.status_code == 200
    retry_claim = client.post(
        f"/api/internal/backups/action-requests/{passed_protection_request['id']}/claim",
        headers={"X-Internal-Component-Token": "phase3-test-component-token"},
        json={
            "component_reference": "provider-job-42",
            "correlation_id": passed_protection_request["correlation_id"],
        },
    )
    assert retry_claim.status_code == 200
    protection_started = client.post(
        f"/api/internal/backups/{backup_id}/protection-result",
        headers={"X-Internal-Component-Token": "phase3-test-component-token"},
        json={
            "protection_status": "pending",
            "execution_status": "executing",
            "component_reference": "provider-job-42",
            "action_request_id": passed_protection_request["id"],
        },
    )
    assert protection_started.json()["execution_status"] == "executing"
    protected = client.post(
        f"/api/internal/backups/{backup_id}/protection-result",
        headers={"X-Internal-Component-Token": "phase3-test-component-token"},
        json={
            "protection_status": "protected",
            "execution_status": "succeeded",
            "component_reference": "provider-job-42",
            "action_request_id": passed_protection_request["id"],
            "correlation_id": passed_protection_request["correlation_id"],
        },
    )
    assert protected.status_code == 200
    assert protected.json()["backup"]["protection_status"] == "protected"
    assert passed_protection_request["execution_status"] == "not_started"
    not_yet_verified = client.get(f"/api/backups/{backup_id}/recovery-eligibility").json()
    assert not_yet_verified["eligible"] is False
    assert not_yet_verified["reasons"] == ["verification_missing"]
    rejected_selection = client.post(f"/api/backups/{backup_id}/select-for-recovery")
    assert rejected_selection.status_code == 409
    assert rejected_selection.json()["detail"]["reasons"] == ["verification_missing"]
    filtered = client.get(
        "/api/backups",
        params={
            "asset_id": asset.id,
            "lifecycle_status": "available",
            "protection_status": "protected",
            "backup_type": "full",
            "from": "2000-01-01T00:00:00Z",
            "to": "2100-01-01T00:00:00Z",
        },
    )
    assert filtered.status_code == 200
    assert filtered.json()["total"] == 1

    verification_request = client.post(
        f"/api/backups/{backup_id}/integrity-verifications",
        json={"reason": "Scheduled integrity check", "requested_by": "spoofed-requester", "correlation_id": correlation_id},
    )
    assert verification_request.status_code == 201
    requested = verification_request.json()
    assert requested["result_status"] == "queued"
    verification_id = requested["verification_id"]

    verification_action_request = db.scalar(
        select(ActionRequest).where(ActionRequest.verification_id == verification_id)
    )
    assert verification_action_request is not None
    approved_verification = client.post(
        f"/api/action-requests/{verification_action_request.id}/approve",
        headers={"Authorization": "Bearer phase6-approver-test-token"},
        json={},
    )
    assert approved_verification.status_code == 200
    worker_claim = client.post(
        f"/api/internal/integrity-verifications/{verification_id}/claim",
        headers={"X-Internal-Component-Token": "phase3-test-component-token"},
        json={
            "component_reference": "verifier-job-001",
            "correlation_id": correlation_id,
        },
    )
    assert worker_claim.status_code == 200, worker_claim.text
    assert worker_claim.json()["result_status"] == "running"

    internal_result_path = f"/api/internal/integrity-verifications/{verification_id}/result"
    result_body = {
        "result_status": "passed",
        "algorithm": "component-defined-v1",
        "expected_digest": "b" * 64,
        "observed_digest": "b" * 64,
        "verifier_component": "spoofed-value-is-ignored",
        "component_reference": "verifier-job-001",
        "verifier_version": "2.4",
        "correlation_id": correlation_id,
    }
    assert client.post(internal_result_path, json=result_body).status_code == 401
    verified_response = client.post(
        internal_result_path,
        headers={"X-Internal-Component-Token": "phase3-test-component-token"},
        json=result_body,
    )
    assert verified_response.status_code == 200, verified_response.text
    verification = verified_response.json()
    assert verification["verification_id"] == verification_id
    assert verification["backup_id"] == backup_id
    assert verification["asset_id"] == asset.id
    assert verification["result_status"] == "passed"
    assert verification["correlation_id"] == correlation_id

    eligible = client.get(f"/api/backups/{backup_id}/recovery-eligibility").json()
    assert eligible == {"eligible": True, "backup_id": backup_id, "reasons": []}
    selected = client.post(f"/api/backups/{backup_id}/select-for-recovery")
    assert selected.status_code == 200
    assert selected.json()["eligible"] is True
    inventory_item = client.get("/api/backups", params={"asset_id": asset.id}).json()["items"][0]
    assert inventory_item["verified"] is True
    assert inventory_item["recovery_eligible"] is True

    failed_verification = client.post(
        f"/api/backups/{backup_id}/integrity-verifications",
        json={"reason": "Repeat test"},
    ).json()
    assert failed_verification["correlation_id"] != correlation_id
    failed_action_request = db.scalar(
        select(ActionRequest).where(ActionRequest.verification_id == failed_verification["verification_id"])
    )
    assert failed_action_request is not None
    failed_approved = client.post(
        f"/api/action-requests/{failed_action_request.id}/approve",
        headers={"Authorization": "Bearer phase6-approver-test-token"},
        json={},
    )
    assert failed_approved.status_code == 200
    failed_claim = client.post(
        f"/api/internal/integrity-verifications/{failed_verification['verification_id']}/claim",
        headers={"X-Internal-Component-Token": "phase3-test-component-token"},
        json={
            "component_reference": "verifier-job-002",
            "correlation_id": failed_verification["correlation_id"],
        },
    )
    assert failed_claim.status_code == 200
    failed_result = client.post(
        f"/api/internal/integrity-verifications/{failed_verification['verification_id']}/result",
        headers={"X-Internal-Component-Token": "phase3-test-component-token"},
        json={
            "result_status": "failed",
            "observed_digest": "mismatch-evidence",
            "verifier_component": "integrity-agent",
            "component_reference": "verifier-job-002",
            "failure_reason": "Component reported mismatch",
            "correlation_id": failed_verification["correlation_id"],
        },
    )
    assert failed_result.status_code == 200
    assert failed_result.json()["correlation_id"] == failed_verification["correlation_id"]
    assert client.get(f"/api/backups/{backup_id}/recovery-eligibility").json()["eligible"] is False

    for lifecycle in ("quarantined", "expired", "unavailable"):
        blocked = _register_backup(client, asset.id, f"lifecycle-{lifecycle}", lifecycle_status=lifecycle)
        assert blocked.status_code == 201
        blocked_backup = blocked.json()
        assert client.get(f"/api/backups/{blocked_backup['backup_id']}/recovery-eligibility").json()["reasons"] == [
            f"backup_{lifecycle}",
            "verification_missing",
        ]

    separate_producer = _register_backup(
        client,
        asset.id,
        "ext-001",
        created_by_component="backup-agent-b",
    )
    assert separate_producer.status_code == 201
    assert separate_producer.json()["backup_id"] != backup_id

    assert client.get("/").status_code == 200
    assert client.get("/api/health").json() == {"status": "ok"}
    assert client.get("/docs").status_code == 200
    paths = app.openapi()["paths"]
    assert "/api/internal/backups" in paths
    assert "/api/internal/backups/{backup_id}/protection-result" in paths
    assert "/api/backups/{backup_id}/integrity-verifications" in paths
    assert "/api/internal/integrity-verifications/{verification_id}/result" in paths

    actions = set(db.scalars(select(AuditEvent.action)).all())
    assert {
        "backup.registered",
        "backup.protection.requested",
        "backup.protection.approved",
        "backup.protection.started",
        "backup.protection.failed",
        "backup.protection.succeeded",
        "integrity_verification.requested",
        "integrity_verification.passed",
        "integrity_verification.failed",
        "recovery.eligibility_check_passed",
        "recovery.eligibility_check_failed",
        "backup.selected_for_recovery",
    } <= actions
    assert db.scalar(select(func.count(IntegrityVerification.id))) == 2
    assert db.scalar(select(func.count(Backup.id))) == 5
    assert db.query(AuditEvent).filter(AuditEvent.correlation_id == correlation_id).count() >= 4


def test_verification_cannot_be_passed_without_trusted_reference(client: TestClient, db: Session):
    asset = Asset(hostname="phase3-no-manifest-host")
    db.add(asset)
    db.commit()
    backup = _register_backup(
        client,
        asset.id,
        "no-manifest",
        manifest_reference=None,
        protection_status="not_protected",
    ).json()
    verification = client.post(
        f"/api/backups/{backup['backup_id']}/integrity-verifications",
        json={},
    ).json()
    response = client.post(
        f"/api/internal/integrity-verifications/{verification['verification_id']}/result",
        headers={"X-Internal-Component-Token": "phase3-test-component-token"},
        json={
            "result_status": "passed",
            "observed_digest": "untrusted-frontend-value",
            "verifier_component": "integrity-agent",
        },
    )
    assert response.status_code == 422
    assert db.get(IntegrityVerification, verification["verification_id"]).result_status == "queued"