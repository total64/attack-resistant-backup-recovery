"""API-to-worker lifecycle tests; every host/filesystem side effect is test-confined."""
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.backup.backup_manager import BackupResult
from app.backup.protection import LockResult
from app.database.session import get_db
from app.isolation.firewall import MockFirewall
from app.main import app
from app.models import ActionRequest, Asset, AuditEvent, Backup, Base, IntegrityVerification
from app.workers.backup_worker import BackupCreationWorker
from app.workers.integrity_worker import IntegrityVerificationWorker
from app.workers.isolation_worker import IsolationWorker
from app.workers.protection_worker import BackupProtectionWorker
from app.workers.recovery_worker import RecoveryWorker

COMPONENTS = [
    {"component_id": "backup-worker", "token": "backup-test-token", "scopes": ["backups:write"]},
    {"component_id": "verify-worker", "token": "verify-test-token", "scopes": ["verification:write"]},
    {"component_id": "isolation-worker", "token": "isolation-test-token", "scopes": ["isolation:write"]},
    {"component_id": "recovery-worker", "token": "recovery-test-token", "scopes": ["recovery:write"]},
]
USERS = [
    {"token": "analyst-test-token", "user_id": "worker-test-analyst", "role": "analyst"},
    {"token": "approver-test-token", "user_id": "worker-test-approver", "role": "approver"},
]


class WorkerHTTP:
    def __init__(self, client: TestClient, token: str):
        self.client = client
        self.headers = {"X-Internal-Component-Token": token}

    def post(self, path: str, payload: dict) -> dict:
        response = self.client.post(path, headers=self.headers, json=payload)
        if response.status_code >= 400:
            raise RuntimeError(f"HTTP {response.status_code}: {response.text}")
        return response.json()


class SafeCopyManager:
    """Copy double confined to pytest's temporary directories."""
    def create_backup(self, backup_id: str, source_path: str, destination_path: str):
        source = Path(source_path)
        destination = Path(destination_path)
        shutil.copytree(source, destination)
        files = [path for path in destination.rglob("*") if path.is_file()]
        now = datetime.now(timezone.utc).isoformat()
        return BackupResult(backup_id, str(source), str(destination), now, now, "COMPLETED",
                            len(files), sum(path.stat().st_size for path in files))


@pytest.fixture
def system(tmp_path, monkeypatch):
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(engine)
    db = Session(engine, expire_on_commit=False)
    monkeypatch.setenv("MVP_COMPONENT_TOKENS", json.dumps(COMPONENTS))
    monkeypatch.setenv("MVP_USER_TOKENS", json.dumps(USERS))

    def override_db():
        yield db

    app.dependency_overrides[get_db] = override_db
    with TestClient(app) as client:
        yield client, db, tmp_path
    app.dependency_overrides.clear()
    db.close()
    engine.dispose()


def set_user(client: TestClient, token: str):
    client.headers["Authorization"] = f"Bearer {token}"


def approve(client: TestClient, action_id: str):
    set_user(client, "approver-test-token")
    response = client.post(f"/api/action-requests/{action_id}/approve", json={})
    assert response.status_code == 200, response.text
    set_user(client, "analyst-test-token")


def test_backup_create_approve_claim_result_and_integrity_worker(system):
    client, db, root = system
    set_user(client, "analyst-test-token")
    asset = Asset(hostname="worker-backup-host")
    db.add(asset)
    db.commit()
    source = root / "source"
    source.mkdir()
    (source / "data.txt").write_text("temporary test backup")

    request = client.post("/api/action-requests", json={
        "action_type": "create_backup", "asset_id": asset.id, "request_reason": "test backup creation",
    })
    assert request.status_code == 201, request.text
    action = request.json()
    assert action["approval_status"] == "pending" and action["execution_status"] == "not_started"
    approve(client, action["id"])

    result = BackupCreationWorker(
        WorkerHTTP(client, "backup-test-token"), asset_sources={asset.id: str(source)},
        storage_root=str(root / "vault"), manifest_root=str(root / "manifests"),
        component_reference="pytest-backup", manager=SafeCopyManager(),
    ).execute(action["id"], asset_id=asset.id, correlation_id=action["correlation_id"])
    assert result["execution_status"] == "succeeded"
    backup = db.get(Backup, result["backup"]["backup_id"])
    assert backup is not None
    assert db.get(ActionRequest, action["id"]).execution_status == "succeeded"

    verify_request = client.post(f"/api/backups/{backup.id}/integrity-verifications", json={})
    assert verify_request.status_code == 201
    verification = db.get(IntegrityVerification, verify_request.json()["verification_id"])
    verify_action = db.scalar(select(ActionRequest).where(ActionRequest.verification_id == verification.id))
    assert client.post(
        f"/api/internal/integrity-verifications/{verification.id}/claim",
        headers={"X-Internal-Component-Token": "verify-test-token"},
        json={"component_reference": "pytest-verifier", "correlation_id": verification.correlation_id},
    ).status_code == 409
    approve(client, verify_action.id)
    verified = IntegrityVerificationWorker(
        WorkerHTTP(client, "verify-test-token"), backup_paths={backup.id: backup.storage_reference},
        manifest_root=str(root / "manifests"), component_reference="pytest-verifier",
    ).execute(verification.id, backup_id=backup.id, correlation_id=verification.correlation_id)
    assert verified["result_status"] == "passed", verified.get("failure_reason")
    assert verified["expected_digest"] == verified["observed_digest"]
    assert db.get(ActionRequest, verify_action.id).execution_status == "succeeded"
    actions = set(db.scalars(select(AuditEvent.action)).all())
    assert {"backup.creation.started", "backup.creation.succeeded", "integrity_verification.started", "integrity_verification.passed"} <= actions


def test_approved_protection_and_isolation_require_approval(system, monkeypatch):
    client, db, root = system
    set_user(client, "analyst-test-token")
    asset = Asset(hostname="worker-isolation-host")
    db.add(asset)
    db.flush()
    backup = Backup(asset_id=asset.id, source_component="test-worker", external_backup_id="backup-1",
                    lifecycle_status="available", protection_status="not_protected", encryption_status="unknown")
    db.add(backup)
    db.commit()

    protect = client.post("/api/action-requests", json={
        "action_type": "protect_backup", "asset_id": asset.id, "backup_id": backup.id,
    })
    assert protect.status_code == 201
    protect_ar = protect.json()
    approve(client, protect_ar["id"])
    monkeypatch.setattr("app.backup.protection.lock_backup", lambda _path: LockResult("tmp", True, 1, "now"))
    protected = BackupProtectionWorker(
        WorkerHTTP(client, "backup-test-token"), backup_paths={backup.id: str(root / "backup")},
        component_reference="pytest-protector",
    ).execute(protect_ar["id"], backup_id=backup.id, correlation_id=protect_ar["correlation_id"])
    assert protected["backup"]["protection_status"] == "protected"

    isolate = client.post("/api/action-requests", json={
        "action_type": "isolate", "asset_id": asset.id, "isolation_mode": "network",
    })
    assert isolate.status_code == 201
    isolate_ar = isolate.json()
    created = client.post("/api/isolation-requests", json={
        "action_request_id": isolate_ar["id"], "asset_id": asset.id, "isolation_mode": "network",
        "correlation_id": isolate_ar["correlation_id"],
    })
    assert created.status_code == 201
    isolation = created.json()
    firewall = MockFirewall()
    worker = IsolationWorker(WorkerHTTP(client, "isolation-test-token"), firewall=firewall,
                             asset_hosts={asset.id: "mock-host"}, component_reference="pytest-isolator")
    with pytest.raises(RuntimeError):
        worker.execute(isolation["isolation_action_id"], asset_id=asset.id,
                       correlation_id=isolation["correlation_id"])
    assert not firewall.is_isolated("mock-host")
    approve(client, isolate_ar["id"])
    result = worker.execute(isolation["isolation_action_id"], asset_id=asset.id,
                            correlation_id=isolation["correlation_id"])
    assert result["execution_status"] == "isolated"
    assert client.get(f"/api/assets/{asset.id}/isolation").json()["isolation_state"] == "isolated"
    audit_actions = set(db.scalars(select(AuditEvent.action)).all())
    assert {"backup.protection.started", "backup.protection.succeeded", "isolation.started", "isolation.succeeded"} <= audit_actions


def test_internal_scope_denial_and_scanner_requirement(system):
    client, db, root = system
    denied = client.get("/api/internal/backups/queue",
                        headers={"X-Internal-Component-Token": "isolation-test-token"})
    assert denied.status_code == 403
    audit = db.scalar(select(AuditEvent).where(AuditEvent.action == "internal_component.request_rejected"))
    assert audit is not None and audit.result_status == "rejected"
    with pytest.raises(ValueError, match="scanner callback"):
        RecoveryWorker(WorkerHTTP(client, "recovery-test-token"), backup_paths={}, restore_paths={},
                       trusted_file_hashes={}, scanner=None, component_reference="missing-scanner")
