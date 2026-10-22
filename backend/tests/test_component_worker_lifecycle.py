"""API-to-worker lifecycle tests; every host/filesystem side effect is test-confined."""
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.backup.backup_manager import BackupResult
from app.backup.encryption import generate_key
from app.backup.protection import LockResult
from app.database.session import get_db
from app.isolation.firewall import MockFirewall
from app.main import app
from app.models import ActionRequest, Asset, AuditEvent, Backup, Base, IntegrityVerification, ThreatIncident
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
    with pytest.raises(RuntimeError, match="requires explicit approver authorization"):
        BackupCreationWorker(
            WorkerHTTP(client, "backup-test-token"), asset_sources={asset.id: str(source)},
            storage_root=str(root / "unapproved-vault"), manifest_root=str(root / "unapproved-manifests"),
            component_reference="pytest-unapproved", manager=SafeCopyManager(),
        ).execute(action["id"], asset_id=asset.id, correlation_id=action["correlation_id"])
    assert not (root / "unapproved-vault").exists()
    approve(client, action["id"])

    result = BackupCreationWorker(
        WorkerHTTP(client, "backup-test-token"), asset_sources={asset.id: str(source)},
        storage_root=str(root / "vault"), manifest_root=str(root / "manifests"),
        component_reference="pytest-backup", manager=SafeCopyManager(), encryption_key=generate_key(),
    ).execute(action["id"], asset_id=asset.id, correlation_id=action["correlation_id"])
    assert result["execution_status"] == "succeeded"
    backup = db.get(Backup, result["backup"]["backup_id"])
    assert backup is not None
    assert backup.encryption_status == "encrypted"
    assert list(Path(backup.storage_reference).glob("*.enc"))
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


class FailingCopyManager:
    def create_backup(self, _backup_id: str, _source_path: str, _destination_path: str):
        raise OSError("simulated local copy failure")


def test_backup_worker_reports_failure_after_claim(system):
    client, db, root = system
    set_user(client, "analyst-test-token")
    asset = Asset(hostname="worker-backup-failure-host")
    db.add(asset)
    db.commit()
    source = root / "failure-source"
    source.mkdir()
    request = client.post("/api/action-requests", json={
        "action_type": "create_backup", "asset_id": asset.id,
        "request_reason": "test a reported worker error",
    })
    assert request.status_code == 201, request.text
    action = request.json()
    approve(client, action["id"])

    result = BackupCreationWorker(
        WorkerHTTP(client, "backup-test-token"), asset_sources={asset.id: str(source)},
        storage_root=str(root / "failed-vault"), manifest_root=str(root / "failed-manifests"),
        component_reference="pytest-failing-backup", manager=FailingCopyManager(),
    ).execute(action["id"], asset_id=asset.id, correlation_id=action["correlation_id"])

    assert result["execution_status"] == "failed"
    stored_action = db.get(ActionRequest, action["id"])
    assert stored_action.execution_status == "failed"
    assert stored_action.failure_reason == "Backup preparation failed (OSError)"
    assert db.scalar(select(Backup).where(Backup.asset_id == asset.id)) is None
    assert db.scalar(select(AuditEvent).where(AuditEvent.action == "backup.creation.failed")) is not None


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


@pytest.mark.parametrize(
    ("scanner_result", "expected_status", "expected_scan_status"),
    [
        ({"passed": True, "evidence_reference": "evidence://pytest/recovery"}, "completed", "passed"),
        ({"passed": False, "evidence_reference": "evidence://pytest/blocked"}, "failed", "failed"),
        ({"passed": True}, "failed", "inconclusive"),
    ],
)
def test_isolation_and_recovery_worker_follow_authorized_lifecycle(
    system, scanner_result, expected_status, expected_scan_status,
):
    client, db, root = system
    set_user(client, "analyst-test-token")
    asset = Asset(hostname="worker-recovery-host")
    db.add(asset)
    db.flush()
    incident = ThreatIncident(
        title="Worker recovery integration test",
        threat_type="endpoint_activity",
        asset_id=asset.id,
        detected_at=datetime.now(timezone.utc),
        lifecycle_status="contained",
    )
    db.add(incident)
    db.flush()

    content = b"recovery data confined to pytest temporary storage"
    backup_path = root / "recovery-backup"
    backup_path.mkdir()
    (backup_path / "data.txt").write_bytes(content)
    file_hash = hashlib.sha256(content).hexdigest()
    backup = Backup(
        asset_id=asset.id, source_component="pytest", external_backup_id="recovery-backup-1",
        lifecycle_status="available", protection_status="protected", encryption_status="encrypted",
        storage_reference=str(backup_path),
    )
    db.add(backup)
    db.flush()
    verification = IntegrityVerification(
        backup_id=backup.id, result_status="passed", expected_digest=file_hash,
        observed_digest=file_hash, completed_at=datetime.now(timezone.utc),
    )
    db.add(verification)
    db.commit()

    isolate_request = client.post("/api/action-requests", json={
        "action_type": "isolate", "asset_id": asset.id, "incident_id": incident.id,
        "isolation_mode": "network", "request_reason": "contain test host",
        "correlation_id": incident.correlation_id,
    })
    assert isolate_request.status_code == 201, isolate_request.text
    isolate_action_request = isolate_request.json()
    created_isolation = client.post("/api/isolation-requests", json={
        "action_request_id": isolate_action_request["id"], "asset_id": asset.id,
        "incident_id": incident.id, "isolation_mode": "network",
        "correlation_id": isolate_action_request["correlation_id"],
    })
    assert created_isolation.status_code == 201, created_isolation.text
    isolation = created_isolation.json()
    approve(client, isolate_action_request["id"])
    firewall = MockFirewall()
    isolation_result = IsolationWorker(
        WorkerHTTP(client, "isolation-test-token"), firewall=firewall,
        asset_hosts={asset.id: "pytest-host"}, component_reference="pytest-recovery-isolator",
    ).execute(isolation["isolation_action_id"], asset_id=asset.id,
              correlation_id=isolation["correlation_id"])
    assert isolation_result["execution_status"] == "isolated"
    assert firewall.is_isolated("pytest-host")

    recovery_request = client.post("/api/action-requests", json={
        "action_type": "recover", "asset_id": asset.id, "incident_id": incident.id,
        "backup_id": backup.id, "verification_id": verification.id,
        "request_reason": "recover into isolated pytest target",
        "correlation_id": incident.correlation_id,
    })
    assert recovery_request.status_code == 201, recovery_request.text
    recovery_action = recovery_request.json()
    approve(client, recovery_action["id"])
    create_job = client.post("/api/recovery-jobs", json={
        "action_request_id": recovery_action["id"], "asset_id": asset.id,
        "incident_id": incident.id, "backup_id": backup.id,
        "verification_id": verification.id, "recovery_environment": "pytest-isolated",
        "correlation_id": recovery_action["correlation_id"],
    })
    assert create_job.status_code == 201, create_job.text
    job = create_job.json()
    assert job["job_status"] == "approved"
    dispatched = client.post(f"/api/recovery-jobs/{job['id']}/dispatch")
    assert dispatched.status_code == 200, dispatched.text
    queued = dispatched.json()
    assert queued["job_status"] == "queued"

    worker_job = {
        "recovery_job_id": queued["id"],
        **{key: queued[key] for key in (
            "asset_id", "incident_id", "backup_id", "verification_id", "correlation_id",
        )},
    }
    restore_path = root / "isolated-restore"
    worker = RecoveryWorker(
        WorkerHTTP(client, "recovery-test-token"), backup_paths={backup.id: str(backup_path)},
        restore_paths={asset.id: str(restore_path)},
        trusted_file_hashes={backup.id: {"data.txt": file_hash}},
        scanner=lambda _path: scanner_result,
        component_reference="pytest-recovery-worker",
    )
    recovered = worker.execute(worker_job)

    assert recovered["job_status"] == expected_status
    assert recovered["malware_scan_status"] == expected_scan_status
    assert recovered["cutover_status"] == "not_requested"
    stored_action = db.get(ActionRequest, recovery_action["id"])
    assert stored_action.execution_status == ("succeeded" if expected_status == "completed" else "failed")
    if expected_status == "completed":
        assert (restore_path / "data.txt").read_bytes() == content
        assert recovered["security_validation_status"] == "passed"
        assert recovered["result_evidence_reference"] == scanner_result["evidence_reference"]
    else:
        assert recovered["failure_reason"]
    audit_actions = set(db.scalars(select(AuditEvent.action)).all())
    assert {"isolation.started", "isolation.succeeded", "recovery.job_created", "recovery.dispatched", "recovery.restoring"} <= audit_actions
    assert "recovery.completed" in audit_actions if expected_status == "completed" else "recovery.failed" in audit_actions
