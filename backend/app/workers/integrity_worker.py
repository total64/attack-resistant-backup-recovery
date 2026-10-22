"""Approved integrity worker backed by immutable sidecar hash verification."""
from datetime import datetime, timezone

from app.backup.recovery_point import RecoveryPoint
from app.backup.verification import verify_recovery_point


class IntegrityVerificationWorker:
    def __init__(self, client, *, backup_paths: dict[str, str], manifest_root: str, component_reference: str):
        self.client = client
        self.backup_paths = dict(backup_paths)
        self.manifest_root = manifest_root
        self.component_reference = component_reference

    def execute(self, verification_id: str, *, backup_id: str, correlation_id: str) -> dict:
        backup_path = self.backup_paths.get(backup_id)
        if not backup_path:
            raise ValueError("Backup path must come from trusted worker configuration")
        claim = self.client.post(
            f"/api/internal/integrity-verifications/{verification_id}/claim",
            {"component_reference": self.component_reference, "correlation_id": correlation_id},
        )
        verification = claim.get("verification", {})
        backup = claim.get("backup", {})
        if verification.get("backup_id") != backup_id or backup.get("backup_id") != backup_id:
            raise ValueError("Claimed verification does not belong to the configured backup")
        manifest_id = backup.get("external_backup_id")
        if not manifest_id:
            raise ValueError("Claimed backup is missing its external manifest identifier")
        point = RecoveryPoint.create(manifest_id, "worker-source", backup_path, "available", 0, 0)
        try:
            result = verify_recovery_point(point, self.manifest_root)
        except Exception as error:
            checked_at = datetime.now(timezone.utc).isoformat()
            return self.client.post(
                f"/api/internal/integrity-verifications/{verification_id}/result",
                {
                    "result_status": "error",
                    "algorithm": "sha256-directory-manifest-v1",
                    "verification_evidence_reference": f"worker://{self.component_reference}/{manifest_id}",
                    "verifier_component": "server-resolved",
                    "component_reference": self.component_reference,
                    "verifier_version": "sha256-worker-v1",
                    "started_at": checked_at,
                    "completed_at": checked_at,
                    "failure_reason": f"Integrity verifier raised {type(error).__name__}",
                    "correlation_id": correlation_id,
                },
            )
        passed = result.is_intact
        payload = {
            "result_status": "passed" if passed else "failed",
            "algorithm": "sha256-directory-manifest-v1",
            "expected_digest": result.expected_hash,
            "trusted_manifest_reference": backup.get("manifest_reference") or f"{self.manifest_root.rstrip('/')}/{manifest_id}.sha256",
            "observed_digest": result.actual_hash,
            "verification_evidence_reference": f"worker://{self.component_reference}/{manifest_id}",
            "verifier_component": "server-resolved",
            "component_reference": self.component_reference,
            "verifier_version": "sha256-worker-v1",
            "started_at": result.checked_at,
            "completed_at": result.checked_at,
            "failure_reason": result.error,
            "correlation_id": correlation_id,
        }
        return self.client.post(
            f"/api/internal/integrity-verifications/{verification_id}/result", payload
        )
