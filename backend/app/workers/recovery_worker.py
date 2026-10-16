"""Approved recovery worker adapter requiring a real injected malware scanner."""
from collections.abc import Callable
from pathlib import Path

from app.recovery.backup_verifier import BackupVerifier
from app.recovery.recovery_manager import RecoveryManager
from app.recovery.restore_validator import RestoreValidator


class RecoveryWorker:
    """Claim an approved queued job, restore into an isolated target, then validate.

    Paths/hash manifests are trusted deployment configuration. `scanner` is
    mandatory; this adapter cannot report completed recovery without its passed
    result and evidence reference. The destination must be an isolated recovery
    environment, not a production/cutover path.
    """

    def __init__(
        self,
        client,
        *,
        backup_paths: dict[str, str],
        restore_paths: dict[str, str],
        trusted_file_hashes: dict[str, dict[str, str]],
        scanner: Callable[[Path], dict] | None,
        component_reference: str,
        recovery_manager: RecoveryManager | None = None,
    ):
        if scanner is None:
            raise ValueError("A deployed malware scanner callback is required before recovery work can be claimed")
        self.client = client
        self.backup_paths = {key: Path(value).expanduser().resolve() for key, value in backup_paths.items()}
        self.restore_paths = {key: Path(value).expanduser().resolve() for key, value in restore_paths.items()}
        self.trusted_file_hashes = trusted_file_hashes
        self.scanner = scanner
        self.component_reference = component_reference
        self.manager = recovery_manager or RecoveryManager(BackupVerifier(), RestoreValidator())

    def execute(self, job: dict) -> dict:
        identifiers = ("recovery_job_id", "asset_id", "incident_id", "backup_id", "verification_id", "correlation_id")
        if any(not job.get(key) for key in identifiers):
            raise ValueError("Queued recovery job is missing required references")
        backup_id = job["backup_id"]
        backup_path = self.backup_paths.get(backup_id)
        restore_path = self.restore_paths.get(job["asset_id"])
        expected_hashes = self.trusted_file_hashes.get(backup_id)
        if backup_path is None or restore_path is None or not expected_hashes:
            raise ValueError("Backup, isolated restore target, and trusted hashes must be preconfigured")

        job_id = job["recovery_job_id"]
        base = f"/api/internal/recovery-jobs/{job_id}"
        common = {
            "asset_id": job["asset_id"],
            "incident_id": job["incident_id"],
            "backup_id": backup_id,
            "verification_id": job["verification_id"],
            "correlation_id": job["correlation_id"],
            "component_reference": self.component_reference,
        }
        claimed = self.client.post(f"{base}/claim", {
            "component_reference": self.component_reference,
            "correlation_id": job["correlation_id"],
        })
        if claimed.get("job_status") != "restoring":
            raise RuntimeError("Backend did not move the approved queued job to restoring")

        restored = self.manager.recover(
            str(backup_path), str(restore_path), expected_hashes,
            list(expected_hashes.keys()),
        )
        if not restored.get("success"):
            return self.client.post(f"{base}/result", {
                **common,
                "job_status": "failed",
                "malware_scan_status": "not_started",
                "security_validation_status": "failed",
                "failure_reason": str(restored.get("reason") or restored.get("error") or restored.get("status")),
            })

        security_check = BackupVerifier().verify_backup(str(restore_path), expected_hashes)
        if not security_check.get("trusted"):
            return self.client.post(f"{base}/result", {
                **common,
                "job_status": "failed",
                "malware_scan_status": "not_started",
                "security_validation_status": "failed",
                "failure_reason": "Restored output failed hash validation",
            })

        scan = self.scanner(restore_path)
        if not isinstance(scan, dict) or not scan.get("evidence_reference"):
            return self.client.post(f"{base}/result", {
                **common,
                "job_status": "failed",
                "malware_scan_status": "inconclusive",
                "security_validation_status": "passed",
                "failure_reason": "Malware scanner did not return a verifiable evidence reference",
            })
        if scan.get("passed") is not True:
            return self.client.post(f"{base}/result", {
                **common,
                "job_status": "failed",
                "malware_scan_status": "failed",
                "security_validation_status": "passed",
                "failure_reason": "Malware scanner did not confirm a clean recovery point",
                "result_evidence_reference": scan["evidence_reference"],
            })
        return self.client.post(f"{base}/result", {
            **common,
            "job_status": "completed",
            "malware_scan_status": "passed",
            "security_validation_status": "passed",
            "outcome": "Restore completed in the configured isolated recovery environment; cutover was not requested.",
            "result_evidence_reference": scan["evidence_reference"],
        })
