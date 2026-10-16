"""Approved backup creation worker using the team's copy/hash/encryption helpers."""
from datetime import datetime, timezone
from pathlib import Path
import shutil
from uuid import uuid4

from app.backup.backup_manager import BackupManager
from app.backup.encryption import encrypt_backup_dir
from app.backup.verification import write_trusted_hash


class BackupCreationWorker:
    """Execute approved create_backup requests for configured asset sources.

    `asset_sources` and storage/manifest roots are trusted worker configuration,
    never values received from the ActionRequest payload. An optional Fernet key
    is supplied from external secret management and is never persisted here.
    """

    def __init__(self, client, *, asset_sources: dict[str, str], storage_root: str,
                 manifest_root: str, component_reference: str, encryption_key: bytes | None = None,
                 manager: BackupManager | None = None):
        self.client = client
        self.asset_sources = {key: Path(value).expanduser().resolve() for key, value in asset_sources.items()}
        self.storage_root = Path(storage_root).expanduser().resolve()
        self.manifest_root = Path(manifest_root).expanduser().resolve()
        self.component_reference = component_reference
        self.encryption_key = encryption_key
        self.manager = manager or BackupManager()

    def execute(self, action_request_id: str, *, asset_id: str, correlation_id: str) -> dict:
        source = self.asset_sources.get(asset_id)
        if source is None or not source.is_dir():
            raise ValueError("Asset must map to an existing source directory in trusted worker configuration")
        backup_id = str(uuid4())
        self.storage_root.mkdir(parents=True, exist_ok=True)
        self.manifest_root.mkdir(parents=True, exist_ok=True)
        target = self.storage_root / backup_id
        staging = self.storage_root / f".{backup_id}.staging"

        self.client.post(
            f"/api/internal/backups/action-requests/{action_request_id}/claim",
            {"component_reference": self.component_reference, "correlation_id": correlation_id},
        )
        result = self.manager.create_backup(backup_id, str(source), str(staging))
        if result.status != "COMPLETED":
            return self.client.post(
                f"/api/internal/backups/action-requests/{action_request_id}/creation-result",
                {
                    "execution_status": "failed",
                    "failure_reason": result.error or "Backup creation failed",
                    "component_reference": self.component_reference,
                    "correlation_id": correlation_id,
                },
            )

        encrypted = self.encryption_key is not None
        if encrypted:
            encrypted_result = encrypt_backup_dir(staging, target, self.encryption_key)
            if not encrypted_result.success:
                shutil.rmtree(staging, ignore_errors=True)
                shutil.rmtree(target, ignore_errors=True)
                return self.client.post(
                    f"/api/internal/backups/action-requests/{action_request_id}/creation-result",
                    {
                        "execution_status": "failed",
                        "failure_reason": "Backup encryption failed: " + "; ".join(encrypted_result.errors),
                        "component_reference": self.component_reference,
                        "correlation_id": correlation_id,
                    },
                )
            shutil.rmtree(staging)
        else:
            staging.rename(target)

        try:
            manifest = write_trusted_hash(target, backup_id, self.manifest_root)
        except (OSError, ValueError, FileExistsError) as error:
            shutil.rmtree(target, ignore_errors=True)
            return self.client.post(
                f"/api/internal/backups/action-requests/{action_request_id}/creation-result",
                {
                    "execution_status": "failed",
                    "failure_reason": f"Trusted manifest could not be recorded: {error}",
                    "component_reference": self.component_reference,
                    "correlation_id": correlation_id,
                },
            )
        file_count, size_bytes = BackupManager._get_statistics(target)
        return self.client.post(
            f"/api/internal/backups/action-requests/{action_request_id}/creation-result",
            {
                "execution_status": "succeeded",
                "external_backup_id": backup_id,
                "created_at": datetime.now(timezone.utc).isoformat(),
                "backup_type": "full",
                "size_bytes": size_bytes,
                "storage_reference": str(target),
                "manifest_reference": str(manifest),
                "encryption_status": "encrypted" if encrypted else "not_encrypted",
                "component_reference": self.component_reference,
                "correlation_id": correlation_id,
            },
        )
