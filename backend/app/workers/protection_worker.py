"""Approved backup protection worker using the real immutable-bit helper."""


class BackupProtectionWorker:
    def __init__(self, client, *, backup_paths: dict[str, str], component_reference: str):
        self.client = client
        self.backup_paths = dict(backup_paths)
        self.component_reference = component_reference

    def execute(self, action_request_id: str, *, backup_id: str, correlation_id: str) -> dict:
        path = self.backup_paths.get(backup_id)
        if not path:
            raise ValueError("Backup path must come from trusted worker configuration")
        action_request = self.client.post(
            f"/api/internal/backups/action-requests/{action_request_id}/claim",
            {"component_reference": self.component_reference, "correlation_id": correlation_id},
        )
        if action_request.get("action_type") != "protect_backup" or action_request.get("backup_id") != backup_id:
            raise ValueError("Claimed action does not target this backup protection operation")
        from app.backup.protection import lock_backup

        result = lock_backup(path)
        status = "succeeded" if result.success else "failed"
        return self.client.post(
            f"/api/internal/backups/{backup_id}/protection-result",
            {
                "protection_status": "protected" if result.success else "failed",
                "execution_status": status,
                "component_reference": self.component_reference,
                "failure_reason": result.error,
                "action_request_id": action_request_id,
                "correlation_id": correlation_id,
            },
        )
