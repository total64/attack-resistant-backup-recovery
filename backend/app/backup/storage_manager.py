from pathlib import Path
import re

_BACKUP_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")


class BackupStorageManager:
    """Create and locate isolated recovery-point directories beneath a root."""

    def __init__(self, storage_path: str):
        self.storage_path = Path(storage_path).expanduser().resolve()

    @staticmethod
    def _validate_backup_id(backup_id: str) -> None:
        if not _BACKUP_ID.fullmatch(backup_id):
            raise ValueError("backup_id must be a simple identifier without path separators")

    def create_recovery_point(self, backup_id: str) -> Path:
        self._validate_backup_id(backup_id)
        recovery_point = (self.storage_path / backup_id).resolve()
        if not recovery_point.is_relative_to(self.storage_path):
            raise ValueError("Recovery point path escapes the configured storage root")
        recovery_point.mkdir(parents=True, exist_ok=False)
        return recovery_point

    def get_recovery_point(self, backup_id: str) -> Path:
        self._validate_backup_id(backup_id)
        recovery_point = (self.storage_path / backup_id).resolve()
        if not recovery_point.is_relative_to(self.storage_path):
            raise ValueError("Recovery point path escapes the configured storage root")
        return recovery_point

    def recovery_point_exists(self, backup_id: str) -> bool:
        return self.get_recovery_point(backup_id).is_dir()

    def list_recovery_points(self) -> list[Path]:
        if not self.storage_path.exists():
            return []
        return sorted(path for path in self.storage_path.iterdir() if path.is_dir())
