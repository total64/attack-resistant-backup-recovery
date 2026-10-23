"""Filesystem backup worker primitive; API requests remain approval/worker gated."""
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import subprocess

from .integrity import calculate_directory_sha256


@dataclass
class BackupResult:
    backup_id: str
    source_path: str
    destination_path: str
    started_at: str
    completed_at: str | None
    status: str
    file_count: int
    size_bytes: int
    manifest_sha256: str | None = None
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "backup_id": self.backup_id,
            "source_path": self.source_path,
            "destination_path": self.destination_path,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "status": self.status,
            "file_count": self.file_count,
            "size_bytes": self.size_bytes,
            "manifest_sha256": self.manifest_sha256,
            "error": self.error,
        }


class BackupManager:
    """Create a non-destructive copy and hash it; never use rsync --delete."""

    def __init__(self, rsync_path: str = "rsync"):
        self.rsync_path = rsync_path

    def create_backup(self, backup_id: str, source_path: str, destination_path: str) -> BackupResult:
        started_at = datetime.now(timezone.utc).isoformat()
        source = Path(source_path).expanduser().resolve()
        destination = Path(destination_path).expanduser().resolve()

        def failed(message: str, completed_at: str | None = None) -> BackupResult:
            return BackupResult(
                backup_id=backup_id,
                source_path=str(source),
                destination_path=str(destination),
                started_at=started_at,
                completed_at=completed_at,
                status="FAILED",
                file_count=0,
                size_bytes=0,
                error=message,
            )

        if not source.is_dir():
            return failed("Source path is not an existing directory.")
        if source == destination or source in destination.parents or destination in source.parents:
            return failed("Source and destination must be separate, non-overlapping directory trees.")
        try:
            destination.mkdir(parents=True, exist_ok=True)
            completed = subprocess.run(
                [self.rsync_path, "-a", "--", f"{source}/", f"{destination}/"],
                check=True,
                capture_output=True,
                text=True,
                timeout=3600,
            )
            del completed
            file_count = 0
            size_bytes = 0
            for item in destination.rglob("*"):
                if item.is_symlink():
                    return failed("Backup contains a symbolic link; refusing to mark it trusted.", datetime.now(timezone.utc).isoformat())
                if item.is_file():
                    file_count += 1
                    size_bytes += item.stat().st_size
            manifest_sha256 = calculate_directory_sha256(destination)
            return BackupResult(
                backup_id=backup_id,
                source_path=str(source),
                destination_path=str(destination),
                started_at=started_at,
                completed_at=datetime.now(timezone.utc).isoformat(),
                status="COMPLETED",
                file_count=file_count,
                size_bytes=size_bytes,
                manifest_sha256=manifest_sha256,
            )
        except (OSError, subprocess.SubprocessError) as error:
            return failed(str(error), datetime.now(timezone.utc).isoformat())

    @staticmethod
    def _get_statistics(path: Path) -> tuple[int, int]:
        files = [item for item in path.rglob("*") if item.is_file()]
        return len(files), sum(item.stat().st_size for item in files)
