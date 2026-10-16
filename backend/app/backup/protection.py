"""Explicit Linux immutable-attribute helpers for an authorized backup worker.

These functions are not called by HTTP ingestion or tests; workers must call
them only after a separately approved action request has been claimed.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import platform
import subprocess


@dataclass
class LockResult:
    path: str
    success: bool
    file_count: int
    attempted_at: str
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "success": self.success,
            "file_count": self.file_count,
            "attempted_at": self.attempted_at,
            "error": self.error,
        }


def _run_chattr(flag: str, target: Path) -> None:
    subprocess.run(["chattr", flag, str(target)], check=True, capture_output=True, text=True)


def lock_backup(directory_path: str | Path) -> LockResult:
    root = Path(directory_path).expanduser().resolve()
    timestamp = datetime.now(timezone.utc).isoformat()
    if not root.is_dir():
        return LockResult(str(root), False, 0, timestamp, "Backup directory does not exist or is not a directory.")
    if platform.system() != "Linux":
        return LockResult(str(root), False, 0, timestamp, "Immutable locking requires Linux.")
    targets = list(root.rglob("*"))
    if any(target.is_symlink() for target in targets):
        return LockResult(str(root), False, 0, timestamp, "Symbolic links are not accepted for immutable backup protection.")
    files = [target for target in targets if target.is_file()]
    directories = sorted([root, *(target for target in targets if target.is_dir())], key=lambda path: len(path.parts), reverse=True)
    processed = 0
    try:
        for target in files + directories:
            _run_chattr("+i", target)
            processed += 1
    except (subprocess.CalledProcessError, FileNotFoundError, OSError) as error:
        return LockResult(str(root), False, processed, timestamp, str(error))
    return LockResult(str(root), True, processed, timestamp)


def unlock_backup(directory_path: str | Path) -> LockResult:
    root = Path(directory_path).expanduser().resolve()
    timestamp = datetime.now(timezone.utc).isoformat()
    if not root.is_dir():
        return LockResult(str(root), False, 0, timestamp, "Backup directory does not exist or is not a directory.")
    if platform.system() != "Linux":
        return LockResult(str(root), False, 0, timestamp, "Immutable locking requires Linux.")
    targets = list(root.rglob("*"))
    if any(target.is_symlink() for target in targets):
        return LockResult(str(root), False, 0, timestamp, "Symbolic links are not accepted for immutable backup protection.")
    directories = sorted([root, *(target for target in targets if target.is_dir())], key=lambda path: len(path.parts))
    files = [target for target in targets if target.is_file()]
    processed = 0
    try:
        for target in directories + files:
            _run_chattr("-i", target)
            processed += 1
    except (subprocess.CalledProcessError, FileNotFoundError, OSError) as error:
        return LockResult(str(root), False, processed, timestamp, str(error))
    return LockResult(str(root), True, processed, timestamp)


def is_locked(directory_path: str | Path) -> bool:
    root = Path(directory_path).expanduser().resolve()
    if not root.is_dir() or platform.system() != "Linux":
        return False
    try:
        result = subprocess.run(["lsattr", "-d", str(root)], check=True, capture_output=True, text=True)
    except (subprocess.CalledProcessError, FileNotFoundError, OSError):
        return False
    return "i" in result.stdout.split()[0]
