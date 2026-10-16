from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
import re

from .integrity import calculate_directory_sha256
from .recovery_point import RecoveryPoint

SIDECAR_SUFFIX = ".sha256"
STATUS_VERIFIED = "VERIFIED"
STATUS_TAMPERED = "TAMPERED"
STATUS_MISSING = "MISSING"
STATUS_UNVERIFIED = "UNVERIFIED"
STATUS_ERROR = "ERROR"
_BACKUP_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,127}$")


@dataclass
class VerificationResult:
    backup_id: str
    destination_path: str
    expected_hash: str | None
    actual_hash: str | None
    is_intact: bool
    status: str
    checked_at: str
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "backup_id": self.backup_id,
            "destination_path": self.destination_path,
            "expected_hash": self.expected_hash,
            "actual_hash": self.actual_hash,
            "is_intact": self.is_intact,
            "status": self.status,
            "checked_at": self.checked_at,
            "error": self.error,
        }


def _sidecar_path(storage_dir: str | Path, backup_id: str) -> Path:
    if not _BACKUP_ID.fullmatch(backup_id):
        raise ValueError("backup_id must be a simple identifier without path separators")
    root = Path(storage_dir).expanduser().resolve()
    sidecar = (root / f"{backup_id}{SIDECAR_SUFFIX}").resolve()
    if not sidecar.is_relative_to(root):
        raise ValueError("Manifest path escapes the configured storage root")
    return sidecar


def write_trusted_hash(destination_path: str | Path, backup_id: str, storage_dir: str | Path) -> Path:
    """Record the initial trusted hash without silently replacing an existing baseline."""
    digest = calculate_directory_sha256(destination_path)
    sidecar = _sidecar_path(storage_dir, backup_id)
    sidecar.parent.mkdir(parents=True, exist_ok=True)
    with sidecar.open("x", encoding="ascii") as manifest:
        manifest.write(digest)
    return sidecar


def read_trusted_hash(backup_id: str, storage_dir: str | Path) -> str | None:
    sidecar = _sidecar_path(storage_dir, backup_id)
    if not sidecar.exists():
        return None
    value = sidecar.read_text(encoding="ascii").strip()
    return value or None


def verify_recovery_point(recovery_point: RecoveryPoint, storage_dir: str | Path) -> VerificationResult:
    checked_at = datetime.now(timezone.utc).isoformat()
    expected = read_trusted_hash(recovery_point.backup_id, storage_dir)
    if expected is None:
        return VerificationResult(
            recovery_point.backup_id, recovery_point.destination_path, None, None,
            False, STATUS_UNVERIFIED, checked_at, "No trusted hash recorded for this backup.",
        )
    try:
        actual = calculate_directory_sha256(recovery_point.destination_path)
    except FileNotFoundError:
        return VerificationResult(
            recovery_point.backup_id, recovery_point.destination_path, expected, None,
            False, STATUS_MISSING, checked_at, "Backup directory not found.",
        )
    except (OSError, ValueError) as error:
        return VerificationResult(
            recovery_point.backup_id, recovery_point.destination_path, expected, None,
            False, STATUS_ERROR, checked_at, str(error),
        )
    intact = actual == expected
    return VerificationResult(
        recovery_point.backup_id,
        recovery_point.destination_path,
        expected,
        actual,
        intact,
        STATUS_VERIFIED if intact else STATUS_TAMPERED,
        checked_at,
        None if intact else "Content hash does not match the trusted hash.",
    )


def apply_result_to_recovery_point(result: VerificationResult, recovery_point: RecoveryPoint) -> RecoveryPoint:
    return replace(recovery_point, integrity_status=result.status)


def is_backup_safe_for_recovery(file_path: str | Path, stored_hash: str) -> bool:
    try:
        return calculate_directory_sha256(file_path) == stored_hash
    except (OSError, ValueError):
        return False
