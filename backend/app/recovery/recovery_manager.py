from pathlib import Path
import shutil

from .backup_verifier import BackupVerifier
from .recovery_operation import RecoveryOperation
from .restore_validator import RestoreValidator


class RecoveryManager:
    """Safe local restore utility for a recovery worker or controlled tests.

    The web API does not call this class directly: its approval, isolation,
    verification and internal component-claim gates remain authoritative.
    """

    def __init__(self, backup_verifier: BackupVerifier, restore_validator: RestoreValidator):
        self.backup_verifier = backup_verifier
        self.restore_validator = restore_validator

    def recover(
        self,
        backup_path: str,
        restore_path: str,
        expected_hashes: dict[str, str],
        expected_files: list[str] | None = None,
    ) -> dict:
        operation = RecoveryOperation(backup_path, restore_path)
        verification = self.backup_verifier.verify_backup(backup_path, expected_hashes)
        operation.verification = verification
        if not verification["trusted"]:
            operation.fail("RECOVERY_BLOCKED", "Backup is not trusted.")
            result = operation.to_dict()
            result.update(success=False, reason="BACKUP_NOT_TRUSTED")
            return result

        backup = Path(backup_path)
        restore = Path(restore_path)
        try:
            backup = backup.resolve(strict=True)
            restore = restore.resolve()
            if not backup.is_dir() or restore == backup or backup in restore.parents or restore in backup.parents:
                raise ValueError("Backup and restore destination must be separate, non-overlapping directory trees")
            for item in backup.rglob("*"):
                if item.is_symlink():
                    raise ValueError(f"Symbolic links are not accepted in recovery data: {item.relative_to(backup)}")
                if item.is_file() and not item.resolve(strict=True).is_relative_to(backup):
                    raise ValueError(f"Recovery file escapes the backup root: {item}")
        except (OSError, ValueError) as error:
            operation.fail("RESTORE_PATH_INVALID", str(error))
            result = operation.to_dict()
            result["success"] = False
            return result

        try:
            restore.mkdir(parents=True, exist_ok=True)
            for item in backup.iterdir():
                destination = restore / item.name
                if item.is_dir():
                    shutil.copytree(item, destination, dirs_exist_ok=True, symlinks=False)
                else:
                    shutil.copy2(item, destination, follow_symlinks=False)
        except (OSError, shutil.Error) as error:
            operation.fail("RESTORE_FAILED", str(error))
            result = operation.to_dict()
            result["success"] = False
            return result

        if expected_files is not None:
            validation = self.restore_validator.validate_files(str(restore), expected_files)
            operation.validation = validation
            if not validation["success"]:
                operation.fail("RESTORE_VALIDATION_FAILED", "Restored files failed validation.")
                result = operation.to_dict()
                result["success"] = False
                return result

        operation.complete()
        result = operation.to_dict()
        result["success"] = True
        return result
