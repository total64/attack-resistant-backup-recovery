<<<<<<< HEAD
import hashlib
=======
>>>>>>> integration/deploy-main
from pathlib import Path


class BackupVerifier:
<<<<<<< HEAD
    def verify_backup(
        self,
        backup_path: str,
        expected_hashes: dict[str, str],
    ) -> dict:
        backup = Path(backup_path)

        if not backup.exists():
            return {
                "success": False,
                "status": "BACKUP_NOT_FOUND",
                "backup_path": str(backup),
                "trusted": False,
            }

        if not backup.is_dir():
            return {
                "success": False,
                "status": "BACKUP_PATH_INVALID",
                "backup_path": str(backup),
                "trusted": False,
            }

        if not expected_hashes:
            return {
                "success": False,
                "status": "NO_INTEGRITY_DATA",
                "backup_path": str(backup),
                "trusted": False,
            }

        mismatches = []

        for relative_path, expected_hash in expected_hashes.items():
            file_path = backup / relative_path

            if not file_path.is_file():
                mismatches.append(
                    {
                        "file": relative_path,
                        "reason": "FILE_NOT_FOUND",
                    }
                )
                continue

            actual_hash = self._calculate_hash(file_path)

            if actual_hash != expected_hash.lower():
                mismatches.append(
                    {
                        "file": relative_path,
                        "reason": "HASH_MISMATCH",
                        "expected_hash": expected_hash.lower(),
                        "actual_hash": actual_hash,
                    }
                )

=======
    """Validate trusted per-file digests before restoring a recovery point."""

    def verify_backup(self, backup_path: str, expected_hashes: dict[str, str]) -> dict:
        backup = Path(backup_path).resolve()
        if not backup.exists():
            return {"success": False, "status": "BACKUP_NOT_FOUND", "backup_path": str(backup), "trusted": False}
        if not backup.is_dir():
            return {"success": False, "status": "BACKUP_PATH_INVALID", "backup_path": str(backup), "trusted": False}
        if not expected_hashes:
            return {"success": False, "status": "NO_INTEGRITY_DATA", "backup_path": str(backup), "trusted": False}

        mismatches = []
        for relative_name, expected_hash in expected_hashes.items():
            relative = Path(relative_name)
            if relative.is_absolute() or ".." in relative.parts or not relative.parts:
                mismatches.append({"file": relative_name, "reason": "INVALID_RELATIVE_PATH"})
                continue
            candidate = backup.joinpath(relative).resolve()
            if not candidate.is_relative_to(backup) or candidate.is_symlink():
                mismatches.append({"file": relative_name, "reason": "PATH_ESCAPES_BACKUP"})
                continue
            if not candidate.is_file():
                mismatches.append({"file": relative_name, "reason": "FILE_NOT_FOUND"})
                continue
            actual_hash = self._calculate_hash(candidate)
            if actual_hash != expected_hash.lower():
                mismatches.append({
                    "file": relative_name,
                    "reason": "HASH_MISMATCH",
                    "expected_hash": expected_hash.lower(),
                    "actual_hash": actual_hash,
                })
>>>>>>> integration/deploy-main
        if mismatches:
            return {
                "success": False,
                "status": "INTEGRITY_FAILED",
                "backup_path": str(backup),
                "trusted": False,
                "mismatches": mismatches,
            }
<<<<<<< HEAD

=======
>>>>>>> integration/deploy-main
        return {
            "success": True,
            "status": "BACKUP_VERIFIED",
            "backup_path": str(backup),
            "trusted": True,
            "files_verified": len(expected_hashes),
        }

<<<<<<< HEAD
    def _calculate_hash(self, file_path: Path) -> str:
        digest = hashlib.sha256()

        with file_path.open("rb") as file:
            for chunk in iter(lambda: file.read(1024 * 1024), b""):
                digest.update(chunk)

        return digest.hexdigest()
=======
    @staticmethod
    def _calculate_hash(file_path: Path) -> str:
        import hashlib

        digest = hashlib.sha256()
        with file_path.open("rb") as file:
            for chunk in iter(lambda: file.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()
>>>>>>> integration/deploy-main
