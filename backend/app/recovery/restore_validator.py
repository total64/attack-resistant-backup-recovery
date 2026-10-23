from hashlib import sha256
from pathlib import Path


<<<<<<< HEAD
class RestoreValidator:
    def validate_path(self, restore_path: str) -> dict:
        path = Path(restore_path)

        if not path.exists():
            return {
                "success": False,
                "status": "RESTORE_PATH_NOT_FOUND",
                "path": str(path),
            }

        if not path.is_dir():
            return {
                "success": False,
                "status": "RESTORE_PATH_INVALID",
                "path": str(path),
            }

        return {
            "success": True,
            "status": "RESTORE_PATH_VALID",
            "path": str(path),
        }

    def validate_files(
        self,
        restore_path: str,
        expected_files: list[str],
    ) -> dict:
        path_result = self.validate_path(restore_path)

        if not path_result["success"]:
            return path_result

        root = Path(restore_path)
        missing_files = [
            file for file in expected_files
            if not (root / file).is_file()
        ]

        if missing_files:
            return {
                "success": False,
                "status": "FILES_MISSING",
                "path": str(root),
                "missing_files": missing_files,
            }

        return {
            "success": True,
            "status": "FILES_VALID",
            "path": str(root),
            "files_checked": len(expected_files),
        }

    def calculate_hash(self, file_path: str) -> str:
        path = Path(file_path)
        digest = sha256()

        with path.open("rb") as file:
            for chunk in iter(lambda: file.read(1024 * 1024), b""):
                digest.update(chunk)

        return digest.hexdigest()

    def validate_hash(
        self,
        file_path: str,
        expected_hash: str,
    ) -> dict:
        path = Path(file_path)

        if not path.is_file():
            return {
                "success": False,
                "status": "FILE_NOT_FOUND",
                "path": str(path),
            }

        actual_hash = self.calculate_hash(str(path))

        if actual_hash != expected_hash.lower():
            return {
                "success": False,
                "status": "INTEGRITY_FAILED",
                "path": str(path),
                "expected_hash": expected_hash.lower(),
                "actual_hash": actual_hash,
            }

        return {
            "success": True,
            "status": "INTEGRITY_VALID",
            "path": str(path),
            "hash": actual_hash,
        }
=======
def _safe_child(root: Path, relative_name: str) -> Path:
    relative = Path(relative_name)
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise ValueError("Expected file paths must be safe relative paths")
    child = (root / relative).resolve()
    if not child.is_relative_to(root):
        raise ValueError("Expected file path escapes the configured directory")
    return child


class RestoreValidator:
    def validate_path(self, restore_path: str) -> dict:
        path = Path(restore_path).resolve()
        if not path.exists():
            return {"success": False, "status": "RESTORE_PATH_NOT_FOUND", "path": str(path)}
        if not path.is_dir():
            return {"success": False, "status": "RESTORE_PATH_INVALID", "path": str(path)}
        return {"success": True, "status": "RESTORE_PATH_VALID", "path": str(path)}

    def validate_files(self, restore_path: str, expected_files: list[str]) -> dict:
        path = Path(restore_path).resolve()
        path_result = self.validate_path(restore_path)
        if not path_result["success"]:
            return path_result
        try:
            missing_files = [name for name in expected_files if not _safe_child(path, name).is_file()]
        except ValueError as error:
            return {"success": False, "status": "INVALID_EXPECTED_PATH", "path": str(path), "error": str(error)}
        if missing_files:
            return {"success": False, "status": "FILES_MISSING", "path": str(path), "missing_files": missing_files}
        return {"success": True, "status": "FILES_VALID", "path": str(path), "files_checked": len(expected_files)}

    @staticmethod
    def calculate_hash(file_path: str) -> str:
        digest = sha256()
        with Path(file_path).open("rb") as file:
            for chunk in iter(lambda: file.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def validate_hash(self, file_path: str, expected_hash: str) -> dict:
        path = Path(file_path).resolve()
        if not path.is_file():
            return {"success": False, "status": "FILE_NOT_FOUND", "path": str(path)}
        actual_hash = self.calculate_hash(str(path))
        if actual_hash != expected_hash.lower():
            return {
                "success": False, "status": "INTEGRITY_FAILED", "path": str(path),
                "expected_hash": expected_hash.lower(), "actual_hash": actual_hash,
            }
        return {"success": True, "status": "INTEGRITY_VALID", "path": str(path), "hash": actual_hash}
>>>>>>> integration/deploy-main
