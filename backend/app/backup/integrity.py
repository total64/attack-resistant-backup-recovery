"""Deterministic SHA-256 manifests for backup recovery points."""
import hashlib
from pathlib import Path


def calculate_sha256(file_path: str | Path) -> str:
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Backup file not found: {path}")
    if not path.is_file():
        raise IsADirectoryError(f"Path is not a file: {path}")
    digest = hashlib.sha256()
    with path.open("rb") as file:
        for block in iter(lambda: file.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_backup_integrity(file_path: str | Path, stored_hash: str) -> bool:
    try:
        return calculate_sha256(file_path) == stored_hash.lower()
    except (FileNotFoundError, IsADirectoryError, OSError):
        return False


def calculate_directory_sha256(directory_path: str | Path) -> str:
    root = Path(directory_path)
    if not root.exists():
        raise FileNotFoundError(f"Backup directory not found: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Path is not a directory: {root}")
    digest = hashlib.sha256()
    for item in sorted(root.rglob("*")):
        if item.is_symlink():
            raise ValueError(f"Symbolic links are not accepted in backup manifests: {item}")
        if item.is_file():
            digest.update(item.relative_to(root).as_posix().encode("utf-8"))
            digest.update(b"\0")
            digest.update(calculate_sha256(item).encode("ascii"))
            digest.update(b"\0")
    return digest.hexdigest()
