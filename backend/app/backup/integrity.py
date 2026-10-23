<<<<<<< HEAD

import hashlib
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def calculate_sha256(file_path: str | Path) -> str:
    sha256_hash = hashlib.sha256()
    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"Backup file not found: {path}")

    if not path.is_file():
        raise IsADirectoryError(f"Path is not a file: {path}")

    with path.open("rb") as file:
        for byte_block in iter(lambda: file.read(65536), b""):
            sha256_hash.update(byte_block)

    return sha256_hash.hexdigest()
=======
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
>>>>>>> integration/deploy-main


def verify_backup_integrity(file_path: str | Path, stored_hash: str) -> bool:
    try:
<<<<<<< HEAD
        current_hash = calculate_sha256(file_path)

        if current_hash != stored_hash:
            logger.warning(
                f"Integrity mismatch for {file_path}: "
                f"expected {stored_hash}, got {current_hash}"
            )
            return False

        logger.info(f"Integrity verified for {file_path}")
        return True

    except (FileNotFoundError, IsADirectoryError) as error:
        logger.error(f"Could not read backup file {file_path}: {error}")
        return False

    except Exception as error:
        logger.error(f"Error verifying backup: {error}")
=======
        return calculate_sha256(file_path) == stored_hash.lower()
    except (FileNotFoundError, IsADirectoryError, OSError):
>>>>>>> integration/deploy-main
        return False


def calculate_directory_sha256(directory_path: str | Path) -> str:
    root = Path(directory_path)
<<<<<<< HEAD

    if not root.exists():
        raise FileNotFoundError(f"Backup directory not found: {root}")

    if not root.is_dir():
        raise NotADirectoryError(f"Path is not a directory: {root}")

    entries = []

    for item in sorted(root.rglob("*")):
        if item.is_file():
            relative_path = item.relative_to(root).as_posix()
            file_hash = calculate_sha256(item)
            entries.append((relative_path, file_hash))

    master = hashlib.sha256()

    for relative_path, file_hash in entries:
        master.update(relative_path.encode("utf-8"))
        master.update(b"\0")
        master.update(file_hash.encode("utf-8"))
        master.update(b"\0")

    return master.hexdigest()
=======
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
>>>>>>> integration/deploy-main
