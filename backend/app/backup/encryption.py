<<<<<<< HEAD
"""
Backup encryption at rest using Fernet (symmetric authenticated encryption).

Implements FR-B05: store backups encrypted at rest. Each backup file is
encrypted individually with a per-backup key. The encrypted file gets a
.enc suffix; the key is stored separately.

For the MVP, keys are stored as plain files next to the encrypted backups.
In production this should be replaced with a proper key management system
(KMS, HashiCorp Vault, or an OS keyring).

Uses the cryptography library (pip install cryptography).
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
import logging

from cryptography.fernet import Fernet, InvalidToken


logger = logging.getLogger(__name__)

ENCRYPTED_SUFFIX = ".enc"
KEY_SUFFIX = ".key"
=======
"""Fernet helpers for an authorized backup worker; no key is created implicitly."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import os
from pathlib import Path

ENCRYPTED_SUFFIX = ".enc"
>>>>>>> integration/deploy-main


@dataclass
class EncryptionResult:
    source_path: str
    destination_path: str
    file_count: int
    success: bool
    attempted_at: str
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "source_path": self.source_path,
            "destination_path": self.destination_path,
            "file_count": self.file_count,
            "success": self.success,
            "attempted_at": self.attempted_at,
            "errors": self.errors,
        }


def generate_key() -> bytes:
<<<<<<< HEAD
    """Generate a fresh Fernet key. Store securely."""
=======
    from cryptography.fernet import Fernet

>>>>>>> integration/deploy-main
    return Fernet.generate_key()


def save_key(key: bytes, key_path: str | Path) -> Path:
<<<<<<< HEAD
    """Write a Fernet key to disk. Creates parent directories."""
    path = Path(key_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key)
=======
    path = Path(key_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as file:
        file.write(key)
>>>>>>> integration/deploy-main
    return path


def load_key(key_path: str | Path) -> bytes:
<<<<<<< HEAD
    """Read a Fernet key from disk."""
    return Path(key_path).read_bytes()


def encrypt_file(source: str | Path, destination: str | Path, key: bytes) -> Path:
    """
    Encrypt a single file to destination.

    The destination is written with the encrypted bytes. The original file
    is not modified.
    """
    src = Path(source)
    dst = Path(destination)

    if not src.exists():
        raise FileNotFoundError(f"Source file not found: {src}")

    dst.parent.mkdir(parents=True, exist_ok=True)

    fernet = Fernet(key)
    plaintext = src.read_bytes()
    ciphertext = fernet.encrypt(plaintext)
    dst.write_bytes(ciphertext)

=======
    path = Path(key_path)
    if path.stat().st_mode & 0o077:
        raise PermissionError("Encryption key file permissions must be restricted to its owner")
    return path.read_bytes()


def encrypt_file(source: str | Path, destination: str | Path, key: bytes) -> Path:
    from cryptography.fernet import Fernet

    src = Path(source)
    dst = Path(destination)
    if not src.is_file() or src.is_symlink():
        raise FileNotFoundError(f"Regular source file not found: {src}")
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_bytes(Fernet(key).encrypt(src.read_bytes()))
>>>>>>> integration/deploy-main
    return dst


def decrypt_file(source: str | Path, destination: str | Path, key: bytes) -> Path:
<<<<<<< HEAD
    """
    Decrypt an encrypted file.

    Raises InvalidToken if the ciphertext was tampered with or the key is
    wrong — this is the authentication guarantee Fernet provides.
    """
    src = Path(source)
    dst = Path(destination)

    if not src.exists():
        raise FileNotFoundError(f"Encrypted file not found: {src}")

    dst.parent.mkdir(parents=True, exist_ok=True)

    fernet = Fernet(key)
    ciphertext = src.read_bytes()
    plaintext = fernet.decrypt(ciphertext)
    dst.write_bytes(plaintext)

=======
    from cryptography.fernet import Fernet

    src = Path(source)
    if not src.is_file() or src.is_symlink():
        raise FileNotFoundError(f"Regular encrypted file not found: {src}")
    dst = Path(destination)
    dst.parent.mkdir(parents=True, exist_ok=True)
    # Fernet authentication is checked before writing plaintext to destination.
    plaintext = Fernet(key).decrypt(src.read_bytes())
    dst.write_bytes(plaintext)
>>>>>>> integration/deploy-main
    return dst


def is_encrypted(path: str | Path) -> bool:
<<<<<<< HEAD
    """Check whether a path has the encrypted suffix."""
    return Path(path).name.endswith(ENCRYPTED_SUFFIX)


def encrypt_backup_dir(
    source_dir: str | Path,
    destination_dir: str | Path,
    key: bytes,
) -> EncryptionResult:
    """
    Recursively encrypt every file under source_dir into destination_dir.

    Directory structure is preserved. Files get a .enc suffix.
    """
    src = Path(source_dir)
    dst = Path(destination_dir)
    attempted_at = datetime.now(timezone.utc).isoformat()
    errors: list[str] = []
    encrypted_count = 0

    if not src.exists() or not src.is_dir():
        return EncryptionResult(
            source_path=str(src),
            destination_path=str(dst),
            file_count=0,
            success=False,
            attempted_at=attempted_at,
            errors=["Source directory does not exist or is not a directory."],
        )

    dst.mkdir(parents=True, exist_ok=True)

    for item in src.rglob("*"):
        if not item.is_file():
            continue
        relative = item.relative_to(src)
        target = dst / (str(relative) + ENCRYPTED_SUFFIX)

        try:
            encrypt_file(item, target, key)
            encrypted_count += 1
        except Exception as error:
            logger.error("Failed to encrypt %s: %s", item, error)
            errors.append(f"{item}: {error}")

    return EncryptionResult(
        source_path=str(src),
        destination_path=str(dst),
        file_count=encrypted_count,
        success=len(errors) == 0,
        attempted_at=attempted_at,
        errors=errors,
    )


def decrypt_backup_dir(
    source_dir: str | Path,
    destination_dir: str | Path,
    key: bytes,
) -> EncryptionResult:
    """
    Recursively decrypt every .enc file under source_dir into destination_dir.

    The .enc suffix is stripped from decrypted files.
    """
    src = Path(source_dir)
    dst = Path(destination_dir)
    attempted_at = datetime.now(timezone.utc).isoformat()
    errors: list[str] = []
    decrypted_count = 0

    if not src.exists() or not src.is_dir():
        return EncryptionResult(
            source_path=str(src),
            destination_path=str(dst),
            file_count=0,
            success=False,
            attempted_at=attempted_at,
            errors=["Source directory does not exist or is not a directory."],
        )

    dst.mkdir(parents=True, exist_ok=True)

    for item in src.rglob("*"):
        if not item.is_file() or not is_encrypted(item):
            continue

        relative = item.relative_to(src)
        stripped = Path(str(relative)[: -len(ENCRYPTED_SUFFIX)])
        target = dst / stripped

        try:
            decrypt_file(item, target, key)
            decrypted_count += 1
        except InvalidToken:
            errors.append(f"{item}: authentication failed (wrong key or tampered).")
        except Exception as error:
            logger.error("Failed to decrypt %s: %s", item, error)
            errors.append(f"{item}: {error}")

    return EncryptionResult(
        source_path=str(src),
        destination_path=str(dst),
        file_count=decrypted_count,
        success=len(errors) == 0,
        attempted_at=attempted_at,
        errors=errors,
    )
=======
    return Path(path).name.endswith(ENCRYPTED_SUFFIX)


def _transform_directory(source_dir: str | Path, destination_dir: str | Path, key: bytes, *, encrypt: bool) -> EncryptionResult:
    from cryptography.fernet import InvalidToken

    source = Path(source_dir).expanduser().resolve()
    destination = Path(destination_dir).expanduser().resolve()
    attempted_at = datetime.now(timezone.utc).isoformat()
    operation = encrypt_file if encrypt else decrypt_file
    errors = []
    count = 0
    if (
        not source.is_dir()
        or destination == source
        or source in destination.parents
        or destination in source.parents
    ):
        return EncryptionResult(str(source), str(destination), 0, False, attempted_at,
                                ["Source and destination must be separate, non-overlapping directory trees."])
    destination.mkdir(parents=True, exist_ok=True)
    for item in source.rglob("*"):
        if item.is_symlink():
            errors.append(f"{item}: symbolic links are not accepted")
            continue
        if not item.is_file() or (not encrypt and not is_encrypted(item)):
            continue
        relative = item.relative_to(source)
        target_relative = Path(f"{relative}{ENCRYPTED_SUFFIX}") if encrypt else Path(str(relative)[:-len(ENCRYPTED_SUFFIX)])
        try:
            operation(item, destination / target_relative, key)
            count += 1
        except (OSError, InvalidToken, ValueError) as error:
            errors.append(f"{relative}: {error}")
    return EncryptionResult(str(source), str(destination), count, not errors, attempted_at, errors)


def encrypt_backup_dir(source_dir: str | Path, destination_dir: str | Path, key: bytes) -> EncryptionResult:
    return _transform_directory(source_dir, destination_dir, key, encrypt=True)


def decrypt_backup_dir(source_dir: str | Path, destination_dir: str | Path, key: bytes) -> EncryptionResult:
    return _transform_directory(source_dir, destination_dir, key, encrypt=False)
>>>>>>> integration/deploy-main
