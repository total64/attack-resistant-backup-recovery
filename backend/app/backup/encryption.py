"""Fernet helpers for an authorized backup worker; no key is created implicitly."""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import os
from pathlib import Path

ENCRYPTED_SUFFIX = ".enc"


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
    from cryptography.fernet import Fernet

    return Fernet.generate_key()


def save_key(key: bytes, key_path: str | Path) -> Path:
    path = Path(key_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as file:
        file.write(key)
    return path


def load_key(key_path: str | Path) -> bytes:
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
    return dst


def decrypt_file(source: str | Path, destination: str | Path, key: bytes) -> Path:
    from cryptography.fernet import Fernet

    src = Path(source)
    if not src.is_file() or src.is_symlink():
        raise FileNotFoundError(f"Regular encrypted file not found: {src}")
    dst = Path(destination)
    dst.parent.mkdir(parents=True, exist_ok=True)
    # Fernet authentication is checked before writing plaintext to destination.
    plaintext = Fernet(key).decrypt(src.read_bytes())
    dst.write_bytes(plaintext)
    return dst


def is_encrypted(path: str | Path) -> bool:
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
