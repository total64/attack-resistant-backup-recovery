"""Filesystem backup/integrity primitives for explicitly authorized workers."""
from .backup_manager import BackupManager, BackupResult
from .encryption import (
    EncryptionResult,
    decrypt_backup_dir,
    decrypt_file,
    encrypt_backup_dir,
    encrypt_file,
    generate_key,
    load_key,
    save_key,
)
from .integrity import calculate_directory_sha256, calculate_sha256, verify_backup_integrity
from .protection import LockResult, is_locked, lock_backup, unlock_backup
from .recovery_point import RecoveryPoint
from .storage_manager import BackupStorageManager
from .verification import VerificationResult, verify_recovery_point, write_trusted_hash

__all__ = [
    "BackupManager", "BackupResult", "BackupStorageManager", "EncryptionResult",
    "LockResult", "RecoveryPoint", "VerificationResult",
    "calculate_directory_sha256", "calculate_sha256", "verify_backup_integrity",
    "decrypt_backup_dir", "decrypt_file", "encrypt_backup_dir", "encrypt_file",
    "generate_key", "is_locked", "load_key", "lock_backup", "save_key",
    "unlock_backup", "verify_recovery_point", "write_trusted_hash",
]
