import hashlib
import shutil
from pathlib import Path

import pytest

from app.backup.encryption import decrypt_file, encrypt_file, generate_key, load_key, save_key
from app.backup.backup_manager import BackupManager
from app.backup.protection import lock_backup
from app.backup.recovery_point import RecoveryPoint
from app.backup.storage_manager import BackupStorageManager
from app.backup.verification import verify_recovery_point, write_trusted_hash
from app.isolation.firewall import MockFirewall
from app.isolation.isolation_manager import IsolationManager
from app.recovery.backup_verifier import BackupVerifier
from app.recovery.recovery_manager import RecoveryManager
from app.recovery.restore_validator import RestoreValidator


def test_trusted_directory_manifest_detects_tampering(tmp_path):
    content = tmp_path / "point" / "document.txt"
    content.parent.mkdir()
    content.write_text("trusted data")
    manifest_dir = tmp_path / "manifests"
    write_trusted_hash(content.parent, "backup-001", manifest_dir)
    recovery_point = RecoveryPoint.create(
        "backup-001", str(tmp_path), str(content.parent), "COMPLETED", 1, content.stat().st_size
    )
    assert verify_recovery_point(recovery_point, manifest_dir).status == "VERIFIED"
    content.write_text("modified data")
    assert verify_recovery_point(recovery_point, manifest_dir).status == "TAMPERED"


def test_backup_manager_runs_non_destructive_copy_and_hashes_result(tmp_path, monkeypatch):
    source = tmp_path / "source"
    source.mkdir()
    (source / "important.txt").write_text("recovery data")
    destination = tmp_path / "backups" / "backup-1"
    captured = {}

    def fake_rsync(command, **kwargs):
        captured["command"] = command
        source_path = Path(command[-2].rstrip("/"))
        destination_path = Path(command[-1].rstrip("/"))
        shutil.copytree(source_path, destination_path, dirs_exist_ok=True)
        return object()

    monkeypatch.setattr("app.backup.backup_manager.subprocess.run", fake_rsync)
    result = BackupManager().create_backup("backup-1", str(source), str(destination))
    assert result.status == "COMPLETED"
    assert result.file_count == 1
    assert result.manifest_sha256
    assert "--delete" not in captured["command"]


def test_manifest_is_not_silently_replaced(tmp_path):
    backup = tmp_path / "backup"
    backup.mkdir()
    (backup / "data").write_text("baseline")
    manifests = tmp_path / "manifests"
    write_trusted_hash(backup, "fixed-id", manifests)
    (backup / "data").write_text("changed")
    with pytest.raises(FileExistsError):
        write_trusted_hash(backup, "fixed-id", manifests)


def test_backup_storage_rejects_path_traversal(tmp_path):
    storage = BackupStorageManager(str(tmp_path / "storage"))
    with pytest.raises(ValueError):
        storage.get_recovery_point("../outside")
    point = storage.create_recovery_point("safe-backup-1")
    assert point.is_dir()
    assert storage.recovery_point_exists("safe-backup-1")


def test_fernet_file_roundtrip_and_restricted_key_file(tmp_path):
    pytest.importorskip("cryptography.fernet")
    key = generate_key()
    source = tmp_path / "source.txt"
    encrypted = tmp_path / "source.txt.enc"
    restored = tmp_path / "restored.txt"
    source.write_text("authenticated data")
    encrypt_file(source, encrypted, key)
    assert encrypted.read_bytes() != source.read_bytes()
    decrypt_file(encrypted, restored, key)
    assert restored.read_text() == source.read_text()
    key_path = save_key(key, tmp_path / "keys" / "backup.key")
    assert key_path.stat().st_mode & 0o077 == 0
    assert load_key(key_path) == key


def test_backup_verifier_rejects_traversal_and_detects_bad_digest(tmp_path):
    backup = tmp_path / "backup"
    backup.mkdir()
    (backup / "good.txt").write_text("good")
    verifier = BackupVerifier()
    digest = hashlib.sha256(b"good").hexdigest()
    assert verifier.verify_backup(str(backup), {"good.txt": digest})["trusted"]
    traversal = verifier.verify_backup(str(backup), {"../outside": digest})
    assert not traversal["trusted"]
    assert traversal["mismatches"][0]["reason"] == "INVALID_RELATIVE_PATH"


def test_recovery_requires_trusted_hash_and_restores_only_to_sibling_directory(tmp_path):
    backup = tmp_path / "backup"
    destination = tmp_path / "restored"
    backup.mkdir()
    data = backup / "record.txt"
    data.write_text("restore content")
    digest = hashlib.sha256(data.read_bytes()).hexdigest()
    manager = RecoveryManager(BackupVerifier(), RestoreValidator())
    result = manager.recover(str(backup), str(destination), {"record.txt": digest}, ["record.txt"])
    assert result["success"] is True
    assert (destination / "record.txt").read_text() == "restore content"

    blocked = manager.recover(str(backup), str(backup / "nested"), {"record.txt": digest})
    assert blocked["success"] is False
    assert blocked["status"] == "RESTORE_PATH_INVALID"


def test_isolation_manager_uses_only_mock_firewall():
    firewall = MockFirewall()
    manager = IsolationManager(firewall)
    isolated = manager.isolate_host("test-host", "controlled test", "HIGH")
    assert isolated["success"] is True
    assert manager.get_status("test-host")["status"] == "ISOLATED"
    released = manager.restore_host("test-host")
    assert released["success"] is True
    assert not firewall.is_isolated("test-host")


def test_immutable_lock_reports_worker_operation_not_performed_on_non_linux(tmp_path, monkeypatch):
    import app.backup.protection as protection

    monkeypatch.setattr(protection.platform, "system", lambda: "TestOS")
    result = lock_backup(tmp_path)
    assert result.success is False
    assert "requires Linux" in result.error
