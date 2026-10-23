from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass
class RecoveryPoint:
    backup_id: str
    source_path: str
    destination_path: str
    created_at: str
    status: str
    file_count: int
    size_bytes: int
    integrity_status: str = "UNVERIFIED"

    @classmethod
    def create(
        cls,
        backup_id: str,
        source_path: str,
        destination_path: str,
        status: str,
        file_count: int,
        size_bytes: int,
<<<<<<< HEAD
    ):
=======
    ) -> "RecoveryPoint":
>>>>>>> integration/deploy-main
        return cls(
            backup_id=backup_id,
            source_path=source_path,
            destination_path=destination_path,
            created_at=datetime.now(timezone.utc).isoformat(),
            status=status,
            file_count=file_count,
            size_bytes=size_bytes,
        )

    def to_dict(self) -> dict:
        return {
            "backup_id": self.backup_id,
            "source_path": self.source_path,
            "destination_path": self.destination_path,
            "created_at": self.created_at,
            "status": self.status,
            "file_count": self.file_count,
            "size_bytes": self.size_bytes,
            "integrity_status": self.integrity_status,
<<<<<<< HEAD
        }
=======
        }
>>>>>>> integration/deploy-main
