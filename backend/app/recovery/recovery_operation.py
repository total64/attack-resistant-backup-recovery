from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4


@dataclass
class RecoveryOperation:
    backup_path: str
    restore_path: str
<<<<<<< HEAD
    operation_id: str = field(
        default_factory=lambda: str(uuid4())
    )
    started_at: str = field(
        default_factory=lambda: datetime.now(
            timezone.utc
        ).isoformat()
    )
=======
    operation_id: str = field(default_factory=lambda: str(uuid4()))
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
>>>>>>> integration/deploy-main
    completed_at: str | None = None
    status: str = "STARTED"
    verification: dict | None = None
    validation: dict | None = None
    error: str | None = None

<<<<<<< HEAD
    def complete(
        self,
        status: str = "RECOVERY_COMPLETED",
    ) -> None:
        self.status = status
        self.completed_at = datetime.now(
            timezone.utc
        ).isoformat()

    def fail(
        self,
        status: str,
        error: str | None = None,
    ) -> None:
        self.status = status
        self.error = error
        self.completed_at = datetime.now(
            timezone.utc
        ).isoformat()
=======
    def complete(self, status: str = "RECOVERY_COMPLETED") -> None:
        self.status = status
        self.completed_at = datetime.now(timezone.utc).isoformat()

    def fail(self, status: str, error: str | None = None) -> None:
        self.status = status
        self.error = error
        self.completed_at = datetime.now(timezone.utc).isoformat()
>>>>>>> integration/deploy-main

    def to_dict(self) -> dict:
        return {
            "operation_id": self.operation_id,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "backup_path": self.backup_path,
            "restore_path": self.restore_path,
            "status": self.status,
            "verification": self.verification,
            "validation": self.validation,
            "error": self.error,
<<<<<<< HEAD
        }
=======
        }
>>>>>>> integration/deploy-main
