from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ResponseAction(str, Enum):
    ALLOW = "ALLOW"
    ALERT = "ALERT"
    PROTECT = "PROTECT"
    ISOLATE = "ISOLATE"
    RECOVER = "RECOVER"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class SecurityEvent:
    event_id: str
    timestamp: datetime
    source: str
    event_type: str
    severity: int
    raw_data: dict[str, Any] = field(default_factory=dict)
    host_id: str | None = None

    def __post_init__(self) -> None:
        if not 1 <= self.severity <= 10:
            raise ValueError(f"severity must be between 1 and 10, got {self.severity}")


@dataclass
class RiskAssessment:
    risk_score: float
    risk_level: RiskLevel
    factors: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=_utc_now)

    def __post_init__(self) -> None:
        if not 0 <= self.risk_score <= 100:
            raise ValueError(f"risk_score must be between 0 and 100, got {self.risk_score}")

    @staticmethod
    def level_from_score(score: float) -> RiskLevel:
        if score >= 75:
            return RiskLevel.CRITICAL
        if score >= 50:
            return RiskLevel.HIGH
        if score >= 25:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW


@dataclass
class BackupStatus:
    backup_id: str
    timestamp: datetime
    integrity_verified: bool
    trusted: bool
    location: str

    def is_safe_to_restore(self) -> bool:
        return self.integrity_verified and self.trusted


@dataclass
class Decision:
    action: ResponseAction
    reason: str
    risk_assessment: RiskAssessment
    confidence: float
    decision_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=_utc_now)
    triggering_events: list[SecurityEvent] = field(default_factory=list)
    actions_to_execute: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be between 0.0 and 1.0, got {self.confidence}")
