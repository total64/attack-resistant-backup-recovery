<<<<<<< HEAD
"""
models.py - Data models for the Cyber Resilience Decision Engine.

This file defines the "shapes" of the data the Decision Engine works with.
Think of each class as a form with named fields:

    SecurityEvent   -> something suspicious that was detected (input)
    RiskAssessment  -> how dangerous the situation is (calculated)
    BackupStatus    -> the health of a backup (input)
    Decision        -> what the engine decides to do (output)
    ResponseAction  -> the list of possible actions (ALLOW ... RECOVER)

The other files in the decision engine (risk scorer, rules, executor, etc.)
will all import these classes, so they all speak the same "language".
"""

# This lets us use modern type hints (like `list[str]`) safely in all
# Python 3.8+ versions. It must be the first import in the file.
=======
>>>>>>> integration/deploy-main
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
<<<<<<< HEAD
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _utc_now() -> datetime:
    """Return the current time in UTC (timezone-aware).

    We always use UTC so timestamps from different machines can be compared
    safely, no matter which time zone each team member's computer is in.
    """
    return datetime.now(timezone.utc)


def _new_id() -> str:
    """Generate a unique ID string, e.g. '3f2b8c1e-....'.

    uuid4() creates a random ID that is practically guaranteed to be unique,
    so we never accidentally give two decisions the same ID.
    """
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Enums (fixed sets of allowed values)
# ---------------------------------------------------------------------------

class ResponseAction(str, Enum):
    """The possible responses the Decision Engine can choose, from mildest
    to strongest.

    Inheriting from `str` means each value behaves like a normal string,
    which makes it easy to save as JSON or send through an API.

        ALLOW   - Everything looks normal; do nothing special.
        ALERT   - Something looks odd; notify the security team.
        PROTECT - Strengthen defenses (e.g. lock backups, take an extra
                  snapshot) before anything gets damaged.
        ISOLATE - Cut off the affected system/network from everything else
                  to stop an attack from spreading.
        RECOVER - Damage has happened; restore from a trusted backup.
    """

=======
from typing import Any


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class ResponseAction(str, Enum):
>>>>>>> integration/deploy-main
    ALLOW = "ALLOW"
    ALERT = "ALERT"
    PROTECT = "PROTECT"
    ISOLATE = "ISOLATE"
    RECOVER = "RECOVER"


class RiskLevel(str, Enum):
<<<<<<< HEAD
    """A human-friendly label for a numeric risk score.

    Score ranges (used by RiskAssessment.level_from_score):
        0  - 24  -> LOW
        25 - 49  -> MEDIUM
        50 - 74  -> HIGH
        75 - 100 -> CRITICAL
    """

=======
>>>>>>> integration/deploy-main
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


<<<<<<< HEAD
# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------
# A @dataclass automatically writes __init__, __repr__ and __eq__ for us,
# so we only list the fields. Fields WITHOUT a default value are required
# and must come first; fields WITH a default come after.

@dataclass
class SecurityEvent:
    """One suspicious or noteworthy thing detected somewhere in the system.

    Events are produced by other team members' components (for example the
    monitoring or detection modules) and fed into the Decision Engine.

    Attributes:
        event_id:   Unique ID of this event (e.g. "evt-001").
        timestamp:  When the event happened.
        source:     Where it came from (e.g. "file_monitor", "network_ids").
        event_type: What kind of event it is (e.g. "mass_file_encryption",
                    "failed_login", "backup_deletion_attempt").
        severity:   How serious the detector thinks it is, from 1 (minor)
                    to 10 (extreme).
        raw_data:   Extra details exactly as the detector reported them
                    (file names, IP addresses, etc.). Free-form dictionary.
    """

=======
@dataclass
class SecurityEvent:
>>>>>>> integration/deploy-main
    event_id: str
    timestamp: datetime
    source: str
    event_type: str
    severity: int
<<<<<<< HEAD
    # field(default_factory=dict) gives every event its OWN empty dict.
    # (Writing `= {}` directly is a classic Python bug: all objects would
    # share the same dictionary.)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    host_id: Optional[str] = None # which host/asset the event came from
    def __post_init__(self) -> None:
        """Runs automatically right after the object is created.

        We use it to reject bad data early, so mistakes are caught here
        instead of causing confusing bugs later in the engine.
        """
        if not 1 <= self.severity <= 10:
            raise ValueError(
                f"severity must be between 1 and 10, got {self.severity}"
            )
=======
    raw_data: dict[str, Any] = field(default_factory=dict)
    host_id: str | None = None

    def __post_init__(self) -> None:
        if not 1 <= self.severity <= 10:
            raise ValueError(f"severity must be between 1 and 10, got {self.severity}")
>>>>>>> integration/deploy-main


@dataclass
class RiskAssessment:
<<<<<<< HEAD
    """The result of analysing events and deciding how risky things are.

    Attributes:
        risk_score: A number from 0 (totally safe) to 100 (worst case).
        risk_level: The label matching the score (LOW/MEDIUM/HIGH/CRITICAL).
        factors:    Human-readable reasons that pushed the score up, e.g.
                    ["Mass file encryption detected", "Backup deletion attempt"].
                    Useful for explaining WHY the score is what it is.
        timestamp:  When this assessment was made.
    """

    risk_score: float
    risk_level: RiskLevel
    factors: List[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=_utc_now)

    def __post_init__(self) -> None:
        """Validate the score range."""
        if not 0 <= self.risk_score <= 100:
            raise ValueError(
                f"risk_score must be between 0 and 100, got {self.risk_score}"
            )

    @staticmethod
    def level_from_score(score: float) -> RiskLevel:
        """Convert a numeric score into a RiskLevel label.

        A @staticmethod doesn't need an existing object; you call it
        directly on the class:

            level = RiskAssessment.level_from_score(82)  # RiskLevel.CRITICAL

        Args:
            score: Number from 0 to 100.

        Returns:
            The matching RiskLevel.
        """
=======
    risk_score: float
    risk_level: RiskLevel
    factors: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=_utc_now)

    def __post_init__(self) -> None:
        if not 0 <= self.risk_score <= 100:
            raise ValueError(f"risk_score must be between 0 and 100, got {self.risk_score}")

    @staticmethod
    def level_from_score(score: float) -> RiskLevel:
>>>>>>> integration/deploy-main
        if score >= 75:
            return RiskLevel.CRITICAL
        if score >= 50:
            return RiskLevel.HIGH
        if score >= 25:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW


@dataclass
class BackupStatus:
<<<<<<< HEAD
    """The health and trustworthiness of one backup.

    Before recovering, the engine must be sure the backup it restores from
    is clean. Restoring from an infected backup would re-infect the system!

    Attributes:
        backup_id:          Unique ID of the backup.
        timestamp:          When the backup was created.
        integrity_verified: True if checks (e.g. hash comparison) confirmed
                            the backup was not corrupted or modified.
        trusted:            True if the backup is considered safe to restore
                            (e.g. created before the attack began).
        location:           Where it is stored (e.g. "/backups/2026-09-27"
                            or "offsite-vault-1").
    """

=======
>>>>>>> integration/deploy-main
    backup_id: str
    timestamp: datetime
    integrity_verified: bool
    trusted: bool
    location: str

    def is_safe_to_restore(self) -> bool:
<<<<<<< HEAD
        """Return True only if the backup is BOTH verified AND trusted.

        We require both conditions. A backup that is intact but created
        after the attack started could still contain malware.
        """
=======
>>>>>>> integration/deploy-main
        return self.integrity_verified and self.trusted


@dataclass
class Decision:
<<<<<<< HEAD
    """The final output of the Decision Engine: what to do and why.

    Attributes:
        decision_id:       Unique ID for this decision (useful for audit logs).
        timestamp:         When the decision was made.
        action:            The chosen ResponseAction (ALLOW, ALERT, ...).
        reason:            A plain-English explanation of why this action
                           was chosen.
        triggering_events: The SecurityEvents that led to this decision.
        risk_assessment:   The RiskAssessment the decision was based on.
        confidence:        How sure the engine is, from 0.0 (guessing) to
                           1.0 (certain).
        actions_to_execute: Concrete step-by-step tasks for the rest of the
                           system to carry out, e.g.
                           ["disable_network_share", "lock_backup_vault"].
    """

=======
>>>>>>> integration/deploy-main
    action: ResponseAction
    reason: str
    risk_assessment: RiskAssessment
    confidence: float
<<<<<<< HEAD
    # Fields below have defaults, so they come after the required ones.
    # decision_id and timestamp are filled in automatically.
    decision_id: str = field(default_factory=_new_id)
    timestamp: datetime = field(default_factory=_utc_now)
    triggering_events: List[SecurityEvent] = field(default_factory=list)
    actions_to_execute: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        """Validate the confidence range."""
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(
                f"confidence must be between 0.0 and 1.0, got {self.confidence}"
            )
=======
    decision_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=_utc_now)
    triggering_events: list[SecurityEvent] = field(default_factory=list)
    actions_to_execute: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"confidence must be between 0.0 and 1.0, got {self.confidence}")
>>>>>>> integration/deploy-main
