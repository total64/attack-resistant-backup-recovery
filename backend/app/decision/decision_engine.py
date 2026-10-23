<<<<<<< HEAD
"""
decision_engine.py - The "brain" that decides how the system should respond.

The flow, in plain English:

    events + backups
          |
          v
    RiskScorer  ->  RiskAssessment (score + level)
          |
          v
    Step 1: pick a BASE action from the risk level
              LOW -> ALLOW, MEDIUM -> ALERT, HIGH -> PROTECT, CRITICAL -> ISOLATE
    Step 2: ESCALATE if attackers are going after the backups
    Step 3: If files are already being destroyed, look for a SAFE backup
              - found     -> RECOVER
              - not found -> ISOLATE (containing the damage is the best we can do)
    Step 4: calculate a confidence value and the list of concrete tasks
          |
          v
    Decision
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, List, Optional

from .models import (
    BackupStatus,
    Decision,
    ResponseAction,
    RiskLevel,
    SecurityEvent,
)
from .risk_scorer import RiskScorer


# ---------------------------------------------------------------------------
# Tunable settings
# ---------------------------------------------------------------------------

# Event types that mean data is ALREADY being damaged.
DAMAGE_EVENT_TYPES = frozenset({"mass_file_encryption", "ransomware_note_detected"})

# Event types that mean the BACKUPS themselves are under attack.
BACKUP_THREAT_TYPES = frozenset({"backup_deletion_attempt", "backup_tampering"})

# Simple starting confidence for each risk level. Higher risk levels come
# from stronger evidence, so we are more sure about them.
BASE_CONFIDENCE: Dict[RiskLevel, float] = {
=======
from __future__ import annotations

from datetime import datetime, timezone

from .models import BackupStatus, Decision, ResponseAction, RiskLevel, SecurityEvent
from .risk_scorer import RiskScorer

DAMAGE_EVENT_TYPES = frozenset({"mass_file_encryption", "ransomware_note_detected"})
BACKUP_THREAT_TYPES = frozenset({"backup_deletion_attempt", "backup_tampering"})
BASE_CONFIDENCE = {
>>>>>>> integration/deploy-main
    RiskLevel.LOW: 0.60,
    RiskLevel.MEDIUM: 0.65,
    RiskLevel.HIGH: 0.75,
    RiskLevel.CRITICAL: 0.85,
}
<<<<<<< HEAD

# The concrete tasks other parts of the system should perform for each
# action. These are just names (strings); the team member who builds the
# executor decides how to actually run them.
ACTION_STEPS: Dict[ResponseAction, List[str]] = {
    ResponseAction.ALLOW: [],
    ResponseAction.ALERT: [
        "notify_security_team",
        "increase_logging_level",
    ],
    ResponseAction.PROTECT: [
        "notify_security_team",
        "lock_backup_vault",
        "create_emergency_snapshot",
        "increase_logging_level",
    ],
    ResponseAction.ISOLATE: [
        "notify_security_team",
        "lock_backup_vault",
        "disconnect_affected_systems_from_network",
        "suspend_suspicious_processes",
        "create_forensic_snapshot",
    ],
    ResponseAction.RECOVER: [
        "notify_security_team",
        "disconnect_affected_systems_from_network",
        "suspend_suspicious_processes",
        "create_forensic_snapshot",
        # A "restore_from_backup:<id>" step is added at runtime.
        "verify_system_after_restore",
    ],
}


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

def _as_utc(moment: datetime) -> datetime:
    """Make sure a datetime has timezone info (assume UTC if it has none).

    Comparing a "naive" datetime (no timezone) with an "aware" one crashes
    in Python, so we normalise everything first.
    """
    if moment.tzinfo is None:
        return moment.replace(tzinfo=timezone.utc)
    return moment


# ---------------------------------------------------------------------------
# Main class
# ---------------------------------------------------------------------------

class DecisionEngine:
    """Chooses a response to a set of security events.

    Example:
        engine = DecisionEngine()
        decision = engine.decide(events, backups)
        print(decision.action, decision.reason)
    """

    def __init__(self, scorer: Optional[RiskScorer] = None) -> None:
        """Create the engine.

        Args:
            scorer: Optional custom RiskScorer. If omitted, a default one
                    is created. (Passing one in is handy for testing.)
        """
        self.scorer = scorer if scorer is not None else RiskScorer()

    # ------------------------------------------------------------------
    # Public method
    # ------------------------------------------------------------------
    def decide(
        self,
        events: List[SecurityEvent],
        backups: Optional[List[BackupStatus]] = None,
        now: Optional[datetime] = None,
    ) -> Decision:
        """Analyse the situation and return a Decision.

        Args:
            events:  Recent security events (can be empty).
            backups: Known backups and their health (can be empty or None).
            now:     Optional fixed "current time" for testing.

        Returns:
            A fully filled-in Decision.
        """
        if backups is None:
            backups = []
        if now is None:
            now = datetime.now(timezone.utc)

        # Ask the scorer how risky things are.
        assessment = self.scorer.assess(events, now)
        level = assessment.risk_level

        # Which kinds of events do we have?
        event_types = {event.event_type for event in events}
        damage_detected = bool(event_types & DAMAGE_EVENT_TYPES)
        backups_threatened = bool(event_types & BACKUP_THREAT_TYPES)

        # We collect explanation sentences here and join them at the end.
        reasons: List[str] = [
            f"Risk score is {assessment.risk_score} ({level.value})."
        ]
        backup_to_use: Optional[BackupStatus] = None

        # ---- Step 1: base action from the risk level -----------------
=======
ACTION_STEPS = {
    ResponseAction.ALLOW: [],
    ResponseAction.ALERT: ["notify_security_team", "increase_logging_level"],
    ResponseAction.PROTECT: ["notify_security_team", "lock_backup_vault", "create_emergency_snapshot", "increase_logging_level"],
    ResponseAction.ISOLATE: ["notify_security_team", "lock_backup_vault", "disconnect_affected_systems_from_network", "suspend_suspicious_processes", "create_forensic_snapshot"],
    ResponseAction.RECOVER: ["notify_security_team", "disconnect_affected_systems_from_network", "suspend_suspicious_processes", "create_forensic_snapshot", "verify_system_after_restore"],
}


def _as_utc(moment: datetime) -> datetime:
    return moment.replace(tzinfo=timezone.utc) if moment.tzinfo is None else moment


class DecisionEngine:
    def __init__(self, scorer: RiskScorer | None = None) -> None:
        self.scorer = scorer if scorer is not None else RiskScorer()

    def decide(
        self,
        events: list[SecurityEvent],
        backups: list[BackupStatus] | None = None,
        now: datetime | None = None,
    ) -> Decision:
        backups = backups or []
        now = now or datetime.now(timezone.utc)
        assessment = self.scorer.assess(events, now)
        level = assessment.risk_level
        event_types = {event.event_type for event in events}
        damage_detected = bool(event_types & DAMAGE_EVENT_TYPES)
        backups_threatened = bool(event_types & BACKUP_THREAT_TYPES)
        reasons = [f"Risk score is {assessment.risk_score} ({level.value})."]
        backup_to_use = None

>>>>>>> integration/deploy-main
        if level == RiskLevel.LOW:
            action = ResponseAction.ALLOW
            reasons.append("No significant threat detected; allowing normal operation.")
        elif level == RiskLevel.MEDIUM:
            action = ResponseAction.ALERT
            reasons.append("Suspicious activity detected; alerting the security team.")
        elif level == RiskLevel.HIGH:
            action = ResponseAction.PROTECT
            reasons.append("High risk; strengthening defenses to protect data.")
<<<<<<< HEAD
        else:  # CRITICAL
            action = ResponseAction.ISOLATE
            reasons.append("Critical risk; isolating affected systems to stop the spread.")

        # ---- Step 2: escalate if the backups are being attacked ------
        # Backups are our last line of defense, so an attack on them
        # deserves at least PROTECT even if the total score looks modest.
        if backups_threatened and action in (ResponseAction.ALLOW, ResponseAction.ALERT):
            action = ResponseAction.PROTECT
            reasons.append(
                "Backups are being targeted, so the response was escalated to PROTECT."
            )

        # ---- Step 3: recovery, but only from a SAFE backup -----------
=======
        else:
            action = ResponseAction.ISOLATE
            reasons.append("Critical risk; isolating affected systems to stop the spread.")

        if backups_threatened and action in (ResponseAction.ALLOW, ResponseAction.ALERT):
            action = ResponseAction.PROTECT
            reasons.append("Backups are being targeted, so the response was escalated to PROTECT.")

>>>>>>> integration/deploy-main
        if damage_detected and level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            backup_to_use = self._select_backup(backups, events)
            if backup_to_use is not None:
                action = ResponseAction.RECOVER
                reasons.append(
<<<<<<< HEAD
                    f"Data damage detected; recovering from trusted backup "
                    f"'{backup_to_use.backup_id}' at {backup_to_use.location}."
                )
            else:
                # Never restore from an unverified backup: it could
                # re-infect the system. Contain the attack instead.
                action = ResponseAction.ISOLATE
                reasons.append(
                    "Data damage detected but NO safe backup is available "
                    "(none both verified and created before the attack). "
                    "Isolating instead; manual review is required."
                )

        # ---- Step 4: confidence and concrete tasks -------------------
        confidence = self._calculate_confidence(level, events, events_present=bool(events))

        steps = list(ACTION_STEPS[action])  # copy so we never edit the original
        if action == ResponseAction.RECOVER and backup_to_use is not None:
            # Insert the restore step just before the final verification step.
            steps.insert(-1, f"restore_from_backup:{backup_to_use.backup_id}")

=======
                    f"Data damage detected; recovering from trusted backup '{backup_to_use.backup_id}' at {backup_to_use.location}."
                )
            else:
                action = ResponseAction.ISOLATE
                reasons.append(
                    "Data damage detected but NO safe backup is available (none both verified and created before the attack). Isolating instead; manual review is required."
                )

        confidence = self._calculate_confidence(level, events, bool(events))
        steps = list(ACTION_STEPS[action])
        if action == ResponseAction.RECOVER and backup_to_use is not None:
            steps.insert(-1, f"restore_from_backup:{backup_to_use.backup_id}")
>>>>>>> integration/deploy-main
        return Decision(
            action=action,
            reason=" ".join(reasons),
            risk_assessment=assessment,
            confidence=confidence,
            triggering_events=list(events),
            actions_to_execute=steps,
        )

<<<<<<< HEAD
    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _select_backup(
        backups: List[BackupStatus],
        events: List[SecurityEvent],
    ) -> Optional[BackupStatus]:
        """Pick the best backup to restore from, or None if none is safe.

        Rules:
            1. The backup must be verified AND trusted (is_safe_to_restore).
            2. It must have been created BEFORE the earliest suspicious
               event, otherwise it might already contain the attack.
            3. Among the remaining ones, choose the NEWEST (least data loss).
        """
        # When did the attack seem to begin?
        attack_start = min(_as_utc(event.timestamp) for event in events)

        candidates = [
            backup
            for backup in backups
            if backup.is_safe_to_restore()
            and _as_utc(backup.timestamp) < attack_start
        ]
        if not candidates:
            return None

        # max() with a key returns the item with the latest timestamp.
        return max(candidates, key=lambda backup: _as_utc(backup.timestamp))

    @staticmethod
    def _calculate_confidence(
        level: RiskLevel,
        events: List[SecurityEvent],
        events_present: bool,
    ) -> float:
        """Estimate how sure the engine is (0.0 to 1.0).

        Idea: evidence from several INDEPENDENT sources is more convincing
        than lots of events from one source.
        """
        if not events_present:
            # Nothing detected at all: quite sure everything is fine.
            return 0.95

        confidence = BASE_CONFIDENCE[level]

        # +0.03 for each extra distinct source, up to +0.10 in total.
        distinct_sources = len({event.source for event in events})
        confidence += min(0.10, 0.03 * (distinct_sources - 1))

        return round(min(confidence, 0.99), 2)
=======
    @staticmethod
    def _select_backup(backups: list[BackupStatus], events: list[SecurityEvent]) -> BackupStatus | None:
        attack_start = min(_as_utc(event.timestamp) for event in events)
        candidates = [
            backup for backup in backups
            if backup.is_safe_to_restore() and _as_utc(backup.timestamp) < attack_start
        ]
        return max(candidates, key=lambda backup: _as_utc(backup.timestamp)) if candidates else None

    @staticmethod
    def _calculate_confidence(level: RiskLevel, events: list[SecurityEvent], events_present: bool) -> float:
        if not events_present:
            return 0.95
        confidence = BASE_CONFIDENCE[level]
        distinct_sources = len({event.source for event in events})
        confidence += min(0.10, 0.03 * (distinct_sources - 1))
        return round(min(confidence, 0.99), 2)
>>>>>>> integration/deploy-main
