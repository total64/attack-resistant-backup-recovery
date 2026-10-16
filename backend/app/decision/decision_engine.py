from __future__ import annotations

from datetime import datetime, timezone

from .models import BackupStatus, Decision, ResponseAction, RiskLevel, SecurityEvent
from .risk_scorer import RiskScorer

DAMAGE_EVENT_TYPES = frozenset({"mass_file_encryption", "ransomware_note_detected"})
BACKUP_THREAT_TYPES = frozenset({"backup_deletion_attempt", "backup_tampering"})
BASE_CONFIDENCE = {
    RiskLevel.LOW: 0.60,
    RiskLevel.MEDIUM: 0.65,
    RiskLevel.HIGH: 0.75,
    RiskLevel.CRITICAL: 0.85,
}
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

        if level == RiskLevel.LOW:
            action = ResponseAction.ALLOW
            reasons.append("No significant threat detected; allowing normal operation.")
        elif level == RiskLevel.MEDIUM:
            action = ResponseAction.ALERT
            reasons.append("Suspicious activity detected; alerting the security team.")
        elif level == RiskLevel.HIGH:
            action = ResponseAction.PROTECT
            reasons.append("High risk; strengthening defenses to protect data.")
        else:
            action = ResponseAction.ISOLATE
            reasons.append("Critical risk; isolating affected systems to stop the spread.")

        if backups_threatened and action in (ResponseAction.ALLOW, ResponseAction.ALERT):
            action = ResponseAction.PROTECT
            reasons.append("Backups are being targeted, so the response was escalated to PROTECT.")

        if damage_detected and level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            backup_to_use = self._select_backup(backups, events)
            if backup_to_use is not None:
                action = ResponseAction.RECOVER
                reasons.append(
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
        return Decision(
            action=action,
            reason=" ".join(reasons),
            risk_assessment=assessment,
            confidence=confidence,
            triggering_events=list(events),
            actions_to_execute=steps,
        )

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
