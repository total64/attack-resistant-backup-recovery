from __future__ import annotations

from datetime import datetime, timezone

from .models import RiskAssessment, SecurityEvent

EVENT_WEIGHTS = {
    "mass_file_encryption": 40,
    "ransomware_note_detected": 40,
    "backup_deletion_attempt": 35,
    "backup_tampering": 35,
    "privilege_escalation": 25,
    "lateral_movement": 25,
    "suspicious_process": 15,
    "unauthorized_access": 15,
    "failed_login": 5,
}
DEFAULT_EVENT_WEIGHT = 8
RECENCY_BRACKETS = [(10, 1.0), (60, 0.7), (24 * 60, 0.4)]
OLD_EVENT_MULTIPLIER = 0.1
CORRELATION_RULES = [
    (frozenset({"mass_file_encryption", "backup_deletion_attempt"}), 20,
     "Correlated: file encryption together with backup deletion (typical ransomware pattern)"),
    (frozenset({"privilege_escalation", "lateral_movement"}), 15,
     "Correlated: privilege escalation with lateral movement (attacker spreading through the network)"),
    (frozenset({"failed_login", "unauthorized_access"}), 10,
     "Correlated: failed logins followed by unauthorized access (possible brute-force success)"),
]
DIVERSITY_THRESHOLD = 3
DIVERSITY_BONUS = 10


def _recency_multiplier(event_time: datetime, now: datetime) -> float:
    if event_time.tzinfo is None:
        event_time = event_time.replace(tzinfo=timezone.utc)
    age_minutes = max(0, (now - event_time).total_seconds() / 60)
    for max_age, multiplier in RECENCY_BRACKETS:
        if age_minutes <= max_age:
            return multiplier
    return OLD_EVENT_MULTIPLIER


def _score_single_event(event: SecurityEvent, now: datetime) -> float:
    return (
        EVENT_WEIGHTS.get(event.event_type, DEFAULT_EVENT_WEIGHT)
        * (event.severity / 10)
        * _recency_multiplier(event.timestamp, now)
    )


class RiskScorer:
    def assess(self, events: list[SecurityEvent], now: datetime | None = None) -> RiskAssessment:
        now = now or datetime.now(timezone.utc)
        if not events:
            return RiskAssessment(0, RiskAssessment.level_from_score(0), ["No security events detected"], now)
        total = 0.0
        factors = []
        for event in events:
            points = _score_single_event(event, now)
            total += points
            factors.append(f"{event.event_type} from {event.source} (severity {event.severity}/10): +{points:.1f}")
        present_types = {event.event_type for event in events}
        for required_types, bonus, explanation in CORRELATION_RULES:
            if required_types.issubset(present_types):
                total += bonus
                factors.append(f"{explanation}: +{bonus:.1f}")
        if len(present_types) >= DIVERSITY_THRESHOLD:
            total += DIVERSITY_BONUS
            factors.append(f"{len(present_types)} different event types detected at once: +{DIVERSITY_BONUS:.1f}")
        final_score = round(max(0.0, min(100.0, total)), 1)
        return RiskAssessment(final_score, RiskAssessment.level_from_score(final_score), factors, now)
