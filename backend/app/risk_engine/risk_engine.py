from dataclasses import dataclass

from .risk_rules import RISK_RULES


@dataclass(frozen=True)
class RiskEvent:
    event_id: str
    host_id: str
    indicators: dict


@dataclass(frozen=True)
class RiskAssessment:
    event_id: str
    host_id: str
    risk_score: float
    risk_level: str
    threat_type: str
    triggered_rules: tuple[str, ...]

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "host_id": self.host_id,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "threat_type": self.threat_type,
            "triggered_rules": list(self.triggered_rules),
        }


class RiskEngine:
    def __init__(self, rules=RISK_RULES):
        self.rules = rules

    def assess(self, event: RiskEvent) -> RiskAssessment:
        score = 0.0
        triggered_rules = []
        threat_types = []
        for rule in self.rules:
            if rule.condition(event.indicators):
                score += rule.score
                triggered_rules.append(rule.name)
                threat_types.append(rule.threat_type)
        score = min(score, 100.0)
        return RiskAssessment(
            event_id=event.event_id,
            host_id=event.host_id,
            risk_score=score,
            risk_level=self._get_risk_level(score),
            threat_type=self._get_threat_type(threat_types),
            triggered_rules=tuple(triggered_rules),
        )

    @staticmethod
    def _get_risk_level(score: float) -> str:
        if score >= 80:
            return "CRITICAL"
        if score >= 60:
            return "HIGH"
        if score >= 30:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _get_threat_type(threat_types: list[str]) -> str:
        priority = (
            "ransomware_behavior", "backup_destruction", "privilege_escalation",
            "defense_evasion", "suspicious_activity",
        )
        for threat_type in priority:
            if threat_type in threat_types:
                return threat_type
        return threat_types[0] if threat_types else "unknown"
