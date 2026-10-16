from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class RiskRule:
    name: str
    score: float
    threat_type: str
    condition: Callable[[dict], bool]


RISK_RULES = (
    RiskRule("mass_file_encryption", 40.0, "ransomware_behavior", lambda values: values.get("mass_file_encryption", False)),
    RiskRule("mass_file_modification", 25.0, "ransomware_behavior", lambda values: values.get("mass_file_modification", False)),
    RiskRule("backup_deletion", 35.0, "backup_destruction", lambda values: values.get("backup_deletion", False)),
    RiskRule("suspicious_process", 20.0, "suspicious_activity", lambda values: values.get("suspicious_process", False)),
    RiskRule("privilege_escalation", 30.0, "privilege_escalation", lambda values: values.get("privilege_escalation", False)),
    RiskRule("security_service_disabled", 35.0, "defense_evasion", lambda values: values.get("security_service_disabled", False)),
)
