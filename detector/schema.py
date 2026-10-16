"""Normalized record format produced by the detector pipeline."""
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Optional
import uuid


@dataclass
class Detection:
    detection_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    agent_id: str = ""
    agent_name: str = ""
    host: str = ""
    detection_type: str = ""
    severity: str = "medium"
    evidence: dict = field(default_factory=dict)
    raw_alert_id: Optional[str] = None
    wazuh_rule_id: Optional[str] = None
    wazuh_rule_level: Optional[int] = None

    def to_dict(self) -> dict:
        return asdict(self)
