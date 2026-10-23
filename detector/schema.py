<<<<<<< HEAD
"""
The handoff contract between Detection (Member 1) and the Risk Engine
(Member 2). This is the normalized record format written to the shared
DB / queue for every detection event.

Keep this file as the single source of truth for the schema - if the
format changes, update it here first and tell Member 2.
"""
from dataclasses import dataclass, field, asdict
=======
"""Normalized record format produced by the detector pipeline."""
from dataclasses import asdict, dataclass, field
>>>>>>> integration/deploy-main
from datetime import datetime, timezone
from typing import Optional
import uuid


@dataclass
class Detection:
<<<<<<< HEAD
    # Identity
    detection_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    # Where it happened
    agent_id: str = ""
    agent_name: str = ""
    host: str = ""

    # What kind of detection this is
    # one of: "mass_file_modification", "suspicious_extension",
    #         "ransom_note", "high_entropy_write", "backup_deletion_attempt",
    #         "ransomware_confirmed"
    detection_type: str = ""

    # "low" | "medium" | "high" | "critical" - Detection's own opinion;
    # Risk Engine may recompute/override this with its own scoring.
    severity: str = "medium"

    # Free-form evidence blob, structure depends on detection_type
    # e.g. {"files_changed": 214, "window_seconds": 8}
    # e.g. {"file": "/data/report.docx.locked", "entropy": 7.91}
    evidence: dict = field(default_factory=dict)

    # Link back to the source Wazuh alert for auditing/forensics
=======
    detection_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    agent_id: str = ""
    agent_name: str = ""
    host: str = ""
    detection_type: str = ""
    severity: str = "medium"
    evidence: dict = field(default_factory=dict)
>>>>>>> integration/deploy-main
    raw_alert_id: Optional[str] = None
    wazuh_rule_id: Optional[str] = None
    wazuh_rule_level: Optional[int] = None

    def to_dict(self) -> dict:
        return asdict(self)
