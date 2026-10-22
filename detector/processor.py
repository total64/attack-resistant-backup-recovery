"""Normalize Wazuh syscheck alerts into ransomware-related detections."""
import logging

from . import config
from .analysis import (
    MassChangeTracker,
    has_suspicious_extension,
    looks_like_ransom_note,
    sample_file_entropy,
)
from .schema import Detection

log = logging.getLogger("detector.processor")
_tracker = MassChangeTracker()


def _extract_file_path(alert: dict) -> str | None:
    syscheck = alert.get("syscheck", {})
    if isinstance(syscheck, dict) and syscheck.get("path"):
        return syscheck["path"]
    return alert.get("full_log")


def is_fim_alert(alert: dict) -> bool:
    groups = alert.get("rule", {}).get("groups", [])
    return "syscheck" in groups


def process_alert(alert: dict) -> list[Detection]:
    detections: list[Detection] = []
    if not is_fim_alert(alert):
        return detections

    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    agent_id = agent.get("id", "unknown")
    agent_name = agent.get("name", "unknown")
    file_path = _extract_file_path(alert)
    base_kwargs = {
        "agent_id": agent_id,
        "agent_name": agent_name,
        "host": agent_name,
        "raw_alert_id": alert.get("id"),
        "wazuh_rule_id": str(rule.get("id", "")),
        "wazuh_rule_level": rule.get("level"),
    }

    count = _tracker.record(agent_id)
    if _tracker.is_mass_change(agent_id):
        detections.append(Detection(
            detection_type="mass_file_modification",
            severity="high",
            evidence={"files_changed": count, "window_seconds": config.MASS_CHANGE_WINDOW_SECONDS},
            **base_kwargs,
        ))

    if file_path:
        if has_suspicious_extension(file_path):
            detections.append(Detection(
                detection_type="suspicious_extension", severity="high",
                evidence={"file": file_path}, **base_kwargs,
            ))
        if looks_like_ransom_note(file_path):
            detections.append(Detection(
                detection_type="ransom_note", severity="critical",
                evidence={"file": file_path}, **base_kwargs,
            ))
        entropy = sample_file_entropy(file_path)
        if entropy is not None and entropy >= config.ENTROPY_SUSPICIOUS_THRESHOLD:
            detections.append(Detection(
                detection_type="high_entropy_write", severity="medium",
                evidence={"file": file_path, "entropy": round(entropy, 2)}, **base_kwargs,
            ))

    if str(rule.get("id")) == "100104":
        detections.append(Detection(
            detection_type="ransomware_confirmed", severity="critical",
            evidence={"description": rule.get("description", "")}, **base_kwargs,
        ))

    if detections:
        log.info("Alert -> %d detection(s) for agent=%s file=%s", len(detections), agent_name, file_path)
    return detections
