<<<<<<< HEAD
"""
Turns a raw Wazuh alert (dict, as parsed from alerts.json) into zero or
more normalized Detection records, applying the extra heuristics from
analysis.py on top of whatever Wazuh's own rules already flagged.
"""
import logging

=======
"""Normalize Wazuh syscheck alerts into ransomware-related detections."""
import logging

from . import config
>>>>>>> integration/deploy-main
from .analysis import (
    MassChangeTracker,
    has_suspicious_extension,
    looks_like_ransom_note,
    sample_file_entropy,
)
<<<<<<< HEAD
from . import config
from .schema import Detection

log = logging.getLogger("detector.processor")

=======
from .schema import Detection

log = logging.getLogger("detector.processor")
>>>>>>> integration/deploy-main
_tracker = MassChangeTracker()


def _extract_file_path(alert: dict) -> str | None:
<<<<<<< HEAD
    """
    Wazuh syscheck alerts carry the file path in a few possible places
    depending on version/decoder. Check the common ones.
    """
    syscheck = alert.get("syscheck", {})
    if isinstance(syscheck, dict) and syscheck.get("path"):
        return syscheck["path"]
    if alert.get("full_log"):
        # crude fallback: syscheck full_log often contains the path
        return alert["full_log"]
    return None
=======
    syscheck = alert.get("syscheck", {})
    if isinstance(syscheck, dict) and syscheck.get("path"):
        return syscheck["path"]
    return alert.get("full_log")
>>>>>>> integration/deploy-main


def is_fim_alert(alert: dict) -> bool:
    groups = alert.get("rule", {}).get("groups", [])
    return "syscheck" in groups


def process_alert(alert: dict) -> list[Detection]:
<<<<<<< HEAD
    """
    Main entry point: given one parsed Wazuh alert dict, return a list
    of Detection records (usually 0 or 1, occasionally more if several
    heuristics fire on the same event).
    """
    detections: list[Detection] = []

=======
    detections: list[Detection] = []
>>>>>>> integration/deploy-main
    if not is_fim_alert(alert):
        return detections

    rule = alert.get("rule", {})
    agent = alert.get("agent", {})
    agent_id = agent.get("id", "unknown")
    agent_name = agent.get("name", "unknown")
    file_path = _extract_file_path(alert)
<<<<<<< HEAD

    base_kwargs = dict(
        agent_id=agent_id,
        agent_name=agent_name,
        host=agent_name,
        raw_alert_id=alert.get("id"),
        wazuh_rule_id=str(rule.get("id", "")),
        wazuh_rule_level=rule.get("level"),
    )

    # 1. Mass-change tracking (sliding window, independent of Wazuh's
    #    own frequency rule - gives us a second, code-side confirmation)
=======
    base_kwargs = {
        "agent_id": agent_id,
        "agent_name": agent_name,
        "host": agent_name,
        "raw_alert_id": alert.get("id"),
        "wazuh_rule_id": str(rule.get("id", "")),
        "wazuh_rule_level": rule.get("level"),
    }

>>>>>>> integration/deploy-main
    count = _tracker.record(agent_id)
    if _tracker.is_mass_change(agent_id):
        detections.append(Detection(
            detection_type="mass_file_modification",
            severity="high",
<<<<<<< HEAD
            evidence={
                "files_changed": count,
                "window_seconds": config.MASS_CHANGE_WINDOW_SECONDS,
            },
=======
            evidence={"files_changed": count, "window_seconds": config.MASS_CHANGE_WINDOW_SECONDS},
>>>>>>> integration/deploy-main
            **base_kwargs,
        ))

    if file_path:
<<<<<<< HEAD
        # 2. Suspicious extension
        if has_suspicious_extension(file_path):
            detections.append(Detection(
                detection_type="suspicious_extension",
                severity="high",
                evidence={"file": file_path},
                **base_kwargs,
            ))

        # 3. Ransom note naming pattern
        if looks_like_ransom_note(file_path):
            detections.append(Detection(
                detection_type="ransom_note",
                severity="critical",
                evidence={"file": file_path},
                **base_kwargs,
            ))

        # 4. Entropy sample (only worth doing on modify/add events,
        #    and only if the file still exists locally - agent-side
        #    deployments would need this to run on the endpoint itself,
        #    not the manager)
        entropy = sample_file_entropy(file_path)
        if entropy is not None and entropy >= config.ENTROPY_SUSPICIOUS_THRESHOLD:
            detections.append(Detection(
                detection_type="high_entropy_write",
                severity="medium",
                evidence={"file": file_path, "entropy": round(entropy, 2)},
                **base_kwargs,
            ))

    # 5. Wazuh already scored this a "confirmed ransomware" correlation
    #    (our custom rule 100104) - pass that through as the highest tier.
    if str(rule.get("id")) == "100104":
        detections.append(Detection(
            detection_type="ransomware_confirmed",
            severity="critical",
            evidence={"description": rule.get("description", "")},
            **base_kwargs,
        ))

    if detections:
        log.info("Alert -> %d detection(s) for agent=%s file=%s",
                  len(detections), agent_name, file_path)

=======
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
>>>>>>> integration/deploy-main
    return detections
