"""Convert detector records into the backend SecurityEventCreate contract."""
from . import config
from .schema import Detection

VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_SUMMARY_TEMPLATES = {
    "mass_file_modification": "Mass file modification on {host}: {files_changed} files in {window_seconds}s",
    "suspicious_extension": "Ransomware-style file extension on {host}: {file}",
    "ransom_note": "Possible ransom note created on {host}: {file}",
    "high_entropy_write": "High-entropy (encrypted-looking) file write on {host}: {file}",
    "backup_deletion_attempt": "Backup or shadow-copy deletion attempt on {host}",
    "ransomware_confirmed": "Ransomware behavior confirmed on {host}",
}


class _SafeDict(dict):
    def __missing__(self, key):
        return "unknown"


def normalize_severity(severity: str | None) -> str:
    value = (severity or "").strip().lower()
    return value if value in VALID_SEVERITIES else "medium"


def build_summary(detection: Detection) -> str:
    template = _SUMMARY_TEMPLATES.get(
        detection.detection_type, "{detection_type} detected on {host}"
    )
    values = _SafeDict(detection.evidence or {})
    values.update(
        host=detection.host or detection.agent_name or "unknown host",
        detection_type=detection.detection_type or "detection",
    )
    return template.format_map(values)


def source_event_id(detection: Detection) -> str:
    if detection.raw_alert_id:
        return f"{detection.raw_alert_id}:{detection.detection_type}"[:255]
    return detection.detection_id[:255]


def asset_reference(detection: Detection) -> dict:
    if config.DETECTOR_ASSET_ID:
        return {"asset_id": config.DETECTOR_ASSET_ID}
    return {
        "asset_external_ref": {
            "external_source": config.DETECTOR_ASSET_EXTERNAL_SOURCE,
            "external_id": detection.agent_name or detection.agent_id or "unknown",
        }
    }


def detection_to_payload(detection: Detection) -> dict:
    evidence = dict(detection.evidence or {})
    evidence.update(
        detection_id=detection.detection_id,
        wazuh_alert_id=detection.raw_alert_id,
        wazuh_rule_id=detection.wazuh_rule_id,
        wazuh_rule_level=detection.wazuh_rule_level,
        agent_id=detection.agent_id,
        agent_name=detection.agent_name,
    )
    indicators = []
    file_path = (detection.evidence or {}).get("file")
    if file_path:
        indicators.append({"type": "file_path", "value": file_path})
    payload = {
        "source": config.DETECTOR_SOURCE,
        "source_event_id": source_event_id(detection),
        "occurred_at": detection.timestamp,
        "event_type": detection.detection_type,
        "event_severity": normalize_severity(detection.severity),
        "summary": build_summary(detection),
        "indicators": indicators,
        "evidence": evidence,
    }
    payload.update(asset_reference(detection))
    return payload
