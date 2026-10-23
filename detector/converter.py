<<<<<<< HEAD
"""
Converts a detector `Detection` into the JSON body expected by the backend's
`POST /api/internal/security-events` endpoint (schema `SecurityEventCreate`).

Field mapping:
    source            <- DETECTOR_SOURCE ("wazuh-detector")
    source_event_id   <- "<wazuh alert id>:<detection_type>" (deterministic, so
                         replaying the same alert is reported as a duplicate by
                         the API instead of creating a second event)
    occurred_at       <- Detection.timestamp
    event_type        <- Detection.detection_type
    event_severity    <- Detection.severity (low/medium/high/critical)
    summary           <- one-line description
    asset_id | asset_external_ref   <- exactly one (the API requires that)
    indicators        <- file path, when the detection has one
    evidence          <- the detection's evidence plus Wazuh rule/alert info
"""
from . import config
from .schema import Detection

# Values accepted by the API's EventSeverity enum.
VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}

=======
"""Convert detector records into the backend SecurityEventCreate contract."""
from . import config
from .schema import Detection

VALID_SEVERITIES = {"info", "low", "medium", "high", "critical"}
>>>>>>> integration/deploy-main
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


<<<<<<< HEAD
def normalize_severity(severity: str) -> str:
    """Map a detector severity onto the API enum, defaulting to 'medium'."""
=======
def normalize_severity(severity: str | None) -> str:
>>>>>>> integration/deploy-main
    value = (severity or "").strip().lower()
    return value if value in VALID_SEVERITIES else "medium"


<<<<<<< HEAD
def build_summary(d: Detection) -> str:
    template = _SUMMARY_TEMPLATES.get(
        d.detection_type, "{detection_type} detected on {host}"
    )
    values = _SafeDict(d.evidence or {})
    values.update(host=d.host or d.agent_name or "unknown host",
                  detection_type=d.detection_type or "detection")
    return template.format_map(values)


def source_event_id(d: Detection) -> str:
    """
    Stable ID so the same alert + detection type is deduplicated by the API.
    Falls back to the detection's own UUID when no Wazuh alert ID is known.
    """
    if d.raw_alert_id:
        return f"{d.raw_alert_id}:{d.detection_type}"[:255]
    return d.detection_id[:255]


def asset_reference(d: Detection) -> dict:
    """Exactly one of asset_id / asset_external_ref, as the API requires."""
    if config.DETECTOR_ASSET_ID:
        return {"asset_id": config.DETECTOR_ASSET_ID}
    external_id = d.agent_name or d.agent_id or "unknown"
    return {
        "asset_external_ref": {
            "external_source": config.DETECTOR_ASSET_EXTERNAL_SOURCE,
            "external_id": external_id,
=======
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
>>>>>>> integration/deploy-main
        }
    }


<<<<<<< HEAD
def detection_to_payload(d: Detection) -> dict:
    """Build the request body for POST /api/internal/security-events."""
    evidence = dict(d.evidence or {})
    evidence.update(
        detection_id=d.detection_id,
        wazuh_alert_id=d.raw_alert_id,
        wazuh_rule_id=d.wazuh_rule_id,
        wazuh_rule_level=d.wazuh_rule_level,
        agent_id=d.agent_id,
        agent_name=d.agent_name,
    )

    indicators = []
    file_path = (d.evidence or {}).get("file")
    if file_path:
        indicators.append({"type": "file_path", "value": file_path})

    payload = {
        "source": config.DETECTOR_SOURCE,
        "source_event_id": source_event_id(d),
        "occurred_at": d.timestamp,
        "event_type": d.detection_type,
        "event_severity": normalize_severity(d.severity),
        "summary": build_summary(d),
        "indicators": indicators,
        "evidence": evidence,
    }
    payload.update(asset_reference(d))
=======
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
>>>>>>> integration/deploy-main
    return payload
