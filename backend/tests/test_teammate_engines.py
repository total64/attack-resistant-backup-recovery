from datetime import datetime, timedelta, timezone

from app.decision import BackupStatus, DecisionEngine, ResponseAction, SecurityEvent
from app.risk_engine import RiskEngine, RiskEvent


NOW = datetime(2026, 10, 16, 12, tzinfo=timezone.utc)


def test_risk_rules_score_ransomware_indicators():
    assessment = RiskEngine().assess(RiskEvent(
        event_id="evt-1",
        host_id="asset-1",
        indicators={
            "mass_file_encryption": True,
            "mass_file_modification": True,
            "backup_deletion": True,
        },
    ))
    assert assessment.risk_score == 100
    assert assessment.risk_level == "CRITICAL"
    assert assessment.threat_type == "ransomware_behavior"
    assert len(assessment.triggered_rules) == 3


def test_decision_engine_never_recovers_from_unverified_backup():
    event = SecurityEvent(
        event_id="evt-2",
        timestamp=NOW,
        source="detector",
        event_type="mass_file_encryption",
        severity=10,
    )
    backup_attack = SecurityEvent(
        event_id="evt-2-backup",
        timestamp=NOW,
        source="backup-monitor",
        event_type="backup_deletion_attempt",
        severity=10,
    )
    backup = BackupStatus(
        backup_id="backup-1",
        timestamp=NOW - timedelta(hours=1),
        integrity_verified=False,
        trusted=True,
        location="test-only",
    )
    decision = DecisionEngine().decide([event, backup_attack], [backup], now=NOW)
    assert decision.action == ResponseAction.ISOLATE
    assert not any(step.startswith("restore_from_backup:") for step in decision.actions_to_execute)


def test_decision_engine_selects_verified_preincident_backup_as_recommendation():
    event = SecurityEvent(
        event_id="evt-3",
        timestamp=NOW,
        source="detector",
        event_type="mass_file_encryption",
        severity=10,
    )
    backup_attack = SecurityEvent(
        event_id="evt-3-backup",
        timestamp=NOW,
        source="backup-monitor",
        event_type="backup_deletion_attempt",
        severity=10,
    )
    backup = BackupStatus(
        backup_id="backup-2",
        timestamp=NOW - timedelta(hours=1),
        integrity_verified=True,
        trusted=True,
        location="isolated-test-storage",
    )
    decision = DecisionEngine().decide([event, backup_attack], [backup], now=NOW)
    assert decision.action == ResponseAction.RECOVER
    assert "restore_from_backup:backup-2" in decision.actions_to_execute
    # This is a proposed response only; API ActionRequest approval is separate.
