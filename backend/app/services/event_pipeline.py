"""Persist one accepted security event through threat, risk and decision services.

Decisions are recommendation records only. ActionRequest, approval and internal
component-result endpoints remain the sole execution path for operations.
"""
from datetime import datetime, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.decisions import create_decision
from app.api.risk_assessments import create_risk_assessment
from app.api.threats import create_threat
from app.decision.decision_engine import DecisionEngine
from app.decision.models import (
    BackupStatus,
    RiskAssessment as EngineRiskAssessment,
    RiskLevel as EngineRiskLevel,
    SecurityEvent as EngineSecurityEvent,
)
from app.enums import ActionType, RiskLevel
from app.models import (
    Backup,
    Decision,
    IntegrityVerification,
    RiskAssessment,
    SecurityEvent,
    SystemSettings,
    ThreatIncident,
)
from app.risk import risk_level_for_score
from app.risk_engine import RiskEngine, RiskEvent
from app.schemas import DecisionCreate, RiskAssessmentCreate, ThreatIncidentCreate
from app.services.backup_readiness import latest_completed_verification
from app.services.internal_auth import ComponentPrincipal


_PIPELINE_PRINCIPALS = {
    scope: ComponentPrincipal("event-processing-pipeline", frozenset({scope}))
    for scope in ("threats:write", "risk_assessments:write", "decisions:write")
}
_EVENT_TYPE_ALIASES = {
    "mass_file_modification": "mass_file_modification",
    "suspicious_extension": "mass_file_encryption",
    "high_entropy_write": "mass_file_encryption",
    "ransom_note": "mass_file_encryption",
    "ransomware_confirmed": "mass_file_encryption",
    "backup_deletion_attempt": "backup_deletion",
    "suspicious_process": "suspicious_process",
    "privilege_escalation": "privilege_escalation",
    "security_service_disabled": "security_service_disabled",
}
_DECISION_LEVELS = {
    RiskLevel.LOW: EngineRiskLevel.LOW,
    RiskLevel.MEDIUM: EngineRiskLevel.MEDIUM,
    RiskLevel.HIGH: EngineRiskLevel.HIGH,
    RiskLevel.CRITICAL: EngineRiskLevel.CRITICAL,
}


class _PersistedRiskScorer:
    """Make the existing DecisionEngine consume the policy-classified DB score."""

    def __init__(self, score: int, level: RiskLevel, factors: list[str]):
        self.assessment = EngineRiskAssessment(
            risk_score=score,
            risk_level=_DECISION_LEVELS[level],
            factors=factors,
            timestamp=datetime.now(timezone.utc),
        )

    def assess(self, _events, now=None):
        if now is None:
            return self.assessment
        return EngineRiskAssessment(
            risk_score=self.assessment.risk_score,
            risk_level=self.assessment.risk_level,
            factors=self.assessment.factors,
            timestamp=now,
        )


def _risk_indicators(event: SecurityEvent) -> dict[str, bool]:
    evidence = event.evidence or {}
    indicators: dict[str, bool] = {}
    mapped = _EVENT_TYPE_ALIASES.get(event.event_type)
    if mapped:
        indicators[mapped] = True
    if event.event_type == "ransomware_confirmed":
        indicators["mass_file_modification"] = True
    for key in (
        "mass_file_encryption", "mass_file_modification", "backup_deletion",
        "suspicious_process", "privilege_escalation", "security_service_disabled",
    ):
        if evidence.get(key) is True:
            indicators[key] = True
    return indicators


def _eligible_backups(db: Session, asset_id: str) -> list[BackupStatus]:
    backups = db.scalars(select(Backup).where(
        Backup.asset_id == asset_id,
        Backup.lifecycle_status == "available",
    )).all()
    eligible = []
    now = datetime.now(timezone.utc)
    for backup in backups:
        verification = latest_completed_verification(db, backup.id)
        if verification is None or verification.result_status != "passed" or verification.completed_at is None:
            continue
        completed_at = verification.completed_at
        if completed_at.tzinfo is None:
            completed_at = completed_at.replace(tzinfo=timezone.utc)
        if completed_at > now or now - completed_at > timedelta(hours=24):
            continue
        latest_verification_id = db.scalar(
            select(IntegrityVerification.id)
            .where(IntegrityVerification.backup_id == backup.id)
            .order_by(IntegrityVerification.created_at.desc(), IntegrityVerification.id.desc())
            .limit(1)
        )
        if latest_verification_id != verification.id:
            continue
        eligible.append(BackupStatus(
            backup_id=backup.id,
            timestamp=backup.backup_created_at or backup.created_at,
            integrity_verified=True,
            trusted=True,
            location=backup.storage_reference or backup.external_backup_id,
        ))
    return eligible


def process_security_event(db: Session, event: SecurityEvent) -> None:
    """Create/resume incident → rule assessment → persisted risk → decision."""
    if event.asset_id is None:
        raise ValueError("An affected asset is required for threat processing")

    rule_result = RiskEngine().assess(
        RiskEvent(event.id, event.asset_id, _risk_indicators(event))
    )
    incident = db.get(ThreatIncident, event.incident_id) if event.incident_id else None
    if incident is None:
        incident = create_threat(
            ThreatIncidentCreate(
                title=event.summary[:255],
                threat_type=rule_result.threat_type,
                asset_id=event.asset_id,
                description=event.summary,
                indicators=event.indicators,
                detection_source=event.source,
                event_ids=[event.id],
                detected_at=event.occurred_at,
                correlation_id=event.correlation_id,
            ),
            db,
            _PIPELINE_PRINCIPALS["threats:write"],
        )

    assessment = db.scalar(
        select(RiskAssessment)
        .where(RiskAssessment.incident_id == incident.id, RiskAssessment.asset_id == event.asset_id)
        .order_by(RiskAssessment.assessed_at.desc())
        .limit(1)
    )
    if assessment is None:
        score = round(rule_result.risk_score)
        settings = db.scalar(select(SystemSettings).where(SystemSettings.is_singleton.is_(True)))
        risk_level_for_score(score, settings.risk_thresholds if settings else None)
        assessment = create_risk_assessment(
            RiskAssessmentCreate(
                incident_id=incident.id,
                asset_id=event.asset_id,
                score=score,
                factors=[{"rule": name} for name in rule_result.triggered_rules],
                confidence=1.0 if rule_result.triggered_rules else 0.5,
                model_version="risk-rules-v1",
                policy_version="risk-policy-v1",
                assessed_at=datetime.now(timezone.utc),
                correlation_id=incident.correlation_id,
            ),
            db,
            _PIPELINE_PRINCIPALS["risk_assessments:write"],
        )

    level = RiskLevel(assessment.risk_level)
    existing = db.scalar(
        select(Decision)
        .where(
            Decision.incident_id == incident.id,
            Decision.assessment_id == assessment.id,
            Decision.asset_id == event.asset_id,
        )
        .order_by(Decision.created_at.desc())
        .limit(1)
    )
    if existing is None:
        source_event = EngineSecurityEvent(
            event_id=event.id,
            timestamp=event.occurred_at,
            source=event.source,
            event_type={
                "ransom_note": "ransomware_note_detected",
                "ransomware_confirmed": "mass_file_encryption",
                "high_entropy_write": "mass_file_encryption",
                "suspicious_extension": "mass_file_encryption",
            }.get(event.event_type, event.event_type),
            severity={"info": 2, "low": 3, "medium": 5, "high": 7, "critical": 9}.get(event.event_severity, 5),
            raw_data=event.evidence or {},
            host_id=event.asset_id,
        )
        proposal = DecisionEngine(scorer=_PersistedRiskScorer(
            assessment.score,
            level,
            [str(factor) for factor in assessment.factors],
        )).decide([source_event], _eligible_backups(db, event.asset_id))
        action = {
            "ISOLATE": ActionType.ISOLATE,
            "RECOVER": ActionType.RECOVER,
            "PROTECT": ActionType.PROTECT_BACKUP,
        }.get(proposal.action.value)
        recommendations = []
        if action == ActionType.PROTECT_BACKUP:
            backup_exists = db.scalar(select(Backup.id).where(
                Backup.asset_id == event.asset_id,
                Backup.lifecycle_status == "available",
            ).limit(1)) is not None
            if backup_exists:
                recommendations.append(action)
        elif action is not None:
            recommendations.append(action)
        create_decision(
            DecisionCreate(
                incident_id=incident.id,
                assessment_id=assessment.id,
                asset_id=event.asset_id,
                recommended_actions=recommendations,
                rationale=proposal.reason,
                approval_required=bool(recommendations),
                policy_version="decision-policy-v1",
                decision_engine_version="decision-engine-v1",
                correlation_id=assessment.correlation_id,
            ),
            db,
            _PIPELINE_PRINCIPALS["decisions:write"],
        )

    event.processing_status = "processed"
    db.commit()
    db.refresh(event)
