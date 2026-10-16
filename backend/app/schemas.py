from datetime import datetime, timezone
import re
from typing import Annotated, Any, Generic, Literal, TypeVar
from uuid import UUID

from pydantic import AliasChoices, AfterValidator, BaseModel, ConfigDict, Field, field_validator, model_validator

from .enums import (
    ActionExecutionStatus,
    ActionType,
    AssetIsolationState,
    ApprovalStatus,
    BackupLifecycleStatus,
    BackupProtectionStatus,
    CutoverStatus,
    DecisionStatus,
    EventProcessingStatus,
    EventSeverity,
    IncidentLifecycleStatus,
    IsolationExecutionStatus,
    IsolationMode,
    IsolationNetworkState,
    RecoveryJobStatus,
    RecoveryCheckStatus,
    RiskAssessmentStatus,
    RiskLevel,
    VerificationStatus,
)


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


UTCDateTime = Annotated[datetime, AfterValidator(_as_utc)]
RiskScore = Annotated[int, Field(ge=0, le=100)]
Confidence = Annotated[float, Field(ge=0, le=1)]
_SECRET_KEY_MARKERS = (
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "credential",
    "authorization",
)
_SECRET_VALUE_PATTERNS = (
    re.compile(
        r"(?:password|passwd|token|api[_-]?key|private[_-]?key|authorization)\s*[:=]\s*\S+",
        re.IGNORECASE,
    ),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]+=*", re.IGNORECASE),
    re.compile(r"[a-z][a-z0-9+.-]*://[^/@:\s]+:[^/@\s]+@", re.IGNORECASE),
)


def _reject_secret_fields(value: Any, path: str = "") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized_key = str(key).lower().replace("-", "_")
            if any(marker in normalized_key for marker in _SECRET_KEY_MARKERS):
                raise ValueError(f"Secret-like field '{path}{key}' is not allowed")
            _reject_secret_fields(child, f"{path}{key}.")
    elif isinstance(value, list):
        for child in value:
            _reject_secret_fields(child, path)


def _reject_sensitive_content(value: Any) -> None:
    """Reject credential-like field names and recognizable embedded secrets."""
    _reject_secret_fields(value)
    if isinstance(value, dict):
        children = value.values()
    elif isinstance(value, list):
        children = value
    else:
        children = (value,)
    for child in children:
        if isinstance(child, str) and any(pattern.search(child) for pattern in _SECRET_VALUE_PATTERNS):
            raise ValueError("Credential-like content is not allowed")
        if isinstance(child, (dict, list)):
            _reject_sensitive_content(child)


class APIModel(BaseModel):
    model_config = ConfigDict(from_attributes=True, use_enum_values=True)


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=1024)


class ChangePasswordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    current_password: str = Field(min_length=1, max_length=1024)
    new_password: str = Field(min_length=12, max_length=1024)


class AuthenticatedUser(APIModel):
    user_id: str
    role: str
    display_name: str | None = None
    csrf_token: str


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    password: str = Field(min_length=12, max_length=1024)
    display_name: str | None = Field(default=None, max_length=255)
    role: str | None = None

    @field_validator("username", mode="before")
    @classmethod
    def trim_username(cls, value):
        return value.strip() if isinstance(value, str) else value

    @model_validator(mode="after")
    def validate_register_fields(self):
        if self.display_name is not None:
            self.display_name = self.display_name.strip() or None
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{2,63}", self.username):
            raise ValueError("Username must contain 3–64 letters, digits, dots, underscores, or hyphens")
        if self.role is not None and self.role != "viewer":
            raise ValueError("Public registration does not allow selecting elevated roles; the default role is viewer")
        return self


class UserAccountCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=3, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
    display_name: str | None = Field(default=None, max_length=255)
    role: Literal["viewer", "analyst", "approver"]
    initial_password: str = Field(min_length=12, max_length=1024)

    @field_validator("username", mode="before")
    @classmethod
    def trim_username(cls, value):
        return value.strip() if isinstance(value, str) else value

    @model_validator(mode="after")
    def normalize_account_fields(self):
        if self.display_name is not None:
            self.display_name = self.display_name.strip() or None
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{2,63}", self.username):
            raise ValueError("Username must contain 3–64 letters, digits, dots, underscores, or hyphens")
        return self


class UserAccountUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    role: Literal["viewer", "analyst", "approver", "admin"] | None = None
    is_active: bool | None = None
    display_name: str | None = Field(default=None, max_length=255)

    @field_validator("display_name", mode="before")
    @classmethod
    def trim_display_name(cls, value):
        return value.strip() if isinstance(value, str) else value


class UserAccountRead(APIModel):
    user_id: str
    username: str
    display_name: str | None
    role: str
    is_active: bool = True
    created_by_user_id: str
    created_at: UTCDateTime
    source: str = "database"


class AdminOverviewRead(APIModel):
    user_counts: dict[str, int]
    system_health: dict[str, Any]
    security_summary: dict[str, int]
    backup_recovery_summary: dict[str, int]
    audit_summary: dict[str, Any]


class RiskThresholds(APIModel):
    low_min: int = Field(ge=0, le=100)
    low_max: int = Field(ge=0, le=100)
    medium_min: int = Field(ge=0, le=100)
    medium_max: int = Field(ge=0, le=100)
    high_min: int = Field(ge=0, le=100)
    high_max: int = Field(ge=0, le=100)
    critical_min: int = Field(ge=0, le=100)
    critical_max: int = Field(ge=0, le=100)

    @model_validator(mode="after")
    def validate_contiguous_bands(self):
        if self.low_min != 0 or self.critical_max != 100:
            raise ValueError("Risk thresholds must cover the full 0–100 score range")
        if not (
            self.low_min <= self.low_max < self.medium_min <= self.medium_max
            < self.high_min <= self.high_max < self.critical_min <= self.critical_max
        ):
            raise ValueError("Risk threshold bands must be ordered and non-overlapping")
        if not (
            self.low_max + 1 == self.medium_min
            and self.medium_max + 1 == self.high_min
            and self.high_max + 1 == self.critical_min
        ):
            raise ValueError("Risk threshold bands must be contiguous with no gaps")
        return self


T = TypeVar("T")


class Page(APIModel, Generic[T]):
    items: list[T]
    page: int = Field(ge=1)
    page_size: int = Field(ge=1, le=100)
    total: int = Field(ge=0)


class AssetCreate(APIModel):
    external_source: str | None = Field(default=None, max_length=100)
    external_id: str | None = Field(default=None, max_length=255)
    hostname: str = Field(min_length=1, max_length=255)
    asset_type: str | None = Field(default=None, max_length=100)
    environment: str | None = Field(default=None, max_length=100)
    criticality: str | None = Field(default=None, max_length=50)
    network_segment: str | None = Field(default=None, max_length=255)

    @model_validator(mode="after")
    def validate_external_reference(self):
        if (self.external_source is None) != (self.external_id is None):
            raise ValueError("external_source and external_id must be provided together")
        return self


class AssetRead(APIModel):
    id: UUID
    external_source: str | None
    external_id: str | None
    hostname: str
    asset_type: str | None
    environment: str | None
    criticality: str | None
    network_segment: str | None
    monitoring_status: str
    created_at: UTCDateTime
    updated_at: UTCDateTime


class AssetExternalReference(APIModel):
    external_source: str = Field(min_length=1, max_length=100)
    external_id: str = Field(min_length=1, max_length=255)


class SecurityEventCreate(APIModel):
    source: str = Field(min_length=1, max_length=100)
    source_event_id: str = Field(min_length=1, max_length=255)
    asset_id: UUID | None = None
    asset_external_ref: AssetExternalReference | None = None
    incident_id: UUID | None = None
    occurred_at: UTCDateTime
    event_type: str = Field(min_length=1, max_length=100)
    event_severity: EventSeverity
    summary: str = Field(min_length=1)
    indicators: list[dict[str, Any]] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    source_component: str | None = Field(default=None, max_length=100)
    correlation_id: UUID | None = None

    @model_validator(mode="after")
    def validate_asset_reference_and_safe_content(self):
        if (self.asset_id is None) == (self.asset_external_ref is None):
            raise ValueError("Provide exactly one of asset_id or asset_external_ref")
        _reject_sensitive_content(self.summary)
        _reject_sensitive_content(self.indicators)
        _reject_sensitive_content(self.evidence)
        return self


class SecurityEventRead(APIModel):
    id: UUID
    source: str
    source_event_id: str
    asset_id: UUID | None
    incident_id: UUID | None
    occurred_at: UTCDateTime
    received_at: UTCDateTime
    event_type: str
    event_severity: EventSeverity
    processing_status: EventProcessingStatus
    summary: str
    indicators: list[dict[str, Any]]
    evidence: dict[str, Any]
    source_component: str | None
    correlation_id: UUID


class SecurityEventIngestResponse(APIModel):
    event: SecurityEventRead
    duplicate: bool
    correlation_id: UUID


class SecurityEventActivityPoint(APIModel):
    bucket_start: UTCDateTime
    events: int = Field(ge=0)
    critical_events: int = Field(ge=0)


class SecurityEventSummary(APIModel):
    total_events: int = Field(ge=0)
    critical_events: int = Field(ge=0)
    pending_processing_events: int = Field(ge=0)
    events_today: int = Field(ge=0)
    monitored_assets: int = Field(ge=0)
    activity: list[SecurityEventActivityPoint]


class ThreatSummary(APIModel):
    total_incidents: int = Field(ge=0)
    active_threats: int = Field(ge=0)
    critical_risk_incidents: int = Field(ge=0)
    resolved_incidents: int = Field(ge=0)


class DashboardSummary(APIModel):
    total_security_events: int
    active_threats: int
    high_risk_incidents: int
    critical_risk_incidents: int
    risk_distribution: dict[str, int]
    recent_events: list[SecurityEventRead]


class ThreatIncidentCreate(APIModel):
    title: str = Field(min_length=1, max_length=255)
    threat_type: str = Field(min_length=1, max_length=100)
    asset_id: UUID | None = None
    asset_ids: list[UUID] = Field(default_factory=list)
    asset_external_refs: list[AssetExternalReference] = Field(default_factory=list)
    description: str | None = None
    indicators: list[dict[str, Any]] = Field(default_factory=list)
    detection_source: str | None = Field(default=None, max_length=100)
    event_ids: list[UUID] = Field(default_factory=list)
    detected_at: UTCDateTime
    correlation_id: UUID | None = None

    @model_validator(mode="after")
    def validate_assets_and_safe_content(self):
        if not (self.asset_id or self.asset_ids or self.asset_external_refs):
            raise ValueError("Provide at least one asset reference")
        _reject_sensitive_content(self.description)
        _reject_sensitive_content(self.indicators)
        return self


class ThreatIncidentRead(APIModel):
    id: UUID
    title: str
    threat_type: str
    asset_id: UUID
    affected_asset_ids: list[UUID]
    description: str | None
    indicators: list[dict[str, Any]]
    detection_source: str | None
    detected_at: UTCDateTime
    lifecycle_status: IncidentLifecycleStatus
    current_risk_assessment_id: UUID | None
    correlation_id: UUID
    created_at: UTCDateTime
    updated_at: UTCDateTime
    resolved_at: UTCDateTime | None


class RiskAssessmentCreate(APIModel):
    incident_id: UUID
    asset_id: UUID
    score: RiskScore
    factors: list[dict[str, Any]] = Field(default_factory=list)
    confidence: Confidence | None = None
    model_version: str | None = Field(default=None, max_length=100)
    policy_version: str | None = Field(default=None, max_length=100)
    assessed_at: UTCDateTime | None = None
    correlation_id: UUID | None = None

    @model_validator(mode="after")
    def validate_safe_factors(self):
        _reject_sensitive_content(self.factors)
        return self


class RiskAssessmentRead(APIModel):
    id: UUID
    incident_id: UUID
    asset_id: UUID
    score: RiskScore
    risk_level: RiskLevel
    factors: list[dict[str, Any]]
    confidence: Confidence | None
    model_version: str | None
    policy_version: str | None
    status: RiskAssessmentStatus
    assessed_at: UTCDateTime
    correlation_id: UUID


class DecisionCreate(APIModel):
    incident_id: UUID
    assessment_id: UUID
    asset_id: UUID
    recommended_actions: list[ActionType] = Field(
        description="Proposed actions only; creating a decision does not request, approve, or execute them.",
    )
    rationale: str = Field(min_length=1)
    approval_required: bool = True
    policy_version: str | None = Field(default=None, max_length=100)
    decision_engine_version: str | None = Field(
        default=None,
        max_length=100,
        validation_alias=AliasChoices("decision_engine_version", "engine_version"),
    )
    correlation_id: UUID | None = None

    @model_validator(mode="after")
    def validate_rationale(self):
        _reject_sensitive_content(self.rationale)
        return self


class DecisionRead(APIModel):
    id: UUID
    incident_id: UUID
    assessment_id: UUID
    asset_id: UUID
    recommended_actions: list[ActionType] = Field(
        description="Recommendation only. It is distinct from action requests and their approval/execution status."
    )
    rationale: str
    approval_required: bool
    decision_status: DecisionStatus = Field(description="Decision recommendation status; not an action execution status.")
    policy_version: str | None
    decision_engine_version: str | None = Field(validation_alias="engine_version")
    created_at: UTCDateTime
    correlation_id: UUID


class ActionRequestCreate(APIModel):
    action_type: ActionType
    decision_id: UUID | None = None
    incident_id: UUID | None = None
    asset_id: UUID | None = None
    backup_id: UUID | None = None
    verification_id: UUID | None = None
    isolation_mode: IsolationMode | None = None
    request_reason: str | None = None
    correlation_id: UUID | None = None

    @model_validator(mode="after")
    def validate_safe_reason(self):
        if self.action_type == ActionType.ISOLATE:
            if self.asset_id is None or self.isolation_mode is None:
                raise ValueError("isolate requests require asset_id and isolation_mode")
        elif self.action_type == ActionType.RECOVER:
            if not all((self.asset_id, self.incident_id, self.backup_id, self.verification_id)):
                raise ValueError("recover requests require asset_id, incident_id, backup_id, and verification_id")
        elif self.isolation_mode is not None:
            raise ValueError("isolation_mode is only valid for isolate requests")
        if self.action_type == ActionType.RELEASE_ISOLATION:
            raise ValueError("Use the isolation release endpoint for release_isolation requests")
        _reject_sensitive_content(self.request_reason)
        return self


class ActionRequestApproval(APIModel):
    pass


class ActionRequestRejection(APIModel):
    reason: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_reason(self):
        _reject_sensitive_content(self.reason)
        return self


class ActionRequestRead(APIModel):
    id: UUID
    action_type: ActionType = Field(description="Action explicitly requested, distinct from a decision recommendation.")
    decision_id: UUID | None
    incident_id: UUID | None
    asset_id: UUID | None
    backup_id: UUID | None
    verification_id: UUID | None
    isolation_mode: IsolationMode | None
    requested_by_type: str
    requested_by_id: str | None
    request_reason: str | None
    approval_status: ApprovalStatus = Field(description="Approval lifecycle for this request; independent of recommendation status.")
    approved_by_id: str | None
    approved_at: UTCDateTime | None
    execution_status: ActionExecutionStatus = Field(description="Execution lifecycle for this request; no execution is implied by a decision.")
    started_at: UTCDateTime | None
    completed_at: UTCDateTime | None
    component_result: dict[str, Any]
    failure_reason: str | None
    correlation_id: UUID
    created_at: UTCDateTime
    updated_at: UTCDateTime


class BackupCreate(APIModel):
    asset_id: UUID
    created_by_component: str = Field(min_length=1, max_length=100)
    external_backup_id: str = Field(min_length=1, max_length=255)
    created_at: UTCDateTime
    backup_type: str | None = Field(default=None, max_length=100)
    size_bytes: int | None = Field(default=None, ge=0)
    storage_reference: str | None = Field(default=None, max_length=1024)
    manifest_reference: str | None = Field(default=None, max_length=1024)
    protection_status: BackupProtectionStatus
    lifecycle_status: BackupLifecycleStatus
    encryption_status: str = Field(min_length=1, max_length=50)
    correlation_id: UUID | None = None

    @model_validator(mode="after")
    def validate_safe_references(self):
        _reject_sensitive_content(self.storage_reference)
        _reject_sensitive_content(self.manifest_reference)
        _reject_sensitive_content(self.encryption_status)
        return self


class BackupRead(APIModel):
    backup_id: UUID = Field(validation_alias=AliasChoices("backup_id", "id"))
    asset_id: UUID
    created_by_component: str = Field(validation_alias=AliasChoices("created_by_component", "source_component"))
    external_backup_id: str
    backup_type: str | None
    size_bytes: int | None
    storage_reference: str | None
    manifest_reference: str | None
    lifecycle_status: BackupLifecycleStatus
    protection_status: BackupProtectionStatus
    encryption_status: str
    created_at: UTCDateTime | None = Field(validation_alias=AliasChoices("backup_created_at", "created_at"))
    correlation_id: UUID
    updated_at: UTCDateTime


class BackupCandidateRead(BackupRead):
    verified: bool
    recovery_eligible: bool
    eligibility_reasons: list[str]


class RecoveryEligibilityRead(APIModel):
    eligible: bool
    backup_id: UUID
    reasons: list[str]


class IntegrityVerificationCreate(APIModel):
    reason: str | None = None
    correlation_id: UUID | None = None

    @model_validator(mode="after")
    def validate_safe_request(self):
        _reject_sensitive_content(self.reason)
        return self


class IntegrityVerificationResult(APIModel):
    result_status: VerificationStatus
    algorithm: str | None = Field(default=None, max_length=50)
    expected_digest: str | None = Field(default=None, max_length=512)
    trusted_manifest_reference: str | None = Field(default=None, max_length=1024)
    observed_digest: str | None = Field(default=None, max_length=512)
    verification_evidence_reference: str | None = Field(default=None, max_length=1024)
    verifier_component: str = Field(min_length=1, max_length=100)
    component_reference: str = Field(min_length=1, max_length=255)
    verifier_version: str | None = Field(default=None, max_length=100)
    started_at: UTCDateTime | None = None
    completed_at: UTCDateTime | None = None
    failure_reason: str | None = None
    correlation_id: UUID | None = None

    @model_validator(mode="after")
    def validate_component_result(self):
        if self.result_status == VerificationStatus.QUEUED:
            raise ValueError("Component results cannot set verification status to queued")
        if self.result_status == VerificationStatus.PASSED:
            if not (self.observed_digest or self.verification_evidence_reference):
                raise ValueError("A passed result requires observed digest or verification evidence")
        _reject_sensitive_content(self.trusted_manifest_reference)
        _reject_sensitive_content(self.verification_evidence_reference)
        _reject_sensitive_content(self.component_reference)
        _reject_sensitive_content(self.failure_reason)
        return self


class BackupProtectionResult(APIModel):
    protection_status: BackupProtectionStatus
    execution_status: ActionExecutionStatus
    component_reference: str | None = Field(default=None, max_length=255)
    completed_at: UTCDateTime | None = None
    failure_reason: str | None = None
    correlation_id: UUID | None = None
    action_request_id: UUID | None = None

    @model_validator(mode="after")
    def validate_reported_outcome(self):
        expected = {
            ActionExecutionStatus.EXECUTING: BackupProtectionStatus.PENDING,
            ActionExecutionStatus.SUCCEEDED: BackupProtectionStatus.PROTECTED,
            ActionExecutionStatus.FAILED: BackupProtectionStatus.FAILED,
        }
        if self.execution_status not in expected:
            raise ValueError("Protection result execution_status must be executing, succeeded, or failed")
        if self.protection_status != expected[self.execution_status]:
            raise ValueError("Protection and execution statuses must describe the same outcome")
        if self.execution_status == ActionExecutionStatus.FAILED and not self.failure_reason:
            raise ValueError("A failed protection report requires failure_reason")
        _reject_sensitive_content(self.component_reference)
        _reject_sensitive_content(self.failure_reason)
        return self


class BackupWorkerClaim(APIModel):
    component_reference: str = Field(min_length=1, max_length=255)
    correlation_id: UUID

    @model_validator(mode="after")
    def validate_reference(self):
        _reject_sensitive_content(self.component_reference)
        return self


class BackupCreationResult(APIModel):
    execution_status: ActionExecutionStatus
    external_backup_id: str | None = Field(default=None, min_length=1, max_length=255)
    created_at: UTCDateTime | None = None
    backup_type: str | None = Field(default=None, max_length=100)
    size_bytes: int | None = Field(default=None, ge=0)
    storage_reference: str | None = Field(default=None, max_length=1024)
    manifest_reference: str | None = Field(default=None, max_length=1024)
    encryption_status: str | None = Field(default=None, max_length=50)
    failure_reason: str | None = Field(default=None, max_length=4000)
    component_reference: str = Field(min_length=1, max_length=255)
    correlation_id: UUID

    @model_validator(mode="after")
    def validate_result(self):
        if self.execution_status not in {ActionExecutionStatus.SUCCEEDED, ActionExecutionStatus.FAILED}:
            raise ValueError("Backup creation result must be succeeded or failed")
        if self.execution_status == ActionExecutionStatus.SUCCEEDED:
            if not all((self.external_backup_id, self.created_at, self.storage_reference, self.manifest_reference, self.encryption_status)):
                raise ValueError("Successful backup creation requires an ID, timestamps, storage, manifest, and encryption status")
        elif not self.failure_reason:
            raise ValueError("Failed backup creation requires failure_reason")
        _reject_sensitive_content(self.component_reference)
        _reject_sensitive_content(self.storage_reference)
        _reject_sensitive_content(self.manifest_reference)
        _reject_sensitive_content(self.failure_reason)
        return self


class BackupCreationResultRead(APIModel):
    backup: BackupRead | None
    action_request_id: UUID
    execution_status: ActionExecutionStatus
    correlation_id: UUID


class IntegrityVerificationClaim(APIModel):
    component_reference: str = Field(min_length=1, max_length=255)
    correlation_id: UUID

    @model_validator(mode="after")
    def validate_reference(self):
        _reject_sensitive_content(self.component_reference)
        return self


class BackupProtectionResultRead(APIModel):
    backup: BackupRead
    action_request_id: UUID | None
    execution_status: ActionExecutionStatus
    correlation_id: UUID


class IntegrityVerificationRead(APIModel):
    verification_id: UUID = Field(validation_alias=AliasChoices("verification_id", "id"))
    backup_id: UUID
    asset_id: UUID
    algorithm: str | None
    expected_digest: str | None
    observed_digest: str | None
    verification_evidence_reference: str | None
    trusted_manifest_reference: str | None
    result_status: VerificationStatus
    verifier_component: str | None
    verifier_version: str | None
    started_at: UTCDateTime | None
    completed_at: UTCDateTime | None
    failure_reason: str | None
    correlation_id: UUID


class IntegrityVerificationClaimRead(APIModel):
    verification: IntegrityVerificationRead
    backup: BackupRead


class IntegrityVerificationRequested(APIModel):
    verification_id: UUID
    backup_id: UUID
    result_status: VerificationStatus
    requested_at: UTCDateTime
    correlation_id: UUID


class IsolationActionCreate(APIModel):
    action_request_id: UUID
    asset_id: UUID
    incident_id: UUID | None = None
    decision_id: UUID | None = None
    isolation_mode: IsolationMode
    reason: str | None = None
    correlation_id: UUID | None = None

    @model_validator(mode="after")
    def validate_reason(self):
        _reject_sensitive_content(self.reason)
        return self


class IsolationReleaseCreate(APIModel):
    reason: str | None = None
    correlation_id: UUID | None = None

    @model_validator(mode="after")
    def validate_reason(self):
        _reject_sensitive_content(self.reason)
        return self


class IsolationComponentResult(APIModel):
    execution_status: IsolationExecutionStatus
    network_state: IsolationNetworkState
    acknowledged_at: UTCDateTime | None = None
    completed_at: UTCDateTime | None = None
    component_reference: str = Field(min_length=1, max_length=255)
    failure_reason: str | None = None
    correlation_id: UUID

    @model_validator(mode="after")
    def validate_component_result(self):
        if self.execution_status not in {
            IsolationExecutionStatus.EXECUTING,
            IsolationExecutionStatus.ISOLATED,
            IsolationExecutionStatus.RELEASED,
            IsolationExecutionStatus.FAILED,
            IsolationExecutionStatus.CANCELLED,
        }:
            raise ValueError("Component result status must be executing, isolated, released, failed, or cancelled")
        if self.execution_status == IsolationExecutionStatus.ISOLATED and self.network_state != IsolationNetworkState.ISOLATED:
            raise ValueError("Confirmed isolation requires network_state=isolated")
        if self.execution_status == IsolationExecutionStatus.FAILED and not self.failure_reason:
            raise ValueError("Failed isolation results require failure_reason")
        _reject_sensitive_content(self.component_reference)
        _reject_sensitive_content(self.failure_reason)
        return self


class IsolationActionRead(APIModel):
    isolation_action_id: UUID = Field(validation_alias=AliasChoices("isolation_action_id", "id"))
    action_request_id: UUID
    asset_id: UUID
    incident_id: UUID | None
    decision_id: UUID | None
    operation: ActionType
    execution_status: IsolationExecutionStatus
    isolation_mode: IsolationMode | None
    network_state: IsolationNetworkState | None
    requested_at: UTCDateTime
    acknowledged_at: UTCDateTime | None
    completed_at: UTCDateTime | None
    released_at: UTCDateTime | None
    component_reference: str | None
    failure_reason: str | None
    correlation_id: UUID


class AssetIsolationRead(APIModel):
    asset_id: UUID
    isolation_state: AssetIsolationState
    active_isolation_action_id: UUID | None
    execution_status: IsolationExecutionStatus | None
    network_state: IsolationNetworkState | None
    isolation_mode: IsolationMode | None
    requested_at: UTCDateTime | None
    acknowledged_at: UTCDateTime | None
    component_reference: str | None


class RecoveryJobCreate(APIModel):
    action_request_id: UUID
    asset_id: UUID
    incident_id: UUID
    backup_id: UUID
    verification_id: UUID
    recovery_environment: str | None = Field(default=None, max_length=255)
    correlation_id: UUID | None = None

    @model_validator(mode="after")
    def validate_safe_environment(self):
        _reject_sensitive_content(self.recovery_environment)
        return self


class RecoveryJobRead(APIModel):
    id: UUID
    action_request_id: UUID
    asset_id: UUID
    incident_id: UUID
    backup_id: UUID
    verification_id: UUID
    recovery_environment: str | None
    job_status: RecoveryJobStatus
    cutover_status: CutoverStatus
    malware_scan_status: str
    security_validation_status: str
    started_at: UTCDateTime | None
    completed_at: UTCDateTime | None
    outcome: str | None
    failure_reason: str | None
    component_reference: str | None
    result_evidence_reference: str | None
    correlation_id: UUID


class RecoveryComponentClaim(APIModel):
    component_reference: str = Field(min_length=1, max_length=255)
    correlation_id: UUID

    @model_validator(mode="after")
    def validate_component_reference(self):
        _reject_sensitive_content(self.component_reference)
        return self


class RecoveryComponentResult(APIModel):
    job_status: RecoveryJobStatus
    asset_id: UUID
    incident_id: UUID
    backup_id: UUID
    verification_id: UUID
    correlation_id: UUID
    component_reference: str = Field(min_length=1, max_length=255)
    malware_scan_status: RecoveryCheckStatus
    security_validation_status: RecoveryCheckStatus
    outcome: str | None = Field(default=None, max_length=4000)
    failure_reason: str | None = Field(default=None, max_length=4000)
    result_evidence_reference: str | None = Field(default=None, max_length=1024)

    @model_validator(mode="after")
    def validate_component_result(self):
        if self.job_status not in {
            RecoveryJobStatus.SCANNING,
            RecoveryJobStatus.COMPLETED,
            RecoveryJobStatus.FAILED,
        }:
            raise ValueError("Component result status must be scanning, completed, or failed")
        if self.job_status == RecoveryJobStatus.FAILED and not self.failure_reason:
            raise ValueError("Failed recovery results require failure_reason")
        if self.job_status == RecoveryJobStatus.COMPLETED:
            if self.malware_scan_status != RecoveryCheckStatus.PASSED:
                raise ValueError("Completed recovery requires a passed malware scan")
            if self.security_validation_status != RecoveryCheckStatus.PASSED:
                raise ValueError("Completed recovery requires passed security validation")
            if not self.result_evidence_reference:
                raise ValueError("Completed recovery requires a result evidence reference")
            if not self.outcome:
                raise ValueError("Completed recovery requires a component-reported outcome")
        _reject_sensitive_content(self.component_reference)
        _reject_sensitive_content(self.outcome)
        _reject_sensitive_content(self.failure_reason)
        _reject_sensitive_content(self.result_evidence_reference)
        return self


class RecoveryJobCancel(APIModel):
    reason: str = Field(min_length=1, max_length=4000)

    @model_validator(mode="after")
    def validate_reason(self):
        _reject_sensitive_content(self.reason)
        return self


class AuditEventCreate(APIModel):
    actor_type: str = Field(min_length=1, max_length=50)
    actor_id: str | None = Field(default=None, max_length=255)
    action: str = Field(min_length=1, max_length=150)
    result_status: str = Field(min_length=1, max_length=50)
    resource_type: str | None = Field(default=None, max_length=100)
    resource_id: UUID | None = None
    asset_id: UUID | None = None
    incident_id: UUID | None = None
    event_id: UUID | None = None
    assessment_id: UUID | None = None
    decision_id: UUID | None = None
    action_request_id: UUID | None = None
    backup_id: UUID | None = None
    verification_id: UUID | None = None
    isolation_action_id: UUID | None = None
    recovery_job_id: UUID | None = None
    source_component: str | None = Field(default=None, max_length=100)
    reason: str | None = None
    safe_metadata: dict[str, Any] = Field(default_factory=dict)
    correlation_id: UUID | None = None
    occurred_at: UTCDateTime | None = None

    @model_validator(mode="after")
    def validate_safe_metadata(self):
        _reject_secret_fields(self.safe_metadata)
        return self


class AuditEventRead(APIModel):
    id: UUID
    actor_type: str
    actor_id: str | None
    action: str
    result_status: str
    resource_type: str | None
    resource_id: UUID | None
    asset_id: UUID | None
    incident_id: UUID | None
    event_id: UUID | None
    assessment_id: UUID | None
    decision_id: UUID | None
    action_request_id: UUID | None
    backup_id: UUID | None
    verification_id: UUID | None
    isolation_action_id: UUID | None
    recovery_job_id: UUID | None
    source_component: str | None
    reason: str | None
    safe_metadata: dict[str, Any]
    correlation_id: UUID
    occurred_at: UTCDateTime


class SystemSettingsUpdate(APIModel):
    model_config = ConfigDict(extra="forbid")

    risk_thresholds: RiskThresholds | None = None

    @model_validator(mode="after")
    def validate_no_secret_fields(self):
        if any(getattr(self, name) is None for name in self.model_fields_set):
            raise ValueError("Settings fields cannot be null")
        if not self.model_fields_set:
            raise ValueError("Provide at least one settings field to update")
        return self


class SystemSettingsRead(APIModel):
    id: UUID
    version: int
    risk_thresholds: RiskThresholds
    isolation_policy: dict[str, Any]
    backup_policy: dict[str, Any]
    recovery_policy: dict[str, Any]
    notification_policy: dict[str, Any]
    created_at: UTCDateTime
    updated_at: UTCDateTime

    @model_validator(mode="after")
    def validate_no_secret_fields(self):
        for policy in (
            self.isolation_policy,
            self.backup_policy,
            self.recovery_policy,
            self.notification_policy,
        ):
            _reject_secret_fields(policy)
        return self