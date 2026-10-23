from enum import Enum


class StringEnum(str, Enum):
    """String enum suitable for API values and database columns."""


class EventProcessingStatus(StringEnum):
    RECEIVED = "received"
    NORMALIZED = "normalized"
    PROCESSED = "processed"
    REJECTED = "rejected"


class EventSeverity(StringEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentLifecycleStatus(StringEnum):
    NEW = "new"
    TRIAGED = "triaged"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    RECOVERY_IN_PROGRESS = "recovery_in_progress"
    RECOVERED = "recovered"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    CLOSED = "closed"


class RiskAssessmentStatus(StringEnum):
    COMPLETED = "completed"
    FAILED = "failed"


class RiskLevel(StringEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DecisionStatus(StringEnum):
    PROPOSED = "proposed"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    SUPERSEDED = "superseded"


class ApprovalStatus(StringEnum):
    NOT_REQUIRED = "not_required"
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    REVOKED = "revoked"


class ActionExecutionStatus(StringEnum):
    NOT_STARTED = "not_started"
    QUEUED = "queued"
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class BackupLifecycleStatus(StringEnum):
    AVAILABLE = "available"
    QUARANTINED = "quarantined"
    EXPIRED = "expired"
    UNAVAILABLE = "unavailable"


class BackupProtectionStatus(StringEnum):
    PROTECTED = "protected"
    PENDING = "pending"
    FAILED = "failed"
    NOT_PROTECTED = "not_protected"
    UNKNOWN = "unknown"


class VerificationStatus(StringEnum):
    QUEUED = "queued"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"
    CANCELLED = "cancelled"
    ERROR = "error"


class IsolationExecutionStatus(StringEnum):
    REQUESTED = "requested"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    EXECUTING = "executing"
    ISOLATED = "isolated"
    FAILED = "failed"
    RELEASE_REQUESTED = "release_requested"
    RELEASED = "released"
    CANCELLED = "cancelled"


class IsolationMode(StringEnum):
    NETWORK = "network"
    HOST = "host"
    FULL = "full"


class IsolationNetworkState(StringEnum):
    CONNECTED = "connected"
    ISOLATING = "isolating"
    ISOLATED = "isolated"
    RELEASING = "releasing"
    UNKNOWN = "unknown"


class AssetIsolationState(StringEnum):
    NOT_ISOLATED = "not_isolated"
    ISOLATION_PENDING = "isolation_pending"
    ISOLATED = "isolated"
    RELEASE_PENDING = "release_pending"


class RecoveryJobStatus(StringEnum):
    REQUESTED = "requested"
    AWAITING_APPROVAL = "awaiting_approval"
    APPROVED = "approved"
    QUEUED = "queued"
    RESTORING = "restoring"
    SCANNING = "scanning"
    VALIDATION_FAILED = "validation_failed"
    READY_FOR_CUTOVER = "ready_for_cutover"
    CUTOVER_IN_PROGRESS = "cutover_in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class RecoveryCheckStatus(StringEnum):
    NOT_STARTED = "not_started"
    RUNNING = "running"
    PASSED = "passed"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"


class CutoverStatus(StringEnum):
    NOT_REQUESTED = "not_requested"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ActionType(StringEnum):
    CREATE_BACKUP = "create_backup"
    PROTECT_BACKUP = "protect_backup"
    ISOLATE = "isolate"
    RELEASE_ISOLATION = "release_isolation"
    VERIFY_BACKUP = "verify_backup"
    RECOVER = "recover"