<<<<<<< HEAD
"""
Cyber Resilience Decision Engine (Member 3's component).

This package decides how the backup and recovery system should respond
to security events.

Files in this package:
    models.py          - Data shapes (SecurityEvent, Decision, ...)
    risk_scorer.py     - Turns events into a 0-100 risk score
    decision_engine.py - Chooses the response (ALLOW ... RECOVER)
    decision_logger.py - Keeps an audit trail of every decision

Because of the imports below, teammates can write:

    from app.decision import DecisionEngine, SecurityEvent

instead of importing from each individual file.
"""

from .decision_engine import DecisionEngine
from .decision_logger import DecisionLogger
from .models import (
    BackupStatus,
    Decision,
    ResponseAction,
    RiskAssessment,
    RiskLevel,
    SecurityEvent,
)
from .risk_scorer import RiskScorer

# __all__ lists the names that are considered the "public" part of this
# package. It also controls what `from app.decision import *` gives.
__all__ = [
    "BackupStatus",
    "Decision",
    "DecisionEngine",
    "DecisionLogger",
    "ResponseAction",
    "RiskAssessment",
    "RiskLevel",
    "RiskScorer",
    "SecurityEvent",
]
=======
"""Decision recommendations; operational dispatch is handled by ActionRequest workflows."""
from .decision_engine import DecisionEngine
from .models import BackupStatus, Decision, ResponseAction, RiskAssessment, RiskLevel, SecurityEvent
from .risk_scorer import RiskScorer

__all__ = [
    "BackupStatus", "Decision", "DecisionEngine", "ResponseAction",
    "RiskAssessment", "RiskLevel", "RiskScorer", "SecurityEvent",
]
>>>>>>> integration/deploy-main
