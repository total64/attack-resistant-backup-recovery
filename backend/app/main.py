from contextlib import asynccontextmanager
from json import JSONDecodeError, loads
import os
from uuid import UUID, uuid4

from dotenv import load_dotenv

# Load .env from the backend/ directory (the working directory when running uvicorn)
# so that secrets configured in .env are available without needing manual export.
# Explicit environment variables always take precedence (override=False is the default).
load_dotenv()


from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.api import api_router
from app.database.init_db import initialize_database
from app.database.session import SessionLocal
from app.models import IsolationAction, RecoveryJob
from app.services.audit import record_phase2_audit


@asynccontextmanager
async def lifespan(_app: FastAPI):
    initialize_database()
    yield

from app.backup.routes import router as backup_router

app = FastAPI(
    title="Attack-Resistant Backup & Recovery API",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        origin.strip()
        for origin in os.getenv(
            "CORS_ALLOWED_ORIGINS",
            "http://localhost:5173,http://localhost:5174",
        ).split(",")
        if origin.strip()
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    """Avoid reflecting raw request values and audit invalid internal submissions."""
    path = request.url.path
    internal_resources = {
        "/api/internal/security-events": ("security_event.received", "security_event"),
        "/api/internal/threats": ("threat_incident.create", "threat_incident"),
        "/api/internal/risk-assessments": ("risk_assessment.create", "risk_assessment"),
        "/api/internal/decisions": ("decision.create", "decision"),
        "/api/internal/backups": ("backup.registration_rejected", "backup"),
    }
    matched_resource = internal_resources.get(path)
    if path == "/api/action-requests" and request.method == "POST":
        try:
            body = loads(await request.body())
        except (JSONDecodeError, UnicodeDecodeError, TypeError, ValueError):
            body = None
        if isinstance(body, dict) and body.get("action_type") == "recover":
            matched_resource = ("recovery.request_rejected", "action_request")
    if path == "/api/recovery-jobs" and request.method == "POST":
        matched_resource = ("recovery.request_rejected", "recovery_job")
    if path.startswith("/api/internal/integrity-verifications/") and path.endswith("/result"):
        matched_resource = ("integrity_verification.result_rejected", "integrity_verification")
    if path.startswith("/api/internal/isolation/") and path.endswith("/result"):
        matched_resource = ("isolation.component_result_rejected", "isolation_action")
    if path.startswith("/api/internal/recovery-jobs/") and path.endswith(("/result", "/claim")):
        matched_resource = ("recovery.component_result_rejected", "recovery_job")
    if matched_resource is None and path.startswith("/api/internal/backups/") and path.endswith("/protection-result"):
        matched_resource = ("backup.protection_result_rejected", "backup")
    if matched_resource is not None:
        action, resource_type = matched_resource
        correlation_id = uuid4()
        try:
            body = loads(await request.body())
            if isinstance(body, dict) and body.get("correlation_id"):
                correlation_id = UUID(str(body["correlation_id"]))
        except (JSONDecodeError, UnicodeDecodeError, TypeError, ValueError):
            pass
        with SessionLocal() as db:
            audit_context = {}
            if resource_type == "isolation_action":
                try:
                    isolation_action_id = UUID(path.split("/")[4])
                    isolation_action = db.get(IsolationAction, str(isolation_action_id))
                except (IndexError, ValueError):
                    isolation_action = None
                if isolation_action is not None:
                    audit_context = {
                        "resource_id": isolation_action.id,
                        "isolation_action_id": isolation_action.id,
                        "asset_id": isolation_action.asset_id,
                        "incident_id": isolation_action.incident_id,
                        "decision_id": isolation_action.decision_id,
                        "action_request_id": isolation_action.action_request_id,
                        "correlation_id": isolation_action.correlation_id,
                    }
            elif resource_type == "recovery_job":
                try:
                    recovery_job_id = UUID(path.split("/")[4])
                    recovery_job = db.get(RecoveryJob, str(recovery_job_id))
                except (IndexError, ValueError):
                    recovery_job = None
                if recovery_job is not None:
                    audit_context = {
                        "resource_id": recovery_job.id,
                        "recovery_job_id": recovery_job.id,
                        "asset_id": recovery_job.asset_id,
                        "incident_id": recovery_job.incident_id,
                        "action_request_id": recovery_job.action_request_id,
                        "backup_id": recovery_job.backup_id,
                        "verification_id": recovery_job.verification_id,
                        "correlation_id": recovery_job.correlation_id,
                    }
            record_phase2_audit(
                db,
                action=action,
                result_status="rejected",
                resource_type=resource_type,
                correlation_id=correlation_id,
                source_component="internal_api",
                reason="Request validation failed",
                safe_metadata={"method": request.method, "path": path},
                **audit_context,
            )
            db.commit()

    safe_errors = [
        {"loc": error.get("loc", ()), "msg": error.get("msg", "Invalid request"), "type": error.get("type", "value_error")}
        for error in exc.errors()
    ]
    return JSONResponse(status_code=422, content={"detail": safe_errors})

app.include_router(backup_router)

@app.get("/")
def root():
    return {
        "message": "Attack-Resistant Backup & Recovery API is running"
    }
