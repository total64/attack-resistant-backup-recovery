# Backend API

Minimal FastAPI + SQLAlchemy foundation for the Attack-Resistant Backup & Recovery System.

## Structure

- `app/main.py` creates the FastAPI app, keeps the existing root and health endpoints, includes routers, and initializes missing database tables on startup.
- `app/api/` contains browser-facing read routers, basic asset registration, and the Phase 2 internal ingestion endpoints.
- `app/models.py` contains SQLAlchemy entities and relationships.
- `app/schemas.py` contains request/response validation schemas.
- `app/database/` contains the engine, session dependency, and idempotent database initialization.
- `app/services/` contains shared domain helpers, including the append-oriented audit recorder.
- `app/risk.py` is the shared score-to-risk-level mapping.
- `app/services/asset_resolution.py` resolves existing internal or external asset references without silently creating assets.
- `app/services/backup_readiness.py` checks whether the latest completed verification for an exact backup permits recovery eligibility.

## Local setup

From the `backend/` directory, activate the existing virtual environment and install dependencies:

```bash
source venv/bin/activate
python -m pip install -r requirements.txt
```

Initialize the database explicitly (safe to run more than once):

```bash
python -m app.database.init_db
```

Then start the API (set the component token for trusted Phase 3/4 reporting):

```bash
BACKUP_COMPONENT_TOKEN=<component-token> uvicorn app.main:app --reload
```

The app also initializes missing tables and the default singleton settings row when it starts.

Install backend test dependencies from this directory with `python -m pip install -r requirements-dev.txt`, then run `pytest -q`.
The backend uses SQLAlchemy `create_all` and does not include Alembic migrations. Phase 3 applies a narrow additive initialization update for its new verification evidence/timestamp columns on existing databases; future schema changes should use a migration strategy rather than relying on `create_all`.

## Database configuration

The default SQLite file is `backend/data/attack_resistant.db`. Local database files are ignored by Git. To select a different SQLAlchemy-compatible database URL, set `DATABASE_URL` before starting the API, for example with a PostgreSQL URL after installing its driver. SQLite-specific connection behavior is enabled only for SQLite URLs.

The database stores metadata and workflow records only; backup file contents are not stored here.

## API documentation

- Swagger UI: `http://localhost:8000/docs`
- Health: `http://localhost:8000/api/health`

## Current scope

### Teammate components brought into this working tree

The Wazuh detector now delivers authenticated normalized events to `POST /api/internal/security-events`; that ingestion path runs the `app.risk_engine` threat rules, stores a policy-classified risk assessment, and invokes the `app.decision` engine to create a recommendation-only decision. Event processing failures remain persisted as `normalized` and are audited; redelivery can retry the pipeline. The API continues to enforce asset resolution, deduplication, secret-content rejection, component scopes, and human approval before operational requests.

The local worker libraries in `app.backup`, `app.recovery`, and `app.isolation` are utility code, not a claim of automatic execution. Backup copy/integrity, Fernet encryption, Linux immutable flags, recovery restore, and firewall operations are called only by an explicit worker/operator. The API's worker status transitions and approval gates remain the source of truth. The transferred backup helper intentionally does not use rsync `--delete`, rejects symlinks/unsafe restore paths, and will not silently replace a trusted hash baseline. The SSH `HostControl` implementation using automatic host-key acceptance was not transferred; a secure known-host-key provisioning model is required before an SSH worker is safe.

Run project tests from the project root (`pytest -q`). The detector suite uses only fake HTTP responses. Never run the old live-host test against a real host; the destination tests exercise isolation with an in-memory mock.

Implemented: database/session foundation, SQLite initialization, the core workflow models and relationships, Pydantic request/response schemas, shared risk score mapping, paginated read endpoints, basic asset registration, settings read, an append-oriented audit recording helper, normalized security-event ingestion with `(source, source_event_id)` idempotency, threat incident creation and controlled lifecycle operations, historical risk assessments, a recommendation-only decision contract, and a database-derived dashboard summary.

Phase 1/2 ingestion routes do not have production authentication; Phase 6B adds MVP per-component token/scope checks to these internal ingestion routes:

- `POST /api/internal/security-events`
- `POST /api/internal/threats`
- `POST /api/internal/risk-assessments`
- `POST /api/internal/decisions`

Browser-facing read routes include `GET /api/security-events`, `GET /api/threats`, `GET /api/risk-assessments`, `GET /api/decisions`, and `GET /api/dashboard/summary`. API payloads and routes are documented in `/docs`.

### Phase 3: backup metadata, protection reporting, and verification state

The database stores backup metadata and component-reported verification evidence only; it never stores backup content or credentials. `GET /api/backups` supports `asset_id`, `lifecycle_status`, `protection_status`, `backup_type`, `from`, and `to` and returns safe metadata plus `verified`, `recovery_eligible`, and eligibility reasons. Detail is `GET /api/backups/{backup_id}`. Candidate inventory is `GET /api/assets/{asset_id}/recovery-points`. Readiness is `GET /api/backups/{backup_id}/recovery-eligibility`; `POST /api/backups/{backup_id}/select-for-recovery` records a readiness-checked selection only and does not execute recovery.

The trusted component reports metadata to `POST /api/internal/backups`, protection outcomes to `POST /api/internal/backups/{backup_id}/protection-result`, and verification outcomes to `POST /api/internal/integrity-verifications/{verification_id}/result`. These internal reporting routes require `X-Internal-Component-Token` authenticated through `MVP_COMPONENT_TOKENS`; the legacy `BACKUP_COMPONENT_TOKEN` remains temporarily supported for Phase 3–5 routes. Missing or invalid component authentication fails with `401`. Backup registration is idempotent on `(created_by_component, external_backup_id)`: a duplicate returns the original record unchanged with HTTP 200.

Request verification with `POST /api/backups/{backup_id}/integrity-verifications` and request-only metadata (`reason`, optional `correlation_id`). The authenticated user is recorded as requester; client-supplied actor identity is not accepted as authority. The initial result remains `queued`; the component owns the actual verification algorithm and reports evidence separately. The backend does not synthesize or compare checksums. A passed result requires an expected digest or trusted manifest reference and observed digest or trusted evidence reference. `/api/action-requests` supports `protect_backup` and `verify_backup`; approval/execution lifecycle remains distinct from component results.

Intentionally not implemented: real backup storage, creation, or immutability; actual integrity algorithms; Wazuh integration; network isolation commands; recovery execution; production user authentication; message brokers; or frontend integration. No development seed backups are added. Existing Phase 1/2 behavior remains in place.

### Phase 4: system isolation / containment orchestration

Isolation uses the existing `ActionRequest` and `IsolationAction` records. Create an isolate ActionRequest at `POST /api/action-requests` (`action_type: isolate`, `asset_id`, controlled `isolation_mode`, optional incident/decision, reason, and correlation). It remains pending/not-started unless a linked decision explicitly says approval is not required. Dispatch/track it with `POST /api/isolation-requests`; duplicate active isolation is rejected. Approval/rejection uses `POST /api/action-requests/{action_request_id}/approve` and `/reject`.

The integration reads `GET /api/isolation`, `GET /api/isolation/{isolation_action_id}`, and `GET /api/assets/{asset_id}/isolation`. Only `POST /api/internal/isolation/{isolation_action_id}/result` can record component results; it uses the same `X-Internal-Component-Token` / `BACKUP_COMPONENT_TOKEN` safeguard as Phase 3. The derived asset state distinguishes `not_isolated`, `isolation_pending`, `isolated`, and `release_pending`. Release creates a separate `release_isolation` ActionRequest and IsolationAction through `POST /api/isolation-requests/{isolation_action_id}/release`; only a confirmed component result changes it to released. Releases with active incidents or unfinished recovery state return `policy_requires_review` rather than guessing policy. An incident may become `contained` only after all of its affected assets have confirmed isolation; isolation never marks an incident resolved.

The token is an integration safeguard, not production authentication. This backend does not issue firewall/EDR/network commands and never fabricates a successful isolation outcome.

### Phase 5: recovery orchestration

Recovery requests use `POST /api/action-requests` with `action_type: recover` and explicit asset, incident, backup, and integrity-verification IDs. Requests always begin pending approval; a decision recommendation never grants approval. Approve or reject through the existing ActionRequest transition endpoints. Create a `RecoveryJob` with `POST /api/recovery-jobs` only after approval and all safety gates pass. `POST /api/recovery-jobs/{recovery_job_id}/dispatch` rechecks authorization, references, backup eligibility, verification freshness, and confirmed isolation before moving the job to `queued`; it does not execute restoration.

Only the token-authenticated recovery component can claim work with `POST /api/internal/recovery-jobs/{recovery_job_id}/claim` or report component outcomes with `POST /api/internal/recovery-jobs/{recovery_job_id}/result`. Claiming moves `queued` to `restoring`. Component reports advance `restoring` to `scanning`, then to `completed` or `failed`; the backend records the reports and does not perform restoration or synthesize success. Completion requires component-reported passed malware scanning and security validation plus an evidence reference. Exact duplicate reports are idempotent; conflicting terminal reports and illegal transitions are rejected. `POST /api/recovery-jobs/{recovery_job_id}/cancel` is allowed only while approved and before dispatch. Cutover is not active: `cutover_status` remains `not_requested` and does not affect the recovery state machine.

Recovery requires an available backup, the exact selected verification in `passed` state with a completion timestamp, a currently confirmed asset isolation, an approved recovery ActionRequest, and consistent asset/incident/backup/verification/decision references. The MVP verification freshness rule is explicit: the passed verification must have completed within the prior 24 hours and no later verification record may exist for that backup, including one still queued or running. These checks run when recording the recovery request (except isolation/approval), creating the job, dispatching it, and when a component claims queued work. Important transitions and rejected component reports are audited using the recovery correlation ID. Internal component tokens remain integration safeguards, not production authentication. React integration and real storage/restoration are not included.

### Phase 6A: MVP authentication and authorization

Human-facing `/api` routes (except login, logout, root, health, and API documentation) require authentication. The browser signs in at `POST /api/auth/login` with a configured username/password; the API verifies a PBKDF2-SHA256 password hash and issues a random, opaque session in an `HttpOnly`, `SameSite=Lax` cookie. The raw session identifier is never returned in JSON and only its SHA-256 digest is stored in the database. Sessions expire after 8 hours by default (`MVP_SESSION_TTL_SECONDS`, clamped to 5 minutes–24 hours) and are revoked on logout. Cookie-authenticated state-changing requests require a separate double-submit CSRF token (`arbr_csrf` cookie plus `X-CSRF-Token` header); login requests with an Origin are restricted to `CORS_ALLOWED_ORIGINS`.

Configure login identities using `MVP_USER_CREDENTIALS`, a JSON array with `username`, stable `user_id`, `role`, `password_hash`, and optional `display_name`. Never put plaintext passwords or real hashes in source control. Generate a hash interactively from `backend/` with `python scripts/create_user_credential.py`; the helper prompts for the password without echoing it and prints one JSON entry to place in a protected environment/secret store. For local HTTP development only, set `AUTH_COOKIE_SECURE=false`; leave the default `true` for HTTPS deployments. The default trusted frontend origins are `http://localhost:5173` and `http://localhost:5174` (Vite's fallback when 5173 is occupied). Set `CORS_ALLOWED_ORIGINS` to the exact comma-separated frontend origins for other development or deployment addresses.

For local use, create a credential entry with the helper, configure `MVP_USER_CREDENTIALS` in the API process environment (preserving any other configured users), and run `set -a; source .env; set +a; uvicorn app.main:app --reload` from this directory when storing settings in the ignored, owner-only `.env` file. Start the Vite frontend from `frontend/` with `npm install` (first run only) and `npm run dev`; then open `http://localhost:5173`. `POST /api/auth/login` establishes the session, `GET /api/auth/me` restores it after reload, and `POST /api/auth/logout` revokes it. `POST /api/auth/change-password` verifies the current password, stores the new PBKDF2-SHA256 hash in the database, and revokes all active sessions. The frontend includes a Change password link. The frontend keeps only the non-authenticating CSRF nonce in memory; no token/password is stored in a Vite variable or browser storage.

The prior `MVP_USER_TOKENS` environment-configured Bearer credentials remain supported for existing scripts and integrations. They are not used by browser login and are not exposed to the frontend. Never commit real token values. Missing or invalid credentials return `401`; authenticated users without a required role receive `403`.

The prior `MVP_USER_TOKENS` environment-configured Bearer credentials remain supported for existing scripts and integrations. They are not used by browser login and are not exposed to the frontend. Never commit real token values. Missing or invalid credentials return `401`; authenticated users without a required role receive `403`.

### Public Sign Up & Account Registration
Public registration is supported at `POST /api/auth/register`. To maintain defense-in-depth and least-privilege access:
- Public accounts are automatically assigned the least-privileged `viewer` role.
- Public users cannot choose their role or self-escalate to `admin`, `analyst`, or `approver`. Any payload attempting role escalation is rejected (HTTP 422).
- Passwords must be at least 12 characters and are stored only as secure PBKDF2-SHA256 hashes (600,000 iterations).
- Duplicate usernames (case-insensitive) are rejected with HTTP 409 Conflict.
- All registrations are audited in the append-only audit trail (`user_account.registered`).

### Administrative Interface & Account Governance
Authorized administrators (`role: admin`) access the administrative backend through:
- `GET /api/users`: Lists all accounts (both database-provisioned and environment-configured identities), displaying safe metadata without exposing password hashes or credentials.
- `GET /api/users/{user_id}`: Retrieves specific account details safely.
- `POST /api/users`: Allows administrators to provision operations accounts (`viewer`, `analyst`, `approver`).
- `PATCH /api/users/{user_id}`: Allows administrators to update roles (`viewer`, `analyst`, `approver`, `admin`) and activate/deactivate accounts (`is_active: bool`). Deactivating an account or altering its role immediately invalidates active sessions.
- **Last Administrator Protection**: The backend verifies total active administrators across both configured and database identities. Any administrative operation that would deactivate or demote the last remaining active administrator is strictly rejected (HTTP 400 with code `cannot_remove_last_admin`).
- `GET /api/admin/overview`: Provides consolidated real metrics covering user directory totals, database health, Wazuh integration status (clearly distinguishing configured from unavailable), backup/recovery statistics, and recent administrative audit events.

### Initial Administrator Provisioning Procedure
If no administrator account exists, authorized operators can bootstrap the first administrator safely without hardcoded default credentials or public elevation endpoints using the bootstrap CLI utility:

```bash
# Interactive mode (prompts securely for password without echo)
PYTHONPATH=backend python backend/scripts/bootstrap_admin.py

# Non-interactive / scriptable mode
PYTHONPATH=backend python backend/scripts/bootstrap_admin.py --username admin --password "StrongPasswordAtLeast12Chars" --display-name "System Administrator"
```

This procedure:
1. Validates username pattern and password length (minimum 12 characters).
2. Hashes the password using PBKDF2-SHA256.
3. Inserts or updates the administrator in `user_accounts` with `role="admin"` and `is_active=True`.
4. Records an audit event (`user_account.bootstrapped`).
5. Runs safely without deleting or altering other existing records.

Alternatively, operators may generate a credentials entry for `MVP_USER_CREDENTIALS` using `python backend/scripts/create_user_credential.py`.

Roles are `viewer` (authenticated reads), `analyst` (reads plus asset registration and analyst workflow/lifecycle operations), `approver` (reads plus ActionRequest approval/rejection), and `admin` (all human-user operations). Authenticated users can read settings; only `admin` can update active risk thresholds through `PUT /api/settings` or manage accounts. Risk threshold updates are used when classifying newly created risk assessments; existing assessments are not rewritten. Other policy JSON columns have no active consumer and are read-only through the current settings API/UI; no controls imply that those policies change execution. Admin authority does not bypass requester/approver separation: the authenticated requester cannot approve or reject their own ActionRequest. Caller-provided actor IDs are not authoritative; audit attribution and stored human actor fields use the authenticated principal.

Human Bearer authentication is separate from trusted internal component reporting. Internal endpoints use `X-Internal-Component-Token`; a human token cannot substitute for a component token.

This environment-configured mechanism is intended only for a university MVP/development deployment. It is not production enterprise IAM: it has no identity provider, managed user store, MFA, automated credential rotation, or distributed session revocation. Session records are stored in the configured application database; for multi-worker deployments, all workers must use the same database. Keep credentials outside source control and do not expose this service beyond its intended trusted environment.

### Phase 6B: Trusted component authentication

Every `/api/internal/...` write endpoint requires `X-Internal-Component-Token` and a scope assigned to the authenticated component. Configure scoped credentials in `MVP_COMPONENT_TOKENS` as a JSON array of objects with `component_id`, opaque `token`, and `scopes`. For example:

```bash
export MVP_COMPONENT_TOKENS='[{"component_id":"monitor-agent","token":"replace-with-a-long-random-token","scopes":["security_events:write"]},{"component_id":"backup-agent","token":"replace-with-another-long-random-token","scopes":["backups:write"]}]'
```

The supported identities are deployment-defined; use only the components that operate the existing routes. Available scopes map directly to current writes: `security_events:write`, `threats:write`, `risk_assessments:write`, `decisions:write`, `backups:write`, `verification:write`, `isolation:write`, and `recovery:write`. Assign only the necessary scopes. Missing/invalid tokens return `401`; valid components without a route scope receive `403`. Component identity in audit actor/source fields is resolved from the credential, never from the token value or a request actor label. Tokens are compared in constant time and are not returned or recorded in logs/audit metadata.

For Phase 3–5 backward compatibility, `BACKUP_COMPONENT_TOKEN` is still accepted on backup registration/protection, verification result, isolation result, and recovery claim/result routes using the identity `legacy-backup-component`. That compatibility credential carries those four legacy scopes and should be replaced by separately scoped credentials in `MVP_COMPONENT_TOKENS`; it does not authorize Phase 1/2 ingestion. If explicit configuration and the legacy variable contain the same token, authentication fails closed. The backup registration payload's `created_by_component` continues to describe the producer metadata used by Phase 3; audit identity comes from the authenticated component principal.

Human Bearer credentials configured through `MVP_USER_TOKENS` and component tokens configured through `MVP_COMPONENT_TOKENS` are separate mechanisms. They cannot substitute for each other. This is a university-MVP safeguard, not production enterprise IAM: there is no credential issuance/rotation service, per-instance secret management, MFA, or enterprise identity provider. Keep secrets outside source control and restrict the service to its intended environment.