# Attack-Resistant Backup and Recovery System

## Development setup and integrated workflow

The current backend is under `backend/` and its authenticated React frontend is under `frontend/`. Use the project's `backend/venv` if present, install `backend/requirements-dev.txt`, then run the backend from `backend/` with `uvicorn app.main:app --reload`. The backend loads `backend/.env`; keep that private file and the frontend's local environment files out of version control. Run the Vite frontend from `frontend/` with `npm run dev`. The API's cookie-session and CSRF behavior remains in place.

`pytest.ini` makes the backend package and project root visible when pytest is invoked from the repository root. Run `pytest -q` from the root, `npm run lint` and `npm run build` from `frontend/`.

### Detector event path

The detector implementation in `detector/` reads Wazuh alert JSONL, applies its file-integrity heuristics, converts detections to the backend `SecurityEventCreate` contract, and posts to `POST /api/internal/security-events` with `X-Internal-Component-Token`. Configure an existing asset reference and a component credential limited to `security_events:write`; delivery failures are retained locally without saving the credential. Ingestion now creates/resumes the persisted threat → configured risk-level assessment → decision proposal pipeline. Each stage is audited and has a correlation ID. Decisions do not execute actions or bypass analyst/approver roles.

### Worker operations

The downloaded backup, integrity, recovery and isolation worker primitives are available under `backend/app/backup`, `backend/app/recovery`, and `backend/app/isolation`. They are explicit utilities, not automatically invoked by the API. The API's existing ActionRequest approval, internal component scopes, claim/queue and component-result state machines remain authoritative. The backup helper creates a non-destructive rsync copy (no `--delete`) and computes a SHA-256 manifest; verification does not replace an existing trusted manifest. The protection/encryption helpers require explicit worker invocation and are not wired to run on ingestion. Recovery remains blocked without a passing recent verification, authorization and confirmed isolation. No live external services or host changes are performed in tests.

See [README_DETECTION.md](README_DETECTION.md) for detector configuration and limits. Live Wazuh, SSH/firewall, backup worker, integrity worker, recovery worker, and production identity infrastructure must be deployed separately; the UI/backend do not claim those workers are online or report success before a validated component result.

A cybersecurity system that protects an organization’s critical data from ransomware and other cyber threats by monitoring files and backups, detecting and analyzing suspicious activity, protecting and isolating data, and providing recovery options from verified, safe backups.

## The Problem

Cybersecurity threats such as ransomware can target enterprise files and encryption keys, rendering data inaccessible through encryption or deletion. In addition, ransomware may target and destroy backup files, rendering data recovery unrecoverable.

Enterprises need an attack-resistant cybersecurity system that detects and analyzes ransomware and other malicious activity, protects backup data, isolates affected systems, and restores files from protected, verified backups.

## Project Goal
The goal of this project is to design a system that
1. Detects ransomware and other file-encrypting malware through behavioral analysis of file access and modification patterns,
2. Protects enterprise files and backups through isolation and tamper-protection mechanisms,

3. Analyzes and prioritizes security threats based on risk values,
4. Verifies the integrity of backup data to be used for enterprise file recovery,
5. Recovers files from safely isolated, unaltered data backups in response to detected ransomware attacks, and
6. Records relevant events for auditing and forensics.
The proposed solution addresses ransomware and cybersecurity threats by monitoring, detecting, analyzing, protecting, isolating, verifying, and recovering data according to the automated procedure in Figure 1 below:
```
Figure 1: Cybersecurity and Data Recovery Procedure

Monitor
↓
Detect
↓
Analyze Risk
↓
Protect Backup
↓
Isolate
↓
Verify Backup
↓
Recover
↓
Report
```
