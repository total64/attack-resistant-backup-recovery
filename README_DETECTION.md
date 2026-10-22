# Wazuh detector integration

The project now has the Wazuh detector source code in `detector/` and routes detections to the existing authenticated event API. It does not require a second database: the backend SQLAlchemy database remains the persistent system of record.

```text
Wazuh alerts JSONL -> detector processor/heuristics -> API payload converter
  -> POST /api/internal/security-events + X-Internal-Component-Token
  -> persisted event -> threat rules -> risk assessment -> decision proposal
  -> existing approval-gated ActionRequest/component workflows
```

## Configure

1. Register each monitored asset in the backend first. The default reference is `external_source=wazuh` and `external_id=<Wazuh agent name>`; alternatively set `DETECTOR_ASSET_ID` to that existing asset's UUID.
2. Configure a unique, high-entropy secret as `DETECTOR_API_TOKEN`. The same value must appear in `MVP_COMPONENT_TOKENS` for a component with only the `security_events:write` scope. Never use that token in browser/Vite variables.
3. Set `DETECTOR_API_URL` to the backend origin. The sink appends `/api/internal/security-events` itself.
4. Run the detector using the project root as the working directory. Use `--replay sample_alerts.jsonl` for local processing or `--tail` for a Wazuh JSON alert file. Without a token, rejected asset, validation error, server error, or connectivity error, the detector appends the detection (not the credential) to `detections_unsent.jsonl`.

Detection replay uses a stable `(source, source_event_id)` key. An API `201` means the event was created and a `200` means it was a duplicate. The API validates the component scope and existing asset, persists and audits the event, and then connects it to the existing threat/risk/decision logic. A processing error leaves the event persisted in `normalized` status and produces a failed-processing audit record for retry on duplicate submission.

## Safety and limits

The supplied sample alerts are synthetic test inputs; they do not contact Wazuh. File-entropy sampling only works if the detector host can read the alerted path. Wazuh manager rule loading and live Wazuh connectivity are deployment operations, not automated here. Decisions are recommendations only; backup, isolation, and recovery require an explicitly requested/approved workflow and authorized workers. Automated tests do not perform live SSH, firewall, immutable-attribute, or recovery actions.

Run the detector/backend contract suite from the project root with `pytest -q tests/test_detector_api.py backend/tests/test_phase2_workflow.py`.
