<<<<<<< HEAD
# Wazuh detection module

It watches a machine for ransomware-like behaviour and passes what it finds to the backend, so the rest of the system (risk, decisions, isolation, recovery) has something to react to.

There are two halves. A set of custom Wazuh rules that run inside the Wazuh manager, and a small Python service that reads Wazuh's alerts, adds a few checks of its own, and sends the results to the backend API.

```
files change on the endpoint
  -> Wazuh agent
  -> Wazuh manager (our rules run here, alerts land in alerts.json)
  -> detector (Python)
  -> backend API: POST /api/internal/security-events
```

## What's in here

```
rules/local_rules.xml      the custom Wazuh rules
detector/
  processor.py             turns one Wazuh alert into zero or more detections
  analysis.py              entropy check, extension and filename checks, mass-change counter
  converter.py             turns a detection into the JSON the backend expects
  api_sink.py              sends it to the backend (and keeps a local copy if that fails)
  sink.py                  older option: write to a MySQL table or detections.jsonl
  schema.py                the Detection record
  config.py                settings, all read from environment variables
  main.py                  command line entry point
sample_alerts.jsonl        a few made-up alerts for testing without Wazuh
tests/test_detector_api.py unit tests for the converter and the API sink
```

## The Wazuh rules

All of them are in `rules/local_rules.xml` and use IDs 100100 to 100105.

- **100100** matches every file-integrity event, so the other rules have something to count.
- **100101** is meant to fire on a burst of 15 or more file events within 20 seconds from one agent.
- **100102** fires when a file gets an extension that ransomware commonly uses (`.locked`, `.encrypted`, `.wcry` and so on).
- **100103** fires on a file named like a ransom note, such as `READ_ME_TO_DECRYPT.txt`.
- **100104** is the high-confidence one: 10 or more files with those extensions within 30 seconds from the same agent.
- **100105** looks for Windows commands that delete shadow copies or backups (`vssadmin delete shadows` and similar). It needs Sysmon or command logging on the endpoint, and I haven't tested it.

To load them into the manager:

```bash
docker cp rules/local_rules.xml single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml
docker exec single-node-wazuh.manager-1 chown root:wazuh /var/ossec/etc/rules/local_rules.xml
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-analysisd -t
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
```

The `-t` line checks the rules before you restart, so a typo can't take the manager down. If it exits with 0, you're fine.

## The detector

It reads Wazuh alerts, and for file-integrity alerts it checks:

- whether the file has a ransomware-style extension
- whether the name looks like a ransom note
- whether the first few KB of the file look random (high entropy, which is what encrypted data looks like). This only works where the detector can actually open the file, so on the endpoint itself.
- whether lots of files changed in a short time. This is its own counter, separate from rule 100101.

Each finding becomes a detection, and `converter.py` maps it onto the backend's `SecurityEventCreate` format:

| Backend field | What I send |
|---|---|
| `source` | `wazuh-detector` |
| `source_event_id` | the Wazuh alert id plus the detection type, so sending the same alert twice is recognised as a duplicate |
| `event_type` | the detection type, e.g. `suspicious_extension` |
| `event_severity` | `low`, `medium`, `high` or `critical` |
| `summary`, `indicators`, `evidence` | a one-line description, the file path, and details like the Wazuh rule id |
| asset | either a fixed `DETECTOR_ASSET_ID`, or the agent name as an external reference |

If the backend answers 201 the event is new, and 200 means it was already there. If it rejects the event (unknown asset, bad token) or can't be reached, the detection is written to `detections_unsent.jsonl` so nothing is lost. With no token set, nothing is sent at all.

## Running it

The backend only accepts events for an asset that already exists, and it never creates one itself. So before anything else, register the monitored machine. Its external source should be `wazuh` and its external id should be the Wazuh agent name (mine is `test-endpoint`). In my own testing I added the asset straight into the database with the app's models instead of going through the API, because that needs a logged-in analyst.

Then start the backend with a token for the detector (make up your own, and don't commit it):

```bash
export DETECTOR_API_TOKEN=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
export MVP_COMPONENT_TOKENS='[{"component_id":"wazuh-detector","token":"'"$DETECTOR_API_TOKEN"'","scopes":["security_events:write"]}]'
cd backend && python3 -m uvicorn app.main:app --port 8000
```

And run the detector in another terminal with the same token:

```bash
export DETECTOR_API_URL=http://127.0.0.1:8000
export DETECTOR_API_TOKEN=<the same token>

# try it on the sample alerts
python3 -m detector.main --replay sample_alerts.jsonl --sink api

# follow live alerts from the manager
python3 -m detector.main --tail --alerts-path /var/ossec/logs/alerts/alerts.json --sink api
```

Settings you can change with environment variables: `DETECTOR_API_URL`, `DETECTOR_API_TOKEN`, `DETECTOR_SOURCE`, `DETECTOR_ASSET_ID`, `DETECTOR_ASSET_EXTERNAL_SOURCE`, `DETECTOR_API_TIMEOUT_SECONDS`, and the detection thresholds in `config.py`.

## Tests

```bash
python3 -m pytest tests/test_detector_api.py -q
```

These 23 tests cover the field mapping, duplicate handling, and every kind of response from the API (created, duplicate, rejected, server error, unreachable, no token). They don't need the backend or Wazuh running.

=======
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
>>>>>>> integration/deploy-main
