<<<<<<< HEAD
"""
Sends detections to the backend API: POST /api/internal/security-events.

This is what connects the detector to the rest of the pipeline. The backend
stores the event, audits it, and the dashboard / risk / decision components
pick it up from there.

Delivery rules:
  * 201 -> created, 200 -> duplicate (same source + source_event_id): both are
    treated as delivered.
  * 4xx -> the API rejected the event (unknown asset, validation, auth). The
    reason is logged and the detection is saved locally so nothing is lost.
  * 5xx / connection error / timeout -> saved locally to retry later.
  * No token configured -> nothing is sent; the detection is saved locally.

The component token is read from DETECTOR_API_TOKEN and is never logged.
Uses only the standard library, so there are no new dependencies.
"""
=======
"""Authenticated, idempotent delivery of detections to the backend API."""
>>>>>>> integration/deploy-main
import json
import logging
import urllib.error
import urllib.request

from . import config
from .converter import detection_to_payload
from .schema import Detection

log = logging.getLogger("detector.api_sink")
<<<<<<< HEAD

ENDPOINT_PATH = "/api/internal/security-events"
TOKEN_HEADER = "X-Internal-Component-Token"

# Result values returned by ApiSink.write()
=======
ENDPOINT_PATH = "/api/internal/security-events"
TOKEN_HEADER = "X-Internal-Component-Token"
>>>>>>> integration/deploy-main
CREATED = "created"
DUPLICATE = "duplicate"
REJECTED = "rejected"
UNAVAILABLE = "unavailable"
NOT_CONFIGURED = "not_configured"


class ApiSink:
    def __init__(
        self,
        base_url: str | None = None,
        token: str | None = None,
        fallback_path: str = "detections_unsent.jsonl",
        timeout: float | None = None,
    ):
        self.url = (base_url or config.DETECTOR_API_URL).rstrip("/") + ENDPOINT_PATH
        self._token = token if token is not None else config.DETECTOR_API_TOKEN
        self.fallback_path = fallback_path
        self.timeout = timeout if timeout is not None else config.DETECTOR_API_TIMEOUT_SECONDS
        if not self._token:
<<<<<<< HEAD
            log.warning(
                "DETECTOR_API_TOKEN is not set; detections will only be saved to %s",
                self.fallback_path,
            )
=======
            log.warning("DETECTOR_API_TOKEN is not set; events will only be saved to %s", fallback_path)
>>>>>>> integration/deploy-main

    def write(self, detection: Detection) -> str:
        if not self._token:
            self._save_unsent(detection, "no component token configured")
            return NOT_CONFIGURED

<<<<<<< HEAD
        payload = detection_to_payload(detection)
        request = urllib.request.Request(
            self.url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                TOKEN_HEADER: self._token,
            },
=======
        request = urllib.request.Request(
            self.url,
            data=json.dumps(detection_to_payload(detection)).encode("utf-8"),
            headers={"Content-Type": "application/json", TOKEN_HEADER: self._token},
>>>>>>> integration/deploy-main
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
<<<<<<< HEAD
                status = response.status
=======
                response_status = response.status
>>>>>>> integration/deploy-main
                response.read()
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")[:500]
            if 400 <= exc.code < 500:
<<<<<<< HEAD
                log.warning("API rejected detection %s (HTTP %s): %s",
                            detection.detection_id, exc.code, body)
                self._save_unsent(detection, f"HTTP {exc.code}: {body}")
                return REJECTED
            log.warning("API error for detection %s (HTTP %s)", detection.detection_id, exc.code)
            self._save_unsent(detection, f"HTTP {exc.code}")
            return UNAVAILABLE
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            log.warning("API unreachable (%s); saving detection %s locally",
                        exc, detection.detection_id)
            self._save_unsent(detection, f"unreachable: {exc}")
            return UNAVAILABLE

        if status == 200:
            log.info("Detection %s already known to the API (duplicate)", detection.detection_id)
            return DUPLICATE
        log.info("Detection %s delivered to the API (HTTP %s)", detection.detection_id, status)
=======
                log.warning("Backend rejected detection %s (HTTP %s): %s", detection.detection_id, exc.code, body)
                self._save_unsent(detection, f"HTTP {exc.code}: {body}")
                return REJECTED
            log.warning("Backend error for detection %s (HTTP %s)", detection.detection_id, exc.code)
            self._save_unsent(detection, f"HTTP {exc.code}")
            return UNAVAILABLE
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            log.warning("Backend unavailable; saving detection %s locally: %s", detection.detection_id, exc)
            self._save_unsent(detection, f"unreachable: {exc}")
            return UNAVAILABLE

        if response_status == 200:
            return DUPLICATE
        if response_status != 201:
            self._save_unsent(detection, f"unexpected HTTP status {response_status}")
            return UNAVAILABLE
>>>>>>> integration/deploy-main
        return CREATED

    def _save_unsent(self, detection: Detection, reason: str) -> None:
        record = detection.to_dict()
        record["_delivery_error"] = reason
<<<<<<< HEAD
        with open(self.fallback_path, "a") as f:
            f.write(json.dumps(record) + "\n")
=======
        with open(self.fallback_path, "a", encoding="utf-8") as file:
            file.write(json.dumps(record) + "\n")
>>>>>>> integration/deploy-main
