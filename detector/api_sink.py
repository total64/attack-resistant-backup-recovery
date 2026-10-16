"""Authenticated, idempotent delivery of detections to the backend API."""
import json
import logging
import urllib.error
import urllib.request

from . import config
from .converter import detection_to_payload
from .schema import Detection

log = logging.getLogger("detector.api_sink")
ENDPOINT_PATH = "/api/internal/security-events"
TOKEN_HEADER = "X-Internal-Component-Token"
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
            log.warning("DETECTOR_API_TOKEN is not set; events will only be saved to %s", fallback_path)

    def write(self, detection: Detection) -> str:
        if not self._token:
            self._save_unsent(detection, "no component token configured")
            return NOT_CONFIGURED

        request = urllib.request.Request(
            self.url,
            data=json.dumps(detection_to_payload(detection)).encode("utf-8"),
            headers={"Content-Type": "application/json", TOKEN_HEADER: self._token},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                response_status = response.status
                response.read()
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")[:500]
            if 400 <= exc.code < 500:
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
        return CREATED

    def _save_unsent(self, detection: Detection, reason: str) -> None:
        record = detection.to_dict()
        record["_delivery_error"] = reason
        with open(self.fallback_path, "a", encoding="utf-8") as file:
            file.write(json.dumps(record) + "\n")
