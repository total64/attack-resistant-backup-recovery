"""Offline contract tests for Wazuh normalization and authenticated API delivery."""
import io
import json
import urllib.error
from pathlib import Path

import pytest

from detector import api_sink, config, processor
from detector.analysis import MassChangeTracker
from detector.converter import detection_to_payload
from detector.processor import process_alert
from detector.schema import Detection


@pytest.fixture(autouse=True)
def reset_detector(monkeypatch):
    monkeypatch.setattr(processor, "_tracker", MassChangeTracker())
    monkeypatch.setattr(config, "DETECTOR_ASSET_ID", "")
    monkeypatch.setattr(config, "DETECTOR_SOURCE", "wazuh-detector")
    monkeypatch.setattr(config, "DETECTOR_ASSET_EXTERNAL_SOURCE", "wazuh")


def _sample_detections():
    fixture = Path(__file__).resolve().parents[1] / "sample_alerts.jsonl"
    alerts = [json.loads(line) for line in fixture.read_text().splitlines() if line.strip()]
    return [detection for alert in alerts for detection in process_alert(alert)]


class FakeResponse:
    def __init__(self, status):
        self.status = status

    def read(self):
        return b"{}"

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


def test_sample_wazuh_alerts_produce_ransomware_detections():
    detections = _sample_detections()
    types = [item.detection_type for item in detections]
    assert types.count("suspicious_extension") == 3
    assert types.count("ransom_note") == 1


def test_backend_payload_matches_asset_and_event_contract():
    payload = detection_to_payload(_sample_detections()[0])
    assert payload["source"] == "wazuh-detector"
    assert payload["source_event_id"]
    assert payload["event_type"]
    assert payload["event_severity"] in {"info", "low", "medium", "high", "critical"}
    assert payload["asset_external_ref"] == {
        "external_source": "wazuh",
        "external_id": "test-endpoint",
    }
    assert "asset_id" not in payload


def test_api_sink_uses_component_auth_and_duplicate_semantics(monkeypatch, tmp_path):
    observed = {}

    def fake_urlopen(request, timeout=None):
        observed["url"] = request.full_url
        observed["header"] = request.get_header("X-internal-component-token")
        observed["body"] = json.loads(request.data)
        observed["timeout"] = timeout
        return FakeResponse(200)

    monkeypatch.setattr(api_sink.urllib.request, "urlopen", fake_urlopen)
    sink = api_sink.ApiSink(
        base_url="http://localhost:8000",
        token="test-token",
        fallback_path=str(tmp_path / "unsent.jsonl"),
    )
    assert sink.write(_sample_detections()[0]) == api_sink.DUPLICATE
    assert observed["url"] == "http://localhost:8000/api/internal/security-events"
    assert observed["header"] == "test-token"
    assert observed["body"]["event_type"] == "suspicious_extension"
    assert not (tmp_path / "unsent.jsonl").exists()


def test_api_sink_persists_rejected_events_without_token(monkeypatch, tmp_path):
    def reject(_request, timeout=None):
        raise urllib.error.HTTPError(
            "http://localhost/api/internal/security-events", 401, "unauthorized", {}, io.BytesIO(b"denied")
        )

    monkeypatch.setattr(api_sink.urllib.request, "urlopen", reject)
    path = tmp_path / "unsent.jsonl"
    result = api_sink.ApiSink(token="test-token", fallback_path=str(path)).write(_sample_detections()[0])
    assert result == api_sink.REJECTED
    record = json.loads(path.read_text().splitlines()[0])
    assert "HTTP 401" in record["_delivery_error"]
    assert "test-token" not in path.read_text()


def test_missing_component_token_never_sends(monkeypatch, tmp_path):
    def unexpected(*_args, **_kwargs):
        pytest.fail("network request should not happen without a component token")

    monkeypatch.setattr(api_sink.urllib.request, "urlopen", unexpected)
    path = tmp_path / "unsent.jsonl"
    result = api_sink.ApiSink(token="", fallback_path=str(path)).write(_sample_detections()[0])
    assert result == api_sink.NOT_CONFIGURED
    assert path.is_file()
