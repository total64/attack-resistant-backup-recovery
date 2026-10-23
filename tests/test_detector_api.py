<<<<<<< HEAD
"""
Tests for the detector -> backend API integration (converter + ApiSink).
No network needed: urlopen is replaced with a fake.

Run from the repo root:  python3 -m pytest tests/test_detector_api.py -q
"""
=======
"""Offline contract tests for Wazuh normalization and authenticated API delivery."""
>>>>>>> integration/deploy-main
import io
import json
import urllib.error
from pathlib import Path

import pytest

<<<<<<< HEAD
from detector import api_sink, config, converter, processor
from detector.analysis import MassChangeTracker
from detector.processor import process_alert
from detector.schema import Detection

SAMPLE = Path(__file__).resolve().parent.parent / "sample_alerts.jsonl"

# Conservative guess at "secret-like" key names; the backend rejects those.
SECRET_MARKERS = ("password", "secret", "token", "api_key", "apikey", "authorization", "credential", "private_key")


def _detections():
    alerts = [json.loads(line) for line in SAMPLE.read_text().splitlines() if line.strip()]
    return [d for a in alerts for d in process_alert(a)]


def _all_keys(value):
    if isinstance(value, dict):
        for k, v in value.items():
            yield str(k)
            yield from _all_keys(v)
    elif isinstance(value, list):
        for v in value:
            yield from _all_keys(v)


@pytest.fixture(autouse=True)
def _clean_config(monkeypatch):
    # processor keeps a module-level mass-change tracker; start each test fresh
=======
from detector import api_sink, config, processor
from detector.analysis import MassChangeTracker
from detector.converter import detection_to_payload
from detector.processor import process_alert
from detector.schema import Detection


@pytest.fixture(autouse=True)
def reset_detector(monkeypatch):
>>>>>>> integration/deploy-main
    monkeypatch.setattr(processor, "_tracker", MassChangeTracker())
    monkeypatch.setattr(config, "DETECTOR_ASSET_ID", "")
    monkeypatch.setattr(config, "DETECTOR_SOURCE", "wazuh-detector")
    monkeypatch.setattr(config, "DETECTOR_ASSET_EXTERNAL_SOURCE", "wazuh")


<<<<<<< HEAD
# ---------------------------------------------------------------- converter

def test_sample_alerts_produce_detections():
    types = [d.detection_type for d in _detections()]
    assert types.count("suspicious_extension") == 3
    assert types.count("ransom_note") == 1


def test_payload_has_required_api_fields():
    for d in _detections():
        p = converter.detection_to_payload(d)
        for field in ("source", "source_event_id", "occurred_at", "event_type",
                      "event_severity", "summary"):
            assert p[field], field
        assert p["event_type"] == d.detection_type
        assert p["source"] == "wazuh-detector"


def test_exactly_one_asset_reference_external():
    p = converter.detection_to_payload(_detections()[0])
    assert "asset_id" not in p
    assert p["asset_external_ref"] == {"external_source": "wazuh", "external_id": "test-endpoint"}


def test_exactly_one_asset_reference_fixed_id(monkeypatch):
    monkeypatch.setattr(config, "DETECTOR_ASSET_ID", "11111111-1111-1111-1111-111111111111")
    p = converter.detection_to_payload(_detections()[0])
    assert p["asset_id"] == "11111111-1111-1111-1111-111111111111"
    assert "asset_external_ref" not in p


def test_source_event_id_is_deterministic_for_replays():
    d = _detections()[0]
    again = Detection(**{**d.to_dict(), "detection_id": "other-uuid"})
    assert converter.source_event_id(d) == converter.source_event_id(again)
    assert converter.source_event_id(d) == f"{d.raw_alert_id}:{d.detection_type}"


def test_source_event_id_falls_back_to_detection_id():
    d = Detection(detection_type="ransom_note", raw_alert_id=None)
    assert converter.source_event_id(d) == d.detection_id


@pytest.mark.parametrize("given,expected", [
    ("critical", "critical"), ("HIGH", "high"), ("low", "low"),
    ("info", "info"), ("weird", "medium"), ("", "medium"), (None, "medium"),
])
def test_severity_is_mapped_to_api_enum(given, expected):
    assert converter.normalize_severity(given) == expected


def test_indicator_contains_file_path():
    d = [x for x in _detections() if x.detection_type == "ransom_note"][0]
    p = converter.detection_to_payload(d)
    assert p["indicators"] == [{"type": "file_path", "value": "/data/reports/READ_ME_TO_DECRYPT.txt"}]
    assert "READ_ME_TO_DECRYPT.txt" in p["summary"]


def test_mass_change_summary_uses_evidence():
    d = Detection(detection_type="mass_file_modification", host="h1",
                  evidence={"files_changed": 42, "window_seconds": 20})
    assert converter.build_summary(d) == "Mass file modification on h1: 42 files in 20s"


def test_no_secret_like_keys_in_payload():
    for d in _detections():
        keys = [k.lower() for k in _all_keys(converter.detection_to_payload(d))]
        assert not [k for k in keys if any(m in k for m in SECRET_MARKERS)]


# ------------------------------------------------------------------ ApiSink

class _FakeResponse:
=======
def _sample_detections():
    fixture = Path(__file__).resolve().parents[1] / "sample_alerts.jsonl"
    alerts = [json.loads(line) for line in fixture.read_text().splitlines() if line.strip()]
    return [detection for alert in alerts for detection in process_alert(alert)]


class FakeResponse:
>>>>>>> integration/deploy-main
    def __init__(self, status):
        self.status = status

    def read(self):
        return b"{}"

    def __enter__(self):
        return self

<<<<<<< HEAD
    def __exit__(self, *exc):
        return False


def _http_error(code, body=b'{"detail":"nope"}'):
    return urllib.error.HTTPError("http://x", code, "err", {}, io.BytesIO(body))


def _sink(tmp_path, token="test-token"):
    return api_sink.ApiSink(base_url="http://api.test", token=token,
                            fallback_path=str(tmp_path / "unsent.jsonl"))


def test_201_is_created_and_request_is_correct(monkeypatch, tmp_path):
    seen = {}

    def fake_urlopen(request, timeout=None):
        seen["url"] = request.full_url
        seen["method"] = request.get_method()
        seen["token"] = request.get_header("X-internal-component-token")
        seen["body"] = json.loads(request.data)
        return _FakeResponse(201)

    monkeypatch.setattr(api_sink.urllib.request, "urlopen", fake_urlopen)
    result = _sink(tmp_path).write(_detections()[0])

    assert result == api_sink.CREATED
    assert seen["url"] == "http://api.test/api/internal/security-events"
    assert seen["method"] == "POST"
    assert seen["token"] == "test-token"
    assert seen["body"]["event_type"] == "suspicious_extension"
    assert not (tmp_path / "unsent.jsonl").exists()


def test_200_is_duplicate_and_nothing_saved(monkeypatch, tmp_path):
    monkeypatch.setattr(api_sink.urllib.request, "urlopen", lambda r, timeout=None: _FakeResponse(200))
    assert _sink(tmp_path).write(_detections()[0]) == api_sink.DUPLICATE
    assert not (tmp_path / "unsent.jsonl").exists()


def test_4xx_is_rejected_and_saved_locally(monkeypatch, tmp_path):
    def boom(request, timeout=None):
        raise _http_error(404, b'{"detail":"Asset external reference not found"}')

    monkeypatch.setattr(api_sink.urllib.request, "urlopen", boom)
    assert _sink(tmp_path).write(_detections()[0]) == api_sink.REJECTED
    saved = json.loads((tmp_path / "unsent.jsonl").read_text().splitlines()[0])
    assert "Asset external reference not found" in saved["_delivery_error"]
    assert saved["detection_type"] == "suspicious_extension"


def test_5xx_is_unavailable_and_saved_locally(monkeypatch, tmp_path):
    def boom(request, timeout=None):
        raise _http_error(503)

    monkeypatch.setattr(api_sink.urllib.request, "urlopen", boom)
    assert _sink(tmp_path).write(_detections()[0]) == api_sink.UNAVAILABLE
    assert (tmp_path / "unsent.jsonl").exists()


def test_connection_error_is_unavailable_and_saved_locally(monkeypatch, tmp_path):
    def boom(request, timeout=None):
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(api_sink.urllib.request, "urlopen", boom)
    assert _sink(tmp_path).write(_detections()[0]) == api_sink.UNAVAILABLE
    assert (tmp_path / "unsent.jsonl").exists()


def test_without_token_nothing_is_sent(monkeypatch, tmp_path):
    def must_not_be_called(request, timeout=None):
        raise AssertionError("no request should be made without a token")

    monkeypatch.setattr(api_sink.urllib.request, "urlopen", must_not_be_called)
    sink = _sink(tmp_path, token="")
    assert sink.write(_detections()[0]) == api_sink.NOT_CONFIGURED
    assert (tmp_path / "unsent.jsonl").exists()


def test_token_never_written_to_fallback_file(monkeypatch, tmp_path):
    def boom(request, timeout=None):
        raise urllib.error.URLError("down")

    monkeypatch.setattr(api_sink.urllib.request, "urlopen", boom)
    _sink(tmp_path, token="super-secret-value").write(_detections()[0])
    assert "super-secret-value" not in (tmp_path / "unsent.jsonl").read_text()
=======
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
>>>>>>> integration/deploy-main
