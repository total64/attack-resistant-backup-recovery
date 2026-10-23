<<<<<<< HEAD
"""
Entrypoint for the detection service.

Usage:
    python -m detector.main --tail                       # follow live alerts.json
    python -m detector.main --replay sample.json         # process a file once (testing)
    python -m detector.main --replay sample.json --sink api   # send to the backend API

Sinks:
    db   (default) write to the shared MySQL `detections` table, falling back to
         detections.jsonl when the DB is unreachable.
    api  POST each detection to the backend (/api/internal/security-events).
         Needs DETECTOR_API_TOKEN (and an existing asset, see README_DETECTION.md).

The --tail mode is meant to run on/near the Wazuh manager (or wherever
alerts.json is accessible).
=======
"""Read Wazuh alert JSON-lines and deliver normalized detections to the API.

Run ``python -m detector.main --replay sample_alerts.jsonl`` for a local replay
or ``python -m detector.main --tail`` on a Wazuh manager/alert-file host.
>>>>>>> integration/deploy-main
"""
import argparse
import json
import logging
import time

from . import config
<<<<<<< HEAD
from .processor import process_alert

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
=======
from .api_sink import ApiSink
from .processor import process_alert

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
>>>>>>> integration/deploy-main
log = logging.getLogger("detector.main")


def _iter_new_lines(path: str):
<<<<<<< HEAD
    """Follow a file like `tail -f`, yielding new lines as they appear."""
    with open(path, "r") as f:
        f.seek(0, 2)  # jump to end
        while True:
            line = f.readline()
=======
    with open(path, "r", encoding="utf-8") as file:
        file.seek(0, 2)
        while True:
            line = file.readline()
>>>>>>> integration/deploy-main
            if not line:
                time.sleep(0.5)
                continue
            yield line


def _iter_file_lines(path: str):
<<<<<<< HEAD
    """Read a file once, line by line (for --replay testing)."""
    with open(path, "r") as f:
        for line in f:
            if line.strip():
                yield line


def run(lines_iter, sink):
    for line in lines_iter:
        line = line.strip()
        if not line:
            continue
        try:
            alert = json.loads(line)
        except json.JSONDecodeError:
            continue
        for detection in process_alert(alert):
            result = sink.write(detection)
            log.info("Detection %s (%s, %s) -> %s",
                      detection.detection_id, detection.detection_type,
                      detection.severity, result or "written")


def make_sink(name: str):
    if name == "api":
        from .api_sink import ApiSink
        return ApiSink()
    from .sink import DetectionSink
    return DetectionSink()


def main():
    parser = argparse.ArgumentParser(description="Wazuh ransomware detection service")
    parser.add_argument("--tail", action="store_true",
                         help="Follow the live alerts.json file")
    parser.add_argument("--replay", metavar="FILE",
                         help="Process a JSON-lines alert file once, then exit")
    parser.add_argument("--alerts-path", default=config.ALERTS_JSON_PATH,
                         help="Path to alerts.json (default: %(default)s)")
    parser.add_argument("--sink", choices=("db", "api"), default="db",
                         help="Where to send detections (default: %(default)s)")
    args = parser.parse_args()

    if not (args.replay or args.tail):
        parser.print_help()
        return

    sink = make_sink(args.sink)

    if args.replay:
        log.info("Replaying alerts from %s", args.replay)
        run(_iter_file_lines(args.replay), sink)
    else:
        log.info("Tailing %s for new alerts...", args.alerts_path)
=======
    with open(path, "r", encoding="utf-8") as file:
        yield from (line for line in file if line.strip())


def run(lines_iter, sink: ApiSink) -> None:
    for line in lines_iter:
        try:
            alert = json.loads(line)
        except json.JSONDecodeError:
            log.warning("Skipping malformed alert JSON line")
            continue
        if not isinstance(alert, dict):
            log.warning("Skipping alert record that is not a JSON object")
            continue
        for detection in process_alert(alert):
            outcome = sink.write(detection)
            log.info("Detection %s (%s, %s) -> %s", detection.detection_id,
                     detection.detection_type, detection.severity, outcome)


def main() -> None:
    parser = argparse.ArgumentParser(description="Wazuh ransomware detection service")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--tail", action="store_true", help="Follow the live alerts file")
    mode.add_argument("--replay", metavar="FILE", help="Process a JSON-lines alert file once")
    parser.add_argument("--alerts-path", default=config.ALERTS_JSON_PATH,
                        help="Alert file for --tail (default: %(default)s)")
    parser.add_argument("--fallback-path", default="detections_unsent.jsonl",
                        help="Local append-only fallback for undelivered detections")
    args = parser.parse_args()
    sink = ApiSink(fallback_path=args.fallback_path)
    if args.replay:
        run(_iter_file_lines(args.replay), sink)
    else:
>>>>>>> integration/deploy-main
        run(_iter_new_lines(args.alerts_path), sink)


if __name__ == "__main__":
    main()
