"""Read Wazuh alert JSON-lines and deliver normalized detections to the API.

Run ``python -m detector.main --replay sample_alerts.jsonl`` for a local replay
or ``python -m detector.main --tail`` on a Wazuh manager/alert-file host.
"""
import argparse
import json
import logging
import time

from . import config
from .api_sink import ApiSink
from .processor import process_alert

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("detector.main")


def _iter_new_lines(path: str):
    with open(path, "r", encoding="utf-8") as file:
        file.seek(0, 2)
        while True:
            line = file.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line


def _iter_file_lines(path: str):
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
        run(_iter_new_lines(args.alerts_path), sink)


if __name__ == "__main__":
    main()
