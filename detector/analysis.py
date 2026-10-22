"""Wazuh file-integrity heuristics and per-agent change-rate tracking."""
import math
import os
import time
from collections import defaultdict, deque

from . import config


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = defaultdict(int)
    for byte in data:
        counts[byte] += 1
    size = len(data)
    return -sum((count / size) * math.log2(count / size) for count in counts.values())


def sample_file_entropy(path: str, sample_bytes: int = 4096) -> float | None:
    try:
        with open(path, "rb") as file:
            return shannon_entropy(file.read(sample_bytes))
    except OSError:
        return None


def has_suspicious_extension(file_path: str) -> bool:
    lower = file_path.lower()
    return any(lower.endswith(extension) for extension in config.SUSPICIOUS_EXTENSIONS)


def looks_like_ransom_note(file_path: str) -> bool:
    lower = os.path.basename(file_path).lower()
    return lower.endswith((".txt", ".html", ".hta")) and any(
        pattern in lower for pattern in config.RANSOM_NOTE_PATTERNS
    )


class MassChangeTracker:
    def __init__(self, threshold: int | None = None, window_seconds: int | None = None):
        self.threshold = threshold or config.MASS_CHANGE_THRESHOLD
        self.window_seconds = window_seconds or config.MASS_CHANGE_WINDOW_SECONDS
        self._events: dict[str, deque] = defaultdict(deque)

    def record(self, agent_id: str, timestamp: float | None = None) -> int:
        now = timestamp if timestamp is not None else time.time()
        events = self._events[agent_id]
        events.append(now)
        cutoff = now - self.window_seconds
        while events and events[0] < cutoff:
            events.popleft()
        return len(events)

    def is_mass_change(self, agent_id: str) -> bool:
        return len(self._events.get(agent_id, ())) >= self.threshold
