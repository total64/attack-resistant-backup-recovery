<<<<<<< HEAD
"""
Detection heuristics that go beyond what's easy to express in a Wazuh
XML rule: file entropy sampling and a sliding-window mass-change tracker
keyed per agent/host.
"""
=======
"""Wazuh file-integrity heuristics and per-agent change-rate tracking."""
>>>>>>> integration/deploy-main
import math
import os
import time
from collections import defaultdict, deque

from . import config


def shannon_entropy(data: bytes) -> float:
<<<<<<< HEAD
    """
    Compute Shannon entropy (bits/byte, 0-8) of a byte string.
    Encrypted/compressed data trends close to 8.0 (random-looking).
    Plain text usually sits well below that (~3.5-5.0).
    """
    if not data:
        return 0.0
    freq = defaultdict(int)
    for b in data:
        freq[b] += 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def sample_file_entropy(path: str, sample_bytes: int = 4096) -> float | None:
    """
    Read a small sample from the start of a file and compute its entropy.
    Returns None if the file can't be read (deleted, permissions, etc.).
    Sampling instead of reading whole files keeps this cheap even on
    large files during a mass-change event.
    """
    try:
        with open(path, "rb") as f:
            chunk = f.read(sample_bytes)
        return shannon_entropy(chunk)
    except (OSError, IOError):
=======
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
>>>>>>> integration/deploy-main
        return None


def has_suspicious_extension(file_path: str) -> bool:
    lower = file_path.lower()
<<<<<<< HEAD
    return any(lower.endswith(ext) for ext in config.SUSPICIOUS_EXTENSIONS)
=======
    return any(lower.endswith(extension) for extension in config.SUSPICIOUS_EXTENSIONS)
>>>>>>> integration/deploy-main


def looks_like_ransom_note(file_path: str) -> bool:
    lower = os.path.basename(file_path).lower()
<<<<<<< HEAD
    if not lower.endswith((".txt", ".html", ".hta")):
        return False
    return any(pattern in lower for pattern in config.RANSOM_NOTE_PATTERNS)


class MassChangeTracker:
    """
    Sliding-window counter of file-change events per agent, so we can
    flag "N+ file events within T seconds from the same host" even when
    events arrive one at a time from the alert stream, independent of
    whatever the Wazuh-side frequency rule is doing.
    """

    def __init__(self, threshold: int = None, window_seconds: int = None):
=======
    return lower.endswith((".txt", ".html", ".hta")) and any(
        pattern in lower for pattern in config.RANSOM_NOTE_PATTERNS
    )


class MassChangeTracker:
    def __init__(self, threshold: int | None = None, window_seconds: int | None = None):
>>>>>>> integration/deploy-main
        self.threshold = threshold or config.MASS_CHANGE_THRESHOLD
        self.window_seconds = window_seconds or config.MASS_CHANGE_WINDOW_SECONDS
        self._events: dict[str, deque] = defaultdict(deque)

<<<<<<< HEAD
    def record(self, agent_id: str, timestamp: float = None) -> int:
        """
        Record one file-change event for an agent. Returns the current
        count of events within the sliding window for that agent.
        """
        ts = timestamp if timestamp is not None else time.time()
        q = self._events[agent_id]
        q.append(ts)
        cutoff = ts - self.window_seconds
        while q and q[0] < cutoff:
            q.popleft()
        return len(q)
=======
    def record(self, agent_id: str, timestamp: float | None = None) -> int:
        now = timestamp if timestamp is not None else time.time()
        events = self._events[agent_id]
        events.append(now)
        cutoff = now - self.window_seconds
        while events and events[0] < cutoff:
            events.popleft()
        return len(events)
>>>>>>> integration/deploy-main

    def is_mass_change(self, agent_id: str) -> bool:
        return len(self._events.get(agent_id, ())) >= self.threshold
