<<<<<<< HEAD
"""
Configuration for the Wazuh detection service.
Reads from environment variables (matches the project's .env.example pattern).
"""
import os

# Wazuh manager API
WAZUH_API_URL = os.getenv("WAZUH_API_URL", "https://localhost:55000")
WAZUH_API_USER = os.getenv("WAZUH_API_USER", "wazuh-wui")
WAZUH_API_PASSWORD = os.getenv("WAZUH_API_PASSWORD", "")
WAZUH_VERIFY_SSL = os.getenv("WAZUH_VERIFY_SSL", "false").lower() == "true"

# Where to read raw alerts from when not using the API directly.
# Useful for local testing / tailing the manager's own alert log.
ALERTS_JSON_PATH = os.getenv("ALERTS_JSON_PATH", "/var/ossec/logs/alerts/alerts.json")

# Shared DB (matches project .env.example) - where normalized detections
# get written for Member 2's Risk Engine to consume.
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "attack_resistant_db")

# Detection tuning
MASS_CHANGE_THRESHOLD = int(os.getenv("MASS_CHANGE_THRESHOLD", "15"))   # files
MASS_CHANGE_WINDOW_SECONDS = int(os.getenv("MASS_CHANGE_WINDOW_SECONDS", "20"))
ENTROPY_SUSPICIOUS_THRESHOLD = float(os.getenv("ENTROPY_SUSPICIOUS_THRESHOLD", "7.5"))  # bits/byte, max 8

=======
"""Environment-driven Wazuh detector and backend API configuration."""
import os

ALERTS_JSON_PATH = os.getenv("ALERTS_JSON_PATH", "/var/ossec/logs/alerts/alerts.json")
MASS_CHANGE_THRESHOLD = int(os.getenv("MASS_CHANGE_THRESHOLD", "15"))
MASS_CHANGE_WINDOW_SECONDS = int(os.getenv("MASS_CHANGE_WINDOW_SECONDS", "20"))
ENTROPY_SUSPICIOUS_THRESHOLD = float(os.getenv("ENTROPY_SUSPICIOUS_THRESHOLD", "7.5"))
>>>>>>> integration/deploy-main
SUSPICIOUS_EXTENSIONS = {
    ".locked", ".encrypted", ".crypt", ".enc", ".ransom",
    ".wcry", ".wncry", ".locky", ".cerber", ".zzz", ".micro",
}
<<<<<<< HEAD

RANSOM_NOTE_PATTERNS = (
    "readme", "decrypt", "how_to", "restore_files", "ransom",
)

# --- Backend API integration (POST /api/internal/security-events) -----------
# Base URL of the team's FastAPI backend.
DETECTOR_API_URL = os.getenv("DETECTOR_API_URL", "http://127.0.0.1:8000")
# Component token with the `security_events:write` scope. It must match an entry
# in the backend's MVP_COMPONENT_TOKENS. Never hard-code or commit it.
DETECTOR_API_TOKEN = os.getenv("DETECTOR_API_TOKEN", "")
# `source` value stored on every event (part of the unique key with source_event_id).
DETECTOR_SOURCE = os.getenv("DETECTOR_SOURCE", "wazuh-detector")
# How to tell the API which asset an event belongs to. The asset must already
# exist: the API never creates one. Either set a fixed asset UUID...
DETECTOR_ASSET_ID = os.getenv("DETECTOR_ASSET_ID", "")
# ...or leave it empty and the agent name is sent as an external reference
# (external_source / external_id) matched against registered assets.
DETECTOR_ASSET_EXTERNAL_SOURCE = os.getenv("DETECTOR_ASSET_EXTERNAL_SOURCE", "wazuh")
DETECTOR_API_TIMEOUT_SECONDS = float(os.getenv("DETECTOR_API_TIMEOUT_SECONDS", "5"))
=======
RANSOM_NOTE_PATTERNS = ("readme", "decrypt", "how_to", "restore_files", "ransom")

# The component token must have security_events:write only. It is never logged.
DETECTOR_API_URL = os.getenv("DETECTOR_API_URL", "http://127.0.0.1:8000")
DETECTOR_API_TOKEN = os.getenv("DETECTOR_API_TOKEN", "")
DETECTOR_SOURCE = os.getenv("DETECTOR_SOURCE", "wazuh-detector")
DETECTOR_ASSET_ID = os.getenv("DETECTOR_ASSET_ID", "")
DETECTOR_ASSET_EXTERNAL_SOURCE = os.getenv("DETECTOR_ASSET_EXTERNAL_SOURCE", "wazuh")
DETECTOR_API_TIMEOUT_SECONDS = float(os.getenv("DETECTOR_API_TIMEOUT_SECONDS", "5"))

# Retained only for the explicitly selected legacy MySQL JSONL sink.
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "attack_resistant_db")
>>>>>>> integration/deploy-main
