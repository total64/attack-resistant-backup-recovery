"""Environment-driven Wazuh detector and backend API configuration."""
import os

ALERTS_JSON_PATH = os.getenv("ALERTS_JSON_PATH", "/var/ossec/logs/alerts/alerts.json")
MASS_CHANGE_THRESHOLD = int(os.getenv("MASS_CHANGE_THRESHOLD", "15"))
MASS_CHANGE_WINDOW_SECONDS = int(os.getenv("MASS_CHANGE_WINDOW_SECONDS", "20"))
ENTROPY_SUSPICIOUS_THRESHOLD = float(os.getenv("ENTROPY_SUSPICIOUS_THRESHOLD", "7.5"))
SUSPICIOUS_EXTENSIONS = {
    ".locked", ".encrypted", ".crypt", ".enc", ".ransom",
    ".wcry", ".wncry", ".locky", ".cerber", ".zzz", ".micro",
}
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
