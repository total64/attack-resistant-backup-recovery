"""Isolated-host worker state helper; never invoked by API ingestion."""
from datetime import datetime, timezone

from .firewall import Firewall


class IsolationManager:
    def __init__(self, firewall: Firewall):
        self.firewall = firewall
        self.isolated_hosts: dict[str, dict] = {}

    def isolate_host(self, host_id: str, reason: str, risk_level: str) -> dict:
        if host_id in self.isolated_hosts:
            return {"host_id": host_id, "status": "ALREADY_ISOLATED", "success": True}
        if not self.firewall.isolate(host_id):
            return {"host_id": host_id, "status": "ISOLATION_FAILED", "success": False}
        self.isolated_hosts[host_id] = {
            "reason": reason,
            "risk_level": risk_level,
            "isolated_at": datetime.now(timezone.utc).isoformat(),
        }
        return {"host_id": host_id, "status": "ISOLATED", "success": True}

    def restore_host(self, host_id: str) -> dict:
        if host_id not in self.isolated_hosts:
            return {"host_id": host_id, "status": "NOT_ISOLATED", "success": False}
        if not self.firewall.restore(host_id):
            return {"host_id": host_id, "status": "RESTORE_FAILED", "success": False}
        del self.isolated_hosts[host_id]
        return {"host_id": host_id, "status": "RESTORED", "success": True}

    def get_status(self, host_id: str) -> dict:
        if host_id in self.isolated_hosts:
            return {"host_id": host_id, "status": "ISOLATED", "details": self.isolated_hosts[host_id]}
        return {"host_id": host_id, "status": "NORMAL"}
