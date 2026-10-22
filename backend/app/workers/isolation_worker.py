"""Approval-gated isolation adapter over the existing result state machine."""
from app.isolation.firewall import Firewall


class IsolationWorker:
    """Execute isolation only after backend accepts the approved executing transition.

    `asset_hosts` is trusted worker configuration. Client-supplied hostnames are
    never used to choose a network/firewall target.
    """

    def __init__(self, client, *, firewall: Firewall, asset_hosts: dict[str, str], component_reference: str):
        self.client = client
        self.firewall = firewall
        self.asset_hosts = dict(asset_hosts)
        self.component_reference = component_reference

    def execute(self, isolation_action_id: str, *, asset_id: str, correlation_id: str) -> dict:
        host_id = self.asset_hosts.get(asset_id)
        if not host_id:
            raise ValueError("Asset must map to a host in trusted isolation-worker configuration")
        base = f"/api/internal/isolation/{isolation_action_id}/result"
        common = {"component_reference": self.component_reference, "correlation_id": correlation_id}
        started = self.client.post(base, {
            **common,
            "execution_status": "executing",
            "network_state": "isolating",
        })
        # The API enforces approval and transition legality. No host call occurs
        # unless it accepted the executing transition above.
        if started.get("execution_status") != "executing":
            raise RuntimeError("Backend did not accept the isolation executing transition")
        try:
            isolated = self.firewall.isolate(host_id)
            verified = isolated and self.firewall.is_isolated(host_id)
        except Exception as error:
            return self.client.post(base, {
                **common,
                "execution_status": "failed",
                "network_state": "unknown",
                "failure_reason": f"Isolation adapter raised {type(error).__name__}",
            })
        if not verified:
            return self.client.post(base, {
                **common,
                "execution_status": "failed",
                "network_state": "unknown",
                "failure_reason": "Firewall did not confirm the isolation state",
            })
        return self.client.post(base, {
            **common,
            "execution_status": "isolated",
            "network_state": "isolated",
        })

    def release(self, isolation_action_id: str, *, asset_id: str, correlation_id: str) -> dict:
        host_id = self.asset_hosts.get(asset_id)
        if not host_id:
            raise ValueError("Asset must map to a host in trusted isolation-worker configuration")
        base = f"/api/internal/isolation/{isolation_action_id}/result"
        common = {"component_reference": self.component_reference, "correlation_id": correlation_id}
        started = self.client.post(base, {
            **common,
            "execution_status": "executing",
            "network_state": "releasing",
        })
        if started.get("execution_status") != "executing":
            raise RuntimeError("Backend did not accept the approved release transition")
        try:
            released = self.firewall.restore(host_id)
            verified = released and not self.firewall.is_isolated(host_id)
        except Exception as error:
            return self.client.post(base, {
                **common,
                "execution_status": "failed",
                "network_state": "isolated",
                "failure_reason": f"Isolation release adapter raised {type(error).__name__}",
            })
        if not verified:
            return self.client.post(base, {
                **common,
                "execution_status": "failed",
                "network_state": "isolated",
                "failure_reason": "Firewall did not confirm the released state",
            })
        return self.client.post(base, {
            **common,
            "execution_status": "released",
            "network_state": "connected",
        })
