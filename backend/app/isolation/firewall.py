"""Isolation adapters for explicitly deployed, authorized worker processes.

The API control plane does not construct these adapters. Automated tests use
MockFirewall and cannot alter a machine's network configuration.
"""
from abc import ABC, abstractmethod
from collections.abc import Callable


class Firewall(ABC):
    @abstractmethod
    def isolate(self, host_id: str) -> bool:
        raise NotImplementedError

    @abstractmethod
    def restore(self, host_id: str) -> bool:
        raise NotImplementedError

    @abstractmethod
    def is_isolated(self, host_id: str) -> bool:
        raise NotImplementedError


class NftablesFirewall(Firewall):
    """Injected nft command adapter. Caller must provide a scoped worker command runner."""

    TABLE = "arbr_isolation"

    def __init__(self, ssh_command: Callable[[str], tuple[int, str, str]]):
        self.ssh_command = ssh_command

    def _run(self, command: str) -> tuple[int, str, str]:
        return self.ssh_command(command)

    def isolate(self, host_id: str) -> bool:
        del host_id  # command applies only to the worker's preconfigured target
        for command in (
            f"sudo -n nft add rule inet {self.TABLE} input counter drop",
            f"sudo -n nft add rule inet {self.TABLE} output counter drop",
        ):
            if self._run(command)[0] != 0:
                return False
        return True

    def restore(self, host_id: str) -> bool:
        del host_id
        commands = (
            f"sudo -n nft flush chain inet {self.TABLE} input",
            f"sudo -n nft flush chain inet {self.TABLE} output",
            f"sudo -n nft add rule inet {self.TABLE} input iifname lo accept",
            f"sudo -n nft add rule inet {self.TABLE} input ct state established,related accept",
            f"sudo -n nft add rule inet {self.TABLE} output oifname lo accept",
            f"sudo -n nft add rule inet {self.TABLE} output ct state established,related accept",
        )
        for command in commands:
            if self._run(command)[0] != 0:
                return False
        return True

    def is_isolated(self, host_id: str) -> bool:
        del host_id
        code, output, _ = self._run(f"sudo -n nft list chain inet {self.TABLE} input")
        return code == 0 and "drop" in output


class MockFirewall(Firewall):
    def __init__(self):
        self.isolated_hosts: set[str] = set()

    def isolate(self, host_id: str) -> bool:
        self.isolated_hosts.add(host_id)
        return True

    def restore(self, host_id: str) -> bool:
        if host_id not in self.isolated_hosts:
            return False
        self.isolated_hosts.remove(host_id)
        return True

    def is_isolated(self, host_id: str) -> bool:
        return host_id in self.isolated_hosts
