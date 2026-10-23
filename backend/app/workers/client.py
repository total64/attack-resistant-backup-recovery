"""Minimal stdlib HTTP client for separately deployed internal workers."""
import json
import urllib.error
import urllib.request


class WorkerAPIError(RuntimeError):
    def __init__(self, status: int, detail: str):
        super().__init__(f"Internal worker API returned HTTP {status}: {detail}")
        self.status = status
        self.detail = detail


class InternalWorkerClient:
    def __init__(self, base_url: str, component_token: str, *, timeout: float = 10):
        if not base_url.strip() or not component_token:
            raise ValueError("Worker API URL and component token are required")
        self.base_url = base_url.rstrip("/")
        self._token = component_token
        self.timeout = timeout

    def post(self, path: str, payload: dict) -> dict:
        if not path.startswith("/api/internal/"):
            raise ValueError("Worker client only permits internal API paths")
        request = urllib.request.Request(
            self.base_url + path,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Accept": "application/json",
                "Content-Type": "application/json",
                "X-Internal-Component-Token": self._token,
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as error:
            body = error.read().decode("utf-8", errors="replace")[:1000]
            raise WorkerAPIError(error.code, body) from error
