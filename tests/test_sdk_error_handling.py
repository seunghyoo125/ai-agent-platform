from __future__ import annotations

import io
import urllib.error
import urllib.request
from typing import Any

from sdk.python.greenlight_client import GreenlightApiError, GreenlightClient


class _DummyResponse:
    def __init__(self, body: bytes, status: int = 200, request_id: str | None = None):
        self._body = body
        self.status = status
        self.headers = {"X-Request-Id": request_id} if request_id else {}

    def __enter__(self) -> "_DummyResponse":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False

    def read(self) -> bytes:
        return self._body


def test_sdk_parses_http_error_envelope(monkeypatch) -> None:
    def _raise_http_error(_req: Any, timeout: int = 30):
        body = b'{"ok":false,"error":{"code":"AGENT_NOT_FOUND","message":"Agent missing","details":{"agent_id":"a1"}}}'
        raise urllib.error.HTTPError(
            url="http://127.0.0.1:8001/api/agents",
            code=404,
            msg="Not Found",
            hdrs={"X-Request-Id": "req-err-001"},
            fp=io.BytesIO(body),
        )

    monkeypatch.setattr(urllib.request, "urlopen", _raise_http_error)

    client = GreenlightClient("http://127.0.0.1:8001", "test-key", max_retries=0)
    try:
        client.get_agents()
        assert False, "Expected GreenlightApiError"
    except GreenlightApiError as exc:
        assert exc.status_code == 404
        assert exc.code == "AGENT_NOT_FOUND"
        assert exc.message == "Agent missing"
        assert exc.request_id == "req-err-001"
        assert exc.details == {"agent_id": "a1"}


def test_sdk_preserves_last_request_id_on_retry_exhausted_network_error(monkeypatch) -> None:
    calls = {"n": 0}

    def _flaky(_req: Any, timeout: int = 30):
        calls["n"] += 1
        if calls["n"] == 1:
            body = b'{"ok":false,"error":{"code":"TEMP_UNAVAILABLE","message":"retry me"}}'
            raise urllib.error.HTTPError(
                url="http://127.0.0.1:8001/api/agents",
                code=503,
                msg="Service Unavailable",
                hdrs={"X-Request-Id": "req-retry-001"},
                fp=io.BytesIO(body),
            )
        raise urllib.error.URLError("connection dropped")

    monkeypatch.setattr(urllib.request, "urlopen", _flaky)

    client = GreenlightClient(
        "http://127.0.0.1:8001",
        "test-key",
        max_retries=1,
        backoff_base_seconds=0,
    )

    try:
        client.get_agents()
        assert False, "Expected GreenlightApiError"
    except GreenlightApiError as exc:
        assert exc.code == "NETWORK_ERROR"
        assert exc.request_id == "req-retry-001"
