from __future__ import annotations

import json

import pytest

from src.api.services.execution import (
    ExecutionConfigurationError,
    HttpAgentExecutionService,
    get_execution_service,
)


def test_execution_service_auto_falls_back_to_simulated() -> None:
    service = get_execution_service(mode="auto", agent_endpoint=None)
    result = service.execute_case(
        input_text="What is the policy?",
        expected_output="Hybrid 3 days.",
        acceptable_sources="HR Policy 2026",
    )
    assert result["actual_response"].startswith("Hybrid 3 days.")
    assert result["actual_sources"] == "HR Policy 2026"
    assert result["trace"]["executor_mode"] == "simulated"


def test_execution_service_agent_http_parses_json(monkeypatch: pytest.MonkeyPatch) -> None:
    class _FakeHeaders:
        def get(self, key: str, default: str = "") -> str:
            if key.lower() == "content-type":
                return "application/json"
            return default

    class _FakeResponse:
        status = 200
        headers = _FakeHeaders()

        def __enter__(self) -> "_FakeResponse":
            return self

        def __exit__(self, exc_type, exc, tb) -> bool:
            return False

        def read(self) -> bytes:
            return json.dumps(
                {
                    "response": "Acme uses hybrid schedule.",
                    "sources": ["HR Policy 2026", "Employee Handbook"],
                }
            ).encode("utf-8")

    def _fake_urlopen(req, timeout, context):  # type: ignore[no-untyped-def]
        assert req.full_url == "https://agent.example.com/execute"
        assert timeout >= 1
        assert context is not None
        return _FakeResponse()

    monkeypatch.setattr("src.api.services.execution.request.urlopen", _fake_urlopen)
    service = get_execution_service(mode="agent_http", agent_endpoint="https://agent.example.com/execute")
    assert isinstance(service, HttpAgentExecutionService)
    result = service.execute_case(input_text="policy?")
    assert result["actual_response"] == "Acme uses hybrid schedule."
    assert result["actual_sources"] == "HR Policy 2026, Employee Handbook"
    assert result["trace"]["executor_mode"] == "agent_http"
    assert int(result["trace"]["status_code"]) == 200


def test_execution_service_agent_http_requires_endpoint() -> None:
    service = get_execution_service(mode="agent_http", agent_endpoint=None)
    with pytest.raises(ExecutionConfigurationError):
        service.execute_case(input_text="policy?")
