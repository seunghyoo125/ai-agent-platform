from __future__ import annotations

import base64
from typing import Any, Dict, List, Optional

import pytest
from fastapi.testclient import TestClient

import src.api.main as api_main
from src.api.main import app


client = TestClient(app)


@pytest.fixture(autouse=True)
def _reset_rate_limit_state_between_tests() -> None:
    api_main._RATE_LIMIT_STATE.clear()


def _assert_error_envelope(payload: Dict[str, Any], code: str) -> None:
    assert payload.get("ok") is False
    err = payload.get("error")
    assert isinstance(err, dict)
    assert err.get("code") == code
    assert isinstance(err.get("message"), str)


class _FakeCursor:
    def __init__(self, fetchone_values: Optional[List[Any]] = None, fetchall_values: Optional[List[Any]] = None):
        self._fetchone_values = list(fetchone_values or [])
        self._fetchall_values = list(fetchall_values or [])

    def __enter__(self) -> "_FakeCursor":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False

    def execute(self, _sql: str, _params: Any = None) -> None:
        return None

    def fetchone(self) -> Any:
        if self._fetchone_values:
            return self._fetchone_values.pop(0)
        return None

    def fetchall(self) -> Any:
        if self._fetchall_values:
            return self._fetchall_values.pop(0)
        return []


class _FakeConn:
    def __init__(self, cursor: _FakeCursor):
        self._cursor = cursor

    def __enter__(self) -> "_FakeConn":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False

    def cursor(self) -> _FakeCursor:
        return self._cursor


def test_unauthorized_envelope_on_protected_endpoint() -> None:
    response = client.post("/api/eval/runs", json={})

    assert response.status_code == 401
    _assert_error_envelope(response.json(), "UNAUTHORIZED")


def test_forbidden_envelope_for_viewer_on_member_write() -> None:
    app.dependency_overrides[api_main.require_api_key] = lambda: {
        "key_id": "k1",
        "org_id": None,
        "name": "viewer-key",
        "role": "viewer",
    }
    try:
        response = client.post("/api/eval/runs", json={})
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 403
    payload = response.json()
    _assert_error_envelope(payload, "FORBIDDEN")
    assert payload["error"]["details"]["required_role"] == "member"
    assert payload["error"]["details"]["actual_role"] == "viewer"


def test_forbidden_envelope_for_member_on_admin_write() -> None:
    app.dependency_overrides[api_main.require_api_key] = lambda: {
        "key_id": "k2",
        "org_id": None,
        "name": "member-key",
        "role": "member",
    }
    try:
        response = client.post("/api/system/api-keys", json={"name": "x", "org_id": None, "expires_at": None})
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 403
    payload = response.json()
    _assert_error_envelope(payload, "FORBIDDEN")
    assert payload["error"]["details"]["required_role"] == "admin"
    assert payload["error"]["details"]["actual_role"] == "member"


def test_create_api_key_rejects_global_non_admin_role() -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }
    try:
        response = client.post(
            "/api/system/api-keys",
            json={"name": "invalid-global-member", "org_id": None, "role": "member", "expires_at": None},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 400
    _assert_error_envelope(response.json(), "API_KEY_SCOPE_ROLE_INVALID")


def test_validate_db_api_key_rejects_global_non_admin_record() -> None:
    row = ("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", None, "bad-global", "member")

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[row]))

    original = api_main.get_conn
    api_main.get_conn = _fake_get_conn  # type: ignore[assignment]
    try:
        result = api_main._validate_db_api_key("sk_live_bad", touch_last_used=False)
    finally:
        api_main.get_conn = original  # type: ignore[assignment]

    assert result is None


def test_create_agent_forbidden_for_viewer_role() -> None:
    app.dependency_overrides[api_main.require_api_key] = lambda: {
        "key_id": "k-agent-viewer",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "viewer-key",
        "role": "viewer",
    }
    try:
        response = client.post(
            "/api/agents",
            json={
                "org_id": "11111111-1111-1111-1111-111111111111",
                "name": "Restricted Agent",
                "description": "should fail for viewer",
                "agent_type": "search_retrieval",
                "status": "build",
                "model": "gpt-4.1",
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 403
    payload = response.json()
    _assert_error_envelope(payload, "FORBIDDEN")
    assert payload["error"]["details"]["required_role"] == "member"
    assert payload["error"]["details"]["actual_role"] == "viewer"


def test_validation_error_envelope_shape() -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k3",
        "org_id": None,
        "name": "member-key",
        "role": "member",
    }
    try:
        response = client.post("/api/eval/runs", json={})
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 422
    payload = response.json()
    _assert_error_envelope(payload, "VALIDATION_ERROR")
    assert isinstance(payload["error"].get("details"), list)


def test_not_found_error_envelope_from_route_logic(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_viewer] = lambda: {
        "key_id": "k4",
        "org_id": None,
        "name": "viewer-key",
        "role": "viewer",
    }

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[None]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.get("/api/agents/11111111-1111-1111-1111-111111111111")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 404
    _assert_error_envelope(response.json(), "AGENT_NOT_FOUND")


def test_org_scoped_key_rejects_cross_org_agent_list() -> None:
    app.dependency_overrides[api_main.require_viewer] = lambda: {
        "key_id": "k-org-list",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "scoped-viewer",
        "role": "viewer",
    }
    try:
        response = client.get("/api/agents?org_id=22222222-2222-2222-2222-222222222222")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 403
    _assert_error_envelope(response.json(), "FORBIDDEN_ORG_SCOPE")


def test_org_scoped_key_rejects_cross_org_agent_create() -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k-org-create",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "scoped-member",
        "role": "member",
    }
    try:
        response = client.post(
            "/api/agents",
            json={
                "org_id": "22222222-2222-2222-2222-222222222222",
                "name": "x",
                "agent_type": "search_retrieval",
                "status": "build",
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 403
    _assert_error_envelope(response.json(), "FORBIDDEN_ORG_SCOPE")


def test_org_scoped_key_rejects_cross_org_eval_run_create() -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k-org-eval",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "scoped-member",
        "role": "member",
    }
    try:
        response = client.post(
            "/api/eval/runs",
            json={
                "org_id": "22222222-2222-2222-2222-222222222222",
                "agent_id": "33333333-3333-3333-3333-333333333333",
                "name": "cross-org-attempt",
                "type": "eval",
                "config": {},
                "design_context": {},
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 403
    _assert_error_envelope(response.json(), "FORBIDDEN_ORG_SCOPE")


def test_create_eval_template_success(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k-template-create",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }

    inserted = (
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "11111111-1111-1111-1111-111111111111",
        "default-retrieval",
        "Default retrieval eval template",
        "eval",
        "search_retrieval",
        None,
        {"sample_size": "all"},
        {"reason": "template"},
        True,
        "2026-02-24T00:00:00Z",
        "2026-02-24T00:00:00Z",
    )

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[inserted]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.post(
            "/api/eval/templates",
            json={
                "org_id": "11111111-1111-1111-1111-111111111111",
                "name": "default-retrieval",
                "description": "Default retrieval eval template",
                "run_type": "eval",
                "agent_type": "search_retrieval",
                "config": {"sample_size": "all"},
                "design_context": {"reason": "template"},
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 201
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["name"] == "default-retrieval"


def test_list_eval_templates_success(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_viewer] = lambda: {
        "key_id": "k-template-list",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "viewer-key",
        "role": "viewer",
    }

    row = (
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "11111111-1111-1111-1111-111111111111",
        "default-retrieval",
        "Default retrieval eval template",
        "eval",
        "search_retrieval",
        None,
        {"sample_size": "all"},
        {"reason": "template"},
        True,
        "2026-02-24T00:00:00Z",
        "2026-02-24T00:00:00Z",
    )

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchall_values=[[row]]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.get("/api/eval/templates?org_id=11111111-1111-1111-1111-111111111111")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["count"] == 1
    assert payload["data"]["items"][0]["name"] == "default-retrieval"


def test_create_eval_run_with_template_success(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k-run-template",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }

    def _fake_get_conn() -> _FakeConn:
        agent_row = ("22222222-2222-2222-2222-222222222222", "11111111-1111-1111-1111-111111111111", "search_retrieval")
        template_row = (
            "33333333-3333-3333-3333-333333333333",
            "11111111-1111-1111-1111-111111111111",
            "default-template",
            "eval",
            "search_retrieval",
            "44444444-4444-4444-4444-444444444444",
            {"sample_size": "all"},
            {"reason": "template-default"},
            True,
        )
        golden_row = ("44444444-4444-4444-4444-444444444444",)
        insert_row = ("55555555-5555-5555-5555-555555555555", "pending", "2026-02-24T00:00:00Z")
        return _FakeConn(_FakeCursor(fetchone_values=[agent_row, template_row, golden_row, insert_row]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    monkeypatch.setattr(api_main, "_record_activity_event", lambda **_kwargs: None)
    try:
        response = client.post(
            "/api/eval/runs",
            json={
                "org_id": "11111111-1111-1111-1111-111111111111",
                "agent_id": "22222222-2222-2222-2222-222222222222",
                "template_id": "33333333-3333-3333-3333-333333333333",
                "name": "templated-run",
                "type": "eval",
                "config": {"judge_mode": "deterministic"},
                "design_context": {"source": "test"},
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 202
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["status"] == "pending"


def test_create_eval_run_with_template_run_type_mismatch(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k-run-template-mismatch",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }

    def _fake_get_conn() -> _FakeConn:
        agent_row = ("22222222-2222-2222-2222-222222222222", "11111111-1111-1111-1111-111111111111", "search_retrieval")
        template_row = (
            "33333333-3333-3333-3333-333333333333",
            "11111111-1111-1111-1111-111111111111",
            "calibration-template",
            "calibration",
            "search_retrieval",
            None,
            {},
            {},
            True,
        )
        return _FakeConn(_FakeCursor(fetchone_values=[agent_row, template_row]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.post(
            "/api/eval/runs",
            json={
                "org_id": "11111111-1111-1111-1111-111111111111",
                "agent_id": "22222222-2222-2222-2222-222222222222",
                "template_id": "33333333-3333-3333-3333-333333333333",
                "name": "templated-run",
                "type": "eval",
                "config": {},
                "design_context": {},
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 400
    payload = response.json()
    _assert_error_envelope(payload, "EVAL_TEMPLATE_MISMATCH")


def test_agent_invoke_contract_validate_success(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k-contract",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }

    def _fake_get_conn() -> _FakeConn:
        row = (
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "11111111-1111-1111-1111-111111111111",
            "https://agent.example.com/invoke",
        )
        return _FakeConn(_FakeCursor(fetchone_values=[row]))

    def _fake_validate(**_kwargs: Any) -> Dict[str, Any]:
        return {
            "valid": True,
            "issues": [],
            "endpoint": "https://agent.example.com/invoke",
            "status_code": 200,
            "latency_ms": 45.2,
            "content_type": "application/json",
            "response_preview": "{\"response\":\"ok\"}",
            "request_hash": "reqhash",
            "response_hash": "resphash",
            "response_key_used": "response",
            "source_key_used": "sources",
            "extracted_response": "ok",
            "extracted_sources": "doc-a",
        }

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    monkeypatch.setattr(api_main, "validate_agent_invoke_contract", _fake_validate)
    try:
        response = client.post(
            "/api/agents/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/invoke-contract/validate",
            json={"sample_input": "ping"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["valid"] is True
    assert payload["data"]["response_key_used"] == "response"


def test_agent_invoke_contract_validate_cross_org_forbidden(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k-contract-scope",
        "org_id": "99999999-9999-9999-9999-999999999999",
        "name": "member-key",
        "role": "member",
    }

    def _fake_get_conn() -> _FakeConn:
        row = (
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "11111111-1111-1111-1111-111111111111",
            "https://agent.example.com/invoke",
        )
        return _FakeConn(_FakeCursor(fetchone_values=[row]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.post(
            "/api/agents/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/invoke-contract/validate",
            json={"sample_input": "ping"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 403
    _assert_error_envelope(response.json(), "FORBIDDEN_ORG_SCOPE")


def test_golden_set_upload_file_success(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k-upload-file",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }

    def _fake_persist(_payload: Any) -> Dict[str, Any]:
        return {
            "golden_set_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "name": "File Upload GS",
            "case_count": 1,
            "case_ids": ["bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"],
            "created_at": "2026-02-24T00:00:00Z",
        }

    monkeypatch.setattr(api_main, "_persist_golden_set_payload", _fake_persist)
    csv_b64 = base64.b64encode(b"input,expected_output\nWhat is policy?,Hybrid policy\n").decode("utf-8")
    data = {
        "org_id": "11111111-1111-1111-1111-111111111111",
        "agent_id": "22222222-2222-2222-2222-222222222222",
        "name": "File Upload GS",
        "generation_method": "manual",
        "filename": "cases.csv",
        "file_content_base64": csv_b64,
    }
    try:
        response = client.post("/api/golden-sets/upload-file", json=data)
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 201
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["validation_report"]["accepted_rows"] == 1
    assert payload["data"]["validation_report"]["rejected_rows"] == 0


def test_golden_set_upload_file_validation_error(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k-upload-file-invalid",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }
    csv_b64 = base64.b64encode(b"input,difficulty\n,super-hard\n").decode("utf-8")
    data = {
        "org_id": "11111111-1111-1111-1111-111111111111",
        "agent_id": "22222222-2222-2222-2222-222222222222",
        "name": "File Upload GS",
        "generation_method": "manual",
        "filename": "cases.csv",
        "file_content_base64": csv_b64,
    }
    try:
        response = client.post("/api/golden-sets/upload-file", json=data)
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 400
    payload = response.json()
    _assert_error_envelope(payload, "GOLDEN_SET_FILE_VALIDATION_FAILED")


def test_list_golden_set_cases_success(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_viewer] = lambda: {
        "key_id": "k-gs-cases-list",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "viewer-key",
        "role": "viewer",
    }

    case_row = (
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "What is policy?",
        "Hybrid policy",
        "HR Policy 2026",
        "answer",
        None,
        "easy",
        "retrieval",
        "straightforward",
        "hr",
        "verified",
        None,
        "2026-02-24",
        2,
        True,
        None,
        "2026-02-24T00:00:00Z",
        "reviewed",
        "2026-02-24T00:00:00Z",
    )

    def _fake_get_conn() -> _FakeConn:
        gs_row = ("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "11111111-1111-1111-1111-111111111111")
        return _FakeConn(_FakeCursor(fetchone_values=[gs_row, (1,)], fetchall_values=[[case_row]]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.get("/api/golden-sets/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/cases")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["count"] == 1
    assert payload["data"]["items"][0]["version"] == 2


def test_verify_golden_set_case_success(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }

    updated_case = (
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "What is policy?",
        "Hybrid policy",
        "HR Policy 2026",
        "answer",
        None,
        "easy",
        "retrieval",
        "straightforward",
        "hr",
        "verified",
        None,
        "2026-02-24",
        1,
        True,
        None,
        "2026-02-24T00:10:00Z",
        "verified by reviewer",
        "2026-02-24T00:00:00Z",
    )

    def _fake_get_conn() -> _FakeConn:
        gs_row = ("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222")
        current_case = ("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "unverified")
        return _FakeConn(_FakeCursor(fetchone_values=[gs_row, current_case, updated_case]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    monkeypatch.setattr(api_main, "_record_activity_event", lambda **_kwargs: None)
    try:
        response = client.patch(
            "/api/golden-sets/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/cases/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/verify",
            json={"verification_status": "verified", "notes": "verified by reviewer"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["verification_status"] == "verified"


def test_supersede_golden_set_case_success(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }

    new_case_row = (
        "cccccccc-cccc-cccc-cccc-cccccccccccc",
        "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "What is policy v2?",
        "Hybrid policy updated",
        "HR Policy 2027",
        "answer",
        None,
        "easy",
        "retrieval",
        "straightforward",
        "hr",
        "unverified",
        None,
        None,
        2,
        True,
        None,
        None,
        None,
        "2026-02-24T00:20:00Z",
    )

    def _fake_get_conn() -> _FakeConn:
        gs_row = ("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222")
        current_case = ("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "verified", 1)
        new_case_id = ("cccccccc-cccc-cccc-cccc-cccccccccccc",)
        return _FakeConn(_FakeCursor(fetchone_values=[gs_row, current_case, new_case_id, new_case_row]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    monkeypatch.setattr(api_main, "_record_activity_event", lambda **_kwargs: None)
    try:
        response = client.post(
            "/api/golden-sets/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/cases/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/supersede",
            json={
                "input": "What is policy v2?",
                "expected_output": "Hybrid policy updated",
                "acceptable_sources": "HR Policy 2027",
                "evaluation_mode": "answer",
                "difficulty": "easy",
                "capability": "retrieval",
                "scenario_type": "straightforward",
                "domain": "hr",
                "verification_status": "unverified",
                "notes": "superseded by policy refresh",
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["previous_case_id"] == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    assert payload["data"]["new_case"]["version"] == 2


def test_eval_run_start_enqueues_job(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k-queue",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }

    def _fake_get_conn() -> _FakeConn:
        run_row = (
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "11111111-1111-1111-1111-111111111111",
            "22222222-2222-2222-2222-222222222222",
            "33333333-3333-3333-3333-333333333333",
            "eval",
            "pending",
            {},
        )
        return _FakeConn(_FakeCursor(fetchone_values=[run_row]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    monkeypatch.setattr(api_main, "_enforce_calibration_gate", lambda **_kwargs: None)
    monkeypatch.setattr(api_main, "_enforce_golden_set_quality_gate", lambda **_kwargs: None)
    monkeypatch.setattr(api_main, "_enforce_configured_gates", lambda **_kwargs: None)
    monkeypatch.setattr(
        api_main,
        "_enqueue_eval_run_job",
        lambda run_id, org_id, max_attempts=3: {
            "job_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "run_id": run_id,
            "status": "queued",
            "enqueued": True,
            "attempt_count": 0,
            "max_attempts": max_attempts,
            "created_at": "2026-02-24T00:00:00Z",
        },
    )
    monkeypatch.setattr(api_main, "_record_activity_event", lambda **_kwargs: None)
    try:
        response = client.post("/api/eval/runs/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/start")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 202
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["status"] == "queued"
    assert payload["data"]["enqueued"] is True


def test_eval_run_start_returns_deduped_when_active_job_exists(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k-queue-dedupe",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }

    def _fake_get_conn() -> _FakeConn:
        run_row = (
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "11111111-1111-1111-1111-111111111111",
            "22222222-2222-2222-2222-222222222222",
            "33333333-3333-3333-3333-333333333333",
            "eval",
            "pending",
            {},
        )
        return _FakeConn(_FakeCursor(fetchone_values=[run_row]))

    captured_events: list[Dict[str, Any]] = []

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    monkeypatch.setattr(api_main, "_enforce_calibration_gate", lambda **_kwargs: None)
    monkeypatch.setattr(api_main, "_enforce_golden_set_quality_gate", lambda **_kwargs: None)
    monkeypatch.setattr(api_main, "_enforce_configured_gates", lambda **_kwargs: None)
    monkeypatch.setattr(
        api_main,
        "_enqueue_eval_run_job",
        lambda run_id, org_id, max_attempts=3: {
            "job_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "run_id": run_id,
            "status": "running",
            "enqueued": False,
            "attempt_count": 1,
            "max_attempts": max_attempts,
            "created_at": "2026-02-24T00:00:00Z",
        },
    )
    monkeypatch.setattr(api_main, "_record_activity_event", lambda **kwargs: captured_events.append(kwargs))
    try:
        response = client.post("/api/eval/runs/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/start")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 202
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["enqueued"] is False
    assert payload["data"]["status"] == "running"
    assert captured_events
    assert captured_events[0]["event_type"] == "run_queue_deduplicated"


def test_eval_run_start_reopens_failed_run(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k-queue-reopen",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }

    def _fake_get_conn() -> _FakeConn:
        run_row = (
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "11111111-1111-1111-1111-111111111111",
            "22222222-2222-2222-2222-222222222222",
            "33333333-3333-3333-3333-333333333333",
            "eval",
            "failed",
            {},
        )
        return _FakeConn(_FakeCursor(fetchone_values=[run_row]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    monkeypatch.setattr(api_main, "_enforce_calibration_gate", lambda **_kwargs: None)
    monkeypatch.setattr(api_main, "_enforce_golden_set_quality_gate", lambda **_kwargs: None)
    monkeypatch.setattr(api_main, "_enforce_configured_gates", lambda **_kwargs: None)
    monkeypatch.setattr(
        api_main,
        "_enqueue_eval_run_job",
        lambda run_id, org_id, max_attempts=3: {
            "job_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "run_id": run_id,
            "status": "queued",
            "enqueued": True,
            "attempt_count": 0,
            "max_attempts": max_attempts,
            "created_at": "2026-02-24T00:00:00Z",
        },
    )
    monkeypatch.setattr(api_main, "_record_activity_event", lambda **_kwargs: None)
    try:
        response = client.post("/api/eval/runs/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/start")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 202
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["status"] == "queued"


def test_eval_run_cancel_returns_cancelled(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k-queue-cancel",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }

    def _fake_get_conn() -> _FakeConn:
        run_row = (
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "11111111-1111-1111-1111-111111111111",
            "22222222-2222-2222-2222-222222222222",
        )
        return _FakeConn(_FakeCursor(fetchone_values=[run_row]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    monkeypatch.setattr(
        api_main,
        "_cancel_eval_run_job",
        lambda run_id: {"cancelled": True, "job_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "status": "cancelled"},
    )
    monkeypatch.setattr(api_main, "_record_activity_event", lambda **_kwargs: None)
    try:
        response = client.post("/api/eval/runs/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/cancel")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["cancelled"] is True


def test_eval_run_execute_rejects_terminal_status(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k-exec-invalid-status",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }

    run_row = (
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
        "33333333-3333-3333-3333-333333333333",
        "eval",
        "completed",
        {},
    )

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[run_row]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    monkeypatch.setattr(api_main, "_enforce_calibration_gate", lambda **_kwargs: None)
    monkeypatch.setattr(api_main, "_enforce_golden_set_quality_gate", lambda **_kwargs: None)
    monkeypatch.setattr(api_main, "_enforce_configured_gates", lambda **_kwargs: None)
    try:
        response = client.post("/api/eval/runs/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/execute")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 409
    _assert_error_envelope(response.json(), "EVAL_RUN_STATUS_TRANSITION_INVALID")


def test_eval_run_execute_returns_cancelled_when_cancel_requested(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k-exec-cancel",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }

    run_row = (
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
        "33333333-3333-3333-3333-333333333333",
        "eval",
        "pending",
        {},
    )
    agent_row = (None, "search_retrieval", None)
    profile_row = ("44444444-4444-4444-4444-444444444444", "answer", [])
    cancelled_update_row = ("2026-02-24T00:00:00Z",)
    call_count = {"value": 0}

    def _fake_get_conn() -> _FakeConn:
        call_count["value"] += 1
        if call_count["value"] == 1:
            return _FakeConn(_FakeCursor(fetchone_values=[run_row, agent_row, profile_row]))
        return _FakeConn(_FakeCursor(fetchone_values=[cancelled_update_row]))

    class _StubJudge:
        def score_answer_case(self, **_kwargs: Any) -> Dict[str, Any]:
            return {
                "answer_correct": "yes",
                "source_correct": "yes",
                "response_quality": "good",
                "reasoning": "ok",
            }

        def score_criteria_case(self, **_kwargs: Any) -> Dict[str, Any]:
            return {
                "criteria_results": [],
                "dimension_scores": {},
                "overall_score": "good",
                "reasoning": "ok",
            }

    class _StubExecutor:
        def execute_case(self, **_kwargs: Any) -> Dict[str, Any]:
            return {"actual_response": "x", "actual_sources": "y", "trace": {}}

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    monkeypatch.setattr(api_main, "get_judge_service", lambda **_kwargs: _StubJudge())
    monkeypatch.setattr(api_main, "get_execution_service", lambda **_kwargs: _StubExecutor())
    monkeypatch.setattr(api_main, "parse_profile_contract", lambda **_kwargs: {})
    monkeypatch.setattr(api_main, "_is_eval_run_cancel_requested", lambda _run_id: True)
    monkeypatch.setattr(api_main, "_enforce_calibration_gate", lambda **_kwargs: None)
    monkeypatch.setattr(api_main, "_enforce_golden_set_quality_gate", lambda **_kwargs: None)
    monkeypatch.setattr(api_main, "_enforce_configured_gates", lambda **_kwargs: None)
    try:
        response = client.post("/api/eval/runs/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/execute")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["status"] == "cancelled"
    assert payload["data"]["case_count"] == 0


def test_notification_outbox_drain_admin_endpoint(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-outbox",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }
    monkeypatch.setattr(
        api_main,
        "_drain_notification_outbox_batch",
        lambda limit=20: {"picked": int(limit), "sent": 2, "failed": 1, "dead": 0},
    )
    try:
        response = client.post("/api/system/notifications/outbox/drain?limit=3")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["picked"] == 3
    assert payload["data"]["sent"] == 2
    assert payload["data"]["failed"] == 1
    assert payload["data"]["dead"] == 0


def test_notification_outbox_list_admin_endpoint(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-outbox-list",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }

    def _fake_get_conn() -> _FakeConn:
        rows = [
            (
                "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "11111111-1111-1111-1111-111111111111",
                "22222222-2222-2222-2222-222222222222",
                "regression_detected",
                "pending",
                1,
                5,
                "2026-02-24T00:05:00Z",
                None,
                "HTTP 500",
                "req-123",
                "2026-02-24T00:00:00Z",
                "2026-02-24T00:01:00Z",
            )
        ]
        return _FakeConn(_FakeCursor(fetchone_values=[(1,)], fetchall_values=[rows]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.get("/api/system/notifications/outbox?status=pending&event_type=regression_detected")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["count"] == 1
    assert payload["data"]["total_count"] == 1
    assert payload["data"]["items"][0]["status"] == "pending"
    assert payload["data"]["items"][0]["event_type"] == "regression_detected"


def test_notification_outbox_retry_admin_endpoint(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-outbox-retry",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }

    def _fake_get_conn() -> _FakeConn:
        selected = (
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "11111111-1111-1111-1111-111111111111",
            "dead",
            5,
            5,
            "2026-02-24T00:05:00Z",
        )
        updated = (
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "11111111-1111-1111-1111-111111111111",
            "pending",
            0,
            5,
            "2026-02-24T00:06:00Z",
        )
        return _FakeConn(_FakeCursor(fetchone_values=[selected, updated]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.post("/api/system/notifications/outbox/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/retry")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["status"] == "pending"
    assert payload["data"]["attempt_count"] == 0


def test_notification_outbox_retry_rejects_sending(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-outbox-retry-busy",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }

    def _fake_get_conn() -> _FakeConn:
        selected = (
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "11111111-1111-1111-1111-111111111111",
            "sending",
            2,
            5,
            "2026-02-24T00:05:00Z",
        )
        return _FakeConn(_FakeCursor(fetchone_values=[selected]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.post("/api/system/notifications/outbox/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/retry")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 409
    _assert_error_envelope(response.json(), "NOTIFICATION_OUTBOX_IN_PROGRESS")


def test_notification_outbox_dead_letter_summary_endpoint(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-outbox-summary",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(
            _FakeCursor(
                fetchone_values=[(4, 3600)],
                fetchall_values=[
                    [("HTTP 500", 3), ("(unknown)", 1)],
                    [("lt_1h", 1), ("h_1_to_24", 2), ("d_1_to_7", 1)],
                ],
            )
        )

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.get("/api/system/notifications/outbox/dead-letter-summary?event_type=regression_detected")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["total_dead"] == 4
    assert payload["data"]["oldest_dead_age_seconds"] == 3600
    assert payload["data"]["reason_groups"][0]["reason"] == "HTTP 500"
    assert payload["data"]["reason_groups"][0]["count"] == 3
    assert payload["data"]["age_buckets"][0]["bucket"] == "lt_1h"
    assert payload["data"]["age_buckets"][0]["count"] == 1


def test_notification_outbox_dead_letter_summary_enforces_org_scope() -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-outbox-summary-scoped",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "scoped-admin-key",
        "role": "admin",
    }
    try:
        response = client.get(
            "/api/system/notifications/outbox/dead-letter-summary"
            "?org_id=22222222-2222-2222-2222-222222222222"
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 403
    _assert_error_envelope(response.json(), "FORBIDDEN_ORG_SCOPE")


def test_queue_stats_returns_counts(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-queue-stats",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }

    def _fake_get_conn() -> _FakeConn:
        counts_row = (3, 1, 10, 2, 1, 2)
        oldest_row = (120,)
        return _FakeConn(_FakeCursor(fetchone_values=[counts_row, oldest_row]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.get("/api/system/queue/stats")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["queued_count"] == 3
    assert payload["data"]["running_count"] == 1
    assert payload["data"]["retry_backlog_count"] == 2
    assert payload["data"]["oldest_queued_age_seconds"] == 120


def test_queue_stats_enforces_org_scope() -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-scoped-queue-stats",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "scoped-admin-key",
        "role": "admin",
    }
    try:
        response = client.get("/api/system/queue/stats?org_id=22222222-2222-2222-2222-222222222222")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 403
    _assert_error_envelope(response.json(), "FORBIDDEN_ORG_SCOPE")


def test_list_failed_queue_jobs_returns_items(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-failed-jobs",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }

    failed_row = (
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
        "run-name",
        "failed",
        "failed",
        3,
        3,
        "boom",
        "2026-02-24T00:00:00Z",
        "2026-02-24T00:10:00Z",
        "2026-02-24T00:10:00Z",
    )

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchall_values=[[failed_row]], fetchone_values=[(1,)]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.get("/api/system/queue/jobs/failed")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["count"] == 1
    assert payload["data"]["items"][0]["job_status"] == "failed"


def test_retry_queue_job_happy_path(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-retry-job",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }

    def _fake_get_conn() -> _FakeConn:
        first = ("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "11111111-1111-1111-1111-111111111111", "failed", 3, 3)
        updated = ("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "queued", 3, 3, None, "11111111-1111-1111-1111-111111111111")
        return _FakeConn(_FakeCursor(fetchone_values=[first, updated, ("22222222-2222-2222-2222-222222222222", "failed")]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    monkeypatch.setattr(api_main, "_record_activity_event", lambda **_kwargs: None)
    try:
        response = client.post(
            "/api/system/queue/jobs/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/retry",
            headers={"Idempotency-Key": "idem-retry-1"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["status"] == "queued"


def test_cancel_queue_job_non_active_returns_not_cancelled(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-cancel-job",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }

    def _fake_get_conn() -> _FakeConn:
        existing = ("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb", "11111111-1111-1111-1111-111111111111", "failed")
        return _FakeConn(_FakeCursor(fetchone_values=[existing]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.post(
            "/api/system/queue/jobs/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/cancel",
            headers={"Idempotency-Key": "idem-cancel-1"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["cancelled"] is False


def test_queue_admin_mutations_require_idempotency_key() -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-idem-required",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }
    try:
        retry_resp = client.post("/api/system/queue/jobs/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/retry")
        cancel_resp = client.post("/api/system/queue/jobs/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/cancel")
        replay_resp = client.post("/api/system/queue/jobs/failed/replay")
    finally:
        app.dependency_overrides.clear()

    assert retry_resp.status_code == 422
    _assert_error_envelope(retry_resp.json(), "VALIDATION_ERROR")
    assert cancel_resp.status_code == 422
    _assert_error_envelope(cancel_resp.json(), "VALIDATION_ERROR")
    assert replay_resp.status_code == 422
    _assert_error_envelope(replay_resp.json(), "VALIDATION_ERROR")


def test_replay_failed_queue_jobs_happy_path(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-bulk-replay",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }

    selected_rows = [
        (
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "11111111-1111-1111-1111-111111111111",
            3,
            3,
            "22222222-2222-2222-2222-222222222222",
        ),
        (
            "cccccccc-cccc-cccc-cccc-cccccccccccc",
            "dddddddd-dddd-dddd-dddd-dddddddddddd",
            "11111111-1111-1111-1111-111111111111",
            2,
            3,
            "33333333-3333-3333-3333-333333333333",
        ),
    ]
    replayed_rows = [
        (
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "11111111-1111-1111-1111-111111111111",
            3,
            3,
            None,
        ),
        (
            "cccccccc-cccc-cccc-cccc-cccccccccccc",
            "dddddddd-dddd-dddd-dddd-dddddddddddd",
            "11111111-1111-1111-1111-111111111111",
            2,
            3,
            None,
        ),
    ]

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchall_values=[selected_rows, replayed_rows]))

    events: list[Dict[str, Any]] = []
    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    monkeypatch.setattr(api_main, "_record_activity_event", lambda **kwargs: events.append(kwargs))
    try:
        response = client.post(
            "/api/system/queue/jobs/failed/replay?limit=2&delay_seconds=5",
            headers={"Idempotency-Key": "idem-replay-1"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["dry_run"] is False
    assert payload["data"]["selected_count"] == 2
    assert payload["data"]["replayed_count"] == 2
    assert len(payload["data"]["job_ids"]) == 2
    assert len(events) == 2
    assert events[0]["event_type"] == "run_requeued_bulk"


def test_replay_failed_queue_jobs_dry_run(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-bulk-replay-dry",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }

    selected_rows = [
        (
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "11111111-1111-1111-1111-111111111111",
            3,
            3,
            "22222222-2222-2222-2222-222222222222",
        )
    ]

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchall_values=[selected_rows]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    monkeypatch.setattr(api_main, "_record_activity_event", lambda **_kwargs: None)
    try:
        response = client.post(
            "/api/system/queue/jobs/failed/replay?dry_run=true",
            headers={"Idempotency-Key": "idem-replay-dry-1"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["dry_run"] is True
    assert payload["data"]["selected_count"] == 1
    assert payload["data"]["replayed_count"] == 0
    assert payload["data"]["job_ids"][0] == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"


def test_replay_failed_queue_jobs_enforces_org_scope() -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-bulk-replay-scoped",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "scoped-admin-key",
        "role": "admin",
    }
    try:
        response = client.post(
            "/api/system/queue/jobs/failed/replay?org_id=22222222-2222-2222-2222-222222222222",
            headers={"Idempotency-Key": "idem-replay-scope-1"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 403
    _assert_error_envelope(response.json(), "FORBIDDEN_ORG_SCOPE")


def test_reap_stale_queue_jobs_happy_path(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-reap-stale",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }

    selected_rows = [
        (
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "11111111-1111-1111-1111-111111111111",
            "22222222-2222-2222-2222-222222222222",
            "stale_heartbeat",
        )
    ]
    reaped_rows = [
        (
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "11111111-1111-1111-1111-111111111111",
            "failed",
        )
    ]

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchall_values=[selected_rows, reaped_rows]))

    events: list[Dict[str, Any]] = []
    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    monkeypatch.setattr(api_main, "_record_activity_event", lambda **kwargs: events.append(kwargs))
    try:
        response = client.post(
            "/api/system/queue/jobs/reap-stale?limit=1&stale_heartbeat_seconds=60&max_runtime_seconds=900",
            headers={"Idempotency-Key": "idem-reap-1"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["dry_run"] is False
    assert payload["data"]["selected_count"] == 1
    assert payload["data"]["reaped_count"] == 1
    assert payload["data"]["items"][0]["reason"] == "stale_heartbeat"
    assert events and events[0]["event_type"] == "run_reaped"


def test_reap_stale_queue_jobs_dry_run(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-reap-stale-dry",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }

    selected_rows = [
        (
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "11111111-1111-1111-1111-111111111111",
            "22222222-2222-2222-2222-222222222222",
            "runtime_exceeded",
        )
    ]

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchall_values=[selected_rows]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    monkeypatch.setattr(api_main, "_record_activity_event", lambda **_kwargs: None)
    try:
        response = client.post(
            "/api/system/queue/jobs/reap-stale?dry_run=true&limit=1",
            headers={"Idempotency-Key": "idem-reap-dry-1"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["dry_run"] is True
    assert payload["data"]["selected_count"] == 1
    assert payload["data"]["reaped_count"] == 0
    assert payload["data"]["items"][0]["reason"] == "runtime_exceeded"


def test_reap_stale_queue_jobs_enforces_org_scope() -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-reap-stale-scope",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "scoped-admin-key",
        "role": "admin",
    }
    try:
        response = client.post(
            "/api/system/queue/jobs/reap-stale?org_id=22222222-2222-2222-2222-222222222222",
            headers={"Idempotency-Key": "idem-reap-scope-1"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 403
    _assert_error_envelope(response.json(), "FORBIDDEN_ORG_SCOPE")


def test_reap_stale_queue_jobs_requires_idempotency_key() -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-reap-idem",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }
    try:
        response = client.post("/api/system/queue/jobs/reap-stale")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 422
    _assert_error_envelope(response.json(), "VALIDATION_ERROR")


def test_prune_terminal_queue_jobs_happy_path(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-prune",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }

    selected_rows = [
        ("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",),
        ("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",),
    ]
    deleted_rows = [
        ("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",),
        ("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",),
    ]

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchall_values=[selected_rows, deleted_rows]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    response = client.post(
        "/api/system/queue/jobs/prune?retention_days=14&limit=2",
        headers={"Idempotency-Key": "idem-prune-1"},
    )

    app.dependency_overrides.clear()
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["dry_run"] is False
    assert payload["data"]["selected_count"] == 2
    assert payload["data"]["deleted_count"] == 2


def test_prune_terminal_queue_jobs_dry_run(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-prune-dry",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }

    selected_rows = [("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",)]

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchall_values=[selected_rows]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    response = client.post(
        "/api/system/queue/jobs/prune?dry_run=true&retention_days=30&limit=1",
        headers={"Idempotency-Key": "idem-prune-dry-1"},
    )

    app.dependency_overrides.clear()
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["dry_run"] is True
    assert payload["data"]["selected_count"] == 1
    assert payload["data"]["deleted_count"] == 0


def test_prune_terminal_queue_jobs_enforces_org_scope() -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-prune-scope",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "scoped-admin-key",
        "role": "admin",
    }
    try:
        response = client.post(
            "/api/system/queue/jobs/prune?org_id=22222222-2222-2222-2222-222222222222",
            headers={"Idempotency-Key": "idem-prune-scope-1"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 403
    _assert_error_envelope(response.json(), "FORBIDDEN_ORG_SCOPE")


def test_prune_terminal_queue_jobs_requires_idempotency_key() -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-prune-idem",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }
    try:
        response = client.post("/api/system/queue/jobs/prune")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 422
    _assert_error_envelope(response.json(), "VALIDATION_ERROR")


def test_get_queue_maintenance_policy_returns_default_when_missing(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-policy-default",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[None]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.get("/api/system/queue/maintenance-policy?org_id=11111111-1111-1111-1111-111111111111")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["org_id"] == "11111111-1111-1111-1111-111111111111"
    assert payload["data"]["stale_heartbeat_seconds"] == 60
    assert payload["data"]["max_runtime_seconds"] == 900
    assert payload["data"]["retention_days"] == 14


def test_get_queue_maintenance_policy_enforces_org_scope() -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-policy-scope",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "scoped-admin-key",
        "role": "admin",
    }
    try:
        response = client.get("/api/system/queue/maintenance-policy?org_id=22222222-2222-2222-2222-222222222222")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 403
    _assert_error_envelope(response.json(), "FORBIDDEN_ORG_SCOPE")


def test_upsert_queue_maintenance_policy_happy_path(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }

    upsert_row = (
        "11111111-1111-1111-1111-111111111111",
        90,
        1800,
        21,
        250,
        750,
        True,
        0.8,
        0.95,
        120,
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "2026-02-24T00:00:00Z",
        "2026-02-24T00:00:00Z",
    )

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[("11111111-1111-1111-1111-111111111111",), upsert_row]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    response = client.post(
        "/api/system/queue/maintenance-policy",
        json={
            "org_id": "11111111-1111-1111-1111-111111111111",
            "stale_heartbeat_seconds": 90,
            "max_runtime_seconds": 1800,
            "retention_days": 21,
            "reap_limit": 250,
            "prune_limit": 750,
            "schedule_alert_enabled": True,
            "schedule_alert_dedupe_hit_rate_threshold": 0.8,
            "schedule_alert_min_execution_success_rate": 0.95,
            "schedule_alert_cooldown_minutes": 120,
        },
    )

    app.dependency_overrides.clear()
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["stale_heartbeat_seconds"] == 90
    assert payload["data"]["max_runtime_seconds"] == 1800
    assert payload["data"]["retention_days"] == 21
    assert payload["data"]["reap_limit"] == 250
    assert payload["data"]["prune_limit"] == 750
    assert payload["data"]["schedule_alert_enabled"] is True
    assert payload["data"]["schedule_alert_dedupe_hit_rate_threshold"] == 0.8
    assert payload["data"]["schedule_alert_min_execution_success_rate"] == 0.95
    assert payload["data"]["schedule_alert_cooldown_minutes"] == 120


def test_reap_stale_queue_jobs_uses_policy_defaults_when_params_omitted(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-reap-policy-defaults",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }

    policy_row = (
        "11111111-1111-1111-1111-111111111111",
        120,
        2400,
        30,
        300,
        900,
        False,
        0.7,
        0.9,
        60,
        None,
        "2026-02-24T00:00:00Z",
        "2026-02-24T00:00:00Z",
    )
    selected_rows = []

    calls = {"count": 0}

    def _fake_get_conn() -> _FakeConn:
        calls["count"] += 1
        if calls["count"] == 1:
            return _FakeConn(_FakeCursor(fetchone_values=[policy_row]))
        return _FakeConn(_FakeCursor(fetchall_values=[selected_rows]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    monkeypatch.setattr(api_main, "_record_activity_event", lambda **_kwargs: None)
    try:
        response = client.post(
            "/api/system/queue/jobs/reap-stale?org_id=11111111-1111-1111-1111-111111111111&dry_run=true",
            headers={"Idempotency-Key": "idem-reap-policy-defaults-1"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["stale_heartbeat_seconds"] == 120
    assert payload["data"]["max_runtime_seconds"] == 2400
    assert payload["data"]["requested_limit"] == 300


def test_run_queue_maintenance_happy_path(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-maint-run",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }
    monkeypatch.setattr(api_main, "_get_queue_maintenance_policy", lambda _org_id: None)
    insert_row = ("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "2026-02-24T00:00:00Z")

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[insert_row]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    monkeypatch.setattr(
        api_main,
        "reap_stale_queue_jobs",
        lambda **kwargs: {
            "ok": True,
            "data": {
                "org_id": str(kwargs["org_id"]),
                "dry_run": bool(kwargs["dry_run"]),
                "stale_heartbeat_seconds": int(kwargs["stale_heartbeat_seconds"]),
                "max_runtime_seconds": int(kwargs["max_runtime_seconds"]),
                "requested_limit": int(kwargs["limit"]),
                "selected_count": 0,
                "reaped_count": 0,
                "items": [],
            },
        },
    )
    monkeypatch.setattr(
        api_main,
        "prune_terminal_queue_jobs",
        lambda **kwargs: {
            "ok": True,
            "data": {
                "org_id": str(kwargs["org_id"]),
                "dry_run": bool(kwargs["dry_run"]),
                "retention_days": int(kwargs["retention_days"]),
                "requested_limit": int(kwargs["limit"]),
                "selected_count": 0,
                "deleted_count": 0,
                "job_ids": [],
            },
        },
    )
    try:
        response = client.post(
            "/api/system/queue/maintenance/run?org_id=11111111-1111-1111-1111-111111111111&dry_run=true",
            headers={"Idempotency-Key": "idem-maint-run-1"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["run_id"] == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    assert payload["data"]["status"] == "completed"
    assert payload["data"]["org_id"] == "11111111-1111-1111-1111-111111111111"
    assert payload["data"]["dry_run"] is True
    assert payload["data"]["policy"]["stale_heartbeat_seconds"] == 60
    assert payload["data"]["policy"]["retention_days"] == 14
    assert payload["data"]["reap"]["requested_limit"] == 100
    assert payload["data"]["prune"]["requested_limit"] == 500


def test_run_queue_maintenance_enforces_org_scope() -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-maint-run-scope",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "scoped-admin-key",
        "role": "admin",
    }
    try:
        response = client.post(
            "/api/system/queue/maintenance/run?org_id=22222222-2222-2222-2222-222222222222",
            headers={"Idempotency-Key": "idem-maint-run-scope-1"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 403
    _assert_error_envelope(response.json(), "FORBIDDEN_ORG_SCOPE")


def test_run_queue_maintenance_requires_idempotency_key() -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-maint-run-idem",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }
    try:
        response = client.post("/api/system/queue/maintenance/run?org_id=11111111-1111-1111-1111-111111111111")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 422
    _assert_error_envelope(response.json(), "VALIDATION_ERROR")


def test_run_queue_maintenance_rejects_concurrent_active_run(monkeypatch) -> None:
    class _InsertConflictCursor(_FakeCursor):
        def execute(self, _sql: str, _params: Any = None) -> None:
            raise Exception('duplicate key value violates unique constraint "idx_queue_maintenance_runs_one_running_per_org"')

    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-maint-run-conflict",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }
    monkeypatch.setattr(api_main, "_get_queue_maintenance_policy", lambda _org_id: None)
    monkeypatch.setattr(api_main, "get_conn", lambda: _FakeConn(_InsertConflictCursor()))
    try:
        response = client.post(
            "/api/system/queue/maintenance/run?org_id=11111111-1111-1111-1111-111111111111",
            headers={"Idempotency-Key": "idem-maint-run-conflict-1"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 409
    _assert_error_envelope(response.json(), "QUEUE_MAINTENANCE_ALREADY_RUNNING")


def test_list_queue_maintenance_runs_happy_path(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-maint-list",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }
    rows = [
        (
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "11111111-1111-1111-1111-111111111111",
            True,
            "completed",
            None,
            321,
            "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
            "2026-02-24T00:00:00Z",
            "2026-02-24T00:00:01Z",
        )
    ]

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchall_values=[rows], fetchone_values=[(1,)]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.get("/api/system/queue/maintenance/runs?org_id=11111111-1111-1111-1111-111111111111")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["count"] == 1
    assert payload["data"]["items"][0]["status"] == "completed"


def test_get_queue_maintenance_run_detail_happy_path(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-maint-detail",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }
    row = (
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "11111111-1111-1111-1111-111111111111",
        True,
        "completed",
        {"retention_days": 14},
        {"selected_count": 0, "reaped_count": 0},
        {"selected_count": 0, "deleted_count": 0},
        None,
        100,
        "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "2026-02-24T00:00:00Z",
        "2026-02-24T00:00:01Z",
        "2026-02-24T00:00:00Z",
        "2026-02-24T00:00:01Z",
    )

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[row]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.get("/api/system/queue/maintenance/runs/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["id"] == "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    assert payload["data"]["status"] == "completed"


def test_get_queue_maintenance_run_detail_not_found(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-maint-detail-missing",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[None]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.get("/api/system/queue/maintenance/runs/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 404
    _assert_error_envelope(response.json(), "QUEUE_MAINTENANCE_RUN_NOT_FOUND")


def test_reap_stale_queue_maintenance_runs_happy_path(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-maint-reap",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }
    selected = [
        ("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "11111111-1111-1111-1111-111111111111", True, "2026-02-24T00:00:00Z", None, "running")
    ]
    reaped = [
        ("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "11111111-1111-1111-1111-111111111111", True, "2026-02-24T00:00:00Z", 1234, "failed")
    ]

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchall_values=[selected, reaped]))

    audit_calls: List[Dict[str, Any]] = []

    def _fake_record_api_audit_log(**kwargs: Any) -> None:
        audit_calls.append(kwargs)

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    monkeypatch.setattr(api_main, "_record_api_audit_log", _fake_record_api_audit_log)
    try:
        response = client.post(
            "/api/system/queue/maintenance/reap-stale-runs?org_id=11111111-1111-1111-1111-111111111111&limit=5",
            headers={"Idempotency-Key": "idem-maint-reap-1"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["selected_count"] == 1
    assert payload["data"]["reaped_count"] == 1
    assert payload["data"]["items"][0]["status"] == "failed"
    explicit_reap_audits = [c for c in audit_calls if c.get("error_code") == "MAINTENANCE_RUN_REAPED"]
    assert len(explicit_reap_audits) == 1
    assert explicit_reap_audits[0]["path"] == "/api/system/queue/maintenance/reap-stale-runs"


def test_reap_stale_queue_maintenance_runs_enforces_org_scope() -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-maint-reap-scope",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "scoped-admin-key",
        "role": "admin",
    }
    try:
        response = client.post(
            "/api/system/queue/maintenance/reap-stale-runs?org_id=22222222-2222-2222-2222-222222222222",
            headers={"Idempotency-Key": "idem-maint-reap-scope-1"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 403
    _assert_error_envelope(response.json(), "FORBIDDEN_ORG_SCOPE")


def test_reap_stale_queue_maintenance_runs_requires_idempotency_key() -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-maint-reap-idem",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }
    try:
        response = client.post("/api/system/queue/maintenance/reap-stale-runs?org_id=11111111-1111-1111-1111-111111111111")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 422
    _assert_error_envelope(response.json(), "VALIDATION_ERROR")


def test_queue_maintenance_schedule_trigger_executes_when_not_deduped(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }
    run_payload = {
        "run_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "dry_run": True,
        "status": "completed",
        "error_message": None,
        "duration_ms": 1200,
        "triggered_by_api_key_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "policy": {
            "stale_heartbeat_seconds": 60,
            "max_runtime_seconds": 900,
            "retention_days": 14,
            "reap_limit": 100,
            "prune_limit": 500,
        },
        "reap": {
            "org_id": "11111111-1111-1111-1111-111111111111",
            "dry_run": True,
            "stale_heartbeat_seconds": 60,
            "max_runtime_seconds": 900,
            "requested_limit": 100,
            "selected_count": 0,
            "reaped_count": 0,
            "items": [],
        },
        "prune": {
            "org_id": "11111111-1111-1111-1111-111111111111",
            "dry_run": True,
            "retention_days": 14,
            "requested_limit": 500,
            "selected_count": 0,
            "deleted_count": 0,
            "job_ids": [],
        },
        "started_at": "2026-02-24T00:00:00Z",
        "completed_at": "2026-02-24T00:00:01Z",
    }

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[None]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    monkeypatch.setattr(api_main, "run_queue_maintenance", lambda **_kwargs: {"ok": True, "data": run_payload})
    try:
        response = client.post(
            "/api/system/queue/maintenance/schedule-trigger",
            json={
                "org_id": "11111111-1111-1111-1111-111111111111",
                "schedule_name": "hourly-ci",
                "window_minutes": 60,
                "dry_run": True,
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["executed"] is True
    assert payload["data"]["deduped"] is False
    assert payload["data"]["run"]["run_id"] == "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"


def test_queue_maintenance_schedule_trigger_dedupes_existing_window_run(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }
    row = (
        "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "11111111-1111-1111-1111-111111111111",
        True,
        "completed",
        None,
        1200,
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        {
            "stale_heartbeat_seconds": 60,
            "max_runtime_seconds": 900,
            "retention_days": 14,
            "reap_limit": 100,
            "prune_limit": 500,
        },
        {
            "org_id": "11111111-1111-1111-1111-111111111111",
            "dry_run": True,
            "stale_heartbeat_seconds": 60,
            "max_runtime_seconds": 900,
            "requested_limit": 100,
            "selected_count": 0,
            "reaped_count": 0,
            "items": [],
        },
        {
            "org_id": "11111111-1111-1111-1111-111111111111",
            "dry_run": True,
            "retention_days": 14,
            "requested_limit": 500,
            "selected_count": 0,
            "deleted_count": 0,
            "job_ids": [],
        },
        "2026-02-24T00:00:00Z",
        "2026-02-24T00:00:01Z",
    )

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[row]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    monkeypatch.setattr(api_main, "run_queue_maintenance", lambda **_kwargs: (_ for _ in ()).throw(AssertionError("should not execute")))
    try:
        response = client.post(
            "/api/system/queue/maintenance/schedule-trigger",
            json={
                "org_id": "11111111-1111-1111-1111-111111111111",
                "schedule_name": "hourly-ci",
                "window_minutes": 60,
                "dry_run": True,
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["executed"] is False
    assert payload["data"]["deduped"] is True
    assert payload["data"]["run"]["run_id"] == "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"


def test_get_queue_maintenance_schedule_summary_happy_path(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-maint-sched-summary",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }
    trigger_stats = (10, 7, 3, "2026-02-24T10:00:00Z")
    exec_stats = (6, 1)
    latest_exec = ("2026-02-24T09:30:00Z", "completed")

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[trigger_stats, exec_stats, latest_exec]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.get(
            "/api/system/queue/maintenance/schedule-summary?org_id=11111111-1111-1111-1111-111111111111&schedule_name=hourly-ci&window_days=30"
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["org_id"] == "11111111-1111-1111-1111-111111111111"
    assert payload["data"]["schedule_name"] == "hourly-ci"
    assert payload["data"]["window_days"] == 30
    assert payload["data"]["trigger_count"] == 10
    assert payload["data"]["executed_count"] == 7
    assert payload["data"]["deduped_count"] == 3
    assert payload["data"]["dedupe_hit_rate"] == 0.3
    assert payload["data"]["successful_executions"] == 6
    assert payload["data"]["failed_executions"] == 1
    assert payload["data"]["execution_success_rate"] == 6 / 7
    assert payload["data"]["last_executed_run_status"] == "completed"


def test_get_queue_maintenance_schedule_summary_enforces_org_scope() -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-maint-sched-summary-scope",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "scoped-admin-key",
        "role": "admin",
    }
    try:
        response = client.get(
            "/api/system/queue/maintenance/schedule-summary?org_id=22222222-2222-2222-2222-222222222222&window_days=30"
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 403
    _assert_error_envelope(response.json(), "FORBIDDEN_ORG_SCOPE")


def test_notify_queue_maintenance_schedule_summary_dry_run(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }
    summary = api_main.QueueMaintenanceScheduleSummaryData(
        org_id="11111111-1111-1111-1111-111111111111",
        schedule_name="hourly-ci",
        window_days=30,
        trigger_count=10,
        executed_count=7,
        deduped_count=3,
        dedupe_hit_rate=0.3,
        successful_executions=5,
        failed_executions=2,
        execution_success_rate=5 / 7,
        last_triggered_at="2026-02-24T10:00:00Z",
        last_executed_run_started_at="2026-02-24T09:30:00Z",
        last_executed_run_status="failed",
    )
    monkeypatch.setattr(api_main, "_compute_queue_maintenance_schedule_summary_data", lambda **_kwargs: summary)
    monkeypatch.setattr(
        api_main,
        "_get_queue_maintenance_policy",
        lambda _org_id: {
            "schedule_alert_enabled": True,
            "schedule_alert_dedupe_hit_rate_threshold": 0.2,
            "schedule_alert_min_execution_success_rate": 0.9,
        },
    )
    called = {"count": 0}
    monkeypatch.setattr(api_main, "_dispatch_notification", lambda **_kwargs: called.__setitem__("count", called["count"] + 1) or {"sent": True})
    try:
        response = client.post(
            "/api/system/queue/maintenance/schedule-summary/notify",
            headers={"Idempotency-Key": "idem-maint-sched-notify-dry-1"},
            json={
                "org_id": "11111111-1111-1111-1111-111111111111",
                "schedule_name": "hourly-ci",
                "window_days": 30,
                "dry_run": True,
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["anomaly_detected"] is True
    assert len(payload["data"]["alerts"]) >= 1
    assert payload["data"]["notified"] is False
    assert called["count"] == 0


def test_notify_queue_maintenance_schedule_summary_force_notify(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }
    summary = api_main.QueueMaintenanceScheduleSummaryData(
        org_id="11111111-1111-1111-1111-111111111111",
        schedule_name="hourly-ci",
        window_days=30,
        trigger_count=2,
        executed_count=1,
        deduped_count=1,
        dedupe_hit_rate=0.5,
        successful_executions=1,
        failed_executions=0,
        execution_success_rate=1.0,
        last_triggered_at="2026-02-24T10:00:00Z",
        last_executed_run_started_at="2026-02-24T09:30:00Z",
        last_executed_run_status="completed",
    )
    monkeypatch.setattr(api_main, "_compute_queue_maintenance_schedule_summary_data", lambda **_kwargs: summary)
    monkeypatch.setattr(api_main, "_get_queue_maintenance_policy", lambda _org_id: {"schedule_alert_enabled": False})
    monkeypatch.setattr(
        api_main,
        "_dispatch_notification",
        lambda **_kwargs: {"event_type": "maintenance_schedule_anomaly", "queued": True, "sent": True},
    )
    try:
        response = client.post(
            "/api/system/queue/maintenance/schedule-summary/notify",
            headers={"Idempotency-Key": "idem-maint-sched-notify-force-1"},
            json={
                "org_id": "11111111-1111-1111-1111-111111111111",
                "schedule_name": "hourly-ci",
                "window_days": 30,
                "dry_run": False,
                "force_notify": True,
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["notified"] is True
    assert payload["data"]["notification"]["sent"] is True


def test_notify_queue_maintenance_schedule_summary_suppressed_by_cooldown(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }
    summary = api_main.QueueMaintenanceScheduleSummaryData(
        org_id="11111111-1111-1111-1111-111111111111",
        schedule_name="hourly-ci",
        window_days=30,
        trigger_count=10,
        executed_count=6,
        deduped_count=4,
        dedupe_hit_rate=0.4,
        successful_executions=4,
        failed_executions=2,
        execution_success_rate=4 / 6,
        last_triggered_at="2026-02-24T10:00:00Z",
        last_executed_run_started_at="2026-02-24T09:30:00Z",
        last_executed_run_status="failed",
    )
    monkeypatch.setattr(api_main, "_compute_queue_maintenance_schedule_summary_data", lambda **_kwargs: summary)
    monkeypatch.setattr(
        api_main,
        "_get_queue_maintenance_policy",
        lambda _org_id: {
            "schedule_alert_enabled": True,
            "schedule_alert_dedupe_hit_rate_threshold": 0.2,
            "schedule_alert_min_execution_success_rate": 0.95,
            "schedule_alert_cooldown_minutes": 60,
        },
    )
    monkeypatch.setattr(
        api_main,
        "_check_and_mark_schedule_alert_cooldown",
        lambda **_kwargs: {"suppressed": True, "reason": "cooldown", "cooldown_minutes": 60, "last_notified_at": "2026-02-24T09:50:00Z"},
    )
    monkeypatch.setattr(api_main, "_dispatch_notification", lambda **_kwargs: (_ for _ in ()).throw(AssertionError("should not dispatch")))
    try:
        response = client.post(
            "/api/system/queue/maintenance/schedule-summary/notify",
            headers={"Idempotency-Key": "idem-maint-sched-notify-suppress-1"},
            json={
                "org_id": "11111111-1111-1111-1111-111111111111",
                "schedule_name": "hourly-ci",
                "window_days": 30,
                "dry_run": False,
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["anomaly_detected"] is True
    assert payload["data"]["notified"] is False
    assert payload["data"]["notification"]["suppressed"] is True
    assert payload["data"]["notification"]["suppression_reason"] == "cooldown"


def test_notify_queue_maintenance_schedule_summary_requires_idempotency_key() -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-maint-sched-notify-idem",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }
    try:
        response = client.post(
            "/api/system/queue/maintenance/schedule-summary/notify",
            json={"org_id": "11111111-1111-1111-1111-111111111111"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 422
    _assert_error_envelope(response.json(), "VALIDATION_ERROR")


def test_get_queue_maintenance_schedule_alert_delivery_happy_path(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-maint-alert-delivery",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }
    stats_row = (12, 4, 2, 3, 2, 1, "2026-02-24T10:00:00Z", "2026-02-24T09:00:00Z", "2026-02-24T08:00:00Z", "2026-02-24T07:00:00Z")
    state_row = ("2026-02-24T09:05:00Z",)

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[stats_row, state_row]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.get(
            "/api/system/queue/maintenance/schedule-alert-delivery?org_id=11111111-1111-1111-1111-111111111111&schedule_name=hourly-ci&window_days=30"
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["total_notify_events"] == 12
    assert payload["data"]["sent_count"] == 4
    assert payload["data"]["failed_count"] == 2
    assert payload["data"]["suppressed_count"] == 3
    assert payload["data"]["skipped_count"] == 2
    assert payload["data"]["dry_run_count"] == 1


def test_get_queue_maintenance_schedule_alert_delivery_enforces_org_scope() -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-maint-alert-delivery-scope",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "scoped-admin-key",
        "role": "admin",
    }
    try:
        response = client.get(
            "/api/system/queue/maintenance/schedule-alert-delivery?org_id=22222222-2222-2222-2222-222222222222"
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 403
    _assert_error_envelope(response.json(), "FORBIDDEN_ORG_SCOPE")


def test_get_queue_maintenance_metrics_happy_path(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-maint-metrics",
        "org_id": None,
        "name": "admin-key",
        "role": "admin",
    }
    aggregate_row = (5, 1, 3, 1, 2, 1500.0, 1400.0, 2100.0)
    last_row = ("2026-02-24T06:00:00Z", "running")

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[aggregate_row, last_row]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.get("/api/system/queue/maintenance/metrics?org_id=11111111-1111-1111-1111-111111111111&window_days=30")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["org_id"] == "11111111-1111-1111-1111-111111111111"
    assert payload["data"]["window_days"] == 30
    assert payload["data"]["total_runs"] == 5
    assert payload["data"]["running_count"] == 1
    assert payload["data"]["completed_count"] == 3
    assert payload["data"]["failed_count"] == 1
    assert payload["data"]["dry_run_count"] == 2
    assert payload["data"]["failure_rate"] == 0.2
    assert payload["data"]["avg_duration_ms"] == 1500.0
    assert payload["data"]["p50_duration_ms"] == 1400
    assert payload["data"]["p95_duration_ms"] == 2100
    assert payload["data"]["last_run_status"] == "running"


def test_get_queue_maintenance_metrics_enforces_org_scope() -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-admin-maint-metrics-scope",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "scoped-admin-key",
        "role": "admin",
    }
    try:
        response = client.get("/api/system/queue/maintenance/metrics?org_id=22222222-2222-2222-2222-222222222222")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 403
    _assert_error_envelope(response.json(), "FORBIDDEN_ORG_SCOPE")


def test_run_registry_upsert_success(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k-registry-upsert",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }

    upsert_row = (
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
        "baseline",
        "default",
        "33333333-3333-3333-3333-333333333333",
        True,
        "notes",
        {},
        "2026-02-24T00:00:00Z",
        "2026-02-24T00:00:00Z",
    )

    def _fake_get_conn() -> _FakeConn:
        agent_row = ("22222222-2222-2222-2222-222222222222", "11111111-1111-1111-1111-111111111111")
        run_row = ("33333333-3333-3333-3333-333333333333", "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222")
        return _FakeConn(_FakeCursor(fetchone_values=[agent_row, run_row, upsert_row]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    response = client.post(
        "/api/agents/22222222-2222-2222-2222-222222222222/run-registry",
        json={
            "kind": "baseline",
            "name": "default",
            "run_id": "33333333-3333-3333-3333-333333333333",
            "is_active": True,
            "notes": "notes",
            "metadata": {},
        },
    )

    app.dependency_overrides.clear()
    assert response.status_code == 201
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["kind"] == "baseline"
    assert payload["data"]["name"] == "default"


def test_run_registry_list_success(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_viewer] = lambda: {
        "key_id": "k-registry-list",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "viewer-key",
        "role": "viewer",
    }

    list_row = (
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
        "baseline",
        "default",
        "33333333-3333-3333-3333-333333333333",
        True,
        None,
        {},
        "2026-02-24T00:00:00Z",
        "2026-02-24T00:00:00Z",
    )

    def _fake_get_conn() -> _FakeConn:
        agent_row = ("22222222-2222-2222-2222-222222222222", "11111111-1111-1111-1111-111111111111")
        return _FakeConn(_FakeCursor(fetchone_values=[agent_row], fetchall_values=[[list_row]]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    response = client.get("/api/agents/22222222-2222-2222-2222-222222222222/run-registry?kind=baseline")

    app.dependency_overrides.clear()
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["count"] == 1
    assert payload["data"]["items"][0]["kind"] == "baseline"


def test_run_registry_resolve_not_found_returns_null(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_viewer] = lambda: {
        "key_id": "k-registry-resolve",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "viewer-key",
        "role": "viewer",
    }

    def _fake_get_conn() -> _FakeConn:
        agent_row = ("22222222-2222-2222-2222-222222222222", "11111111-1111-1111-1111-111111111111")
        return _FakeConn(_FakeCursor(fetchone_values=[agent_row, None]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    response = client.get("/api/agents/22222222-2222-2222-2222-222222222222/run-registry/resolve?kind=baseline")

    app.dependency_overrides.clear()
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["ref"] is None


def test_run_registry_promote_candidate_success(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k-registry-promote",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }

    promoted_row = (
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
        "baseline",
        "default",
        "33333333-3333-3333-3333-333333333333",
        True,
        "promote after clean compare",
        {"source": "test"},
        "2026-02-24T00:00:00Z",
        "2026-02-24T00:00:00Z",
    )

    def _fake_get_conn() -> _FakeConn:
        agent_row = ("22222222-2222-2222-2222-222222222222", "11111111-1111-1111-1111-111111111111")
        resolved_candidate = ("33333333-3333-3333-3333-333333333333",)
        run_row = ("33333333-3333-3333-3333-333333333333", "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222")
        resolved_baseline = ("66666666-6666-6666-6666-666666666666",)
        baseline_row = ("66666666-6666-6666-6666-666666666666", "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222")
        clean_compare_row = ("99999999-9999-9999-9999-999999999999", "2026-02-24T00:10:00Z")
        return _FakeConn(
            _FakeCursor(
                fetchone_values=[
                    agent_row,
                    resolved_candidate,
                    run_row,
                    resolved_baseline,
                    baseline_row,
                    clean_compare_row,
                    promoted_row,
                ]
            )
        )

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    monkeypatch.setattr(api_main, "_record_activity_event", lambda **_kwargs: None)
    try:
        response = client.post(
            "/api/agents/22222222-2222-2222-2222-222222222222/run-registry/promote-candidate",
            json={
                "candidate_ref": "active",
                "baseline_name": "default",
                "notes": "promote after clean compare",
                "metadata": {"source": "test"},
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["candidate_run_id"] == "33333333-3333-3333-3333-333333333333"
    assert payload["data"]["baseline_ref"]["kind"] == "baseline"
    assert payload["data"]["baseline_ref"]["run_id"] == "33333333-3333-3333-3333-333333333333"


def test_run_registry_promote_candidate_blocked_without_clean_compare(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k-registry-promote-blocked",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }

    def _fake_get_conn() -> _FakeConn:
        agent_row = ("22222222-2222-2222-2222-222222222222", "11111111-1111-1111-1111-111111111111")
        resolved_candidate = ("33333333-3333-3333-3333-333333333333",)
        run_row = ("33333333-3333-3333-3333-333333333333", "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222")
        resolved_baseline = ("66666666-6666-6666-6666-666666666666",)
        baseline_row = ("66666666-6666-6666-6666-666666666666", "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222")
        return _FakeConn(
            _FakeCursor(
                fetchone_values=[
                    agent_row,
                    resolved_candidate,
                    run_row,
                    resolved_baseline,
                    baseline_row,
                    None,
                ]
            )
        )

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.post(
            "/api/agents/22222222-2222-2222-2222-222222222222/run-registry/promote-candidate",
            json={
                "candidate_ref": "active",
                "baseline_name": "default",
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 409
    payload = response.json()
    _assert_error_envelope(payload, "RUN_REGISTRY_PROMOTION_BLOCKED")


def test_eval_compare_reference_mode_resolves_and_compares(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k-compare-ref",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }

    baseline_id = "33333333-3333-3333-3333-333333333333"
    candidate_id = "44444444-4444-4444-4444-444444444444"
    agent_id = "22222222-2222-2222-2222-222222222222"
    org_id = "11111111-1111-1111-1111-111111111111"
    case_id = "55555555-5555-5555-5555-555555555555"

    call_count = {"value": 0}

    def _fake_get_conn() -> _FakeConn:
        call_count["value"] += 1
        if call_count["value"] == 1:
            # agent lookup + baseline/candidate ref resolution
            return _FakeConn(
                _FakeCursor(
                    fetchone_values=[
                        (agent_id, org_id),
                        (baseline_id,),
                        (candidate_id,),
                    ]
                )
            )
        # compare flow: run checks + summaries + result rows
        return _FakeConn(
            _FakeCursor(
                fetchone_values=[
                    (baseline_id, org_id, agent_id),
                    (candidate_id, org_id, agent_id),
                    ("Demo Agent",),
                    (baseline_id, "completed", "2026-02-24T00:00:00Z", "2026-02-24T00:01:00Z", 1, 1, 0, 0, 1, 0, 0, 1, 0, 0),
                    (candidate_id, "completed", "2026-02-24T00:02:00Z", "2026-02-24T00:03:00Z", 1, 1, 0, 0, 1, 0, 0, 1, 0, 0),
                ],
                fetchall_values=[
                    [(case_id, "answer", "yes", "yes", "good")],
                    [(case_id, "answer", "yes", "yes", "good")],
                ],
            )
        )

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    monkeypatch.setattr(api_main, "_record_activity_event", lambda **_kwargs: None)
    monkeypatch.setattr(api_main, "send_webhook_event", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(api_main, "_get_slo_policy", lambda *_args, **_kwargs: None)
    try:
        response = client.get(
            "/api/eval/compare"
            "?agent_id=22222222-2222-2222-2222-222222222222"
            "&baseline_ref=active"
            "&candidate_ref=latest"
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["baseline_run_id"] == baseline_id
    assert payload["data"]["candidate_run_id"] == candidate_id
    assert payload["data"]["regression_count"] == 0


def test_eval_compare_rejects_mixed_direct_and_reference_modes() -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k-compare-invalid",
        "org_id": None,
        "name": "member-key",
        "role": "member",
    }
    try:
        response = client.get(
            "/api/eval/compare"
            "?baseline_run_id=33333333-3333-3333-3333-333333333333"
            "&candidate_run_id=44444444-4444-4444-4444-444444444444"
            "&agent_id=22222222-2222-2222-2222-222222222222"
            "&baseline_ref=active"
            "&candidate_ref=latest"
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 400
    payload = response.json()
    _assert_error_envelope(payload, "EVAL_RUN_COMPARE_INVALID")


def test_launch_certification_create_success(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "admin-key",
        "role": "admin",
    }

    monkeypatch.setattr(
        api_main,
        "_evaluate_launch_gate",
        lambda _agent_id: {
            "agent_id": "22222222-2222-2222-2222-222222222222",
            "can_launch": True,
            "blockers": [],
            "latest_run_id": "44444444-4444-4444-4444-444444444444",
            "latest_run_status": "completed",
            "active_critical_issues": 0,
            "open_slo_violations": 0,
            "readiness_pending_items": 0,
        },
    )

    inserted = (
        "cccccccc-cccc-cccc-cccc-cccccccccccc",
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
        "go",
        "certified",
        "ready",
        [],
        {"gate": {"can_launch": True}},
        "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
        "2026-02-24T00:00:00Z",
    )

    def _fake_get_conn() -> _FakeConn:
        agent_row = ("22222222-2222-2222-2222-222222222222", "11111111-1111-1111-1111-111111111111")
        compare_row = (
            "dddddddd-dddd-dddd-dddd-dddddddddddd",
            {"candidate_run_id": "44444444-4444-4444-4444-444444444444", "regression_count": 0},
            "2026-02-24T00:00:00Z",
        )
        return _FakeConn(_FakeCursor(fetchone_values=[agent_row, compare_row, inserted]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    monkeypatch.setattr(api_main, "_record_activity_event", lambda **_kwargs: None)
    try:
        response = client.post(
            "/api/agents/22222222-2222-2222-2222-222222222222/launch-certify",
            json={"decision": "go", "reason": "ready"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 201
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["certification"]["certification_status"] == "certified"


def test_launch_certification_create_blocked_without_compare(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "admin-key",
        "role": "admin",
    }

    monkeypatch.setattr(
        api_main,
        "_evaluate_launch_gate",
        lambda _agent_id: {
            "agent_id": "22222222-2222-2222-2222-222222222222",
            "can_launch": True,
            "blockers": [],
            "latest_run_id": "44444444-4444-4444-4444-444444444444",
            "latest_run_status": "completed",
            "active_critical_issues": 0,
            "open_slo_violations": 0,
            "readiness_pending_items": 0,
        },
    )

    inserted = (
        "cccccccc-cccc-cccc-cccc-cccccccccccc",
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
        "go",
        "blocked",
        "ready",
        ["No regression compare evidence found."],
        {"gate": {"can_launch": True}},
        "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
        "2026-02-24T00:00:00Z",
    )

    def _fake_get_conn() -> _FakeConn:
        agent_row = ("22222222-2222-2222-2222-222222222222", "11111111-1111-1111-1111-111111111111")
        compare_row = None
        return _FakeConn(_FakeCursor(fetchone_values=[agent_row, compare_row, inserted]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    monkeypatch.setattr(api_main, "_record_activity_event", lambda **_kwargs: None)
    try:
        response = client.post(
            "/api/agents/22222222-2222-2222-2222-222222222222/launch-certify",
            json={"decision": "go", "reason": "ready"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 201
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["certification"]["certification_status"] == "blocked"


def test_list_eval_runs_happy_path(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_viewer] = lambda: {
        "key_id": "k-runs-list",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "viewer-key",
        "role": "viewer",
    }

    row = (
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
        "33333333-3333-3333-3333-333333333333",
        "run-1",
        "eval",
        "completed",
        "2026-02-24T00:00:00Z",
        "2026-02-24T00:01:00Z",
        "2026-02-24T00:02:00Z",
        None,
        2,
        1,
        2,
        1,
    )

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchall_values=[[row]], fetchone_values=[(1,)]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.get("/api/eval/runs?org_id=11111111-1111-1111-1111-111111111111")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["count"] == 1
    assert payload["data"]["items"][0]["name"] == "run-1"
    assert payload["data"]["items"][0]["answer_yes_rate"] == 0.5


def test_list_eval_runs_cross_org_forbidden() -> None:
    app.dependency_overrides[api_main.require_viewer] = lambda: {
        "key_id": "k-runs-list-scope",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "viewer-key",
        "role": "viewer",
    }
    try:
        response = client.get("/api/eval/runs?org_id=99999999-9999-9999-9999-999999999999")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 403
    _assert_error_envelope(response.json(), "FORBIDDEN_ORG_SCOPE")


def test_get_agent_score_trend_happy_path(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_viewer] = lambda: {
        "key_id": "k-score-trend",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "viewer-key",
        "role": "viewer",
    }

    agent_row = ("22222222-2222-2222-2222-222222222222", "11111111-1111-1111-1111-111111111111")
    trend_row = (
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "run-1",
        "eval",
        "completed",
        "2026-02-24T00:00:00Z",
        "2026-02-24T00:01:00Z",
        1,
        1,
        1,
        1,
    )

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[agent_row, (1,)], fetchall_values=[[trend_row]]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.get("/api/agents/22222222-2222-2222-2222-222222222222/score-trend?window_days=30")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["count"] == 1
    assert payload["data"]["items"][0]["quality_good_rate"] == 1.0


def test_get_agent_health_happy_path(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_viewer] = lambda: {
        "key_id": "k-agent-health",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "viewer-key",
        "role": "viewer",
    }

    monkeypatch.setattr(
        api_main,
        "_evaluate_launch_gate",
        lambda _agent_id: {
            "org_id": "11111111-1111-1111-1111-111111111111",
            "can_launch": False,
            "blockers": ["1 readiness item(s) pending."],
            "latest_run_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "latest_run_status": "completed",
            "active_critical_issues": 0,
            "open_slo_violations": 0,
            "readiness_pending_items": 1,
        },
    )

    latest_completed = (
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "2026-02-24T00:01:00Z",
        2,
        1,
        2,
        1,
    )

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[latest_completed, (3,), ("deferred", None)]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.get("/api/agents/22222222-2222-2222-2222-222222222222/health")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["active_issue_count"] == 3
    assert payload["data"]["answer_yes_rate"] == 0.5


def test_get_org_portfolio_health_happy_path(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_viewer] = lambda: {
        "key_id": "k-portfolio-health",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "viewer-key",
        "role": "viewer",
    }

    row = (
        "22222222-2222-2222-2222-222222222222",
        "Agent A",
        "build",
        "completed",
        2,
        2,
        1,
        1,
        0,
        0,
        0,
    )

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchall_values=[[row]], fetchone_values=[(1,)]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.get("/api/orgs/11111111-1111-1111-1111-111111111111/portfolio-health")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["total_agents"] == 1
    assert payload["data"]["healthy_agents"] == 1


def test_get_org_portfolio_health_cross_org_forbidden() -> None:
    app.dependency_overrides[api_main.require_viewer] = lambda: {
        "key_id": "k-portfolio-health-scope",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "viewer-key",
        "role": "viewer",
    }
    try:
        response = client.get("/api/orgs/99999999-9999-9999-9999-999999999999/portfolio-health")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 403
    _assert_error_envelope(response.json(), "FORBIDDEN_ORG_SCOPE")


def test_get_eval_run_artifacts_happy_path(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_viewer] = lambda: {
        "key_id": "k-artifacts-read",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "viewer-key",
        "role": "viewer",
    }

    run_row = ("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "11111111-1111-1111-1111-111111111111")
    artifact_row = (
        "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "cccccccc-cccc-cccc-cccc-cccccccccccc",
        "dddddddd-dddd-dddd-dddd-dddddddddddd",
        "22222222-2222-2222-2222-222222222222",
        "answer",
        "provider",
        "gpt-4.1-mini",
        "v1",
        "hash123",
        "agent_http",
        123.45,
        78.90,
        44.55,
        {"prompt_tokens": 10, "completion_tokens": 20},
        {"input_text": "q"},
        {"answer_correct": "yes"},
        {"executor_mode": "agent_http"},
        "2026-02-24T00:00:00Z",
    )

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[run_row, (1,)], fetchall_values=[[artifact_row]]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.get("/api/eval/runs/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/artifacts?limit=10&offset=0")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["count"] == 1
    assert payload["data"]["items"][0]["judge_prompt_hash"] == "hash123"


def test_get_eval_run_artifacts_cross_org_forbidden(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_viewer] = lambda: {
        "key_id": "k-artifacts-scope",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "viewer-key",
        "role": "viewer",
    }

    run_row = ("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "99999999-9999-9999-9999-999999999999")

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[run_row]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.get("/api/eval/runs/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/artifacts")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 403
    _assert_error_envelope(response.json(), "FORBIDDEN_ORG_SCOPE")


def test_get_eval_run_review_queue_happy_path(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_viewer] = lambda: {
        "key_id": "k-review-queue",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "viewer-key",
        "role": "viewer",
    }

    run_row = ("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", "11111111-1111-1111-1111-111111111111")
    review_row = (
        "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "cccccccc-cccc-cccc-cccc-cccccccccccc",
        "22222222-2222-2222-2222-222222222222",
        "answer",
        "partially",
        "yes",
        "average",
        None,
        "judge reasoning",
        "unreviewed",
        None,
        None,
        {},
        None,
        None,
        "2026-02-24T00:00:00Z",
    )

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[run_row, (1,)], fetchall_values=[[review_row]]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.get("/api/eval/runs/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/review-queue")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["count"] == 1
    assert payload["data"]["items"][0]["review_status"] == "unreviewed"


def test_review_eval_result_accept_happy_path(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }

    selected_row = (
        "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "22222222-2222-2222-2222-222222222222",
        "11111111-1111-1111-1111-111111111111",
        "answer",
        "partially",
        "yes",
        "average",
        None,
    )
    updated_row = (
        "accepted",
        "accept",
        "validated by reviewer",
        {},
        "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
        "2026-02-24T00:00:00Z",
    )

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[selected_row, updated_row]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    monkeypatch.setattr(api_main, "_record_activity_event", lambda **_kwargs: None)
    try:
        response = client.patch(
            "/api/eval/runs/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/results/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/review",
            json={"decision": "accept", "reason": "validated by reviewer"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["review_status"] == "accepted"
    assert payload["data"]["review_decision"] == "accept"


def test_review_eval_result_override_requires_reason(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }

    selected_row = (
        "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "22222222-2222-2222-2222-222222222222",
        "11111111-1111-1111-1111-111111111111",
        "answer",
        "partially",
        "yes",
        "average",
        None,
    )

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[selected_row]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.patch(
            "/api/eval/runs/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/results/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/review",
            json={"decision": "override", "override": {"answer_correct": "yes"}},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 400
    _assert_error_envelope(response.json(), "EVAL_RESULT_REVIEW_REASON_REQUIRED")


def test_review_eval_result_cross_org_forbidden(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }

    selected_row = (
        "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "22222222-2222-2222-2222-222222222222",
        "99999999-9999-9999-9999-999999999999",
        "answer",
        "partially",
        "yes",
        "average",
        None,
    )

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[selected_row]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.patch(
            "/api/eval/runs/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/results/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb/review",
            json={"decision": "accept"},
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 403
    _assert_error_envelope(response.json(), "FORBIDDEN_ORG_SCOPE")


def test_get_agent_calibration_gate_status_happy_path(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_viewer] = lambda: {
        "key_id": "k-cal-gate",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "viewer-key",
        "role": "viewer",
    }

    agent_row = ("22222222-2222-2222-2222-222222222222", "11111111-1111-1111-1111-111111111111")

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[agent_row]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    monkeypatch.setattr(
        api_main,
        "_get_calibration_gate_status",
        lambda **_kwargs: {
            "enabled": True,
            "status": "pass",
            "reasons": [],
            "min_overall_agreement": 0.7,
            "max_age_days": 14,
            "latest_calibration_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "latest_calibration_created_at": "2026-02-24T00:00:00Z",
            "latest_overall_agreement": 0.81,
        },
    )
    try:
        response = client.get("/api/agents/22222222-2222-2222-2222-222222222222/calibration-gate-status")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["status"] == "pass"
    assert payload["data"]["enabled"] is True


def test_start_eval_run_blocked_by_calibration_gate(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k-cal-gate-start",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }

    run_row = (
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
        "33333333-3333-3333-3333-333333333333",
        "eval",
        "pending",
        {},
    )

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[run_row]))

    def _fail_gate(**_kwargs: Any) -> None:
        api_main._error(
            "EVAL_CALIBRATION_GATE_FAILED",
            "Calibration gate blocked run execution: missing recent calibration.",
            409,
        )

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    monkeypatch.setattr(api_main, "_enforce_calibration_gate", _fail_gate)
    monkeypatch.setattr(api_main, "_enforce_golden_set_quality_gate", lambda **_kwargs: None)
    monkeypatch.setattr(api_main, "_enforce_configured_gates", lambda **_kwargs: None)
    try:
        response = client.post("/api/eval/runs/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/start")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 409
    _assert_error_envelope(response.json(), "EVAL_CALIBRATION_GATE_FAILED")


def test_get_golden_set_quality_gate_status_happy_path(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_viewer] = lambda: {
        "key_id": "k-gs-gate",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "viewer-key",
        "role": "viewer",
    }

    gs_row = (
        "33333333-3333-3333-3333-333333333333",
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
    )

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[gs_row]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    monkeypatch.setattr(
        api_main,
        "_get_slo_policy",
        lambda _agent_id: {
            "require_golden_set_quality_gate": True,
            "min_verified_case_ratio": 0.7,
            "min_active_case_count": 20,
        },
    )
    monkeypatch.setattr(
        api_main,
        "_get_golden_set_quality_gate_status",
        lambda **_kwargs: {
            "enabled": True,
            "status": "pass",
            "reasons": [],
            "min_verified_case_ratio": 0.7,
            "min_active_case_count": 20,
            "total_case_count": 40,
            "active_case_count": 30,
            "verified_case_count": 24,
            "verified_case_ratio": 0.8,
        },
    )
    try:
        response = client.get("/api/golden-sets/33333333-3333-3333-3333-333333333333/quality-gate-status")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["status"] == "pass"
    assert payload["data"]["active_case_count"] == 30


def test_start_eval_run_blocked_by_golden_set_quality_gate(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k-gs-gate-start",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }

    run_row = (
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
        "33333333-3333-3333-3333-333333333333",
        "eval",
        "pending",
        {},
    )

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[run_row]))

    def _fail_gate(**_kwargs: Any) -> None:
        api_main._error(
            "EVAL_GOLDEN_SET_QUALITY_GATE_FAILED",
            "Golden set quality gate blocked run execution: verification coverage too low.",
            409,
        )

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    monkeypatch.setattr(api_main, "_enforce_calibration_gate", lambda **_kwargs: None)
    monkeypatch.setattr(api_main, "_enforce_golden_set_quality_gate", _fail_gate)
    monkeypatch.setattr(api_main, "_enforce_configured_gates", lambda **_kwargs: None)
    try:
        response = client.post("/api/eval/runs/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/start")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 409
    _assert_error_envelope(response.json(), "EVAL_GOLDEN_SET_QUALITY_GATE_FAILED")


def test_list_gate_definitions_happy_path(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_viewer] = lambda: {
        "key_id": "k-gate-def-list",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "viewer-key",
        "role": "viewer",
    }
    rows = [
        (
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            None,
            "calibration_freshness",
            "Calibration Freshness Gate",
            "desc",
            "calibration_freshness",
            {},
            {"min_overall_agreement": 0.7, "max_age_days": 14},
            ["eval"],
            True,
            True,
            "2026-02-24T00:00:00Z",
            "2026-02-24T00:00:00Z",
        )
    ]

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[(1,)], fetchall_values=[rows]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.get("/api/gate-definitions?org_id=11111111-1111-1111-1111-111111111111")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["count"] == 1
    assert payload["data"]["items"][0]["key"] == "calibration_freshness"


def test_create_gate_definition_rejects_unsupported_evaluator() -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k-gate-def-create",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }
    try:
        response = client.post(
            "/api/gate-definitions",
            json={
                "org_id": "11111111-1111-1111-1111-111111111111",
                "key": "my_gate",
                "name": "My Gate",
                "evaluator_key": "unknown_evaluator",
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 400
    _assert_error_envelope(response.json(), "GATE_EVALUATOR_UNSUPPORTED")


def test_upsert_agent_gate_binding_happy_path(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k-gate-bind-upsert",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }
    agent_row = ("22222222-2222-2222-2222-222222222222", "11111111-1111-1111-1111-111111111111")
    gate_row = (
        "33333333-3333-3333-3333-333333333333",
        None,
        "golden_set_quality",
        "Golden Set Quality Gate",
        "golden_set_quality",
    )
    binding_row = (
        "44444444-4444-4444-4444-444444444444",
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
        "33333333-3333-3333-3333-333333333333",
        True,
        {"min_verified_case_ratio": 0.9},
        "2026-02-24T00:00:00Z",
        "2026-02-24T00:00:00Z",
    )

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[agent_row, gate_row, binding_row]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.post(
            "/api/agents/22222222-2222-2222-2222-222222222222/gate-bindings",
            json={
                "gate_definition_id": "33333333-3333-3333-3333-333333333333",
                "enabled": True,
                "config": {"min_verified_case_ratio": 0.9},
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 201
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["binding"]["gate_key"] == "golden_set_quality"


def test_start_eval_run_blocked_by_configured_gate(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k-config-gate-start",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }
    run_row = (
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
        "33333333-3333-3333-3333-333333333333",
        "eval",
        "pending",
        {},
    )

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[run_row]))

    def _fail_configured(**_kwargs: Any) -> None:
        api_main._error("EVAL_GATE_FAILED", "Gate blocked run.", 409)

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    monkeypatch.setattr(api_main, "_enforce_calibration_gate", lambda **_kwargs: None)
    monkeypatch.setattr(api_main, "_enforce_golden_set_quality_gate", lambda **_kwargs: None)
    monkeypatch.setattr(api_main, "_enforce_configured_gates", _fail_configured)
    try:
        response = client.post("/api/eval/runs/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/start")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 409
    _assert_error_envelope(response.json(), "EVAL_GATE_FAILED")


def test_list_evaluator_definitions_happy_path(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_viewer] = lambda: {
        "key_id": "k-eval-def-list",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "viewer-key",
        "role": "viewer",
    }
    rows = [
        (
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            None,
            "builtin_answer_deterministic",
            "Builtin Answer Evaluator (Deterministic)",
            "desc",
            "answer",
            "judge_service",
            {"judge_mode": "deterministic"},
            True,
            True,
            "2026-02-24T00:00:00Z",
            "2026-02-24T00:00:00Z",
        )
    ]

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[(1,)], fetchall_values=[rows]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.get("/api/evaluator-definitions?org_id=11111111-1111-1111-1111-111111111111")
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["count"] == 1
    assert payload["data"]["items"][0]["evaluation_mode"] == "answer"


def test_create_evaluator_definition_rejects_unsupported_kind() -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k-eval-def-create",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }
    try:
        response = client.post(
            "/api/evaluator-definitions",
            json={
                "org_id": "11111111-1111-1111-1111-111111111111",
                "key": "custom_evaluator",
                "name": "Custom Evaluator",
                "evaluation_mode": "answer",
                "evaluator_kind": "unknown_kind",
            },
        )
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 400
    _assert_error_envelope(response.json(), "EVALUATOR_KIND_UNSUPPORTED")


def test_upsert_agent_evaluator_binding_happy_path(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k-eval-bind-upsert",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }
    agent_row = ("22222222-2222-2222-2222-222222222222", "11111111-1111-1111-1111-111111111111")
    def_row = (
        "33333333-3333-3333-3333-333333333333",
        None,
        "builtin_answer_deterministic",
        "Builtin Answer Evaluator (Deterministic)",
        "answer",
        "judge_service",
    )
    binding_row = (
        "44444444-4444-4444-4444-444444444444",
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
        "33333333-3333-3333-3333-333333333333",
        "answer",
        True,
        {"judge_mode": "deterministic"},
        "2026-02-24T00:00:00Z",
        "2026-02-24T00:00:00Z",
    )

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[agent_row, def_row, binding_row]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.post(
            "/api/agents/22222222-2222-2222-2222-222222222222/evaluator-bindings",
            json={
                "evaluator_definition_id": "33333333-3333-3333-3333-333333333333",
                "evaluation_mode": "answer",
                "enabled": True,
                "config": {"judge_mode": "deterministic"},
            },
        )
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 201
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["binding"]["evaluation_mode"] == "answer"


def test_start_eval_run_blocked_by_configured_evaluator(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k-config-evaluator-start",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }
    run_row = (
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
        "33333333-3333-3333-3333-333333333333",
        "eval",
        "pending",
        {},
    )

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[run_row]))

    def _fail_configured(**_kwargs: Any) -> None:
        api_main._error("EVALUATOR_CONFIG_ERROR", "Evaluator configuration invalid.", 400)

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    monkeypatch.setattr(api_main, "_enforce_calibration_gate", lambda **_kwargs: None)
    monkeypatch.setattr(api_main, "_enforce_golden_set_quality_gate", lambda **_kwargs: None)
    monkeypatch.setattr(api_main, "_enforce_configured_gates", _fail_configured)
    try:
        response = client.post("/api/eval/runs/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/start")
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 400
    _assert_error_envelope(response.json(), "EVALUATOR_CONFIG_ERROR")


def test_list_run_type_definitions_happy_path(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_viewer] = lambda: {
        "key_id": "k-run-type-def-list",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "viewer-key",
        "role": "viewer",
    }
    rows = [
        (
            "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            None,
            "eval",
            "builtin_eval_default",
            "Builtin Eval Handler",
            "desc",
            "default",
            {},
            True,
            True,
            "2026-02-24T00:00:00Z",
            "2026-02-24T00:00:00Z",
        )
    ]

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[(1,)], fetchall_values=[rows]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.get("/api/run-type-definitions?org_id=11111111-1111-1111-1111-111111111111")
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["items"][0]["run_type"] == "eval"


def test_create_run_type_definition_rejects_unsupported_handler() -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k-run-type-create",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }
    try:
        response = client.post(
            "/api/run-type-definitions",
            json={
                "org_id": "11111111-1111-1111-1111-111111111111",
                "run_type": "eval",
                "key": "custom_eval_handler",
                "name": "Custom Eval Handler",
                "handler_key": "unknown_handler",
            },
        )
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 400
    _assert_error_envelope(response.json(), "RUN_TYPE_HANDLER_UNSUPPORTED")


def test_upsert_agent_run_type_binding_happy_path(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k-run-type-bind-upsert",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }
    agent_row = ("22222222-2222-2222-2222-222222222222", "11111111-1111-1111-1111-111111111111")
    def_row = (
        "33333333-3333-3333-3333-333333333333",
        None,
        "eval",
        "builtin_eval_default",
        "Builtin Eval Handler",
        "default",
    )
    binding_row = (
        "44444444-4444-4444-4444-444444444444",
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
        "eval",
        "33333333-3333-3333-3333-333333333333",
        True,
        {"allow_start": True},
        "2026-02-24T00:00:00Z",
        "2026-02-24T00:00:00Z",
    )

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[agent_row, def_row, binding_row]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.post(
            "/api/agents/22222222-2222-2222-2222-222222222222/run-type-bindings",
            json={
                "run_type_definition_id": "33333333-3333-3333-3333-333333333333",
                "run_type": "eval",
                "enabled": True,
                "config": {"allow_start": True},
            },
        )
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 201
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["binding"]["run_type"] == "eval"


def test_contract_upgrade_preview_reports_risk(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k-contract-preview",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }
    definition_row = (
        "33333333-3333-3333-3333-333333333333",
        "11111111-1111-1111-1111-111111111111",
        "golden_set_quality",
        "Golden Set Quality Gate",
        "1.2.0",
    )
    binding_rows = [
        (
            "44444444-4444-4444-4444-444444444444",
            "22222222-2222-2222-2222-222222222222",
            "1.1.0",
        ),
        (
            "55555555-5555-5555-5555-555555555555",
            "66666666-6666-6666-6666-666666666666",
            "0.9.0",
        ),
    ]

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[definition_row], fetchall_values=[binding_rows]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.post(
            "/api/contracts/upgrade-preview",
            json={
                "definition_type": "gate",
                "definition_id": "33333333-3333-3333-3333-333333333333",
                "target_contract_version": "2.0.0",
                "include_items": True,
                "max_items": 50,
            },
        )
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["status"] == "risky"
    assert payload["data"]["breaking_count"] == 2
    assert payload["data"]["impacted_binding_count"] == 2


def test_contract_upgrade_apply_rejects_builtin_definition(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k-contract-apply-immutable",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }
    definition_row = (
        "33333333-3333-3333-3333-333333333333",
        None,
        "builtin_answer_deterministic",
        "Builtin Answer Evaluator (Deterministic)",
        "1.0.0",
    )

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[definition_row], fetchall_values=[[]]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.post(
            "/api/contracts/apply-upgrade",
            json={
                "definition_type": "evaluator",
                "definition_id": "33333333-3333-3333-3333-333333333333",
                "target_contract_version": "1.1.0",
                "rollout_mode": "definition_only",
            },
        )
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 403
    _assert_error_envelope(response.json(), "CONTRACT_DEFINITION_IMMUTABLE")


def test_contract_upgrade_apply_definition_only_happy_path(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k-contract-apply-ok",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }
    definition_before = (
        "33333333-3333-3333-3333-333333333333",
        "11111111-1111-1111-1111-111111111111",
        "custom_eval_handler",
        "Custom Eval Handler",
        "1.0.0",
    )
    definition_after = (
        "33333333-3333-3333-3333-333333333333",
        "11111111-1111-1111-1111-111111111111",
        "custom_eval_handler",
        "Custom Eval Handler",
        "1.1.0",
    )
    bindings_before = [
        (
            "44444444-4444-4444-4444-444444444444",
            "22222222-2222-2222-2222-222222222222",
            "1.0.0",
        )
    ]
    bindings_after = bindings_before

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(
            _FakeCursor(
                fetchone_values=[definition_before, definition_after],
                fetchall_values=[bindings_before, bindings_after],
            )
        )

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.post(
            "/api/contracts/apply-upgrade",
            json={
                "definition_type": "run_type",
                "definition_id": "33333333-3333-3333-3333-333333333333",
                "target_contract_version": "1.1.0",
                "rollout_mode": "definition_only",
            },
        )
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["rollout_mode"] == "definition_only"
    assert payload["data"]["target_contract_version"] == "1.1.0"
    assert payload["data"]["bindings_updated"] == 0


def test_contract_drift_requires_org_for_global_key() -> None:
    app.dependency_overrides[api_main.require_viewer] = lambda: {
        "key_id": "k-contract-drift-global",
        "org_id": None,
        "name": "global-viewer",
        "role": "viewer",
    }
    try:
        response = client.get("/api/contracts/drift")
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 400
    _assert_error_envelope(response.json(), "ORG_ID_REQUIRED")


def test_contract_drift_happy_path(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_viewer] = lambda: {
        "key_id": "k-contract-drift",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "viewer-key",
        "role": "viewer",
    }
    agent_rows = [("22222222-2222-2222-2222-222222222222",)]

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchall_values=[agent_rows]))

    def _fake_collect(*, agent_id: Any, include_healthy: bool = False) -> List[Dict[str, Any]]:
        assert include_healthy is False
        return [
            {
                "agent_id": agent_id,
                "definition_type": "gate",
                "binding_id": "44444444-4444-4444-4444-444444444444",
                "definition_id": "33333333-3333-3333-3333-333333333333",
                "definition_key": "golden_set_quality",
                "bound_contract_version": "1.0.0",
                "current_contract_version": "2.0.0",
                "drift": "breaking",
                "severity": "error",
                "message": "Major version mismatch.",
            },
            {
                "agent_id": agent_id,
                "definition_type": "evaluator",
                "binding_id": "55555555-5555-5555-5555-555555555555",
                "definition_id": "66666666-6666-6666-6666-666666666666",
                "definition_key": "builtin_answer_deterministic",
                "bound_contract_version": "1.0.0",
                "current_contract_version": "1.1.0",
                "drift": "warning",
                "severity": "warning",
                "message": "Minor/patch drift.",
            },
        ]

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    monkeypatch.setattr(api_main, "_collect_agent_contract_drift_items", _fake_collect)
    try:
        response = client.get("/api/contracts/drift")
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["item_count"] == 2
    assert payload["data"]["breaking_count"] == 1
    assert payload["data"]["warning_count"] == 1
    assert payload["data"]["invalid_count"] == 0
    assert payload["data"]["checked_agent_count"] == 1


def test_get_contract_drift_policy_returns_default_when_missing(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-contract-policy-default",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "admin-key",
        "role": "admin",
    }
    monkeypatch.setattr(api_main, "_get_contract_drift_policy", lambda _org_id: None)
    try:
        response = client.get("/api/system/contracts/drift-policy?org_id=11111111-1111-1111-1111-111111111111")
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["enabled"] is False
    assert payload["data"]["min_drift"] == "breaking"


def test_upsert_contract_drift_policy_happy_path(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "admin-key",
        "role": "admin",
    }
    row = (
        "11111111-1111-1111-1111-111111111111",
        True,
        "warning",
        True,
        250,
        "daily",
        1440,
        True,
        0.8,
        0.6,
        30,
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "2026-02-24T00:00:00Z",
        "2026-02-24T00:00:00Z",
    )

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[("11111111-1111-1111-1111-111111111111",), row]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.post(
            "/api/system/contracts/drift-policy",
            json={
                "org_id": "11111111-1111-1111-1111-111111111111",
                "enabled": True,
                "min_drift": "warning",
                "promote_to_patterns": True,
                "scan_limit": 250,
                "schedule_name": "daily",
                "schedule_window_minutes": 1440,
                "alert_enabled": True,
                "alert_max_dedupe_hit_rate": 0.8,
                "alert_min_execution_rate": 0.6,
                "alert_cooldown_minutes": 30,
            },
        )
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["enabled"] is True
    assert payload["data"]["scan_limit"] == 250
    assert payload["data"]["alert_enabled"] is True
    assert payload["data"]["alert_cooldown_minutes"] == 30


def test_trigger_contract_drift_policy_disabled(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-contract-trigger-disabled",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "admin-key",
        "role": "admin",
    }
    monkeypatch.setattr(api_main, "_get_contract_drift_policy", lambda _org_id: {"enabled": False, "min_drift": "breaking", "scan_limit": 200})
    monkeypatch.setattr(api_main, "_record_api_audit_log", lambda **_kwargs: None)
    try:
        response = client.post(
            "/api/system/contracts/drift/trigger",
            headers={"Idempotency-Key": "idem-contract-drift-disabled"},
            json={"org_id": "11111111-1111-1111-1111-111111111111"},
        )
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["executed"] is False
    assert payload["data"]["reason"] == "policy_disabled"


def test_trigger_contract_drift_policy_executes(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-contract-trigger-execute",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "admin-key",
        "role": "admin",
    }
    monkeypatch.setattr(api_main, "_get_contract_drift_policy", lambda _org_id: {"enabled": True, "min_drift": "breaking", "scan_limit": 200})
    monkeypatch.setattr(api_main, "_record_api_audit_log", lambda **_kwargs: None)
    monkeypatch.setattr(
        api_main,
        "promote_contract_drift_patterns",
        lambda *args, **kwargs: {
            "ok": True,
            "data": {
                "org_id": "11111111-1111-1111-1111-111111111111",
                "agent_id": None,
                "min_drift": "breaking",
                "dry_run": False,
                "scanned_item_count": 2,
                "eligible_item_count": 1,
                "created_pattern_count": 1,
                "reused_pattern_count": 0,
                "pattern_ids": ["77777777-7777-7777-7777-777777777777"],
                "notification": {"event_type": "contract_drift_patterns_promoted", "sent": True},
            },
        },
    )

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[None]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.post(
            "/api/system/contracts/drift/trigger",
            headers={"Idempotency-Key": "idem-contract-drift-execute"},
            json={"org_id": "11111111-1111-1111-1111-111111111111"},
        )
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["executed"] is True
    assert payload["data"]["promote_result"]["created_pattern_count"] == 1


def test_contract_drift_trigger_summary_happy_path(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-contract-trigger-summary",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "admin-key",
        "role": "admin",
    }
    stats_row = (5, 3, 1, 1, 0, "2026-02-25T00:00:00Z")
    events_rows = [
        (
            "req-1",
            200,
            "CONTRACT_DRIFT_TRIGGER_EXECUTED",
            "2026-02-25T00:00:00Z",
            "/api/system/contracts/drift/trigger?schedule_name=daily&dedupe_key=x",
        ),
        (
            "req-2",
            200,
            "CONTRACT_DRIFT_TRIGGER_DEDUPED",
            "2026-02-24T00:00:00Z",
            "/api/system/contracts/drift/trigger?schedule_name=daily&dedupe_key=y",
        ),
    ]

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[stats_row], fetchall_values=[events_rows]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.get(
            "/api/system/contracts/drift/trigger-summary?org_id=11111111-1111-1111-1111-111111111111&schedule_name=daily"
        )
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["trigger_count"] == 5
    assert payload["data"]["executed_count"] == 3
    assert payload["data"]["deduped_count"] == 1
    assert payload["data"]["count"] == 2


def test_notify_contract_drift_trigger_summary_dry_run(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-contract-trigger-notify",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "admin-key",
        "role": "admin",
    }
    monkeypatch.setattr(
        api_main,
        "_compute_contract_drift_trigger_summary_data",
        lambda **_kwargs: api_main.ContractDriftTriggerSummaryData(
            org_id="11111111-1111-1111-1111-111111111111",
            schedule_name="daily",
            window_days=30,
            trigger_count=10,
            executed_count=2,
            deduped_count=7,
            policy_disabled_count=1,
            promotion_disabled_count=0,
            execution_rate=0.2,
            dedupe_hit_rate=0.7,
            last_triggered_at="2026-02-25T00:00:00Z",
            items=[],
            count=0,
            limit=50,
        ),
    )
    monkeypatch.setattr(
        api_main,
        "_get_contract_drift_policy",
        lambda _org_id: {
            "alert_enabled": True,
            "alert_max_dedupe_hit_rate": 0.5,
            "alert_min_execution_rate": 0.8,
            "alert_cooldown_minutes": 60,
        },
    )
    monkeypatch.setattr(api_main, "_record_api_audit_log", lambda **_kwargs: None)

    try:
        response = client.post(
            "/api/system/contracts/drift/trigger-summary/notify",
            headers={"Idempotency-Key": "idem-contract-drift-notify-dry-1"},
            json={
                "org_id": "11111111-1111-1111-1111-111111111111",
                "schedule_name": "daily",
                "window_days": 30,
                "dry_run": True,
            },
        )
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["anomaly_detected"] is True
    assert payload["data"]["dry_run"] is True
    assert payload["data"]["notified"] is False
    assert len(payload["data"]["alerts"]) >= 1


def test_notify_contract_drift_trigger_summary_creates_escalation_pattern_on_failed_send(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-contract-trigger-notify-failed-send",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "admin-key",
        "role": "admin",
    }
    monkeypatch.setattr(
        api_main,
        "_compute_contract_drift_trigger_summary_data",
        lambda **_kwargs: api_main.ContractDriftTriggerSummaryData(
            org_id="11111111-1111-1111-1111-111111111111",
            schedule_name="daily",
            window_days=30,
            trigger_count=4,
            executed_count=1,
            deduped_count=2,
            policy_disabled_count=1,
            promotion_disabled_count=0,
            execution_rate=0.25,
            dedupe_hit_rate=0.5,
            last_triggered_at="2026-02-25T00:00:00Z",
            items=[],
            count=0,
            limit=50,
        ),
    )
    monkeypatch.setattr(
        api_main,
        "_get_contract_drift_policy",
        lambda _org_id: {
            "alert_enabled": True,
            "alert_max_dedupe_hit_rate": 0.3,
            "alert_min_execution_rate": 0.8,
            "alert_cooldown_minutes": 60,
        },
    )
    monkeypatch.setattr(
        api_main,
        "_dispatch_notification",
        lambda **_kwargs: {"event_type": "contract_drift_trigger_anomaly", "sent": False, "error": "send failed"},
    )
    monkeypatch.setattr(
        api_main,
        "_resolve_contract_drift_escalation_agent_id",
        lambda **_kwargs: "22222222-2222-2222-2222-222222222222",
    )
    monkeypatch.setattr(
        api_main,
        "_create_or_reuse_contract_drift_notify_failure_pattern",
        lambda **_kwargs: {"created": True, "pattern_id": "33333333-3333-3333-3333-333333333333"},
    )
    monkeypatch.setattr(api_main, "_record_api_audit_log", lambda **_kwargs: None)

    try:
        response = client.post(
            "/api/system/contracts/drift/trigger-summary/notify",
            headers={"Idempotency-Key": "idem-contract-drift-notify-failed-send-1"},
            json={
                "org_id": "11111111-1111-1111-1111-111111111111",
                "schedule_name": "daily",
                "agent_id": "22222222-2222-2222-2222-222222222222",
                "window_days": 30,
                "dry_run": False,
                "force_notify": True,
            },
        )
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["notified"] is False
    assert payload["data"]["notification"]["sent"] is False
    assert payload["data"]["escalation_pattern"]["created"] is True
    assert payload["data"]["escalation_pattern"]["pattern_id"] == "33333333-3333-3333-3333-333333333333"


def test_get_contract_drift_trigger_alert_delivery_happy_path(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-contract-trigger-alert-delivery",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "admin-key",
        "role": "admin",
    }
    stats_row = (12, 5, 1, 2, 3, 1, "2026-02-25T00:00:00Z", "2026-02-24T00:00:00Z", "2026-02-23T00:00:00Z", "2026-02-22T00:00:00Z")
    state_row = ("2026-02-25T00:00:00Z",)

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[stats_row, state_row]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    try:
        response = client.get(
            "/api/system/contracts/drift/trigger-alert-delivery?org_id=11111111-1111-1111-1111-111111111111&schedule_name=daily&window_days=30"
        )
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["total_notify_events"] == 12
    assert payload["data"]["sent_count"] == 5
    assert payload["data"]["suppressed_count"] == 2


def test_run_contract_drift_schedule_happy_path(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "k-contract-drift-schedule-run",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "admin-key",
        "role": "admin",
    }
    monkeypatch.setattr(
        api_main,
        "_get_contract_drift_policy",
        lambda _org_id: {"schedule_name": "daily", "schedule_window_minutes": 1440},
    )
    monkeypatch.setattr(
        api_main,
        "trigger_contract_drift_policy",
        lambda **_kwargs: {
            "ok": True,
            "data": {
                "org_id": "11111111-1111-1111-1111-111111111111",
                "schedule_name": "daily",
                "window_minutes": 1440,
                "window_started_at": "2026-02-25T00:00:00Z",
                "dedupe_key": "daily:2026-02-25T00:00:00Z",
                "executed": True,
                "deduped": False,
                "policy_enabled": True,
                "min_drift": "breaking",
                "scan_limit": 200,
                "dry_run": False,
                "reason": None,
                "promote_result": None,
            },
        },
    )
    monkeypatch.setattr(
        api_main,
        "notify_contract_drift_trigger_summary",
        lambda **_kwargs: {
            "ok": True,
            "data": {
                "org_id": "11111111-1111-1111-1111-111111111111",
                "schedule_name": "daily",
                "window_days": 30,
                "anomaly_detected": False,
                "dedupe_hit_rate": 0.1,
                "execution_rate": 1.0,
                "threshold_max_dedupe_hit_rate": 0.7,
                "threshold_min_execution_rate": 0.5,
                "alerts": [],
                "dry_run": False,
                "notified": False,
                "notification": {"event_type": "contract_drift_trigger_anomaly", "sent": False},
                "summary": {
                    "org_id": "11111111-1111-1111-1111-111111111111",
                    "schedule_name": "daily",
                    "window_days": 30,
                    "trigger_count": 2,
                    "executed_count": 2,
                    "deduped_count": 0,
                    "policy_disabled_count": 0,
                    "promotion_disabled_count": 0,
                    "execution_rate": 1.0,
                    "dedupe_hit_rate": 0.0,
                    "last_triggered_at": "2026-02-25T00:00:00Z",
                    "items": [],
                    "count": 0,
                    "limit": 50,
                },
            },
        },
    )
    monkeypatch.setattr(api_main, "_record_api_audit_log", lambda **_kwargs: None)

    try:
        response = client.post(
            "/api/system/contracts/drift/schedule-run",
            headers={"Idempotency-Key": "idem-contract-drift-schedule-run-1"},
            json={"org_id": "11111111-1111-1111-1111-111111111111"},
        )
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["schedule_name"] == "daily"
    assert payload["data"]["trigger"]["executed"] is True
    assert payload["data"]["notify"]["anomaly_detected"] is False


def test_promote_contract_drift_patterns_dry_run(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k-contract-drift-promote-dry",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }
    monkeypatch.setattr(
        api_main,
        "get_contract_drift",
        lambda **_kwargs: {
            "ok": True,
            "data": {
                "items": [
                    {
                        "agent_id": "22222222-2222-2222-2222-222222222222",
                        "definition_type": "gate",
                        "binding_id": "44444444-4444-4444-4444-444444444444",
                        "definition_id": "33333333-3333-3333-3333-333333333333",
                        "definition_key": "golden_set_quality",
                        "bound_contract_version": "1.0.0",
                        "current_contract_version": "2.0.0",
                        "drift": "breaking",
                        "severity": "error",
                        "message": "Major version mismatch.",
                    }
                ]
            },
        },
    )
    monkeypatch.setattr(
        api_main,
        "_dispatch_notification",
        lambda **_kwargs: {"event_type": "contract_drift_patterns_promoted", "sent": True},
    )
    monkeypatch.setattr(api_main, "_record_activity_event", lambda **_kwargs: None)
    try:
        response = client.post(
            "/api/contracts/drift/promote-patterns",
            json={
                "org_id": "11111111-1111-1111-1111-111111111111",
                "min_drift": "breaking",
                "dry_run": True,
            },
        )
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["scanned_item_count"] == 1
    assert payload["data"]["eligible_item_count"] == 1
    assert payload["data"]["created_pattern_count"] == 0
    assert payload["data"]["reused_pattern_count"] == 0
    assert payload["data"]["notification"]["event_type"] == "contract_drift_patterns_promoted"


def test_promote_contract_drift_patterns_create_and_reuse(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k-contract-drift-promote",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }
    monkeypatch.setattr(
        api_main,
        "get_contract_drift",
        lambda **_kwargs: {
            "ok": True,
            "data": {
                "items": [
                    {
                        "agent_id": "22222222-2222-2222-2222-222222222222",
                        "definition_type": "gate",
                        "binding_id": "44444444-4444-4444-4444-444444444444",
                        "definition_id": "33333333-3333-3333-3333-333333333333",
                        "definition_key": "golden_set_quality",
                        "bound_contract_version": "1.0.0",
                        "current_contract_version": "2.0.0",
                        "drift": "breaking",
                        "severity": "error",
                        "message": "Major version mismatch.",
                    },
                    {
                        "agent_id": "22222222-2222-2222-2222-222222222222",
                        "definition_type": "evaluator",
                        "binding_id": "55555555-5555-5555-5555-555555555555",
                        "definition_id": "66666666-6666-6666-6666-666666666666",
                        "definition_key": "builtin_answer_deterministic",
                        "bound_contract_version": "1.0.0",
                        "current_contract_version": "1.2.0",
                        "drift": "warning",
                        "severity": "warning",
                        "message": "Minor/patch drift.",
                    },
                ]
            },
        },
    )
    calls: List[Dict[str, Any]] = []

    def _fake_create_or_reuse(**kwargs: Any) -> Dict[str, Any]:
        calls.append(kwargs)
        if len(calls) == 1:
            return {"created": True, "pattern_id": "77777777-7777-7777-7777-777777777777"}
        return {"created": False, "pattern_id": "88888888-8888-8888-8888-888888888888"}

    monkeypatch.setattr(api_main, "_create_or_reuse_contract_drift_pattern", _fake_create_or_reuse)
    monkeypatch.setattr(api_main, "_record_activity_event", lambda **_kwargs: None)
    monkeypatch.setattr(
        api_main,
        "_dispatch_notification",
        lambda **_kwargs: {"event_type": "contract_drift_patterns_promoted", "queued": True, "sent": False},
    )
    try:
        response = client.post(
            "/api/contracts/drift/promote-patterns",
            json={
                "org_id": "11111111-1111-1111-1111-111111111111",
                "min_drift": "warning",
                "dry_run": False,
            },
        )
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["eligible_item_count"] == 2
    assert payload["data"]["created_pattern_count"] == 1
    assert payload["data"]["reused_pattern_count"] == 1
    assert len(payload["data"]["pattern_ids"]) == 2
    assert payload["data"]["notification"]["event_type"] == "contract_drift_patterns_promoted"


def test_start_eval_run_blocked_by_sync_only_handler(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k-run-type-start-mode",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }
    run_row = (
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
        "33333333-3333-3333-3333-333333333333",
        "eval",
        "pending",
        {},
    )

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[run_row]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    monkeypatch.setattr(
        api_main,
        "_resolve_run_type_handler",
        lambda **_kwargs: {"handler_key": "sync_only", "handler_config": {}, "binding": None},
    )
    try:
        response = client.post("/api/eval/runs/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/start")
    finally:
        app.dependency_overrides.clear()
    assert response.status_code == 409
    _assert_error_envelope(response.json(), "EVAL_RUN_HANDLER_MODE_INVALID")


def test_get_agent_contract_status_happy_path(monkeypatch) -> None:
    app.dependency_overrides[api_main.require_viewer] = lambda: {
        "key_id": "k-contract-status",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "viewer-key",
        "role": "viewer",
    }
    agent_row = ("22222222-2222-2222-2222-222222222222", "11111111-1111-1111-1111-111111111111")

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[agent_row]))

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    monkeypatch.setattr(
        api_main,
        "_compute_agent_contract_issues",
        lambda **_kwargs: {
            "status": "pass",
            "issues": [],
            "resolved_handler_key": "default",
            "enabled_gate_binding_count": 1,
            "enabled_evaluator_binding_count": 1,
        },
    )
    try:
        response = client.get("/api/agents/22222222-2222-2222-2222-222222222222/contract-status?run_type=eval&entrypoint=start")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["ok"] is True
    assert payload["data"]["status"] == "pass"
    assert payload["data"]["resolved_handler_key"] == "default"


def test_start_eval_run_blocked_by_agent_contract_validation(monkeypatch) -> None:
    api_main._RATE_LIMIT_STATE.clear()
    app.dependency_overrides[api_main.require_member] = lambda: {
        "key_id": "k-contract-start",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "name": "member-key",
        "role": "member",
    }
    run_row = (
        "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "11111111-1111-1111-1111-111111111111",
        "22222222-2222-2222-2222-222222222222",
        "33333333-3333-3333-3333-333333333333",
        "eval",
        "pending",
        {},
    )

    def _fake_get_conn() -> _FakeConn:
        return _FakeConn(_FakeCursor(fetchone_values=[run_row]))

    def _fail_contract(**_kwargs: Any) -> None:
        api_main._error("AGENT_CONTRACT_VALIDATION_FAILED", "Agent contract validation failed: broken binding", 409)

    monkeypatch.setattr(api_main, "get_conn", _fake_get_conn)
    monkeypatch.setattr(api_main, "_enforce_calibration_gate", lambda **_kwargs: None)
    monkeypatch.setattr(api_main, "_enforce_golden_set_quality_gate", lambda **_kwargs: None)
    monkeypatch.setattr(api_main, "_enforce_configured_gates", lambda **_kwargs: None)
    monkeypatch.setattr(api_main, "_enforce_agent_contract_issues", _fail_contract)
    try:
        response = client.post("/api/eval/runs/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa/start")
    finally:
        app.dependency_overrides.clear()

    assert response.status_code == 409
    _assert_error_envelope(response.json(), "AGENT_CONTRACT_VALIDATION_FAILED")
