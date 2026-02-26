from fastapi.testclient import TestClient

import src.api.main as api_main
from src.api.main import app


client = TestClient(app)


def _reset_rate_limit_state() -> None:
    api_main._RATE_LIMIT_STATE.clear()


def test_legacy_api_path_sets_deprecation_and_version_headers() -> None:
    _reset_rate_limit_state()
    response = client.get("/api/not-a-real-endpoint")

    assert response.status_code == 404
    assert response.headers.get("X-API-Version") == "v1"
    assert response.headers.get("Deprecation") == "true"


def test_v1_api_path_sets_version_header_without_deprecation() -> None:
    _reset_rate_limit_state()
    response = client.get("/api/v1/not-a-real-endpoint")

    assert response.status_code == 404
    assert response.headers.get("X-API-Version") == "v1"
    assert response.headers.get("Deprecation") is None


def test_non_api_path_has_no_api_version_headers() -> None:
    _reset_rate_limit_state()
    response = client.get("/health")

    assert response.status_code == 200
    assert response.headers.get("X-API-Version") is None
    assert response.headers.get("Deprecation") is None
