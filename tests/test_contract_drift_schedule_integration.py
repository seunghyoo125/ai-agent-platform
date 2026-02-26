from __future__ import annotations

import os
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient

import src.api.main as api_main
from src.api.main import app


client = TestClient(app)


def _integration_enabled() -> bool:
    return os.getenv("RUN_DB_INTEGRATION", "0") == "1"


@pytest.mark.skipif(not _integration_enabled(), reason="Set RUN_DB_INTEGRATION=1 to run DB integration tests")
def test_contract_drift_schedule_run_db_integration() -> None:
    org_id = str(uuid4())
    agent_id = str(uuid4())

    with api_main.get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                insert into public.orgs (id, name, slug)
                values (%s, %s, %s)
                """,
                (org_id, f"Integration Org {org_id[:8]}", f"integration-org-{org_id[:8]}"),
            )
            cur.execute(
                """
                insert into public.agents (
                    id, org_id, name, description, agent_type, status, model
                )
                values (%s, %s, %s, %s, 'search_retrieval'::public.agent_type, 'build'::public.agent_status, %s)
                """,
                (
                    agent_id,
                    org_id,
                    f"Integration Agent {agent_id[:8]}",
                    "Integration test agent for contract drift schedule",
                    "gpt-4.1-mini",
                ),
            )

    app.dependency_overrides[api_main.require_admin] = lambda: {
        "key_id": "00000000-0000-0000-0000-000000000001",
        "org_id": org_id,
        "name": "integration-admin",
        "role": "admin",
    }
    try:
        policy_resp = client.post(
            "/api/system/contracts/drift-policy",
            json={
                "org_id": org_id,
                "enabled": True,
                "min_drift": "breaking",
                "promote_to_patterns": True,
                "scan_limit": 200,
                "schedule_name": "integration-daily",
                "schedule_window_minutes": 1440,
                "alert_enabled": True,
                "alert_max_dedupe_hit_rate": 0.7,
                "alert_min_execution_rate": 0.5,
                "alert_cooldown_minutes": 60,
            },
        )
        assert policy_resp.status_code == 200
        assert policy_resp.json()["ok"] is True

        resp = client.post(
            "/api/system/contracts/drift/schedule-run",
            headers={"Idempotency-Key": f"integration-contract-drift-{uuid4()}"},
            json={
                "org_id": org_id,
                "schedule_name": "integration-daily",
                "window_minutes": 1440,
                "summary_window_days": 30,
                "dry_run": True,
                "force": True,
                "force_notify": False,
                "agent_id": agent_id,
            },
        )
    finally:
        app.dependency_overrides.clear()

    assert resp.status_code == 200
    payload = resp.json()
    assert payload["ok"] is True
    assert payload["data"]["org_id"] == org_id
    assert payload["data"]["trigger"]["schedule_name"] == "integration-daily"
    assert payload["data"]["notify"]["schedule_name"] == "integration-daily"
