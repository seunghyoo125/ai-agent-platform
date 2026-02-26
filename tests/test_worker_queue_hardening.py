from __future__ import annotations

from typing import Any

import pytest

import src.api.worker as worker


class _CaptureCursor:
    def __init__(self, fetchone_values: list[Any] | None = None):
        self.fetchone_values = list(fetchone_values or [])
        self.executed_sql: list[str] = []

    def __enter__(self) -> "_CaptureCursor":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False

    def execute(self, sql: str, _params: Any = None) -> None:
        self.executed_sql.append(sql)

    def fetchone(self) -> Any:
        if self.fetchone_values:
            return self.fetchone_values.pop(0)
        return None


class _CaptureConn:
    def __init__(self, cursor: _CaptureCursor):
        self._cursor = cursor

    def __enter__(self) -> "_CaptureConn":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False

    def cursor(self) -> _CaptureCursor:
        return self._cursor


def test_claim_query_enforces_attempt_guard_and_deterministic_order(monkeypatch) -> None:
    cursor = _CaptureCursor(fetchone_values=[None])

    monkeypatch.setattr(worker, "get_conn", lambda: _CaptureConn(cursor))
    result = worker._claim_next_job("worker-test")

    assert result is None
    assert cursor.executed_sql
    sql = cursor.executed_sql[0]
    assert "and j.attempt_count < j.max_attempts" in sql
    assert "and (l.global_cap <= 0 or rg.cnt < l.global_cap)" in sql
    assert "running_by_org" in sql
    assert "next_org" in sql
    assert "and (l.org_cap <= 0 or coalesce(rbo.cnt, 0) < l.org_cap)" in sql
    assert "order by running_org asc, oldest_queued_at asc, j.org_id asc" in sql
    assert "join next_org no on no.org_id = j.org_id" in sql
    assert "order by j.created_at asc, j.id asc" in sql
    assert "for update skip locked" in sql


def test_retry_delay_is_deterministic_and_capped(monkeypatch) -> None:
    monkeypatch.setenv("EVAL_WORKER_RETRY_BASE_SECONDS", "15")
    monkeypatch.setenv("EVAL_WORKER_MAX_RETRY_DELAY_SECONDS", "20")

    assert worker._retry_delay_seconds(1) == 15
    assert worker._retry_delay_seconds(2) == 20
    assert worker._retry_delay_seconds(3) == 20


def test_worker_concurrency_env_defaults_and_override(monkeypatch) -> None:
    monkeypatch.delenv("EVAL_WORKER_MAX_CONCURRENCY_GLOBAL", raising=False)
    monkeypatch.delenv("EVAL_WORKER_MAX_CONCURRENCY_PER_ORG", raising=False)
    assert worker._max_concurrency_global() == 0
    assert worker._max_concurrency_per_org() == 0

    monkeypatch.setenv("EVAL_WORKER_MAX_CONCURRENCY_GLOBAL", "4")
    monkeypatch.setenv("EVAL_WORKER_MAX_CONCURRENCY_PER_ORG", "2")
    assert worker._max_concurrency_global() == 4
    assert worker._max_concurrency_per_org() == 2


def test_worker_marks_job_cancelled_when_execute_returns_cancelled(monkeypatch) -> None:
    job = {
        "job_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
        "org_id": "11111111-1111-1111-1111-111111111111",
        "run_id": "22222222-2222-2222-2222-222222222222",
        "attempt_count": 1,
        "max_attempts": 3,
        "max_runtime_seconds": 30,
        "agent_id": None,
    }
    jobs = [job]
    cancelled_calls: list[tuple[str, str]] = []
    success_calls: list[tuple[str, str]] = []
    failure_calls: list[str] = []

    monkeypatch.setattr(worker, "_worker_id", lambda: "worker-test")
    monkeypatch.setattr(worker, "_poll_seconds", lambda: 0.01)
    monkeypatch.setattr(worker, "_heartbeat_interval_seconds", lambda: 0.01)
    monkeypatch.setattr(worker, "_reap_interval_seconds", lambda: 9999.0)
    monkeypatch.setattr(worker, "_notify_drain_interval_seconds", lambda: 9999.0)
    monkeypatch.setattr(worker, "_reap_stale_jobs", lambda _wid: [])
    monkeypatch.setattr(worker, "_drain_notification_outbox_batch", lambda limit=20: {"picked": 0, "sent": 0, "failed": 0, "dead": 0})
    monkeypatch.setattr(worker, "_worker_ping", lambda _wid, _job_id=None: None)
    monkeypatch.setattr(worker, "_record_activity_event", lambda **_kwargs: None)
    monkeypatch.setattr(worker, "_claim_next_job", lambda _wid: jobs.pop(0) if jobs else None)
    monkeypatch.setattr(
        worker,
        "execute_eval_run",
        lambda run_id, api_key_ctx: {"ok": True, "data": {"status": "cancelled", "run_id": str(run_id)}},
    )
    monkeypatch.setattr(
        worker,
        "_complete_job_cancelled",
        lambda job_id, run_id: cancelled_calls.append((str(job_id), str(run_id))),
    )
    monkeypatch.setattr(
        worker,
        "_complete_job_success",
        lambda job_id, run_id: success_calls.append((str(job_id), str(run_id))),
    )
    monkeypatch.setattr(worker, "_complete_job_failure", lambda _job, error_message: failure_calls.append(error_message))
    monkeypatch.setattr(worker.time, "sleep", lambda _seconds: (_ for _ in ()).throw(KeyboardInterrupt()))

    with pytest.raises(KeyboardInterrupt):
        worker.run_worker_loop()

    assert len(cancelled_calls) == 1
    assert not success_calls
    assert not failure_calls
