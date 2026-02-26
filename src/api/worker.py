from __future__ import annotations

import concurrent.futures
import os
import time
from datetime import UTC, datetime
from typing import Any, Dict, Optional
from uuid import UUID

from src.api.db import get_conn
from src.api.main import _drain_notification_outbox_batch, _record_activity_event, execute_eval_run


def _worker_id() -> str:
    return os.getenv("EVAL_WORKER_ID", f"worker-{os.getpid()}")


def _poll_seconds() -> float:
    return float(os.getenv("EVAL_WORKER_POLL_SECONDS", "2.0"))


def _retry_base_seconds() -> int:
    return int(os.getenv("EVAL_WORKER_RETRY_BASE_SECONDS", "15"))


def _max_retry_delay_seconds() -> int:
    return int(os.getenv("EVAL_WORKER_MAX_RETRY_DELAY_SECONDS", "900"))


def _retry_delay_seconds(attempt_count: int) -> int:
    base = max(1, _retry_base_seconds())
    max_delay = max(base, _max_retry_delay_seconds())
    retry_delay = base * (2 ** max(0, int(attempt_count) - 1))
    return min(retry_delay, max_delay)


def _heartbeat_interval_seconds() -> float:
    return float(os.getenv("EVAL_WORKER_HEARTBEAT_SECONDS", "5.0"))


def _stale_heartbeat_seconds() -> int:
    return int(os.getenv("EVAL_WORKER_STALE_HEARTBEAT_SECONDS", "60"))


def _reap_interval_seconds() -> float:
    return float(os.getenv("EVAL_WORKER_REAP_INTERVAL_SECONDS", "10.0"))


def _notify_drain_interval_seconds() -> float:
    return float(os.getenv("EVAL_WORKER_NOTIFY_DRAIN_SECONDS", "5.0"))


def _default_max_runtime_seconds() -> int:
    return int(os.getenv("EVAL_WORKER_MAX_RUNTIME_SECONDS", "900"))


def _max_concurrency_global() -> int:
    return int(os.getenv("EVAL_WORKER_MAX_CONCURRENCY_GLOBAL", "0"))


def _max_concurrency_per_org() -> int:
    return int(os.getenv("EVAL_WORKER_MAX_CONCURRENCY_PER_ORG", "0"))


def _worker_ping(worker_id: str, current_job_id: Optional[UUID] = None) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                insert into public.eval_worker_heartbeats (worker_id, current_job_id, last_seen_at, metadata)
                values (%s, %s, now(), '{}'::jsonb)
                on conflict (worker_id) do update
                set current_job_id = excluded.current_job_id,
                    last_seen_at = now()
                """,
                (worker_id, str(current_job_id) if current_job_id else None),
            )


def _claim_next_job(worker_id: str) -> Optional[Dict[str, Any]]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                with limits as (
                  select %s::int as global_cap, %s::int as org_cap
                ),
                running_global as (
                  select count(*)::int as cnt
                  from public.eval_run_jobs
                  where status = 'running'
                ),
                running_by_org as (
                  select org_id, count(*)::int as cnt
                  from public.eval_run_jobs
                  where status = 'running'
                  group by org_id
                ),
                next_org as (
                  select
                    j.org_id,
                    coalesce(rbo.cnt, 0) as running_org,
                    min(j.created_at) as oldest_queued_at
                  from public.eval_run_jobs j
                  left join running_by_org rbo on rbo.org_id = j.org_id
                  cross join limits l
                  cross join running_global rg
                  where j.status = 'queued'
                    and (j.not_before is null or j.not_before <= now())
                    and j.attempt_count < j.max_attempts
                    and (l.global_cap <= 0 or rg.cnt < l.global_cap)
                    and (l.org_cap <= 0 or coalesce(rbo.cnt, 0) < l.org_cap)
                  group by j.org_id, coalesce(rbo.cnt, 0)
                  order by running_org asc, oldest_queued_at asc, j.org_id asc
                  limit 1
                ),
                next_job as (
                  select j.id
                  from public.eval_run_jobs j
                  join next_org no on no.org_id = j.org_id
                  where j.status = 'queued'
                    and (j.not_before is null or j.not_before <= now())
                    and j.attempt_count < j.max_attempts
                  order by j.created_at asc, j.id asc
                  for update skip locked
                  limit 1
                )
                update public.eval_run_jobs j
                set
                  status = 'running',
                  locked_at = now(),
                  locked_by = %s,
                  run_started_at = now(),
                  heartbeat_at = now(),
                  max_runtime_seconds = coalesce(j.max_runtime_seconds, %s),
                  attempt_count = j.attempt_count + 1,
                  updated_at = now()
                from next_job nj
                where j.id = nj.id
                returning j.id, j.org_id, j.run_id, j.attempt_count, j.max_attempts, j.max_runtime_seconds
                """,
                (
                    _max_concurrency_global(),
                    _max_concurrency_per_org(),
                    worker_id,
                    _default_max_runtime_seconds(),
                ),
            )
            row = cur.fetchone()
            if not row:
                return None
            cur.execute("select agent_id from public.eval_runs where id = %s", (str(row[2]),))
            run_row = cur.fetchone()
            agent_id = run_row[0] if run_row else None
            return {
                "job_id": row[0],
                "org_id": row[1],
                "run_id": row[2],
                "attempt_count": int(row[3]),
                "max_attempts": int(row[4]),
                "max_runtime_seconds": int(row[5] or _default_max_runtime_seconds()),
                "agent_id": agent_id,
            }


def _heartbeat_job(job_id: UUID, worker_id: str) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                update public.eval_run_jobs
                set heartbeat_at = now(),
                    updated_at = now(),
                    locked_by = %s
                where id = %s
                  and status = 'running'
                """,
                (worker_id, str(job_id)),
            )


def _reap_stale_jobs(worker_id: str) -> list[Dict[str, Any]]:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                with stale as (
                  select id, run_id, org_id
                  from public.eval_run_jobs
                  where status = 'running'
                    and (
                      (heartbeat_at is not null and heartbeat_at < now() - (%s || ' seconds')::interval)
                      or
                      (run_started_at is not null and now() > run_started_at + (max_runtime_seconds || ' seconds')::interval)
                    )
                )
                update public.eval_run_jobs j
                set status = 'failed',
                    completed_at = now(),
                    error_message = coalesce(j.error_message, 'Job reaped: stale heartbeat or max runtime exceeded.'),
                    locked_at = null,
                    locked_by = null,
                    heartbeat_at = null,
                    updated_at = now()
                from stale s
                where j.id = s.id
                returning j.id, j.run_id, j.org_id
                """,
                (str(_stale_heartbeat_seconds()),),
            )
            rows = cur.fetchall()
            reaped: list[Dict[str, Any]] = []
            for r in rows:
                cur.execute("select agent_id from public.eval_runs where id = %s", (str(r[1]),))
                run_row = cur.fetchone()
                agent_id = run_row[0] if run_row else None
                cur.execute(
                    """
                    update public.eval_runs
                    set status = 'failed',
                        completed_at = now(),
                        failure_reason = 'Worker reaped stale/timeout job.'
                    where id = %s
                      and status = 'running'
                    """,
                    (str(r[1]),),
                )
                reaped.append({"job_id": r[0], "run_id": r[1], "org_id": r[2], "agent_id": agent_id})
            return reaped


def _complete_job_success(job_id: UUID, run_id: UUID) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                update public.eval_run_jobs
                set status = 'succeeded',
                    completed_at = now(),
                    error_message = null,
                    locked_at = null,
                    locked_by = null,
                    heartbeat_at = null,
                    updated_at = now()
                where id = %s
                  and run_id = %s
                  and status = 'running'
                """,
                (str(job_id), str(run_id)),
            )


def _complete_job_cancelled(job_id: UUID, run_id: UUID) -> None:
    with get_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                update public.eval_run_jobs
                set status = 'cancelled',
                    cancelled_at = coalesce(cancelled_at, now()),
                    completed_at = coalesce(completed_at, now()),
                    error_message = coalesce(error_message, 'Cancelled during execution.'),
                    locked_at = null,
                    locked_by = null,
                    heartbeat_at = null,
                    updated_at = now()
                where id = %s
                  and run_id = %s
                  and status = 'running'
                """,
                (str(job_id), str(run_id)),
            )


def _complete_job_failure(job: Dict[str, Any], error_message: str) -> None:
    job_id = UUID(str(job["job_id"]))
    run_id = UUID(str(job["run_id"]))
    attempt_count = int(job["attempt_count"])
    max_attempts = int(job["max_attempts"])
    retryable = attempt_count < max_attempts
    retry_delay = _retry_delay_seconds(attempt_count)

    with get_conn() as conn:
        with conn.cursor() as cur:
            if retryable:
                cur.execute(
                    """
                    update public.eval_run_jobs
                    set status = 'queued',
                        not_before = now() + (%s || ' seconds')::interval,
                        error_message = %s,
                        locked_at = null,
                        locked_by = null,
                        heartbeat_at = null,
                        updated_at = now()
                    where id = %s
                      and run_id = %s
                      and status = 'running'
                    """,
                    (str(retry_delay), error_message[:2000], str(job_id), str(run_id)),
                )
            else:
                cur.execute(
                    """
                    update public.eval_run_jobs
                    set status = 'failed',
                        completed_at = now(),
                        error_message = %s,
                        locked_at = null,
                        locked_by = null,
                        heartbeat_at = null,
                        updated_at = now()
                    where id = %s
                      and run_id = %s
                      and status = 'running'
                    """,
                    (error_message[:2000], str(job_id), str(run_id)),
                )


def run_worker_loop() -> None:
    wid = _worker_id()
    poll = _poll_seconds()
    heartbeat_every = _heartbeat_interval_seconds()
    reap_every = _reap_interval_seconds()
    notify_drain_every = _notify_drain_interval_seconds()
    last_reap = 0.0
    last_notify_drain = 0.0
    print(f"[eval-worker] started worker_id={wid} poll={poll}s heartbeat={heartbeat_every}s at {datetime.now(UTC).isoformat()}")
    while True:
        now_mono = time.monotonic()
        if now_mono - last_reap >= reap_every:
            for stale in _reap_stale_jobs(wid):
                agent_id_raw = stale.get("agent_id")
                if agent_id_raw:
                    _record_activity_event(
                        org_id=UUID(str(stale["org_id"])),
                        agent_id=UUID(str(agent_id_raw)),
                        event_type="run_reaped",
                        title="Eval run reaped by worker watchdog",
                        details=f"run_id={str(stale['run_id'])[:8]}",
                        severity="error",
                        metadata={"run_id": str(stale["run_id"]), "job_id": str(stale["job_id"]), "worker_id": wid},
                    )
            last_reap = now_mono

        if now_mono - last_notify_drain >= notify_drain_every:
            _drain_notification_outbox_batch(limit=20)
            last_notify_drain = now_mono

        _worker_ping(wid, None)
        job = _claim_next_job(wid)
        if not job:
            time.sleep(poll)
            continue

        run_id = UUID(str(job["run_id"]))
        org_id = UUID(str(job["org_id"]))
        agent_id_raw = job.get("agent_id")
        agent_id = UUID(str(agent_id_raw)) if agent_id_raw else None
        job_id = UUID(str(job["job_id"]))
        max_runtime_seconds = int(job.get("max_runtime_seconds") or _default_max_runtime_seconds())
        job_started = time.monotonic()
        _worker_ping(wid, job_id)

        if agent_id:
            _record_activity_event(
                org_id=org_id,
                agent_id=agent_id,
                event_type="run_started",
                title="Eval run started by worker",
                details=f"run_id={str(run_id)[:8]}, attempt={job['attempt_count']}",
                severity="info",
                metadata={"run_id": str(run_id), "job_id": str(job["job_id"]), "worker_id": wid},
            )
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(
                    execute_eval_run,
                    run_id=run_id,
                    api_key_ctx={"key_id": "worker", "org_id": None, "name": wid, "role": "admin"},
                )
                result: Optional[Dict[str, Any]] = None
                while True:
                    try:
                        result = future.result(timeout=heartbeat_every)
                        break
                    except concurrent.futures.TimeoutError:
                        _heartbeat_job(job_id, wid)
                        _worker_ping(wid, job_id)
                        elapsed = time.monotonic() - job_started
                        if elapsed > max_runtime_seconds:
                            raise TimeoutError(f"Job exceeded max runtime ({max_runtime_seconds}s).")
            result_status = None
            if isinstance(result, dict):
                result_data = result.get("data")
                if isinstance(result_data, dict):
                    result_status = result_data.get("status")
            if str(result_status) == "cancelled":
                _complete_job_cancelled(job_id, run_id)
            else:
                _complete_job_success(job_id, run_id)
        except Exception as exc:
            _worker_ping(wid, None)
            _complete_job_failure(job, str(exc))
            if agent_id:
                _record_activity_event(
                    org_id=org_id,
                    agent_id=agent_id,
                    event_type="run_worker_error",
                    title="Eval run worker error",
                    details=f"run_id={str(run_id)[:8]}",
                    severity="error",
                    metadata={"run_id": str(run_id), "job_id": str(job["job_id"]), "worker_id": wid, "error": str(exc)},
                )
            continue

        _worker_ping(wid, None)


if __name__ == "__main__":
    run_worker_loop()
