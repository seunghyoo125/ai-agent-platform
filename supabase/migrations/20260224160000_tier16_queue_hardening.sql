begin;

alter table public.eval_run_jobs
  add column if not exists run_started_at timestamptz,
  add column if not exists heartbeat_at timestamptz,
  add column if not exists max_runtime_seconds integer not null default 900;

do $$
begin
  if not exists (
    select 1 from pg_constraint where conname = 'eval_run_jobs_max_runtime_seconds_positive'
  ) then
    alter table public.eval_run_jobs
      add constraint eval_run_jobs_max_runtime_seconds_positive check (max_runtime_seconds > 0);
  end if;
end
$$;

create index if not exists idx_eval_run_jobs_running_heartbeat
  on public.eval_run_jobs(status, heartbeat_at, run_started_at)
  where status = 'running';

create table if not exists public.eval_worker_heartbeats (
  worker_id text primary key,
  current_job_id uuid references public.eval_run_jobs(id) on delete set null,
  last_seen_at timestamptz not null default now(),
  metadata jsonb not null default '{}'::jsonb
);

commit;
