alter table public.eval_runs
  drop constraint if exists eval_runs_completed_timestamp;

alter table public.eval_runs
  add constraint eval_runs_completed_timestamp check (
    (status in ('pending', 'running') and completed_at is null) or
    (status in ('completed', 'failed', 'cancelled') and completed_at is not null)
  );
