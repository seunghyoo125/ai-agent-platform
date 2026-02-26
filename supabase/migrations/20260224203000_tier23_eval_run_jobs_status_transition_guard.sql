create or replace function public.enforce_eval_run_jobs_status_transition()
returns trigger
language plpgsql
as $$
begin
  if tg_op = 'UPDATE' and new.status is distinct from old.status then
    if old.status = 'queued' and new.status in ('running', 'cancelled') then
      return new;
    elsif old.status = 'running' and new.status in ('succeeded', 'failed', 'cancelled', 'queued') then
      return new;
    elsif old.status = 'failed' and new.status = 'queued' then
      return new;
    else
      raise exception 'Invalid eval_run_jobs status transition: % -> %', old.status, new.status
        using errcode = '23514';
    end if;
  end if;
  return new;
end;
$$;

drop trigger if exists trg_eval_run_jobs_status_transition_guard on public.eval_run_jobs;

create trigger trg_eval_run_jobs_status_transition_guard
before update on public.eval_run_jobs
for each row
execute function public.enforce_eval_run_jobs_status_transition();
