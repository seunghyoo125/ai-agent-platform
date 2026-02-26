create or replace function public.enforce_eval_run_status_transition()
returns trigger
language plpgsql
as $$
begin
  if tg_op = 'UPDATE' and new.status is distinct from old.status then
    if old.status = 'pending' and new.status in ('running', 'cancelled') then
      return new;
    elsif old.status = 'running' and new.status in ('completed', 'failed', 'cancelled') then
      return new;
    elsif old.status in ('completed', 'failed', 'cancelled') and new.status = 'pending' then
      return new;
    else
      raise exception 'Invalid eval_runs status transition: % -> %', old.status, new.status
        using errcode = '23514';
    end if;
  end if;
  return new;
end;
$$;

drop trigger if exists trg_eval_runs_status_transition_guard on public.eval_runs;

create trigger trg_eval_runs_status_transition_guard
before update on public.eval_runs
for each row
execute function public.enforce_eval_run_status_transition();
