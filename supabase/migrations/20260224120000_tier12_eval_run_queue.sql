-- Tier 12: Eval run async queue

create table if not exists public.eval_run_jobs (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  run_id uuid not null references public.eval_runs(id) on delete cascade,
  status text not null check (status in ('queued', 'running', 'succeeded', 'failed', 'cancelled')),
  attempt_count integer not null default 0 check (attempt_count >= 0),
  max_attempts integer not null default 3 check (max_attempts >= 1),
  not_before timestamptz null,
  locked_at timestamptz null,
  locked_by text null,
  error_message text null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  completed_at timestamptz null,
  cancelled_at timestamptz null
);

create index if not exists idx_eval_run_jobs_status_not_before
  on public.eval_run_jobs(status, not_before, created_at);

create unique index if not exists uq_eval_run_jobs_active_run
  on public.eval_run_jobs(run_id)
  where status in ('queued', 'running');

create trigger trg_eval_run_jobs_updated_at
before update on public.eval_run_jobs
for each row execute procedure public.set_updated_at();

alter table public.eval_run_jobs enable row level security;

create policy "eval_run_jobs_select_member"
on public.eval_run_jobs
for select
to authenticated
using (public.is_org_member(org_id));

create policy "eval_run_jobs_insert_member"
on public.eval_run_jobs
for insert
to authenticated
with check (public.has_org_role(org_id, array['admin','member']::public.member_role[]));

create policy "eval_run_jobs_update_member"
on public.eval_run_jobs
for update
to authenticated
using (public.has_org_role(org_id, array['admin','member']::public.member_role[]))
with check (public.has_org_role(org_id, array['admin','member']::public.member_role[]));
