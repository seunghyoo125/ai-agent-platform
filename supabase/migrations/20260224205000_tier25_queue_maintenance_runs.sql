begin;

create table if not exists public.queue_maintenance_runs (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  dry_run boolean not null default true,
  status text not null default 'running' check (status in ('running', 'completed', 'failed')),
  policy_snapshot jsonb not null default '{}'::jsonb,
  reap_summary jsonb null,
  prune_summary jsonb null,
  error_message text null,
  duration_ms integer null,
  triggered_by_api_key_id uuid null references public.api_keys(id) on delete set null,
  started_at timestamptz not null default now(),
  completed_at timestamptz null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_queue_maintenance_runs_org_started
  on public.queue_maintenance_runs(org_id, started_at desc);

create index if not exists idx_queue_maintenance_runs_status_started
  on public.queue_maintenance_runs(status, started_at desc);

drop trigger if exists trg_queue_maintenance_runs_updated_at on public.queue_maintenance_runs;
create trigger trg_queue_maintenance_runs_updated_at
before update on public.queue_maintenance_runs
for each row execute function public.set_updated_at();

alter table public.queue_maintenance_runs enable row level security;

drop policy if exists queue_maintenance_runs_select_none on public.queue_maintenance_runs;
create policy queue_maintenance_runs_select_none
on public.queue_maintenance_runs
for select
to authenticated
using (false);

drop policy if exists queue_maintenance_runs_modify_none on public.queue_maintenance_runs;
create policy queue_maintenance_runs_modify_none
on public.queue_maintenance_runs
for all
to authenticated
using (false)
with check (false);

commit;
