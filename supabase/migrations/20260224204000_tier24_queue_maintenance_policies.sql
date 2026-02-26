begin;

create table if not exists public.queue_maintenance_policies (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null unique references public.orgs(id) on delete cascade,
  stale_heartbeat_seconds integer not null default 60 check (stale_heartbeat_seconds between 5 and 86400),
  max_runtime_seconds integer not null default 900 check (max_runtime_seconds between 30 and 86400),
  retention_days integer not null default 14 check (retention_days between 1 and 3650),
  reap_limit integer not null default 100 check (reap_limit between 1 and 5000),
  prune_limit integer not null default 500 check (prune_limit between 1 and 10000),
  updated_by_api_key_id uuid null references public.api_keys(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_queue_maintenance_policies_org on public.queue_maintenance_policies(org_id);

drop trigger if exists trg_queue_maintenance_policies_updated_at on public.queue_maintenance_policies;
create trigger trg_queue_maintenance_policies_updated_at
before update on public.queue_maintenance_policies
for each row execute function public.set_updated_at();

alter table public.queue_maintenance_policies enable row level security;

drop policy if exists queue_maintenance_policies_select_none on public.queue_maintenance_policies;
create policy queue_maintenance_policies_select_none
on public.queue_maintenance_policies
for select
to authenticated
using (false);

drop policy if exists queue_maintenance_policies_modify_none on public.queue_maintenance_policies;
create policy queue_maintenance_policies_modify_none
on public.queue_maintenance_policies
for all
to authenticated
using (false)
with check (false);

commit;
