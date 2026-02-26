begin;

create table if not exists public.run_registry (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  agent_id uuid not null references public.agents(id) on delete cascade,
  kind text not null check (kind in ('baseline', 'candidate')),
  name text not null,
  run_id uuid not null references public.eval_runs(id) on delete cascade,
  is_active boolean not null default true,
  notes text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint run_registry_name_per_kind unique (agent_id, kind, name)
);

create index if not exists idx_run_registry_org_agent_kind
  on public.run_registry(org_id, agent_id, kind, is_active, updated_at desc);

create unique index if not exists uq_run_registry_active_kind
  on public.run_registry(agent_id, kind)
  where is_active = true;

drop trigger if exists trg_run_registry_set_updated_at on public.run_registry;
create trigger trg_run_registry_set_updated_at
before update on public.run_registry
for each row
execute function public.set_updated_at();

alter table public.run_registry enable row level security;

drop policy if exists run_registry_select_member on public.run_registry;
create policy run_registry_select_member
on public.run_registry
for select
to authenticated
using (public.is_org_member(org_id));

drop policy if exists run_registry_manage_org on public.run_registry;
create policy run_registry_manage_org
on public.run_registry
for all
to authenticated
using (public.has_org_role(org_id, array['admin','member']::public.member_role[]))
with check (public.has_org_role(org_id, array['admin','member']::public.member_role[]));

commit;
