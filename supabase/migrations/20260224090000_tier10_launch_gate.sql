begin;

do $$
begin
  if not exists (select 1 from pg_type where typname = 'launch_decision_action') then
    create type public.launch_decision_action as enum ('go', 'no_go', 'deferred');
  end if;
  if not exists (select 1 from pg_type where typname = 'slo_violation_status') then
    create type public.slo_violation_status as enum ('open', 'resolved');
  end if;
end
$$;

alter table public.slo_violations
  add column if not exists status public.slo_violation_status not null default 'open',
  add column if not exists resolved_at timestamptz;

create table if not exists public.launch_decisions (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  agent_id uuid not null references public.agents(id) on delete cascade,
  decision public.launch_decision_action not null,
  reason text,
  blockers jsonb not null default '[]'::jsonb,
  decided_by_api_key_id uuid references public.api_keys(id) on delete set null,
  decided_at timestamptz not null default now(),
  constraint launch_decisions_blockers_is_array
    check (jsonb_typeof(blockers) = 'array')
);

create index if not exists idx_launch_decisions_agent_id on public.launch_decisions(agent_id);
create index if not exists idx_launch_decisions_org_id on public.launch_decisions(org_id);
create index if not exists idx_launch_decisions_decided_at on public.launch_decisions(decided_at desc);
create index if not exists idx_slo_violations_status on public.slo_violations(status);

alter table public.launch_decisions enable row level security;

drop policy if exists launch_decisions_select_member on public.launch_decisions;
create policy launch_decisions_select_member
on public.launch_decisions
for select
to authenticated
using (public.is_org_member(org_id));

drop policy if exists launch_decisions_manage_org on public.launch_decisions;
create policy launch_decisions_manage_org
on public.launch_decisions
for all
to authenticated
using (public.has_org_role(org_id, array['admin','member']::public.member_role[]))
with check (public.has_org_role(org_id, array['admin','member']::public.member_role[]));

commit;
