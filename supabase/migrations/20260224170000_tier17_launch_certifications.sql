begin;

create table if not exists public.launch_certifications (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  agent_id uuid not null references public.agents(id) on delete cascade,
  decision public.launch_decision_action not null,
  certification_status text not null check (certification_status in ('certified', 'blocked')),
  reason text,
  blockers jsonb not null default '[]'::jsonb,
  evidence jsonb not null default '{}'::jsonb,
  created_by_api_key_id uuid references public.api_keys(id) on delete set null,
  created_at timestamptz not null default now()
);

create index if not exists idx_launch_certifications_agent_created
  on public.launch_certifications(agent_id, created_at desc);

alter table public.launch_certifications enable row level security;

drop policy if exists launch_certifications_select_member on public.launch_certifications;
create policy launch_certifications_select_member
on public.launch_certifications
for select
to authenticated
using (public.is_org_member(org_id));

drop policy if exists launch_certifications_manage_org on public.launch_certifications;
create policy launch_certifications_manage_org
on public.launch_certifications
for all
to authenticated
using (public.has_org_role(org_id, array['admin','member']::public.member_role[]))
with check (public.has_org_role(org_id, array['admin','member']::public.member_role[]));

commit;
