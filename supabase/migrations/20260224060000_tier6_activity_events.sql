begin;

do $$
begin
  if not exists (select 1 from pg_type where typname = 'activity_severity') then
    create type public.activity_severity as enum ('info', 'warning', 'error');
  end if;
end
$$;

create table if not exists public.activity_events (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  agent_id uuid not null references public.agents(id) on delete cascade,
  event_type text not null,
  severity public.activity_severity not null default 'info',
  title text not null,
  details text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  constraint activity_events_metadata_is_object
    check (jsonb_typeof(metadata) = 'object')
);

create index if not exists idx_activity_events_org_id on public.activity_events(org_id);
create index if not exists idx_activity_events_agent_id on public.activity_events(agent_id);
create index if not exists idx_activity_events_created_at on public.activity_events(created_at desc);
create index if not exists idx_activity_events_event_type on public.activity_events(event_type);

alter table public.activity_events enable row level security;

drop policy if exists activity_events_select_member on public.activity_events;
create policy activity_events_select_member
on public.activity_events
for select
to authenticated
using (public.is_org_member(org_id));

drop policy if exists activity_events_manage_org on public.activity_events;
create policy activity_events_manage_org
on public.activity_events
for all
to authenticated
using (public.has_org_role(org_id, array['admin','member']::public.member_role[]))
with check (public.has_org_role(org_id, array['admin','member']::public.member_role[]));

commit;
