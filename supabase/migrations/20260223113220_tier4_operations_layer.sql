begin;

do $$
begin
  if not exists (select 1 from pg_type where typname = 'issue_status') then
    create type public.issue_status as enum (
      'detected',
      'diagnosed',
      'assigned',
      'in_progress',
      'fixed',
      'verifying',
      'resolved',
      'regressed',
      'wont_fix'
    );
  end if;
  if not exists (select 1 from pg_type where typname = 'issue_priority') then
    create type public.issue_priority as enum ('critical', 'high', 'medium', 'low');
  end if;
  if not exists (select 1 from pg_type where typname = 'root_cause_type') then
    create type public.root_cause_type as enum ('retrieval', 'prompt', 'data', 'model', 'config');
  end if;
  if not exists (select 1 from pg_type where typname = 'readiness_decision') then
    create type public.readiness_decision as enum ('go', 'no_go', 'deferred');
  end if;
end
$$;

create table if not exists public.issue_patterns (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  agent_id uuid not null references public.agents(id) on delete cascade,
  title text not null,
  primary_tag text not null,
  related_tags text[] not null default '{}',
  status public.issue_status not null default 'detected',
  priority public.issue_priority not null default 'medium',
  root_cause text,
  root_cause_type public.root_cause_type,
  suggested_fix text,
  owner text,
  linked_case_ids uuid[] not null default '{}',
  history jsonb not null default '[]'::jsonb,
  status_history jsonb not null default '[]'::jsonb,
  fix_notes jsonb not null default '[]'::jsonb,
  verification_result jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  resolved_date date,
  constraint issue_patterns_history_is_array
    check (jsonb_typeof(history) = 'array'),
  constraint issue_patterns_status_history_is_array
    check (jsonb_typeof(status_history) = 'array'),
  constraint issue_patterns_fix_notes_is_array
    check (jsonb_typeof(fix_notes) = 'array'),
  constraint issue_patterns_verification_result_is_object
    check (jsonb_typeof(verification_result) = 'object')
);

create table if not exists public.launch_readiness (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  agent_id uuid not null references public.agents(id) on delete cascade,
  items jsonb not null default '[]'::jsonb,
  thresholds jsonb not null default '{}'::jsonb,
  decision public.readiness_decision,
  decision_notes text,
  decision_date date,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint launch_readiness_one_per_agent unique (agent_id),
  constraint launch_readiness_items_is_array
    check (jsonb_typeof(items) = 'array'),
  constraint launch_readiness_thresholds_is_object
    check (jsonb_typeof(thresholds) = 'object')
);

drop trigger if exists trg_issue_patterns_set_updated_at on public.issue_patterns;
create trigger trg_issue_patterns_set_updated_at
before update on public.issue_patterns
for each row
execute function public.set_updated_at();

drop trigger if exists trg_launch_readiness_set_updated_at on public.launch_readiness;
create trigger trg_launch_readiness_set_updated_at
before update on public.launch_readiness
for each row
execute function public.set_updated_at();

create index if not exists idx_issue_patterns_org_id on public.issue_patterns(org_id);
create index if not exists idx_issue_patterns_agent_id on public.issue_patterns(agent_id);
create index if not exists idx_issue_patterns_status on public.issue_patterns(status);
create index if not exists idx_issue_patterns_priority on public.issue_patterns(priority);
create index if not exists idx_launch_readiness_org_id on public.launch_readiness(org_id);
create index if not exists idx_launch_readiness_agent_id on public.launch_readiness(agent_id);

alter table public.issue_patterns enable row level security;
alter table public.launch_readiness enable row level security;

drop policy if exists issue_patterns_select_member on public.issue_patterns;
create policy issue_patterns_select_member
on public.issue_patterns
for select
to authenticated
using (public.is_org_member(org_id));

drop policy if exists issue_patterns_manage_org on public.issue_patterns;
create policy issue_patterns_manage_org
on public.issue_patterns
for all
to authenticated
using (public.has_org_role(org_id, array['admin','member']::public.member_role[]))
with check (public.has_org_role(org_id, array['admin','member']::public.member_role[]));

drop policy if exists launch_readiness_select_member on public.launch_readiness;
create policy launch_readiness_select_member
on public.launch_readiness
for select
to authenticated
using (public.is_org_member(org_id));

drop policy if exists launch_readiness_manage_org on public.launch_readiness;
create policy launch_readiness_manage_org
on public.launch_readiness
for all
to authenticated
using (public.has_org_role(org_id, array['admin','member']::public.member_role[]))
with check (public.has_org_role(org_id, array['admin','member']::public.member_role[]));

commit;
