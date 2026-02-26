begin;

do $$
begin
  if not exists (select 1 from pg_type where typname = 'slo_violation_source') then
    create type public.slo_violation_source as enum ('run_execute', 'run_compare');
  end if;
end
$$;

create table if not exists public.slo_policies (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  agent_id uuid not null references public.agents(id) on delete cascade,
  min_answer_yes_rate numeric,
  min_source_yes_rate numeric,
  min_quality_good_rate numeric,
  max_run_duration_ms integer,
  max_regression_count integer,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint slo_policies_one_per_agent unique (agent_id),
  constraint slo_policies_min_rates_bounds check (
    (min_answer_yes_rate is null or (min_answer_yes_rate >= 0 and min_answer_yes_rate <= 1)) and
    (min_source_yes_rate is null or (min_source_yes_rate >= 0 and min_source_yes_rate <= 1)) and
    (min_quality_good_rate is null or (min_quality_good_rate >= 0 and min_quality_good_rate <= 1))
  ),
  constraint slo_policies_positive_limits check (
    (max_run_duration_ms is null or max_run_duration_ms > 0) and
    (max_regression_count is null or max_regression_count >= 0)
  )
);

create table if not exists public.slo_violations (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  agent_id uuid not null references public.agents(id) on delete cascade,
  policy_id uuid references public.slo_policies(id) on delete set null,
  source public.slo_violation_source not null,
  source_ref_id uuid,
  metric text not null,
  actual_value numeric not null,
  expected_value numeric not null,
  comparator text not null,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  constraint slo_violations_details_is_object check (jsonb_typeof(details) = 'object')
);

drop trigger if exists trg_slo_policies_set_updated_at on public.slo_policies;
create trigger trg_slo_policies_set_updated_at
before update on public.slo_policies
for each row
execute function public.set_updated_at();

create index if not exists idx_slo_policies_agent_id on public.slo_policies(agent_id);
create index if not exists idx_slo_violations_agent_id on public.slo_violations(agent_id);
create index if not exists idx_slo_violations_created_at on public.slo_violations(created_at desc);

alter table public.slo_policies enable row level security;
alter table public.slo_violations enable row level security;

drop policy if exists slo_policies_select_member on public.slo_policies;
create policy slo_policies_select_member
on public.slo_policies
for select
to authenticated
using (public.is_org_member(org_id));

drop policy if exists slo_policies_manage_org on public.slo_policies;
create policy slo_policies_manage_org
on public.slo_policies
for all
to authenticated
using (public.has_org_role(org_id, array['admin','member']::public.member_role[]))
with check (public.has_org_role(org_id, array['admin','member']::public.member_role[]));

drop policy if exists slo_violations_select_member on public.slo_violations;
create policy slo_violations_select_member
on public.slo_violations
for select
to authenticated
using (public.is_org_member(org_id));

drop policy if exists slo_violations_manage_org on public.slo_violations;
create policy slo_violations_manage_org
on public.slo_violations
for all
to authenticated
using (public.has_org_role(org_id, array['admin','member']::public.member_role[]))
with check (public.has_org_role(org_id, array['admin','member']::public.member_role[]));

commit;
