begin;

create table if not exists public.contract_drift_policies (
  org_id uuid primary key references public.orgs(id) on delete cascade,
  enabled boolean not null default false,
  min_drift text not null default 'breaking' check (min_drift in ('warning', 'breaking', 'invalid')),
  promote_to_patterns boolean not null default true,
  scan_limit integer not null default 200 check (scan_limit >= 1 and scan_limit <= 1000),
  schedule_name text not null default 'daily',
  schedule_window_minutes integer not null default 1440 check (schedule_window_minutes >= 5 and schedule_window_minutes <= 10080),
  updated_by_api_key_id uuid references public.api_keys(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_contract_drift_policies_updated_at
  on public.contract_drift_policies(updated_at desc);

create trigger set_contract_drift_policies_updated_at
before update on public.contract_drift_policies
for each row execute function public.set_updated_at();

alter table public.contract_drift_policies enable row level security;

drop policy if exists contract_drift_policies_select_member on public.contract_drift_policies;
create policy contract_drift_policies_select_member
on public.contract_drift_policies
for select
to authenticated
using (public.is_org_member(org_id));

drop policy if exists contract_drift_policies_manage_org on public.contract_drift_policies;
create policy contract_drift_policies_manage_org
on public.contract_drift_policies
for all
to authenticated
using (public.has_org_role(org_id, array['admin','member']::public.member_role[]))
with check (public.has_org_role(org_id, array['admin','member']::public.member_role[]));

commit;
