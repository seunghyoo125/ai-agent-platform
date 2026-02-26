begin;

alter table public.contract_drift_policies
  add column if not exists alert_enabled boolean not null default false,
  add column if not exists alert_max_dedupe_hit_rate numeric(5,4) not null default 0.7000,
  add column if not exists alert_min_execution_rate numeric(5,4) not null default 0.5000,
  add column if not exists alert_cooldown_minutes integer not null default 60;

alter table public.contract_drift_policies
  drop constraint if exists contract_drift_policies_alert_max_dedupe_hit_rate_range;
alter table public.contract_drift_policies
  add constraint contract_drift_policies_alert_max_dedupe_hit_rate_range
  check (alert_max_dedupe_hit_rate >= 0 and alert_max_dedupe_hit_rate <= 1);

alter table public.contract_drift_policies
  drop constraint if exists contract_drift_policies_alert_min_execution_rate_range;
alter table public.contract_drift_policies
  add constraint contract_drift_policies_alert_min_execution_rate_range
  check (alert_min_execution_rate >= 0 and alert_min_execution_rate <= 1);

alter table public.contract_drift_policies
  drop constraint if exists contract_drift_policies_alert_cooldown_minutes_range;
alter table public.contract_drift_policies
  add constraint contract_drift_policies_alert_cooldown_minutes_range
  check (alert_cooldown_minutes >= 0 and alert_cooldown_minutes <= 10080);

create table if not exists public.contract_drift_trigger_alert_state (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  schedule_name text not null,
  alert_fingerprint text not null,
  last_notified_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint contract_drift_trigger_alert_state_org_schedule_unique
    unique (org_id, schedule_name)
);

create index if not exists idx_contract_drift_trigger_alert_state_org
  on public.contract_drift_trigger_alert_state(org_id);

drop trigger if exists trg_contract_drift_trigger_alert_state_updated_at on public.contract_drift_trigger_alert_state;
create trigger trg_contract_drift_trigger_alert_state_updated_at
before update on public.contract_drift_trigger_alert_state
for each row execute function public.set_updated_at();

alter table public.contract_drift_trigger_alert_state enable row level security;

drop policy if exists contract_drift_trigger_alert_state_select_none on public.contract_drift_trigger_alert_state;
create policy contract_drift_trigger_alert_state_select_none
on public.contract_drift_trigger_alert_state
for select
to authenticated
using (false);

drop policy if exists contract_drift_trigger_alert_state_modify_none on public.contract_drift_trigger_alert_state;
create policy contract_drift_trigger_alert_state_modify_none
on public.contract_drift_trigger_alert_state
for all
to authenticated
using (false)
with check (false);

commit;
