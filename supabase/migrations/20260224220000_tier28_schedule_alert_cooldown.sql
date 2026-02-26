begin;

alter table public.queue_maintenance_policies
  add column if not exists schedule_alert_cooldown_minutes integer not null default 60;

alter table public.queue_maintenance_policies
  drop constraint if exists queue_maintenance_policies_schedule_alert_cooldown_range;
alter table public.queue_maintenance_policies
  add constraint queue_maintenance_policies_schedule_alert_cooldown_range
  check (schedule_alert_cooldown_minutes >= 0 and schedule_alert_cooldown_minutes <= 10080);

create table if not exists public.queue_maintenance_schedule_alert_state (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  schedule_name text not null,
  alert_fingerprint text not null,
  last_notified_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint queue_maintenance_schedule_alert_state_org_schedule_unique
    unique (org_id, schedule_name)
);

create index if not exists idx_queue_maintenance_schedule_alert_state_org
  on public.queue_maintenance_schedule_alert_state(org_id);

drop trigger if exists trg_queue_maintenance_schedule_alert_state_updated_at on public.queue_maintenance_schedule_alert_state;
create trigger trg_queue_maintenance_schedule_alert_state_updated_at
before update on public.queue_maintenance_schedule_alert_state
for each row execute function public.set_updated_at();

alter table public.queue_maintenance_schedule_alert_state enable row level security;

drop policy if exists queue_maintenance_schedule_alert_state_select_none on public.queue_maintenance_schedule_alert_state;
create policy queue_maintenance_schedule_alert_state_select_none
on public.queue_maintenance_schedule_alert_state
for select
to authenticated
using (false);

drop policy if exists queue_maintenance_schedule_alert_state_modify_none on public.queue_maintenance_schedule_alert_state;
create policy queue_maintenance_schedule_alert_state_modify_none
on public.queue_maintenance_schedule_alert_state
for all
to authenticated
using (false)
with check (false);

commit;
