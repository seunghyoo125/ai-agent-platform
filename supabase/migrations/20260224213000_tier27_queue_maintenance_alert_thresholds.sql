begin;

alter table public.queue_maintenance_policies
  add column if not exists schedule_alert_enabled boolean not null default false,
  add column if not exists schedule_alert_dedupe_hit_rate_threshold numeric(5,4) not null default 0.7000,
  add column if not exists schedule_alert_min_execution_success_rate numeric(5,4) not null default 0.9000;

alter table public.queue_maintenance_policies
  drop constraint if exists queue_maintenance_policies_schedule_alert_dedupe_threshold_range;
alter table public.queue_maintenance_policies
  add constraint queue_maintenance_policies_schedule_alert_dedupe_threshold_range
  check (schedule_alert_dedupe_hit_rate_threshold >= 0 and schedule_alert_dedupe_hit_rate_threshold <= 1);

alter table public.queue_maintenance_policies
  drop constraint if exists queue_maintenance_policies_schedule_alert_success_rate_range;
alter table public.queue_maintenance_policies
  add constraint queue_maintenance_policies_schedule_alert_success_rate_range
  check (schedule_alert_min_execution_success_rate >= 0 and schedule_alert_min_execution_success_rate <= 1);

commit;
