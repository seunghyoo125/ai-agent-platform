begin;

alter table public.slo_policies
  add column if not exists require_calibration_gate boolean not null default false,
  add column if not exists min_calibration_overall_agreement numeric(5,4) not null default 0.7000,
  add column if not exists max_calibration_age_days integer not null default 14;

alter table public.slo_policies
  drop constraint if exists slo_policies_calibration_gate_bounds;
alter table public.slo_policies
  add constraint slo_policies_calibration_gate_bounds
  check (
    min_calibration_overall_agreement >= 0
    and min_calibration_overall_agreement <= 1
    and max_calibration_age_days >= 1
    and max_calibration_age_days <= 3650
  );

create index if not exists idx_slo_policies_calibration_gate
  on public.slo_policies(require_calibration_gate, max_calibration_age_days);

commit;
