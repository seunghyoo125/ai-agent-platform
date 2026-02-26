begin;

alter table public.slo_policies
  add column if not exists require_golden_set_quality_gate boolean not null default false,
  add column if not exists min_verified_case_ratio numeric(5,4) not null default 0.7000,
  add column if not exists min_active_case_count integer not null default 20;

alter table public.slo_policies
  drop constraint if exists slo_policies_golden_set_quality_gate_bounds;
alter table public.slo_policies
  add constraint slo_policies_golden_set_quality_gate_bounds
  check (
    min_verified_case_ratio >= 0
    and min_verified_case_ratio <= 1
    and min_active_case_count >= 1
    and min_active_case_count <= 1000000
  );

create index if not exists idx_slo_policies_golden_set_quality_gate
  on public.slo_policies(require_golden_set_quality_gate, min_verified_case_ratio, min_active_case_count);

commit;
