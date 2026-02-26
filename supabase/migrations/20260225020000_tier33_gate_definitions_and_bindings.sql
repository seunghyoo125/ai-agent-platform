begin;

create table if not exists public.gate_definitions (
  id uuid primary key default gen_random_uuid(),
  org_id uuid references public.orgs(id) on delete cascade,
  key text not null,
  name text not null,
  description text,
  evaluator_key text not null,
  config_schema jsonb not null default '{}'::jsonb,
  default_config jsonb not null default '{}'::jsonb,
  applies_to_run_types text[] not null default array['eval','regression','ab_comparison']::text[],
  is_builtin boolean not null default false,
  active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint gate_definitions_scope_builtin check ((is_builtin = true and org_id is null) or (is_builtin = false and org_id is not null)),
  constraint gate_definitions_config_schema_is_object check (jsonb_typeof(config_schema) = 'object'),
  constraint gate_definitions_default_config_is_object check (jsonb_typeof(default_config) = 'object'),
  constraint gate_definitions_key_nonempty check (length(trim(key)) > 0),
  constraint gate_definitions_name_nonempty check (length(trim(name)) > 0)
);

create unique index if not exists uq_gate_definitions_scope_key
  on public.gate_definitions (coalesce(org_id, '00000000-0000-0000-0000-000000000000'::uuid), key);

create index if not exists idx_gate_definitions_org_active
  on public.gate_definitions (org_id, active, created_at desc);

create table if not exists public.agent_gate_bindings (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  agent_id uuid not null references public.agents(id) on delete cascade,
  gate_definition_id uuid not null references public.gate_definitions(id) on delete cascade,
  enabled boolean not null default true,
  config jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint agent_gate_bindings_config_is_object check (jsonb_typeof(config) = 'object'),
  constraint agent_gate_bindings_unique unique (agent_id, gate_definition_id)
);

create index if not exists idx_agent_gate_bindings_org_agent
  on public.agent_gate_bindings (org_id, agent_id, enabled, updated_at desc);

insert into public.gate_definitions (
  org_id, key, name, description, evaluator_key, config_schema, default_config, applies_to_run_types, is_builtin, active
)
values
  (
    null,
    'calibration_freshness',
    'Calibration Freshness Gate',
    'Blocks run start/execute if latest calibration is missing, stale, or below agreement threshold.',
    'calibration_freshness',
    '{"type":"object","properties":{"min_overall_agreement":{"type":"number","minimum":0,"maximum":1},"max_age_days":{"type":"integer","minimum":1,"maximum":3650}},"additionalProperties":false}'::jsonb,
    '{"min_overall_agreement":0.7,"max_age_days":14}'::jsonb,
    array['eval','regression','ab_comparison']::text[],
    true,
    true
  ),
  (
    null,
    'golden_set_quality',
    'Golden Set Quality Gate',
    'Blocks run start/execute if active/verified golden set coverage is below threshold.',
    'golden_set_quality',
    '{"type":"object","properties":{"min_verified_case_ratio":{"type":"number","minimum":0,"maximum":1},"min_active_case_count":{"type":"integer","minimum":1,"maximum":1000000}},"additionalProperties":false}'::jsonb,
    '{"min_verified_case_ratio":0.7,"min_active_case_count":20}'::jsonb,
    array['eval','regression','ab_comparison']::text[],
    true,
    true
  )
on conflict do nothing;

update public.gate_definitions
set
  name = 'Calibration Freshness Gate',
  description = 'Blocks run start/execute if latest calibration is missing, stale, or below agreement threshold.',
  evaluator_key = 'calibration_freshness',
  config_schema = '{"type":"object","properties":{"min_overall_agreement":{"type":"number","minimum":0,"maximum":1},"max_age_days":{"type":"integer","minimum":1,"maximum":3650}},"additionalProperties":false}'::jsonb,
  default_config = '{"min_overall_agreement":0.7,"max_age_days":14}'::jsonb,
  applies_to_run_types = array['eval','regression','ab_comparison']::text[],
  active = true,
  updated_at = now()
where org_id is null and key = 'calibration_freshness';

update public.gate_definitions
set
  name = 'Golden Set Quality Gate',
  description = 'Blocks run start/execute if active/verified golden set coverage is below threshold.',
  evaluator_key = 'golden_set_quality',
  config_schema = '{"type":"object","properties":{"min_verified_case_ratio":{"type":"number","minimum":0,"maximum":1},"min_active_case_count":{"type":"integer","minimum":1,"maximum":1000000}},"additionalProperties":false}'::jsonb,
  default_config = '{"min_verified_case_ratio":0.7,"min_active_case_count":20}'::jsonb,
  applies_to_run_types = array['eval','regression','ab_comparison']::text[],
  active = true,
  updated_at = now()
where org_id is null and key = 'golden_set_quality';

alter table public.gate_definitions enable row level security;
alter table public.agent_gate_bindings enable row level security;

drop policy if exists gate_definitions_select_scope on public.gate_definitions;
create policy gate_definitions_select_scope
on public.gate_definitions
for select
using (
  is_builtin = true
  or public.has_org_role(org_id, array['admin','member']::public.member_role[])
);

drop policy if exists gate_definitions_manage_org on public.gate_definitions;
create policy gate_definitions_manage_org
on public.gate_definitions
for all
using (
  org_id is not null
  and public.has_org_role(org_id, array['admin','member']::public.member_role[])
)
with check (
  org_id is not null
  and public.has_org_role(org_id, array['admin','member']::public.member_role[])
);

drop policy if exists agent_gate_bindings_select_member on public.agent_gate_bindings;
create policy agent_gate_bindings_select_member
on public.agent_gate_bindings
for select
using (public.has_org_role(org_id, array['admin','member']::public.member_role[]));

drop policy if exists agent_gate_bindings_manage_org on public.agent_gate_bindings;
create policy agent_gate_bindings_manage_org
on public.agent_gate_bindings
for all
using (public.has_org_role(org_id, array['admin','member']::public.member_role[]))
with check (public.has_org_role(org_id, array['admin','member']::public.member_role[]));

drop trigger if exists trg_gate_definitions_set_updated_at on public.gate_definitions;
create trigger trg_gate_definitions_set_updated_at
before update on public.gate_definitions
for each row
execute function public.set_updated_at();

drop trigger if exists trg_agent_gate_bindings_set_updated_at on public.agent_gate_bindings;
create trigger trg_agent_gate_bindings_set_updated_at
before update on public.agent_gate_bindings
for each row
execute function public.set_updated_at();

commit;
