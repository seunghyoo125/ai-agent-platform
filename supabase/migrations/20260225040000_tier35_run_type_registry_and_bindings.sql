begin;

create table if not exists public.run_type_definitions (
  id uuid primary key default gen_random_uuid(),
  org_id uuid references public.orgs(id) on delete cascade,
  run_type public.eval_run_type not null,
  key text not null,
  name text not null,
  description text,
  handler_key text not null,
  default_config jsonb not null default '{}'::jsonb,
  is_builtin boolean not null default false,
  active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint run_type_definitions_scope_builtin check ((is_builtin = true and org_id is null) or (is_builtin = false and org_id is not null)),
  constraint run_type_definitions_default_config_is_object check (jsonb_typeof(default_config) = 'object'),
  constraint run_type_definitions_key_nonempty check (length(trim(key)) > 0),
  constraint run_type_definitions_name_nonempty check (length(trim(name)) > 0)
);

create unique index if not exists uq_run_type_definitions_scope_type
  on public.run_type_definitions (coalesce(org_id, '00000000-0000-0000-0000-000000000000'::uuid), run_type);

create unique index if not exists uq_run_type_definitions_scope_key
  on public.run_type_definitions (coalesce(org_id, '00000000-0000-0000-0000-000000000000'::uuid), key);

create index if not exists idx_run_type_definitions_org_active
  on public.run_type_definitions (org_id, run_type, active, created_at desc);

create table if not exists public.agent_run_type_bindings (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  agent_id uuid not null references public.agents(id) on delete cascade,
  run_type public.eval_run_type not null,
  run_type_definition_id uuid not null references public.run_type_definitions(id) on delete cascade,
  enabled boolean not null default true,
  config jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint agent_run_type_bindings_config_is_object check (jsonb_typeof(config) = 'object'),
  constraint agent_run_type_bindings_unique unique (agent_id, run_type)
);

create index if not exists idx_agent_run_type_bindings_org_agent
  on public.agent_run_type_bindings (org_id, agent_id, run_type, enabled, updated_at desc);

insert into public.run_type_definitions (
  org_id, run_type, key, name, description, handler_key, default_config, is_builtin, active
)
values
  (null, 'eval'::public.eval_run_type, 'builtin_eval_default', 'Builtin Eval Handler', 'Default run handler for eval runs.', 'default', '{}'::jsonb, true, true),
  (null, 'regression'::public.eval_run_type, 'builtin_regression_default', 'Builtin Regression Handler', 'Default run handler for regression runs.', 'default', '{}'::jsonb, true, true),
  (null, 'ab_comparison'::public.eval_run_type, 'builtin_ab_default', 'Builtin A/B Handler', 'Default run handler for A/B comparison runs.', 'default', '{}'::jsonb, true, true),
  (null, 'calibration'::public.eval_run_type, 'builtin_calibration_default', 'Builtin Calibration Handler', 'Default run handler for calibration runs.', 'default', '{}'::jsonb, true, true)
on conflict do nothing;

alter table public.run_type_definitions enable row level security;
alter table public.agent_run_type_bindings enable row level security;

drop policy if exists run_type_definitions_select_scope on public.run_type_definitions;
create policy run_type_definitions_select_scope
on public.run_type_definitions
for select
using (
  is_builtin = true
  or public.has_org_role(org_id, array['admin','member']::public.member_role[])
);

drop policy if exists run_type_definitions_manage_org on public.run_type_definitions;
create policy run_type_definitions_manage_org
on public.run_type_definitions
for all
using (
  org_id is not null
  and public.has_org_role(org_id, array['admin','member']::public.member_role[])
)
with check (
  org_id is not null
  and public.has_org_role(org_id, array['admin','member']::public.member_role[])
);

drop policy if exists agent_run_type_bindings_select_member on public.agent_run_type_bindings;
create policy agent_run_type_bindings_select_member
on public.agent_run_type_bindings
for select
using (public.has_org_role(org_id, array['admin','member']::public.member_role[]));

drop policy if exists agent_run_type_bindings_manage_org on public.agent_run_type_bindings;
create policy agent_run_type_bindings_manage_org
on public.agent_run_type_bindings
for all
using (public.has_org_role(org_id, array['admin','member']::public.member_role[]))
with check (public.has_org_role(org_id, array['admin','member']::public.member_role[]));

drop trigger if exists trg_run_type_definitions_set_updated_at on public.run_type_definitions;
create trigger trg_run_type_definitions_set_updated_at
before update on public.run_type_definitions
for each row
execute function public.set_updated_at();

drop trigger if exists trg_agent_run_type_bindings_set_updated_at on public.agent_run_type_bindings;
create trigger trg_agent_run_type_bindings_set_updated_at
before update on public.agent_run_type_bindings
for each row
execute function public.set_updated_at();

commit;
