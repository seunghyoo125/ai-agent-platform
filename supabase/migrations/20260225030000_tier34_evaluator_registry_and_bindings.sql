begin;

create table if not exists public.evaluator_definitions (
  id uuid primary key default gen_random_uuid(),
  org_id uuid references public.orgs(id) on delete cascade,
  key text not null,
  name text not null,
  description text,
  evaluation_mode public.eval_mode not null,
  evaluator_kind text not null default 'judge_service',
  default_config jsonb not null default '{}'::jsonb,
  is_builtin boolean not null default false,
  active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint evaluator_definitions_scope_builtin check ((is_builtin = true and org_id is null) or (is_builtin = false and org_id is not null)),
  constraint evaluator_definitions_default_config_is_object check (jsonb_typeof(default_config) = 'object'),
  constraint evaluator_definitions_key_nonempty check (length(trim(key)) > 0),
  constraint evaluator_definitions_name_nonempty check (length(trim(name)) > 0)
);

create unique index if not exists uq_evaluator_definitions_scope_key
  on public.evaluator_definitions (coalesce(org_id, '00000000-0000-0000-0000-000000000000'::uuid), key);

create index if not exists idx_evaluator_definitions_org_active
  on public.evaluator_definitions (org_id, evaluation_mode, active, created_at desc);

create table if not exists public.agent_evaluator_bindings (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  agent_id uuid not null references public.agents(id) on delete cascade,
  evaluator_definition_id uuid not null references public.evaluator_definitions(id) on delete cascade,
  evaluation_mode public.eval_mode not null,
  enabled boolean not null default true,
  config jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint agent_evaluator_bindings_config_is_object check (jsonb_typeof(config) = 'object'),
  constraint agent_evaluator_bindings_unique_mode unique (agent_id, evaluation_mode)
);

create index if not exists idx_agent_evaluator_bindings_org_agent
  on public.agent_evaluator_bindings (org_id, agent_id, evaluation_mode, enabled, updated_at desc);

insert into public.evaluator_definitions (
  org_id, key, name, description, evaluation_mode, evaluator_kind, default_config, is_builtin, active
)
values
  (
    null,
    'builtin_answer_deterministic',
    'Builtin Answer Evaluator (Deterministic)',
    'Default deterministic answer evaluator.',
    'answer'::public.eval_mode,
    'judge_service',
    '{"judge_mode":"deterministic"}'::jsonb,
    true,
    true
  ),
  (
    null,
    'builtin_criteria_deterministic',
    'Builtin Criteria Evaluator (Deterministic)',
    'Default deterministic criteria evaluator.',
    'criteria'::public.eval_mode,
    'judge_service',
    '{"judge_mode":"deterministic"}'::jsonb,
    true,
    true
  )
on conflict do nothing;

alter table public.evaluator_definitions enable row level security;
alter table public.agent_evaluator_bindings enable row level security;

drop policy if exists evaluator_definitions_select_scope on public.evaluator_definitions;
create policy evaluator_definitions_select_scope
on public.evaluator_definitions
for select
using (
  is_builtin = true
  or public.has_org_role(org_id, array['admin','member']::public.member_role[])
);

drop policy if exists evaluator_definitions_manage_org on public.evaluator_definitions;
create policy evaluator_definitions_manage_org
on public.evaluator_definitions
for all
using (
  org_id is not null
  and public.has_org_role(org_id, array['admin','member']::public.member_role[])
)
with check (
  org_id is not null
  and public.has_org_role(org_id, array['admin','member']::public.member_role[])
);

drop policy if exists agent_evaluator_bindings_select_member on public.agent_evaluator_bindings;
create policy agent_evaluator_bindings_select_member
on public.agent_evaluator_bindings
for select
using (public.has_org_role(org_id, array['admin','member']::public.member_role[]));

drop policy if exists agent_evaluator_bindings_manage_org on public.agent_evaluator_bindings;
create policy agent_evaluator_bindings_manage_org
on public.agent_evaluator_bindings
for all
using (public.has_org_role(org_id, array['admin','member']::public.member_role[]))
with check (public.has_org_role(org_id, array['admin','member']::public.member_role[]));

drop trigger if exists trg_evaluator_definitions_set_updated_at on public.evaluator_definitions;
create trigger trg_evaluator_definitions_set_updated_at
before update on public.evaluator_definitions
for each row
execute function public.set_updated_at();

drop trigger if exists trg_agent_evaluator_bindings_set_updated_at on public.agent_evaluator_bindings;
create trigger trg_agent_evaluator_bindings_set_updated_at
before update on public.agent_evaluator_bindings
for each row
execute function public.set_updated_at();

commit;
