begin;

create table if not exists public.eval_templates (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  name text not null,
  description text,
  run_type public.eval_run_type not null default 'eval',
  agent_type public.agent_type,
  default_golden_set_id uuid references public.golden_sets(id) on delete set null,
  config jsonb not null default '{}'::jsonb,
  design_context jsonb not null default '{}'::jsonb,
  is_active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint eval_templates_name_unique unique (org_id, name),
  constraint eval_templates_config_is_object check (jsonb_typeof(config) = 'object'),
  constraint eval_templates_design_context_is_object check (jsonb_typeof(design_context) = 'object')
);

create index if not exists idx_eval_templates_org_updated
  on public.eval_templates(org_id, updated_at desc);

create index if not exists idx_eval_templates_agent_type
  on public.eval_templates(org_id, agent_type, is_active);

drop trigger if exists trg_eval_templates_set_updated_at on public.eval_templates;
create trigger trg_eval_templates_set_updated_at
before update on public.eval_templates
for each row
execute function public.set_updated_at();

alter table public.eval_templates enable row level security;

drop policy if exists eval_templates_select_member on public.eval_templates;
create policy eval_templates_select_member
on public.eval_templates
for select
to authenticated
using (public.is_org_member(org_id));

drop policy if exists eval_templates_manage_org on public.eval_templates;
create policy eval_templates_manage_org
on public.eval_templates
for all
to authenticated
using (public.has_org_role(org_id, array['admin','member']::public.member_role[]))
with check (public.has_org_role(org_id, array['admin','member']::public.member_role[]));

commit;
