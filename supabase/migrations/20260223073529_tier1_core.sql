begin;

create extension if not exists pgcrypto;

-- Enums to prevent taxonomy drift and mixed scales.
do $$
begin
  if not exists (select 1 from pg_type where typname = 'member_role') then
    create type public.member_role as enum ('admin', 'member', 'viewer');
  end if;
  if not exists (select 1 from pg_type where typname = 'platform_role') then
    create type public.platform_role as enum ('admin', 'member', 'viewer');
  end if;
  if not exists (select 1 from pg_type where typname = 'agent_type') then
    create type public.agent_type as enum (
      'search_retrieval',
      'document_generator',
      'dashboard_assistant',
      'triage_classification',
      'analysis'
    );
  end if;
  if not exists (select 1 from pg_type where typname = 'agent_status') then
    create type public.agent_status as enum ('backlog', 'build', 'testing', 'production', 'retired');
  end if;
  if not exists (select 1 from pg_type where typname = 'eval_mode') then
    create type public.eval_mode as enum ('answer', 'criteria');
  end if;
  if not exists (select 1 from pg_type where typname = 'generation_method') then
    create type public.generation_method as enum (
      'documents',
      'prd_schema',
      'data_fixtures',
      'manual',
      'clone',
      'prod_logs'
    );
  end if;
  if not exists (select 1 from pg_type where typname = 'difficulty_level') then
    create type public.difficulty_level as enum ('easy', 'medium', 'hard');
  end if;
  if not exists (select 1 from pg_type where typname = 'capability_type') then
    create type public.capability_type as enum ('retrieval', 'synthesis', 'reasoning', 'extraction');
  end if;
  if not exists (select 1 from pg_type where typname = 'scenario_type') then
    create type public.scenario_type as enum (
      'straightforward',
      'cross_reference',
      'contradiction',
      'version_conflict',
      'authority',
      'temporal',
      'entity_ambiguity',
      'dense_technical'
    );
  end if;
  if not exists (select 1 from pg_type where typname = 'verification_status') then
    create type public.verification_status as enum ('unverified', 'verified', 'disputed');
  end if;
end
$$;

create table if not exists public.orgs (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  slug text not null unique,
  created_at timestamptz not null default now()
);

-- Profile data hangs off Supabase auth identity; no duplicate user table.
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  name text,
  role public.platform_role not null default 'member',
  created_at timestamptz not null default now()
);

create table if not exists public.org_members (
  org_id uuid not null references public.orgs(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role public.member_role not null default 'member',
  joined_at timestamptz not null default now(),
  primary key (org_id, user_id)
);

create table if not exists public.eval_profiles (
  id uuid primary key default gen_random_uuid(),
  org_id uuid references public.orgs(id) on delete cascade,
  name text not null,
  agent_type public.agent_type not null,
  default_eval_mode public.eval_mode not null,
  dimensions jsonb not null default '[]'::jsonb,
  is_builtin boolean not null default false,
  created_at timestamptz not null default now(),
  constraint eval_profiles_dimensions_is_array
    check (jsonb_typeof(dimensions) = 'array'),
  constraint eval_profiles_builtin_scope
    check ((is_builtin and org_id is null) or (not is_builtin and org_id is not null))
);

create table if not exists public.agents (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  name text not null,
  description text,
  agent_type public.agent_type not null,
  status public.agent_status not null default 'backlog',
  model text,
  api_endpoint text,
  owner_user_id uuid references auth.users(id) on delete set null,
  eval_profile_id uuid references public.eval_profiles(id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.golden_sets (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  agent_id uuid not null references public.agents(id) on delete cascade,
  name text not null,
  description text,
  generation_method public.generation_method not null,
  source_files jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now(),
  constraint golden_sets_source_files_is_array
    check (jsonb_typeof(source_files) = 'array')
);

create table if not exists public.golden_set_cases (
  id uuid primary key default gen_random_uuid(),
  golden_set_id uuid not null references public.golden_sets(id) on delete cascade,
  input text not null,
  expected_output text,
  acceptable_sources text,
  evaluation_mode public.eval_mode not null default 'answer',
  evaluation_criteria jsonb,
  difficulty public.difficulty_level not null,
  capability public.capability_type not null,
  scenario_type public.scenario_type not null,
  domain text,
  verification_status public.verification_status not null default 'unverified',
  verified_by uuid references auth.users(id) on delete set null,
  verified_date date,
  created_at timestamptz not null default now(),
  constraint golden_set_cases_mode_shape
    check (
      (evaluation_mode = 'answer' and expected_output is not null and evaluation_criteria is null) or
      (evaluation_mode = 'criteria' and expected_output is null and evaluation_criteria is not null)
    )
);

create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists trg_agents_set_updated_at on public.agents;
create trigger trg_agents_set_updated_at
before update on public.agents
for each row
execute function public.set_updated_at();

create index if not exists idx_org_members_user_id on public.org_members(user_id);
create index if not exists idx_eval_profiles_org_id on public.eval_profiles(org_id);
create index if not exists idx_agents_org_id on public.agents(org_id);
create index if not exists idx_agents_eval_profile_id on public.agents(eval_profile_id);
create index if not exists idx_golden_sets_org_id on public.golden_sets(org_id);
create index if not exists idx_golden_sets_agent_id on public.golden_sets(agent_id);
create index if not exists idx_golden_set_cases_golden_set_id on public.golden_set_cases(golden_set_id);

commit;
