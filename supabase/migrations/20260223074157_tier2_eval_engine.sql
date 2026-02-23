begin;

-- Tier 2 enums for evaluation engine.
do $$
begin
  if not exists (select 1 from pg_type where typname = 'eval_run_type') then
    create type public.eval_run_type as enum ('eval', 'regression', 'ab_comparison', 'calibration');
  end if;
  if not exists (select 1 from pg_type where typname = 'run_status') then
    create type public.run_status as enum ('pending', 'running', 'completed', 'failed');
  end if;
  if not exists (select 1 from pg_type where typname = 'ynp_score') then
    create type public.ynp_score as enum ('yes', 'partially', 'no');
  end if;
  if not exists (select 1 from pg_type where typname = 'quality_score') then
    create type public.quality_score as enum ('good', 'average', 'not_good');
  end if;
  if not exists (select 1 from pg_type where typname = 'match_type') then
    create type public.match_type as enum ('golden_set', 'ad_hoc', 'legacy');
  end if;
end
$$;

create table if not exists public.eval_runs (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  agent_id uuid not null references public.agents(id) on delete cascade,
  golden_set_id uuid references public.golden_sets(id) on delete set null,
  name text not null,
  type public.eval_run_type not null,
  status public.run_status not null default 'pending',
  config jsonb not null default '{}'::jsonb,
  design_context jsonb not null default '{}'::jsonb,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  started_at timestamptz,
  completed_at timestamptz,
  failure_reason text,
  constraint eval_runs_config_is_object check (jsonb_typeof(config) = 'object'),
  constraint eval_runs_design_context_is_object check (jsonb_typeof(design_context) = 'object'),
  constraint eval_runs_completed_timestamp check (
    (status in ('pending', 'running') and completed_at is null) or
    (status in ('completed', 'failed') and completed_at is not null)
  )
);

create table if not exists public.eval_results (
  id uuid primary key default gen_random_uuid(),
  eval_run_id uuid not null references public.eval_runs(id) on delete cascade,
  case_id uuid references public.golden_set_cases(id) on delete set null,
  agent_id uuid not null references public.agents(id) on delete cascade,
  evaluation_mode public.eval_mode not null,

  -- Answer-based fields.
  actual_response text,
  actual_sources text,
  answer_correct public.ynp_score,
  answer_issues text[] not null default '{}',
  source_correct public.ynp_score,
  source_issues text[] not null default '{}',
  response_quality public.quality_score,
  quality_issues text[] not null default '{}',

  -- Criteria-based fields.
  criteria_results jsonb,
  dimension_scores jsonb,
  overall_score text,

  reasoning text,
  tester text,
  search_mode text,
  eval_date date,
  notes text,

  match_type public.match_type not null default 'golden_set',
  matched_case_id uuid references public.golden_set_cases(id) on delete set null,
  created_at timestamptz not null default now(),

  constraint eval_results_unique_per_case_per_run unique (eval_run_id, case_id),
  constraint eval_results_criteria_results_is_array check (
    criteria_results is null or jsonb_typeof(criteria_results) = 'array'
  ),
  constraint eval_results_dimension_scores_is_object check (
    dimension_scores is null or jsonb_typeof(dimension_scores) = 'object'
  ),
  constraint eval_results_mode_shape check (
    (
      evaluation_mode = 'answer'
      and answer_correct is not null
      and source_correct is not null
      and response_quality is not null
      and criteria_results is null
      and dimension_scores is null
    )
    or
    (
      evaluation_mode = 'criteria'
      and answer_correct is null
      and source_correct is null
      and response_quality is null
      and criteria_results is not null
      and dimension_scores is not null
    )
  )
);

create table if not exists public.calibration_runs (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  agent_id uuid not null references public.agents(id) on delete cascade,
  prompt_version text not null,
  judge_model text not null,
  overall_agreement numeric(5,4) not null,
  clean_agreement numeric(5,4),
  per_case_comparison jsonb not null default '[]'::jsonb,
  created_by uuid references auth.users(id) on delete set null,
  created_at timestamptz not null default now(),
  constraint calibration_runs_overall_agreement_range
    check (overall_agreement >= 0 and overall_agreement <= 1),
  constraint calibration_runs_clean_agreement_range
    check (clean_agreement is null or (clean_agreement >= 0 and clean_agreement <= 1)),
  constraint calibration_runs_per_case_is_array
    check (jsonb_typeof(per_case_comparison) = 'array')
);

create index if not exists idx_eval_runs_org_id on public.eval_runs(org_id);
create index if not exists idx_eval_runs_agent_id on public.eval_runs(agent_id);
create index if not exists idx_eval_runs_status on public.eval_runs(status);
create index if not exists idx_eval_runs_type on public.eval_runs(type);
create index if not exists idx_eval_results_eval_run_id on public.eval_results(eval_run_id);
create index if not exists idx_eval_results_case_id on public.eval_results(case_id);
create index if not exists idx_eval_results_agent_id on public.eval_results(agent_id);
create index if not exists idx_calibration_runs_org_id on public.calibration_runs(org_id);
create index if not exists idx_calibration_runs_agent_id on public.calibration_runs(agent_id);

commit;
