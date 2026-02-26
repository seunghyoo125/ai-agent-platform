begin;

create table if not exists public.eval_run_artifacts (
  id uuid primary key default gen_random_uuid(),
  eval_run_id uuid not null references public.eval_runs(id) on delete cascade,
  eval_result_id uuid references public.eval_results(id) on delete set null,
  case_id uuid references public.golden_set_cases(id) on delete set null,
  agent_id uuid not null references public.agents(id) on delete cascade,
  evaluation_mode public.eval_mode not null,
  judge_mode text not null,
  judge_model text,
  judge_prompt_version text,
  judge_prompt_hash text not null,
  executor_mode text not null,
  case_latency_ms numeric(10,2),
  execution_latency_ms numeric(10,2),
  judge_latency_ms numeric(10,2),
  token_usage jsonb not null default '{}'::jsonb,
  judge_input jsonb not null default '{}'::jsonb,
  judge_output jsonb not null default '{}'::jsonb,
  execution_trace jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  constraint eval_run_artifacts_token_usage_is_object check (jsonb_typeof(token_usage) = 'object'),
  constraint eval_run_artifacts_judge_input_is_object check (jsonb_typeof(judge_input) = 'object'),
  constraint eval_run_artifacts_judge_output_is_object check (jsonb_typeof(judge_output) = 'object'),
  constraint eval_run_artifacts_execution_trace_is_object check (jsonb_typeof(execution_trace) = 'object')
);

create index if not exists idx_eval_run_artifacts_run_id on public.eval_run_artifacts(eval_run_id, created_at);
create index if not exists idx_eval_run_artifacts_result_id on public.eval_run_artifacts(eval_result_id);
create index if not exists idx_eval_run_artifacts_case_id on public.eval_run_artifacts(case_id);
create index if not exists idx_eval_run_artifacts_agent_id on public.eval_run_artifacts(agent_id);
create index if not exists idx_eval_run_artifacts_prompt_hash on public.eval_run_artifacts(judge_prompt_hash);

alter table public.eval_run_artifacts enable row level security;

drop policy if exists eval_run_artifacts_select_member on public.eval_run_artifacts;
create policy eval_run_artifacts_select_member
on public.eval_run_artifacts
for select
to authenticated
using (
  exists (
    select 1
    from public.eval_runs er
    where er.id = eval_run_id
      and public.is_org_member(er.org_id)
  )
);

drop policy if exists eval_run_artifacts_manage_org on public.eval_run_artifacts;
create policy eval_run_artifacts_manage_org
on public.eval_run_artifacts
for all
to authenticated
using (
  exists (
    select 1
    from public.eval_runs er
    where er.id = eval_run_id
      and public.has_org_role(er.org_id, array['admin','member']::public.member_role[])
  )
)
with check (
  exists (
    select 1
    from public.eval_runs er
    where er.id = eval_run_id
      and public.has_org_role(er.org_id, array['admin','member']::public.member_role[])
  )
);

commit;
