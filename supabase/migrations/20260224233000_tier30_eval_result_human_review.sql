begin;

do $$
begin
  if not exists (select 1 from pg_type where typname = 'eval_review_status') then
    create type public.eval_review_status as enum ('unreviewed', 'accepted', 'overridden');
  end if;
end
$$;

alter table public.eval_results
  add column if not exists review_status public.eval_review_status not null default 'unreviewed',
  add column if not exists reviewed_by_api_key_id uuid references public.api_keys(id) on delete set null,
  add column if not exists reviewed_at timestamptz,
  add column if not exists review_decision text,
  add column if not exists review_reason text,
  add column if not exists review_override jsonb not null default '{}'::jsonb;

alter table public.eval_results
  drop constraint if exists eval_results_review_override_is_object;
alter table public.eval_results
  add constraint eval_results_review_override_is_object
  check (jsonb_typeof(review_override) = 'object');

create index if not exists idx_eval_results_run_review_status
  on public.eval_results(eval_run_id, review_status, created_at);

create index if not exists idx_eval_results_reviewed_at
  on public.eval_results(reviewed_at);

commit;
