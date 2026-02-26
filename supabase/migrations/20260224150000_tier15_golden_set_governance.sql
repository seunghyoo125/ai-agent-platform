begin;

alter table public.golden_set_cases
  add column if not exists version integer not null default 1,
  add column if not exists is_active boolean not null default true,
  add column if not exists superseded_by uuid references public.golden_set_cases(id) on delete set null,
  add column if not exists last_reviewed_at timestamptz,
  add column if not exists review_notes text;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'golden_set_cases_version_positive'
  ) then
    alter table public.golden_set_cases
      add constraint golden_set_cases_version_positive check (version >= 1);
  end if;
end
$$;

create index if not exists idx_golden_set_cases_active
  on public.golden_set_cases(golden_set_id, is_active, created_at desc);

create index if not exists idx_golden_set_cases_superseded_by
  on public.golden_set_cases(superseded_by);

create table if not exists public.golden_set_case_reviews (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  golden_set_id uuid not null references public.golden_sets(id) on delete cascade,
  case_id uuid not null references public.golden_set_cases(id) on delete cascade,
  review_type text not null check (review_type in ('verify', 'supersede', 'note')),
  previous_status public.verification_status,
  new_status public.verification_status,
  reviewer_api_key_id uuid references public.api_keys(id) on delete set null,
  notes text,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists idx_golden_set_case_reviews_case
  on public.golden_set_case_reviews(case_id, created_at desc);

create index if not exists idx_golden_set_case_reviews_org
  on public.golden_set_case_reviews(org_id, golden_set_id, created_at desc);

alter table public.golden_set_case_reviews enable row level security;

drop policy if exists golden_set_case_reviews_select_member on public.golden_set_case_reviews;
create policy golden_set_case_reviews_select_member
on public.golden_set_case_reviews
for select
to authenticated
using (public.is_org_member(org_id));

drop policy if exists golden_set_case_reviews_manage_org on public.golden_set_case_reviews;
create policy golden_set_case_reviews_manage_org
on public.golden_set_case_reviews
for all
to authenticated
using (public.has_org_role(org_id, array['admin','member']::public.member_role[]))
with check (public.has_org_role(org_id, array['admin','member']::public.member_role[]));

commit;
