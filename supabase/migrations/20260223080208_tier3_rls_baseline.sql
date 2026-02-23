begin;

-- Helpers for org-scoped RLS checks.
create or replace function public.is_org_member(target_org_id uuid)
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.org_members om
    where om.org_id = target_org_id
      and om.user_id = auth.uid()
  );
$$;

create or replace function public.has_org_role(target_org_id uuid, allowed_roles public.member_role[])
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1
    from public.org_members om
    where om.org_id = target_org_id
      and om.user_id = auth.uid()
      and om.role = any(allowed_roles)
  );
$$;

grant execute on function public.is_org_member(uuid) to authenticated;
grant execute on function public.has_org_role(uuid, public.member_role[]) to authenticated;

alter table public.profiles enable row level security;
alter table public.orgs enable row level security;
alter table public.org_members enable row level security;
alter table public.eval_profiles enable row level security;
alter table public.agents enable row level security;
alter table public.golden_sets enable row level security;
alter table public.golden_set_cases enable row level security;
alter table public.eval_runs enable row level security;
alter table public.eval_results enable row level security;
alter table public.calibration_runs enable row level security;

-- profiles
drop policy if exists profiles_select_self on public.profiles;
create policy profiles_select_self
on public.profiles
for select
to authenticated
using (id = auth.uid());

drop policy if exists profiles_insert_self on public.profiles;
create policy profiles_insert_self
on public.profiles
for insert
to authenticated
with check (id = auth.uid());

drop policy if exists profiles_update_self on public.profiles;
create policy profiles_update_self
on public.profiles
for update
to authenticated
using (id = auth.uid())
with check (id = auth.uid());

-- orgs
drop policy if exists orgs_select_member on public.orgs;
create policy orgs_select_member
on public.orgs
for select
to authenticated
using (public.is_org_member(id));

drop policy if exists orgs_manage_admin on public.orgs;
create policy orgs_manage_admin
on public.orgs
for all
to authenticated
using (public.has_org_role(id, array['admin']::public.member_role[]))
with check (public.has_org_role(id, array['admin']::public.member_role[]));

-- org_members
drop policy if exists org_members_select_member on public.org_members;
create policy org_members_select_member
on public.org_members
for select
to authenticated
using (public.is_org_member(org_id));

drop policy if exists org_members_manage_admin on public.org_members;
create policy org_members_manage_admin
on public.org_members
for all
to authenticated
using (public.has_org_role(org_id, array['admin']::public.member_role[]))
with check (public.has_org_role(org_id, array['admin']::public.member_role[]));

-- eval_profiles: built-ins are readable by authenticated users.
drop policy if exists eval_profiles_select_scope on public.eval_profiles;
create policy eval_profiles_select_scope
on public.eval_profiles
for select
to authenticated
using (
  is_builtin = true
  or (org_id is not null and public.is_org_member(org_id))
);

drop policy if exists eval_profiles_manage_org on public.eval_profiles;
create policy eval_profiles_manage_org
on public.eval_profiles
for all
to authenticated
using (
  org_id is not null
  and public.has_org_role(org_id, array['admin','member']::public.member_role[])
)
with check (
  org_id is not null
  and public.has_org_role(org_id, array['admin','member']::public.member_role[])
);

-- agents
drop policy if exists agents_select_member on public.agents;
create policy agents_select_member
on public.agents
for select
to authenticated
using (public.is_org_member(org_id));

drop policy if exists agents_manage_org on public.agents;
create policy agents_manage_org
on public.agents
for all
to authenticated
using (public.has_org_role(org_id, array['admin','member']::public.member_role[]))
with check (public.has_org_role(org_id, array['admin','member']::public.member_role[]));

-- golden_sets
drop policy if exists golden_sets_select_member on public.golden_sets;
create policy golden_sets_select_member
on public.golden_sets
for select
to authenticated
using (public.is_org_member(org_id));

drop policy if exists golden_sets_manage_org on public.golden_sets;
create policy golden_sets_manage_org
on public.golden_sets
for all
to authenticated
using (public.has_org_role(org_id, array['admin','member']::public.member_role[]))
with check (public.has_org_role(org_id, array['admin','member']::public.member_role[]));

-- golden_set_cases (org scope inherited via golden_sets).
drop policy if exists golden_set_cases_select_member on public.golden_set_cases;
create policy golden_set_cases_select_member
on public.golden_set_cases
for select
to authenticated
using (
  exists (
    select 1
    from public.golden_sets gs
    where gs.id = golden_set_id
      and public.is_org_member(gs.org_id)
  )
);

drop policy if exists golden_set_cases_manage_org on public.golden_set_cases;
create policy golden_set_cases_manage_org
on public.golden_set_cases
for all
to authenticated
using (
  exists (
    select 1
    from public.golden_sets gs
    where gs.id = golden_set_id
      and public.has_org_role(gs.org_id, array['admin','member']::public.member_role[])
  )
)
with check (
  exists (
    select 1
    from public.golden_sets gs
    where gs.id = golden_set_id
      and public.has_org_role(gs.org_id, array['admin','member']::public.member_role[])
  )
);

-- eval_runs
drop policy if exists eval_runs_select_member on public.eval_runs;
create policy eval_runs_select_member
on public.eval_runs
for select
to authenticated
using (public.is_org_member(org_id));

drop policy if exists eval_runs_manage_org on public.eval_runs;
create policy eval_runs_manage_org
on public.eval_runs
for all
to authenticated
using (public.has_org_role(org_id, array['admin','member']::public.member_role[]))
with check (public.has_org_role(org_id, array['admin','member']::public.member_role[]));

-- eval_results (org scope inherited via eval_runs).
drop policy if exists eval_results_select_member on public.eval_results;
create policy eval_results_select_member
on public.eval_results
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

drop policy if exists eval_results_manage_org on public.eval_results;
create policy eval_results_manage_org
on public.eval_results
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

-- calibration_runs
drop policy if exists calibration_runs_select_member on public.calibration_runs;
create policy calibration_runs_select_member
on public.calibration_runs
for select
to authenticated
using (public.is_org_member(org_id));

drop policy if exists calibration_runs_manage_org on public.calibration_runs;
create policy calibration_runs_manage_org
on public.calibration_runs
for all
to authenticated
using (public.has_org_role(org_id, array['admin','member']::public.member_role[]))
with check (public.has_org_role(org_id, array['admin','member']::public.member_role[]));

commit;
