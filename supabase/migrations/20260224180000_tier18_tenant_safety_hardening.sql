begin;

-- Compatibility helper: allow text-array callers while preserving role checks.
create or replace function public.has_org_role(target_org_id uuid, allowed_roles text[])
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
      and om.role::text = any(allowed_roles)
  );
$$;

grant execute on function public.has_org_role(uuid, text[]) to authenticated;

-- Enforce global key boundary: org_id is null => role must be admin.
update public.api_keys
set role = 'admin'::public.api_key_role
where org_id is null
  and role <> 'admin'::public.api_key_role;

do $$
begin
  if not exists (
    select 1
    from pg_constraint
    where conname = 'api_keys_global_admin_only'
      and conrelid = 'public.api_keys'::regclass
  ) then
    alter table public.api_keys
      add constraint api_keys_global_admin_only
      check (org_id is not null or role = 'admin'::public.api_key_role);
  end if;
end
$$;

-- Prevent direct authenticated role access to key material table.
alter table public.api_keys enable row level security;
alter table public.api_keys force row level security;

drop policy if exists api_keys_select_none on public.api_keys;
create policy api_keys_select_none
on public.api_keys
for select
to authenticated
using (false);

drop policy if exists api_keys_modify_none on public.api_keys;
create policy api_keys_modify_none
on public.api_keys
for all
to authenticated
using (false)
with check (false);

commit;
