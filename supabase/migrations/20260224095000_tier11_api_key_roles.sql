begin;

do $$
begin
  if not exists (select 1 from pg_type where typname = 'api_key_role') then
    create type public.api_key_role as enum ('admin', 'member', 'viewer');
  end if;
end
$$;

alter table public.api_keys
  add column if not exists role public.api_key_role not null default 'member';

update public.api_keys
set role = 'admin'::public.api_key_role
where org_id is null
  and role = 'member'::public.api_key_role;

create index if not exists idx_api_keys_role on public.api_keys(role);

commit;
