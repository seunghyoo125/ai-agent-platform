begin;

do $$
begin
  if not exists (select 1 from pg_type where typname = 'api_key_status') then
    create type public.api_key_status as enum ('active', 'revoked');
  end if;
end
$$;

create table if not exists public.api_keys (
  id uuid primary key default gen_random_uuid(),
  org_id uuid references public.orgs(id) on delete cascade,
  name text not null,
  key_prefix text not null,
  key_hash text not null unique,
  status public.api_key_status not null default 'active',
  expires_at timestamptz,
  last_used_at timestamptz,
  created_at timestamptz not null default now(),
  constraint api_keys_key_prefix_not_blank check (length(trim(key_prefix)) > 0)
);

create index if not exists idx_api_keys_status on public.api_keys(status);
create index if not exists idx_api_keys_org_id on public.api_keys(org_id);
create index if not exists idx_api_keys_expires_at on public.api_keys(expires_at);

-- Keep key management as service-layer concern for now.
-- RLS can be added when user-facing key admin endpoints are introduced.

commit;
