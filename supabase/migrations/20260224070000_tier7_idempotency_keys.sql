begin;

do $$
begin
  if not exists (select 1 from pg_type where typname = 'idempotency_status') then
    create type public.idempotency_status as enum ('in_progress', 'completed');
  end if;
end
$$;

create table if not exists public.idempotency_keys (
  id uuid primary key default gen_random_uuid(),
  api_key_id uuid not null references public.api_keys(id) on delete cascade,
  method text not null,
  path text not null,
  idempotency_key text not null,
  request_hash text not null,
  status public.idempotency_status not null default 'in_progress',
  response_status integer,
  response_body jsonb,
  created_at timestamptz not null default now(),
  completed_at timestamptz,
  constraint idempotency_unique_key unique (api_key_id, method, path, idempotency_key),
  constraint idempotency_response_shape
    check (
      (status = 'completed' and response_status is not null and response_body is not null) or
      (status = 'in_progress')
    )
);

create index if not exists idx_idempotency_keys_created_at on public.idempotency_keys(created_at desc);
create index if not exists idx_idempotency_keys_api_key on public.idempotency_keys(api_key_id);

alter table public.idempotency_keys enable row level security;

drop policy if exists idempotency_keys_select_none on public.idempotency_keys;
create policy idempotency_keys_select_none
on public.idempotency_keys
for select
to authenticated
using (false);

drop policy if exists idempotency_keys_modify_none on public.idempotency_keys;
create policy idempotency_keys_modify_none
on public.idempotency_keys
for all
to authenticated
using (false)
with check (false);

commit;
