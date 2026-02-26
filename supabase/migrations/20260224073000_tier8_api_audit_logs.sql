begin;

create table if not exists public.api_audit_logs (
  id uuid primary key default gen_random_uuid(),
  request_id text not null,
  api_key_id uuid references public.api_keys(id) on delete set null,
  org_id uuid references public.orgs(id) on delete set null,
  method text not null,
  path text not null,
  status_code integer not null,
  latency_ms integer not null,
  error_code text,
  created_at timestamptz not null default now()
);

create index if not exists idx_api_audit_logs_created_at on public.api_audit_logs(created_at desc);
create index if not exists idx_api_audit_logs_request_id on public.api_audit_logs(request_id);
create index if not exists idx_api_audit_logs_api_key_id on public.api_audit_logs(api_key_id);
create index if not exists idx_api_audit_logs_org_id on public.api_audit_logs(org_id);
create index if not exists idx_api_audit_logs_path on public.api_audit_logs(path);

alter table public.api_audit_logs enable row level security;

drop policy if exists api_audit_logs_select_none on public.api_audit_logs;
create policy api_audit_logs_select_none
on public.api_audit_logs
for select
to authenticated
using (false);

drop policy if exists api_audit_logs_modify_none on public.api_audit_logs;
create policy api_audit_logs_modify_none
on public.api_audit_logs
for all
to authenticated
using (false)
with check (false);

commit;
