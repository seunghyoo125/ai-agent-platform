begin;

create table if not exists public.notification_outbox (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references public.orgs(id) on delete cascade,
  agent_id uuid references public.agents(id) on delete set null,
  event_type text not null,
  payload jsonb not null default '{}'::jsonb,
  status text not null default 'pending' check (status in ('pending', 'sending', 'sent', 'dead')),
  attempt_count integer not null default 0 check (attempt_count >= 0),
  max_attempts integer not null default 5 check (max_attempts >= 1),
  next_attempt_at timestamptz not null default now(),
  sent_at timestamptz,
  last_error text,
  source_request_id text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_notification_outbox_status_next
  on public.notification_outbox(status, next_attempt_at, created_at);

create index if not exists idx_notification_outbox_org_created
  on public.notification_outbox(org_id, created_at desc);

create trigger trg_notification_outbox_updated_at
before update on public.notification_outbox
for each row execute procedure public.set_updated_at();

alter table public.notification_outbox enable row level security;
alter table public.notification_outbox force row level security;

drop policy if exists notification_outbox_select_none on public.notification_outbox;
create policy notification_outbox_select_none
on public.notification_outbox
for select
to authenticated
using (false);

drop policy if exists notification_outbox_modify_none on public.notification_outbox;
create policy notification_outbox_modify_none
on public.notification_outbox
for all
to authenticated
using (false)
with check (false);

commit;
