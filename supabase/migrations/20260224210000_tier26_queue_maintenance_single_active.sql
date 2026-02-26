-- Tier 26: Queue maintenance run concurrency guard
-- Ensure only one active (running) maintenance run per org.

create unique index if not exists idx_queue_maintenance_runs_one_running_per_org
on public.queue_maintenance_runs (org_id)
where status = 'running';
