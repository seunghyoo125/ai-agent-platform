# Supabase Tier 1 Foundation

This repo now includes the Tier 1 migration for Greenlight core primitives:

- `orgs`
- `profiles` (linked to `auth.users`)
- `org_members`
- `eval_profiles`
- `agents`
- `golden_sets`
- `golden_set_cases`

Migration file:

- `/Users/seungyoo/Desktop/ai-agent-platform/supabase/migrations/20260223073529_tier1_core.sql`

## Apply in Supabase Dashboard

1. Open your project SQL Editor.
2. Paste the migration file contents.
3. Run once.

## Why this migration is strict

- Enums prevent taxonomy drift.
- `golden_set_cases_mode_shape` enforces valid field usage by `evaluation_mode`.
- Built-in eval profiles are constrained to global scope (`is_builtin=true` => `org_id is null`).

## Tier 2 migration (now added)

Run this file next:

- `/Users/seungyoo/Desktop/ai-agent-platform/supabase/migrations/20260223074157_tier2_eval_engine.sql`

It adds:

- `eval_runs`
- `eval_results`
- `calibration_runs`

With strict checks for:

- run lifecycle timestamps by status
- answer-mode vs criteria-mode result shape
- agreement score bounds (`0..1`)

Next recommended piece after Tier 2:

- RLS policies for org-scoped access
- seed built-in eval profiles

## Tier 4 migration (operations layer)

Run this file after Tier 3:

- `/Users/seungyoo/Desktop/ai-agent-platform/supabase/migrations/20260223113220_tier4_operations_layer.sql`

It adds:

- `issue_patterns`
- `launch_readiness`

With:

- strict enum validations
- JSON shape checks
- one readiness record per agent
- RLS policies aligned to org membership/role

## Tier 5 migration (API keys)

Run this file after Tier 4:

- `/Users/seungyoo/Desktop/ai-agent-platform/supabase/migrations/20260223142134_tier5_api_keys.sql`

It adds:

- `api_keys` table for hashed bearer-key auth

With:

- key status (`active`/`revoked`)
- optional key expiry
- `last_used_at` tracking
