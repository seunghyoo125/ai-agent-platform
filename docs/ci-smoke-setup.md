# CI Smoke Setup

GitHub Actions workflow:

- `/Users/seungyoo/Desktop/ai-agent-platform/.github/workflows/api-smoke.yml`

This workflow starts the API locally in CI and runs:

- `/Users/seungyoo/Desktop/ai-agent-platform/scripts/ci_quality_gate.sh`
- full `pytest` suite
- SDK generation + drift check
- async worker process (`python3 -m src.api.worker`)

## Required GitHub Secrets

Add these in repository settings:

1. `SUPABASE_DB_URL`
2. `SMOKE_API_KEY`
3. `SMOKE_ORG_ID`
4. `SMOKE_AGENT_ID`
5. `SMOKE_GOLDEN_SET_ID`
6. `SMOKE_ADMIN_API_KEY` (optional; falls back to `SMOKE_API_KEY`)

## Notes

- `SMOKE_API_KEY` must be an active key in `public.api_keys`.
- `SMOKE_API_KEY` should have at least member scope.
- `SMOKE_ADMIN_API_KEY` should be admin if provided (for queue stats/dead-letter gates).
- If you rotate keys, update `SMOKE_API_KEY`.
- If you replace smoke fixtures, update the three smoke IDs.
- Workflow uses `API_PREFIX=/api/v1` (canonical route path) by default.
- Build fails if generated SDK files are stale:
  - `/sdk/python/greenlight_client.py`
  - `/sdk/typescript/greenlightClient.ts`
- Workflow uploads artifacts on every run:
  - `openapi.json`
  - generated SDK files
  - `uvicorn.log`

## Run Later Checklist (Do Not Forget)

When ready to validate in GitHub:

1. Open repository Actions tab.
2. Select workflow `API Smoke`.
3. Click `Run workflow` on branch `main`.
4. Confirm job `quality-gates` passes:
   - SDK drift check
   - full `pytest`
   - queue-aware quality gate (async start/poll/compare/queue checks)
5. Open run artifacts and verify these exist:
   - `openapi.json`
   - `sdk/python/greenlight_client.py`
   - `sdk/typescript/greenlightClient.ts`
   - `uvicorn.log`
   - `worker.log`

If run fails:

1. Check failed step logs first.
2. Download `uvicorn.log` artifact.
3. Fix issue locally, rerun `PYTHONPATH=. pytest -q`, and push again.
