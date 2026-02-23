# CI Smoke Setup

GitHub Actions workflow:

- `/Users/seungyoo/Desktop/ai-agent-platform/.github/workflows/api-smoke.yml`

This workflow starts the API locally in CI and runs:

- `/Users/seungyoo/Desktop/ai-agent-platform/scripts/smoke_api.sh`

## Required GitHub Secrets

Add these in repository settings:

1. `SUPABASE_DB_URL`
2. `SMOKE_API_KEY`
3. `SMOKE_ORG_ID`
4. `SMOKE_AGENT_ID`
5. `SMOKE_GOLDEN_SET_ID`

## Notes

- `SMOKE_API_KEY` must be an active key in `public.api_keys`.
- If you rotate keys, update `SMOKE_API_KEY`.
- If you replace smoke fixtures, update the three smoke IDs.
