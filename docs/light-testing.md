# Light Testing Guide

Use this when you want fast confidence before continuing feature work.

## Prerequisites

- API server running on `BASE_URL`
- Worker running (`python3 -m src.api.worker`)
- Valid org + agent IDs
- API key with member/admin scope

## One-command Light UAT

```bash
BASE_URL=http://127.0.0.1:8001 \
API_PREFIX=/api/v1 \
API_KEY=<member_or_admin_key> \
ADMIN_API_KEY=<admin_key_optional> \
ORG_ID=<org_id> \
AGENT_ID=<agent_id> \
./scripts/light_api_uat.sh
```

This does:
1. health check
2. list agents
3. upload a 1-case golden set
4. create eval run
5. execute eval run
6. assert run summary + results
7. optional drift schedule dry-run

## When to Run Integration Tests

- Per PR: run unit/contract tests only.
- Before merge to `main`: run DB integration tests once.
- Nightly/scheduled CI: run DB integration tests against non-prod Supabase.

Command:

```bash
RUN_DB_INTEGRATION=1 PYTHONPATH=. pytest -q tests/test_contract_drift_schedule_integration.py
```
