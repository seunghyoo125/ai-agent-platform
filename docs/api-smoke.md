# API Smoke Test

Use this script to verify core API flow before merging major changes.

Script:

- `/Users/seungyoo/Desktop/ai-agent-platform/scripts/smoke_api.sh`

Required env vars:

- `BASE_URL` (example: `http://127.0.0.1:8001`)
- `API_KEY` (active DB-backed API key)
- `ORG_ID`
- `AGENT_ID`
- `GOLDEN_SET_ID`

Run:

```bash
BASE_URL=http://127.0.0.1:8001 \
API_KEY=sk_live_xxx \
ORG_ID=23cdb862-a12f-4b6c-84ee-5cb648f9b5bb \
AGENT_ID=e3660b25-47cf-47f3-ab53-c080fb7ffdcc \
GOLDEN_SET_ID=6755aac9-2d1e-46bd-8962-5731dbe4b6b5 \
/Users/seungyoo/Desktop/ai-agent-platform/scripts/smoke_api.sh
```

What it checks:

1. health endpoint
2. agent listing
3. eval run creation
4. eval execution
5. run summary
6. run results
7. validation error envelope contract
