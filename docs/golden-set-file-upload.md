# Golden Set File Upload Script

Script:

- `/Users/seungyoo/Desktop/ai-agent-platform/scripts/upload_golden_set_file.sh`

Purpose:

- Upload local `csv/jsonl/xlsx` golden set file directly to:
  - `POST /api/golden-sets/upload-file` (or `/api/v1/...`)
- Handles base64 payload conversion automatically.

Required env vars:

- `BASE_URL` (example: `http://127.0.0.1:8001`)
- `API_KEY`
- `ORG_ID`
- `AGENT_ID`
- `GOLDEN_SET_NAME`

Optional env vars:

- `API_PREFIX` (default `/api`, set `/api/v1` for versioned path)
- `DESCRIPTION`
- `GENERATION_METHOD` (default `manual`)
- `SOURCE_FILES_JSON` (JSON array string, default `[]`)

Usage:

```bash
BASE_URL=http://127.0.0.1:8001 \
API_PREFIX=/api/v1 \
API_KEY=dev_plain_key_001 \
ORG_ID=23cdb862-a12f-4b6c-84ee-5cb648f9b5bb \
AGENT_ID=e3660b25-47cf-47f3-ab53-c080fb7ffdcc \
GOLDEN_SET_NAME="Acme Retrieval GS from CSV" \
DESCRIPTION="uploaded from script" \
GENERATION_METHOD=manual \
SOURCE_FILES_JSON='["acme-hr-policy.pdf"]' \
/Users/seungyoo/Desktop/ai-agent-platform/scripts/upload_golden_set_file.sh \
/Users/seungyoo/Desktop/ai-agent-platform/examples/golden_set.csv
```

Output:

- Prints JSON summary:
  - `golden_set_id`
  - `name`
  - `case_count`
  - `validation_report` (`total_rows`, `accepted_rows`, `rejected_rows`, row issues)
