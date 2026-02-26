#!/usr/bin/env bash
set -euo pipefail

# Upload local CSV/JSONL/XLSX to /api/golden-sets/upload-file via JSON+base64 payload.
#
# Required env vars:
#   BASE_URL           e.g. http://127.0.0.1:8001
#   API_KEY            active API key
#   ORG_ID             org uuid
#   AGENT_ID           agent uuid
#   GOLDEN_SET_NAME    name for the new golden set
#
# Optional env vars:
#   API_PREFIX         /api (default) or /api/v1
#   DESCRIPTION        optional description
#   GENERATION_METHOD  manual (default)
#   SOURCE_FILES_JSON  JSON array string, e.g. ["doc1.pdf","doc2.pdf"]
#
# Usage:
#   scripts/upload_golden_set_file.sh /absolute/or/relative/path/to/cases.csv

for v in BASE_URL API_KEY ORG_ID AGENT_ID GOLDEN_SET_NAME; do
  if [[ -z "${!v:-}" ]]; then
    echo "Missing env var: $v" >&2
    exit 1
  fi
done

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <file_path>" >&2
  exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required but not installed." >&2
  exit 1
fi

file_path="$1"
if [[ ! -f "$file_path" ]]; then
  echo "File not found: $file_path" >&2
  exit 1
fi

API_PREFIX="${API_PREFIX:-/api}"
GENERATION_METHOD="${GENERATION_METHOD:-manual}"
DESCRIPTION="${DESCRIPTION:-}"
SOURCE_FILES_JSON="${SOURCE_FILES_JSON:-[]}"

filename="$(basename "$file_path")"
file_b64="$(base64 < "$file_path" | tr -d '\n')"

payload="$(jq -n \
  --arg org_id "$ORG_ID" \
  --arg agent_id "$AGENT_ID" \
  --arg name "$GOLDEN_SET_NAME" \
  --arg description "$DESCRIPTION" \
  --arg generation_method "$GENERATION_METHOD" \
  --arg filename "$filename" \
  --arg file_content_base64 "$file_b64" \
  --argjson source_files "$SOURCE_FILES_JSON" \
  '{
    org_id: $org_id,
    agent_id: $agent_id,
    name: $name,
    description: (if $description == "" then null else $description end),
    generation_method: $generation_method,
    source_files: $source_files,
    filename: $filename,
    file_content_base64: $file_content_base64
  }')"

resp="$(curl -s -X POST "${BASE_URL}${API_PREFIX}/golden-sets/upload-file" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d "$payload")"

if ! echo "$resp" | jq -e '.ok == true' >/dev/null; then
  echo "Upload failed:"
  echo "$resp" | jq .
  exit 1
fi

echo "$resp" | jq '{
  golden_set_id: .data.golden_set_id,
  name: .data.name,
  case_count: .data.case_count,
  validation_report: .data.validation_report
}'
