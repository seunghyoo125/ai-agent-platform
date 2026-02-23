#!/usr/bin/env bash
set -euo pipefail

# Required env vars:
#   BASE_URL        e.g. http://127.0.0.1:8001
#   API_KEY         e.g. sk_live_xxx
#   ORG_ID          existing org uuid
#   AGENT_ID        existing agent uuid
#   GOLDEN_SET_ID   golden set uuid attached to AGENT_ID

for v in BASE_URL API_KEY ORG_ID AGENT_ID GOLDEN_SET_ID; do
  if [[ -z "${!v:-}" ]]; then
    echo "Missing env var: $v"
    exit 1
  fi
done

auth_header="Authorization: Bearer ${API_KEY}"

echo "[1/7] Health"
curl -s "${BASE_URL}/health" | jq -e '.ok == true' >/dev/null

echo "[2/7] Agent list"
agents_resp="$(curl -s "${BASE_URL}/api/agents?org_id=${ORG_ID}" -H "${auth_header}")"
if ! echo "${agents_resp}" | jq -e '.ok == true and (.data.count >= 1)' >/dev/null; then
  echo "Agent list check failed. Response:"
  echo "${agents_resp}" | jq .
  exit 1
fi

echo "[3/7] Create eval run"
run_payload="$(jq -n \
  --arg org_id "${ORG_ID}" \
  --arg agent_id "${AGENT_ID}" \
  --arg golden_set_id "${GOLDEN_SET_ID}" \
  '{
    org_id: $org_id,
    agent_id: $agent_id,
    golden_set_id: $golden_set_id,
    name: "smoke-run",
    type: "eval",
    config: {sample_size: "all"},
    design_context: {reason: "smoke test"}
  }')"

run_resp="$(curl -s -X POST "${BASE_URL}/api/eval/runs" \
  -H "${auth_header}" \
  -H "Content-Type: application/json" \
  -d "${run_payload}")"

echo "${run_resp}" | jq -e '.ok == true and .data.run_id != null' >/dev/null
run_id="$(echo "${run_resp}" | jq -r '.data.run_id')"

echo "[4/7] Execute run: ${run_id}"
curl -s -X POST "${BASE_URL}/api/eval/runs/${run_id}/execute" -H "${auth_header}" | jq -e '.ok == true and .data.status == "completed"' >/dev/null

echo "[5/7] Run summary"
curl -s "${BASE_URL}/api/eval/runs/${run_id}/summary" -H "${auth_header}" | jq -e '.ok == true and (.data.total_results >= 1)' >/dev/null

echo "[6/7] Run results"
curl -s "${BASE_URL}/api/eval/runs/${run_id}/results" -H "${auth_header}" | jq -e '.ok == true and (.data.total_count >= 1)' >/dev/null

echo "[7/7] Validation envelope"
curl -s -X POST "${BASE_URL}/api/agents" \
  -H "${auth_header}" \
  -H "Content-Type: application/json" \
  -d '{}' | jq -e '.ok == false and .error.code == "VALIDATION_ERROR"' >/dev/null

echo "Smoke test passed."
