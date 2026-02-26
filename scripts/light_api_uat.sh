#!/usr/bin/env bash
set -euo pipefail

# Light end-to-end API UAT flow:
# 1) health
# 2) list agents
# 3) upload 1-case golden set
# 4) create eval run
# 5) execute run
# 6) summary + results checks
# 7) optional drift schedule dry-run (if ADMIN_API_KEY provided)

# Required:
#   BASE_URL    e.g. http://127.0.0.1:8001
#   API_KEY     member/admin key
#   ORG_ID      org uuid
#   AGENT_ID    existing agent uuid
# Optional:
#   API_PREFIX      default /api
#   ADMIN_API_KEY   admin key for optional scheduler check
#   OPENAI_API_KEY  only needed for provider judge mode

for v in BASE_URL API_KEY ORG_ID AGENT_ID; do
  if [[ -z "${!v:-}" ]]; then
    echo "Missing env var: $v"
    exit 1
  fi
done

API_PREFIX="${API_PREFIX:-/api}"
auth_header="Authorization: Bearer ${API_KEY}"
admin_header="Authorization: Bearer ${ADMIN_API_KEY:-}"
run_ts="$(date -u +%Y%m%d%H%M%S)"

echo "[1/8] Health"
curl -s "${BASE_URL}/health" | jq -e '.ok == true' >/dev/null

echo "[2/8] Agent list"
agent_resp="$(curl -s "${BASE_URL}${API_PREFIX}/agents?org_id=${ORG_ID}&limit=5" -H "${auth_header}")"
echo "${agent_resp}" | jq -e '.ok == true and .data.count >= 1' >/dev/null
agent_type="$(echo "${agent_resp}" | jq -r --arg aid "${AGENT_ID}" '.data.items[] | select(.id == $aid) | .agent_type' | head -n1)"
if [[ -z "${agent_type}" || "${agent_type}" == "null" ]]; then
  echo "Agent ${AGENT_ID} not found under org ${ORG_ID}. Response:"
  echo "${agent_resp}" | jq .
  exit 1
fi
echo "Resolved agent_type=${agent_type}"

echo "[3/8] Upload golden set (1 case)"
if [[ "${agent_type}" == "document_generator" || "${agent_type}" == "analysis" ]]; then
  gs_payload="$(jq -n \
    --arg org_id "${ORG_ID}" \
    --arg agent_id "${AGENT_ID}" \
    --arg name "light-uat-gs-${run_ts}" \
    '{
      org_id: $org_id,
      agent_id: $agent_id,
      name: $name,
      description: "Light UAT golden set (criteria mode)",
      generation_method: "manual",
      source_files: ["uat-source.md"],
      cases: [
        {
          input: "Generate a concise user story for remote-work policy.",
          acceptable_sources: "HR Policy 2026",
          evaluation_mode: "criteria",
          evaluation_criteria: [
            {id: "completeness", label: "Completeness", expected: "Includes role, goal, and value"},
            {id: "accuracy", label: "Accuracy", expected: "Mentions 3 in-office days"},
            {id: "format_compliance", label: "Format Compliance", expected: "Output is valid user-story format"},
            {id: "actionability", label: "Actionability", expected: "Story is implementation-ready"}
          ],
          difficulty: "easy",
          capability: "synthesis",
          scenario_type: "straightforward",
          domain: "hr",
          verification_status: "unverified"
        }
      ]
    }')"
else
  gs_payload="$(jq -n \
    --arg org_id "${ORG_ID}" \
    --arg agent_id "${AGENT_ID}" \
    --arg name "light-uat-gs-${run_ts}" \
    '{
      org_id: $org_id,
      agent_id: $agent_id,
      name: $name,
      description: "Light UAT golden set (answer mode)",
      generation_method: "manual",
      source_files: ["uat-source.md"],
      cases: [
        {
          input: "What is Acme remote work policy?",
          expected_output: "Acme uses a hybrid policy with three in-office days.",
          acceptable_sources: "HR Policy 2026",
          evaluation_mode: "answer",
          difficulty: "easy",
          capability: "retrieval",
          scenario_type: "straightforward",
          domain: "hr",
          verification_status: "unverified"
        }
      ]
    }')"
fi

gs_resp="$(curl -s -X POST "${BASE_URL}${API_PREFIX}/golden-sets/upload" \
  -H "${auth_header}" \
  -H "Content-Type: application/json" \
  -d "${gs_payload}")"

echo "${gs_resp}" | jq -e '.ok == true and .data.golden_set_id != null and .data.case_count >= 1' >/dev/null
golden_set_id="$(echo "${gs_resp}" | jq -r '.data.golden_set_id')"

echo "[4/8] Create eval run"
run_payload="$(jq -n \
  --arg org_id "${ORG_ID}" \
  --arg agent_id "${AGENT_ID}" \
  --arg golden_set_id "${golden_set_id}" \
  --arg name "light-uat-run-${run_ts}" \
  '{
    org_id: $org_id,
    agent_id: $agent_id,
    golden_set_id: $golden_set_id,
    name: $name,
    type: "eval",
    config: {sample_size: "all"},
    design_context: {reason: "light api uat"}
  }')"

run_resp="$(curl -s -X POST "${BASE_URL}${API_PREFIX}/eval/runs" \
  -H "${auth_header}" \
  -H "Content-Type: application/json" \
  -d "${run_payload}")"

echo "${run_resp}" | jq -e '.ok == true and .data.run_id != null' >/dev/null
run_id="$(echo "${run_resp}" | jq -r '.data.run_id')"

echo "[5/8] Execute eval run"
exec_resp="$(curl -s -X POST "${BASE_URL}${API_PREFIX}/eval/runs/${run_id}/execute" -H "${auth_header}")"
if ! echo "${exec_resp}" | jq -e '.ok == true and (.data.status == "completed" or .data.status == "pending" or .data.status == "running")' >/dev/null; then
  echo "Execute failed. Response:"
  echo "${exec_resp}" | jq .
  exit 1
fi

echo "[6/8] Poll run summary"
summary_resp=""
for i in {1..20}; do
  summary_resp="$(curl -s "${BASE_URL}${API_PREFIX}/eval/runs/${run_id}/summary" -H "${auth_header}")"
  status_val="$(echo "${summary_resp}" | jq -r '.data.status // empty')"
  if [[ "${status_val}" == "completed" ]]; then
    break
  fi
  sleep 1
done

if ! echo "${summary_resp}" | jq -e '.ok == true and .data.run_id != null and .data.status == "completed"' >/dev/null; then
  echo "Summary did not reach completed state. Last response:"
  echo "${summary_resp}" | jq .
  exit 1
fi

echo "[7/8] Validate results envelope"
results_resp="$(curl -s "${BASE_URL}${API_PREFIX}/eval/runs/${run_id}/results?limit=20" -H "${auth_header}")"
if ! echo "${results_resp}" | jq -e '.ok == true and .data.total_count >= 1' >/dev/null; then
  echo "Results check failed. Response:"
  echo "${results_resp}" | jq .
  exit 1
fi

echo "[8/8] Optional schedule-run dry run"
if [[ -n "${ADMIN_API_KEY:-}" ]]; then
  schedule_payload="$(jq -n \
    --arg org_id "${ORG_ID}" \
    --arg agent_id "${AGENT_ID}" \
    '{
      org_id: $org_id,
      agent_id: $agent_id,
      summary_window_days: 30,
      dry_run: true,
      force: true,
      force_notify: false
    }')"
  schedule_resp="$(curl -s -X POST "${BASE_URL}${API_PREFIX}/system/contracts/drift/schedule-run" \
    -H "${admin_header}" \
    -H "Idempotency-Key: light-uat-schedule-${run_ts}" \
    -H "Content-Type: application/json" \
    -d "${schedule_payload}")"
  if ! echo "${schedule_resp}" | jq -e '.ok == true and .data.trigger != null and .data.notify != null' >/dev/null; then
    echo "Schedule-run dry test failed. Response:"
    echo "${schedule_resp}" | jq .
    exit 1
  fi
  echo "Schedule-run dry test passed."
else
  echo "Skipped schedule-run dry test (ADMIN_API_KEY not set)."
fi

echo "Light API UAT passed."
echo "run_id=${run_id}"
echo "golden_set_id=${golden_set_id}"
