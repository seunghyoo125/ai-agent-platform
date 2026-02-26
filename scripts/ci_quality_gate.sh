#!/usr/bin/env bash
set -euo pipefail

# CI quality gate for async queue execution + regression compare.
#
# Required env vars:
#   BASE_URL
#   API_KEY
#   ORG_ID
#   AGENT_ID
#   GOLDEN_SET_ID
#
# Optional env vars:
#   API_PREFIX               default: /api/v1
#   ADMIN_API_KEY            default: API_KEY
#   QUEUE_MAX_RUNNING        default: 0
#   ALLOWED_REGRESSIONS      default: 0
#   MIN_ANSWER_DELTA         default: 0
#   MIN_SOURCE_DELTA         default: 0
#   MIN_QUALITY_DELTA        default: 0
#   POLL_MAX_ATTEMPTS        default: 90
#   POLL_SLEEP_SECONDS       default: 2

for v in BASE_URL API_KEY ORG_ID AGENT_ID GOLDEN_SET_ID; do
  if [[ -z "${!v:-}" ]]; then
    echo "Missing env var: $v" >&2
    exit 1
  fi
done

if ! command -v jq >/dev/null 2>&1; then
  echo "jq is required." >&2
  exit 1
fi

API_PREFIX="${API_PREFIX:-/api/v1}"
ADMIN_API_KEY="${ADMIN_API_KEY:-$API_KEY}"
QUEUE_MAX_RUNNING="${QUEUE_MAX_RUNNING:-0}"
ALLOWED_REGRESSIONS="${ALLOWED_REGRESSIONS:-0}"
MIN_ANSWER_DELTA="${MIN_ANSWER_DELTA:-0}"
MIN_SOURCE_DELTA="${MIN_SOURCE_DELTA:-0}"
MIN_QUALITY_DELTA="${MIN_QUALITY_DELTA:-0}"
POLL_MAX_ATTEMPTS="${POLL_MAX_ATTEMPTS:-90}"
POLL_SLEEP_SECONDS="${POLL_SLEEP_SECONDS:-2}"

auth_header="Authorization: Bearer ${API_KEY}"
admin_auth_header="Authorization: Bearer ${ADMIN_API_KEY}"

create_run() {
  local run_name="$1"
  local payload
  payload="$(jq -n \
    --arg org_id "${ORG_ID}" \
    --arg agent_id "${AGENT_ID}" \
    --arg golden_set_id "${GOLDEN_SET_ID}" \
    --arg name "${run_name}" \
    '{
      org_id: $org_id,
      agent_id: $agent_id,
      golden_set_id: $golden_set_id,
      name: $name,
      type: "eval",
      config: {executor_mode: "auto", judge_mode: "deterministic"},
      design_context: {reason: "ci quality gate"}
    }')"

  curl -s -X POST "${BASE_URL}${API_PREFIX}/eval/runs" \
    -H "${auth_header}" \
    -H "Content-Type: application/json" \
    -d "${payload}"
}

start_run() {
  local run_id="$1"
  curl -s -X POST "${BASE_URL}${API_PREFIX}/eval/runs/${run_id}/start" \
    -H "${auth_header}"
}

poll_run_completed() {
  local run_id="$1"
  local i status
  for ((i=1; i<=POLL_MAX_ATTEMPTS; i++)); do
    status="$(curl -s "${BASE_URL}${API_PREFIX}/eval/runs/${run_id}/summary" -H "${auth_header}" | jq -r '.data.status')"
    if [[ "$status" == "completed" ]]; then
      echo "Run ${run_id} completed."
      return 0
    fi
    if [[ "$status" == "failed" ]]; then
      echo "Run ${run_id} failed." >&2
      curl -s "${BASE_URL}${API_PREFIX}/eval/runs/${run_id}" -H "${auth_header}" | jq .
      return 1
    fi
    sleep "$POLL_SLEEP_SECONDS"
  done
  echo "Run ${run_id} did not complete in time." >&2
  curl -s "${BASE_URL}${API_PREFIX}/eval/runs/${run_id}" -H "${auth_header}" | jq .
  return 1
}

echo "[1/27] Health"
curl -s "${BASE_URL}/health" | jq -e '.ok == true' >/dev/null

echo "[2/27] Agent list"
agents_resp="$(curl -s "${BASE_URL}${API_PREFIX}/agents?org_id=${ORG_ID}" -H "${auth_header}")"
echo "${agents_resp}" | jq -e '.ok == true and (.data.count >= 1)' >/dev/null

echo "[3/27] Queue precheck"
queue_before="$(curl -s "${BASE_URL}${API_PREFIX}/system/queue/stats?org_id=${ORG_ID}" -H "${admin_auth_header}")"
echo "${queue_before}" | jq -e '.ok == true' >/dev/null
running_before="$(echo "${queue_before}" | jq -r '.data.running_count')"
if [[ "${running_before}" -gt "${QUEUE_MAX_RUNNING}" ]]; then
  echo "Queue running_count ${running_before} exceeds threshold ${QUEUE_MAX_RUNNING}" >&2
  echo "${queue_before}" | jq .
  exit 1
fi

echo "[4/27] Dead-letter baseline"
failed_before_resp="$(curl -s "${BASE_URL}${API_PREFIX}/system/queue/jobs/failed?org_id=${ORG_ID}&limit=1&offset=0" -H "${admin_auth_header}")"
echo "${failed_before_resp}" | jq -e '.ok == true' >/dev/null
failed_before="$(echo "${failed_before_resp}" | jq -r '.data.total_count')"

echo "[5/27] Create + start baseline run"
baseline_resp="$(create_run "ci-baseline-run")"
echo "${baseline_resp}" | jq -e '.ok == true and .data.run_id != null' >/dev/null
baseline_run_id="$(echo "${baseline_resp}" | jq -r '.data.run_id')"
start_baseline="$(start_run "${baseline_run_id}")"
echo "${start_baseline}" | jq -e '.ok == true and .data.status == "queued"' >/dev/null
poll_run_completed "${baseline_run_id}"

echo "[6/27] Create + start candidate run"
candidate_resp="$(create_run "ci-candidate-run")"
echo "${candidate_resp}" | jq -e '.ok == true and .data.run_id != null' >/dev/null
candidate_run_id="$(echo "${candidate_resp}" | jq -r '.data.run_id')"
start_candidate="$(start_run "${candidate_run_id}")"
echo "${start_candidate}" | jq -e '.ok == true and .data.status == "queued"' >/dev/null
poll_run_completed "${candidate_run_id}"

echo "[7/27] Regression compare gate"
compare_resp="$(curl -s "${BASE_URL}${API_PREFIX}/eval/compare?baseline_run_id=${baseline_run_id}&candidate_run_id=${candidate_run_id}" -H "${auth_header}")"
echo "${compare_resp}" | jq -e '.ok == true' >/dev/null
regression_count="$(echo "${compare_resp}" | jq -r '.data.regression_count')"
answer_delta="$(echo "${compare_resp}" | jq -r '.data.answer_yes_rate_delta')"
source_delta="$(echo "${compare_resp}" | jq -r '.data.source_yes_rate_delta')"
quality_delta="$(echo "${compare_resp}" | jq -r '.data.quality_good_rate_delta')"

if [[ "${regression_count}" -gt "${ALLOWED_REGRESSIONS}" ]]; then
  echo "Regression gate failed: regression_count=${regression_count} > ${ALLOWED_REGRESSIONS}" >&2
  echo "${compare_resp}" | jq .
  exit 1
fi

python3 - <<PY
answer_delta = float("${answer_delta}")
source_delta = float("${source_delta}")
quality_delta = float("${quality_delta}")
min_answer = float("${MIN_ANSWER_DELTA}")
min_source = float("${MIN_SOURCE_DELTA}")
min_quality = float("${MIN_QUALITY_DELTA}")
violations = []
if answer_delta < min_answer:
    violations.append(f"answer_yes_rate_delta={answer_delta} < {min_answer}")
if source_delta < min_source:
    violations.append(f"source_yes_rate_delta={source_delta} < {min_source}")
if quality_delta < min_quality:
    violations.append(f"quality_good_rate_delta={quality_delta} < {min_quality}")
if violations:
    raise SystemExit("SLO delta gate failed: " + "; ".join(violations))
print("SLO delta gate passed.")
PY

echo "[8/27] Promotion safety gate"
promote_payload="$(jq -n \
  --arg baseline_run_id "${baseline_run_id}" \
  --arg candidate_run_id "${candidate_run_id}" \
  '{
    baseline_run_id: $baseline_run_id,
    candidate_run_id: $candidate_run_id,
    baseline_name: "default",
    require_clean_compare: true,
    clean_compare_window_minutes: 120,
    notes: "ci promotion safety gate"
  }')"
promote_resp="$(curl -s -X POST "${BASE_URL}${API_PREFIX}/agents/${AGENT_ID}/run-registry/promote-candidate" \
  -H "${auth_header}" \
  -H "Content-Type: application/json" \
  -d "${promote_payload}")"
echo "${promote_resp}" | jq -e '.ok == true' >/dev/null || {
  echo "Promotion safety gate failed." >&2
  echo "${promote_resp}" | jq .
  exit 1
}

echo "[9/27] Dead-letter postcheck"
failed_after_resp="$(curl -s "${BASE_URL}${API_PREFIX}/system/queue/jobs/failed?org_id=${ORG_ID}&limit=1&offset=0" -H "${admin_auth_header}")"
echo "${failed_after_resp}" | jq -e '.ok == true' >/dev/null
failed_after="$(echo "${failed_after_resp}" | jq -r '.data.total_count')"
if [[ "${failed_after}" -gt "${failed_before}" ]]; then
  echo "Dead-letter gate failed: failed jobs increased (${failed_before} -> ${failed_after})" >&2
  echo "${failed_after_resp}" | jq .
  exit 1
fi

echo "[10/27] Queue postcheck + validation envelope"
queue_after="$(curl -s "${BASE_URL}${API_PREFIX}/system/queue/stats?org_id=${ORG_ID}" -H "${admin_auth_header}")"
echo "${queue_after}" | jq -e '.ok == true' >/dev/null

curl -s -X POST "${BASE_URL}${API_PREFIX}/agents" \
  -H "${auth_header}" \
  -H "Content-Type: application/json" \
  -d '{}' | jq -e '.ok == false and .error.code == "VALIDATION_ERROR"' >/dev/null

echo "[11/27] Admin queue idempotency contract"
curl -s -X POST "${BASE_URL}${API_PREFIX}/system/queue/jobs/failed/replay?dry_run=true&limit=1" \
  -H "${admin_auth_header}" | jq -e '.ok == false and .error.code == "VALIDATION_ERROR"' >/dev/null
curl -s -X POST "${BASE_URL}${API_PREFIX}/system/queue/jobs/failed/replay?dry_run=true&limit=1" \
  -H "${admin_auth_header}" \
  -H "Idempotency-Key: ci-replay-dry-run-001" | jq -e '.ok == true and (.data.dry_run == true)' >/dev/null

echo "[12/27] Admin stale-reap dry-run contract"
curl -s -X POST "${BASE_URL}${API_PREFIX}/system/queue/jobs/reap-stale?dry_run=true&limit=1" \
  -H "${admin_auth_header}" | jq -e '.ok == false and .error.code == "VALIDATION_ERROR"' >/dev/null
curl -s -X POST "${BASE_URL}${API_PREFIX}/system/queue/jobs/reap-stale?dry_run=true&limit=1" \
  -H "${admin_auth_header}" \
  -H "Idempotency-Key: ci-reap-dry-run-001" | jq -e '.ok == true and (.data.dry_run == true)' >/dev/null

echo "[13/27] Admin prune dry-run contract"
curl -s -X POST "${BASE_URL}${API_PREFIX}/system/queue/jobs/prune?dry_run=true&limit=1&retention_days=14" \
  -H "${admin_auth_header}" | jq -e '.ok == false and .error.code == "VALIDATION_ERROR"' >/dev/null
curl -s -X POST "${BASE_URL}${API_PREFIX}/system/queue/jobs/prune?dry_run=true&limit=1&retention_days=14" \
  -H "${admin_auth_header}" \
  -H "Idempotency-Key: ci-prune-dry-run-001" | jq -e '.ok == true and (.data.dry_run == true)' >/dev/null

echo "[14/27] Queue maintenance policy contract"
curl -s "${BASE_URL}${API_PREFIX}/system/queue/maintenance-policy?org_id=${ORG_ID}" \
  -H "${admin_auth_header}" | jq -e '.ok == true and .data.org_id == env.ORG_ID' >/dev/null

echo "[15/27] Queue maintenance runner contract"
curl -s -X POST "${BASE_URL}${API_PREFIX}/system/queue/maintenance/run?org_id=${ORG_ID}&dry_run=true" \
  -H "${admin_auth_header}" | jq -e '.ok == false and .error.code == "VALIDATION_ERROR"' >/dev/null
maint_run_resp="$(curl -s -X POST "${BASE_URL}${API_PREFIX}/system/queue/maintenance/run?org_id=${ORG_ID}&dry_run=true" \
  -H "${admin_auth_header}" \
  -H "Idempotency-Key: ci-maint-run-dry-run-001")"
echo "${maint_run_resp}" | jq -e '.ok == true and (.data.dry_run == true) and (.data.org_id == env.ORG_ID)' >/dev/null
maint_run_id="$(echo "${maint_run_resp}" | jq -r '.data.run_id')"

echo "[16/27] Queue maintenance history contract"
curl -s "${BASE_URL}${API_PREFIX}/system/queue/maintenance/runs?org_id=${ORG_ID}&limit=5&offset=0" \
  -H "${admin_auth_header}" | jq -e '.ok == true and (.data.count >= 1)' >/dev/null
curl -s "${BASE_URL}${API_PREFIX}/system/queue/maintenance/runs/${maint_run_id}" \
  -H "${admin_auth_header}" | jq -e --arg rid "${maint_run_id}" '.ok == true and (.data.id == $rid)' >/dev/null

echo "[17/27] Queue maintenance metrics contract"
curl -s "${BASE_URL}${API_PREFIX}/system/queue/maintenance/metrics?org_id=${ORG_ID}&window_days=30" \
  -H "${admin_auth_header}" | jq -e '
    .ok == true
    and (.data.org_id == env.ORG_ID)
    and (.data.window_days == 30)
    and (.data.total_runs >= 0)
  ' >/dev/null

echo "[18/27] Queue maintenance stale-run reap contract"
curl -s -X POST "${BASE_URL}${API_PREFIX}/system/queue/maintenance/reap-stale-runs?org_id=${ORG_ID}&dry_run=true&limit=1" \
  -H "${admin_auth_header}" | jq -e '.ok == false and .error.code == "VALIDATION_ERROR"' >/dev/null
curl -s -X POST "${BASE_URL}${API_PREFIX}/system/queue/maintenance/reap-stale-runs?org_id=${ORG_ID}&dry_run=true&limit=1" \
  -H "${admin_auth_header}" \
  -H "Idempotency-Key: ci-maint-reap-stale-dry-run-001" | jq -e '.ok == true and (.data.dry_run == true) and (.data.org_id == env.ORG_ID)' >/dev/null

echo "[19/27] Queue maintenance schedule-trigger dedupe contract"
trigger_payload="$(jq -n \
  --arg org_id "${ORG_ID}" \
  '{
    org_id: $org_id,
    schedule_name: "ci-hourly",
    window_minutes: 60,
    dry_run: true
  }')"
first_trigger="$(curl -s -X POST "${BASE_URL}${API_PREFIX}/system/queue/maintenance/schedule-trigger" \
  -H "${admin_auth_header}" \
  -H "Content-Type: application/json" \
  -d "${trigger_payload}")"
echo "${first_trigger}" | jq -e '.ok == true and (.data.executed == true) and (.data.deduped == false)' >/dev/null
second_trigger="$(curl -s -X POST "${BASE_URL}${API_PREFIX}/system/queue/maintenance/schedule-trigger" \
  -H "${admin_auth_header}" \
  -H "Content-Type: application/json" \
  -d "${trigger_payload}")"
echo "${second_trigger}" | jq -e '.ok == true and (.data.executed == false) and (.data.deduped == true)' >/dev/null

echo "[20/27] Queue maintenance schedule summary contract"
curl -s "${BASE_URL}${API_PREFIX}/system/queue/maintenance/schedule-summary?org_id=${ORG_ID}&schedule_name=ci-hourly&window_days=30" \
  -H "${admin_auth_header}" | jq -e '
    .ok == true
    and (.data.org_id == env.ORG_ID)
    and (.data.schedule_name == "ci-hourly")
    and (.data.trigger_count >= 2)
    and (.data.deduped_count >= 1)
  ' >/dev/null

echo "[21/27] Queue maintenance schedule anomaly notify contract"
curl -s -X POST "${BASE_URL}${API_PREFIX}/system/queue/maintenance/schedule-summary/notify" \
  -H "${admin_auth_header}" \
  -H "Content-Type: application/json" \
  -d "{\"org_id\":\"${ORG_ID}\",\"schedule_name\":\"ci-hourly\",\"window_days\":30,\"dry_run\":true,\"force_notify\":true}" \
  | jq -e '.ok == false and .error.code == "VALIDATION_ERROR"' >/dev/null
curl -s -X POST "${BASE_URL}${API_PREFIX}/system/queue/maintenance/schedule-summary/notify" \
  -H "${admin_auth_header}" \
  -H "Idempotency-Key: ci-maint-sched-notify-001" \
  -H "Content-Type: application/json" \
  -d "{\"org_id\":\"${ORG_ID}\",\"schedule_name\":\"ci-hourly\",\"window_days\":30,\"dry_run\":true,\"force_notify\":true}" \
  | jq -e '.ok == true and (.data.org_id == env.ORG_ID) and (.data.dry_run == true)' >/dev/null

echo "[22/27] Queue maintenance schedule alert delivery contract"
curl -s "${BASE_URL}${API_PREFIX}/system/queue/maintenance/schedule-alert-delivery?org_id=${ORG_ID}&schedule_name=ci-hourly&window_days=30" \
  -H "${admin_auth_header}" | jq -e '
    .ok == true
    and (.data.org_id == env.ORG_ID)
    and (.data.schedule_name == "ci-hourly")
    and (.data.total_notify_events >= 1)
  ' >/dev/null

echo "[23/27] Eval run list contract"
curl -s "${BASE_URL}${API_PREFIX}/eval/runs?org_id=${ORG_ID}&limit=10&offset=0" \
  -H "${auth_header}" | jq -e '
    .ok == true
    and (.data.count >= 1)
    and (.data.total_count >= .data.count)
  ' >/dev/null

echo "[24/27] Agent health rollup contracts"
curl -s "${BASE_URL}${API_PREFIX}/agents/${AGENT_ID}/score-trend?window_days=30&limit=10&offset=0" \
  -H "${auth_header}" | jq -e '
    .ok == true
    and (.data.agent_id == env.AGENT_ID)
    and (.data.window_days == 30)
  ' >/dev/null
curl -s "${BASE_URL}${API_PREFIX}/agents/${AGENT_ID}/health" \
  -H "${auth_header}" | jq -e '
    .ok == true
    and (.data.agent_id == env.AGENT_ID)
    and (.data.org_id == env.ORG_ID)
  ' >/dev/null
curl -s "${BASE_URL}${API_PREFIX}/orgs/${ORG_ID}/portfolio-health?limit=10&offset=0" \
  -H "${auth_header}" | jq -e '
    .ok == true
    and (.data.org_id == env.ORG_ID)
    and (.data.total_agents >= .data.count)
  ' >/dev/null

echo "[25/32] Eval run artifacts contract"
curl -s "${BASE_URL}${API_PREFIX}/eval/runs/${baseline_run_id}/artifacts?limit=50&offset=0" \
  -H "${auth_header}" | jq -e --arg rid "${baseline_run_id}" '
    .ok == true
    and (.data.run_id == $rid)
    and (.data.total_count >= .data.count)
  ' >/dev/null

echo "[26/32] Human review queue + decision contract"
curl -s "${BASE_URL}${API_PREFIX}/eval/runs/${baseline_run_id}/review-queue?limit=50&offset=0" \
  -H "${auth_header}" | jq -e --arg rid "${baseline_run_id}" '
    .ok == true
    and (.data.run_id == $rid)
    and (.data.total_count >= .data.count)
  ' >/dev/null
first_result_id="$(curl -s "${BASE_URL}${API_PREFIX}/eval/runs/${baseline_run_id}/results?limit=1&offset=0" \
  -H "${auth_header}" | jq -r '.data.items[0].id')"
if [[ -n "${first_result_id}" && "${first_result_id}" != "null" ]]; then
  curl -s -X PATCH "${BASE_URL}${API_PREFIX}/eval/runs/${baseline_run_id}/results/${first_result_id}/review" \
    -H "${auth_header}" \
    -H "Content-Type: application/json" \
    -d '{"decision":"accept","reason":"ci review contract"}' | jq -e '
      .ok == true
      and (.data.review_status == "accepted")
      and (.data.review_decision == "accept")
    ' >/dev/null
fi

echo "[27/32] Calibration gate status contract"
curl -s "${BASE_URL}${API_PREFIX}/agents/${AGENT_ID}/calibration-gate-status" \
  -H "${auth_header}" | jq -e '
    .ok == true
    and (.data.agent_id == env.AGENT_ID)
    and (.data.status | type == "string")
  ' >/dev/null

echo "[28/32] Golden set quality gate status contract"
curl -s "${BASE_URL}${API_PREFIX}/golden-sets/${GOLDEN_SET_ID}/quality-gate-status" \
  -H "${auth_header}" | jq -e '
    .ok == true
    and (.data.golden_set_id == env.GOLDEN_SET_ID)
    and (.data.status | type == "string")
  ' >/dev/null

echo "[29/32] Gate definitions + bindings contract"
curl -s "${BASE_URL}${API_PREFIX}/gate-definitions?org_id=${ORG_ID}" \
  -H "${auth_header}" | jq -e '
    .ok == true
    and (.data.total_count >= .data.count)
  ' >/dev/null
curl -s "${BASE_URL}${API_PREFIX}/agents/${AGENT_ID}/gate-bindings?limit=50&offset=0" \
  -H "${auth_header}" | jq -e '
    .ok == true
    and (.data.agent_id == env.AGENT_ID)
    and (.data.total_count >= .data.count)
  ' >/dev/null

echo "[30/32] Evaluator definitions + bindings contract"
curl -s "${BASE_URL}${API_PREFIX}/evaluator-definitions?org_id=${ORG_ID}" \
  -H "${auth_header}" | jq -e '
    .ok == true
    and (.data.total_count >= .data.count)
  ' >/dev/null
curl -s "${BASE_URL}${API_PREFIX}/agents/${AGENT_ID}/evaluator-bindings?limit=50&offset=0" \
  -H "${auth_header}" | jq -e '
    .ok == true
    and (.data.agent_id == env.AGENT_ID)
    and (.data.total_count >= .data.count)
  ' >/dev/null

echo "[31/32] Run type definitions + bindings contract"
curl -s "${BASE_URL}${API_PREFIX}/run-type-definitions?org_id=${ORG_ID}" \
  -H "${auth_header}" | jq -e '
    .ok == true
    and (.data.total_count >= .data.count)
  ' >/dev/null
curl -s "${BASE_URL}${API_PREFIX}/agents/${AGENT_ID}/run-type-bindings?limit=50&offset=0" \
  -H "${auth_header}" | jq -e '
    .ok == true
    and (.data.agent_id == env.AGENT_ID)
    and (.data.total_count >= .data.count)
  ' >/dev/null

echo "[32/32] Agent contract preflight status contract"
curl -s "${BASE_URL}${API_PREFIX}/agents/${AGENT_ID}/contract-status?run_type=eval&entrypoint=start&golden_set_id=${GOLDEN_SET_ID}" \
  -H "${auth_header}" | jq -e '
    .ok == true
    and (.data.agent_id == env.AGENT_ID)
    and (.data.status | type == "string")
    and (.data.resolved_handler_key | type == "string")
  ' >/dev/null

echo "CI quality gate passed."
