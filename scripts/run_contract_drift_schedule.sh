#!/usr/bin/env bash
set -euo pipefail

# Required env vars:
#   BASE_URL      e.g. http://127.0.0.1:8001
#   API_KEY       admin-capable API key
#   ORG_ID        org uuid
# Optional env vars:
#   API_PREFIX          default /api
#   SCHEDULE_NAME       default daily
#   WINDOW_MINUTES      default 1440
#   SUMMARY_WINDOW_DAYS default 30
#   DRY_RUN             true|false (default false)
#   FORCE               true|false (default false)
#   FORCE_NOTIFY        true|false (default false)
#   AGENT_ID            optional uuid
#   MIN_DRIFT           warning|breaking|invalid (optional)
#   LIMIT               optional int

for v in BASE_URL API_KEY ORG_ID; do
  if [[ -z "${!v:-}" ]]; then
    echo "Missing env var: $v"
    exit 1
  fi
done

API_PREFIX="${API_PREFIX:-/api}"
SCHEDULE_NAME="${SCHEDULE_NAME:-daily}"
WINDOW_MINUTES="${WINDOW_MINUTES:-1440}"
SUMMARY_WINDOW_DAYS="${SUMMARY_WINDOW_DAYS:-30}"
DRY_RUN="${DRY_RUN:-false}"
FORCE="${FORCE:-false}"
FORCE_NOTIFY="${FORCE_NOTIFY:-false}"

IDEMPOTENCY_KEY="contract-drift-schedule-$(date -u +%Y%m%d%H%M%S)-$RANDOM"
auth_header="Authorization: Bearer ${API_KEY}"

payload="$(jq -n \
  --arg org_id "${ORG_ID}" \
  --arg schedule_name "${SCHEDULE_NAME}" \
  --argjson window_minutes "${WINDOW_MINUTES}" \
  --argjson summary_window_days "${SUMMARY_WINDOW_DAYS}" \
  --argjson dry_run "${DRY_RUN}" \
  --argjson force "${FORCE}" \
  --argjson force_notify "${FORCE_NOTIFY}" \
  --arg agent_id "${AGENT_ID:-}" \
  --arg min_drift "${MIN_DRIFT:-}" \
  --arg limit "${LIMIT:-}" \
  '{
    org_id: $org_id,
    schedule_name: $schedule_name,
    window_minutes: $window_minutes,
    summary_window_days: $summary_window_days,
    dry_run: $dry_run,
    force: $force,
    force_notify: $force_notify
  }
  | if ($agent_id|length) > 0 then . + {agent_id: $agent_id} else . end
  | if ($min_drift|length) > 0 then . + {min_drift: $min_drift} else . end
  | if ($limit|length) > 0 then . + {limit: ($limit|tonumber)} else . end
  ')"

echo "Running contract drift schedule cycle..."
response="$(curl -s -X POST "${BASE_URL}${API_PREFIX}/system/contracts/drift/schedule-run" \
  -H "${auth_header}" \
  -H "Idempotency-Key: ${IDEMPOTENCY_KEY}" \
  -H "Content-Type: application/json" \
  -d "${payload}")"

if ! echo "${response}" | jq -e '.ok == true' >/dev/null; then
  echo "Schedule run failed:"
  echo "${response}" | jq .
  exit 1
fi

echo "${response}" | jq '{
  run: {
    schedule_name: .data.schedule_name,
    dry_run: .data.dry_run,
    trigger_executed: .data.trigger.executed,
    trigger_deduped: .data.trigger.deduped,
    anomaly_detected: .data.notify.anomaly_detected,
    notified: .data.notify.notified,
    escalation_pattern: .data.notify.escalation_pattern
  }
}'

echo "Contract drift schedule cycle passed."
