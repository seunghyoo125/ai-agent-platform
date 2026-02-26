from __future__ import annotations

import hashlib
import hmac
import json
import os
import ssl
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Set, Tuple
from urllib import error, request

import certifi


def _signature_tolerance_seconds() -> int:
    return int(os.getenv("NOTIFY_WEBHOOK_SIGNATURE_TOLERANCE_SECONDS", "300"))


def _signature_header(timestamp: str, body: bytes, secret: str) -> str:
    message = f"v1:{timestamp}:".encode("utf-8") + body
    digest = hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()
    return f"v1={digest}"


def build_webhook_signature_headers(
    *,
    body: bytes,
    secret: str,
    timestamp: Optional[int] = None,
) -> Dict[str, str]:
    ts = int(time.time()) if timestamp is None else int(timestamp)
    ts_s = str(ts)
    return {
        "X-Greenlight-Timestamp": ts_s,
        "X-Greenlight-Signature": _signature_header(ts_s, body, secret),
    }


def verify_webhook_signature(
    *,
    body: bytes,
    signature_header: str,
    timestamp_header: str,
    secret: str,
    now_timestamp: Optional[int] = None,
    tolerance_seconds: Optional[int] = None,
) -> Tuple[bool, Optional[str]]:
    if not secret:
        return False, "missing_secret"
    if not signature_header:
        return False, "missing_signature"
    if not timestamp_header:
        return False, "missing_timestamp"
    try:
        ts = int(timestamp_header)
    except Exception:
        return False, "invalid_timestamp"

    now_ts = int(time.time()) if now_timestamp is None else int(now_timestamp)
    tol = _signature_tolerance_seconds() if tolerance_seconds is None else int(tolerance_seconds)
    if abs(now_ts - ts) > max(1, tol):
        return False, "timestamp_out_of_window"

    expected = _signature_header(str(ts), body, secret)
    if not hmac.compare_digest(expected, signature_header):
        return False, "signature_mismatch"
    return True, None


def _enabled_events() -> Set[str]:
    raw = os.getenv("NOTIFY_WEBHOOK_EVENTS", "").strip()
    if not raw:
        return set()
    return {x.strip() for x in raw.split(",") if x.strip()}


def webhook_is_enabled(event_type: str) -> bool:
    webhook_url = os.getenv("NOTIFY_WEBHOOK_URL", "").strip()
    if not webhook_url:
        return False
    events = _enabled_events()
    return not events or event_type in events


def _notify_format() -> str:
    fmt = os.getenv("NOTIFY_WEBHOOK_FORMAT", "").strip().lower()
    if fmt:
        return fmt
    url = os.getenv("NOTIFY_WEBHOOK_URL", "").strip().lower()
    if "hooks.slack.com" in url:
        return "slack"
    return "json"


def _short_id(value: Any, length: int = 8) -> str:
    if value is None:
        return "n/a"
    s = str(value)
    return s[:length] if len(s) >= length else s


def _fmt_delta_pct(value: Any) -> str:
    try:
        return f"{float(value):+.0%}"
    except Exception:
        return "n/a"


def _regression_severity(regression_count: int) -> str:
    if regression_count >= 10:
        return "critical"
    if regression_count >= 3:
        return "high"
    if regression_count >= 1:
        return "medium"
    return "none"


def _slack_message(event_type: str, payload: Dict[str, Any], sent_at: str) -> Dict[str, Any]:
    if event_type == "regression_detected":
        regression_count = int(payload.get("regression_count", 0) or 0)
        severity = _regression_severity(regression_count)
        agent_display = payload.get("agent_name") or _short_id(payload.get("agent_id"))
        title = f"Regression detected ({regression_count}, {severity})"
        body = (
            f"*Agent:* `{agent_display}`\n"
            f"*Runs:* `{_short_id(payload.get('baseline_run_id'))}` -> `{_short_id(payload.get('candidate_run_id'))}`\n"
            f"*Delta:* answer {_fmt_delta_pct(payload.get('answer_yes_rate_delta'))}, "
            f"source {_fmt_delta_pct(payload.get('source_yes_rate_delta'))}, "
            f"quality {_fmt_delta_pct(payload.get('quality_good_rate_delta'))}"
        )
        pattern_id = payload.get("pattern_id")
        if pattern_id:
            body += f"\n*Issue Pattern:* `{_short_id(pattern_id)}`"
    elif event_type == "pattern_status_changed":
        title = "Issue pattern status changed"
        body = (
            f"*Pattern:* `{_short_id(payload.get('pattern_id'))}`\n"
            f"Status `{payload.get('from_status')}` -> `{payload.get('to_status')}`\n"
            f"Owner: `{payload.get('owner') or 'unassigned'}` | Priority: `{payload.get('priority')}`"
        )
    elif event_type == "slo_violation":
        title = "SLO violation"
        body = (
            f"*Agent:* `{payload.get('agent_id')}`\n"
            f"*Metric:* `{payload.get('metric')}`\n"
            f"*Actual vs Expected:* `{payload.get('actual_value')}` {payload.get('comparator')} `{payload.get('expected_value')}`\n"
            f"*Source:* `{payload.get('source')}` ref `{_short_id(payload.get('source_ref_id'))}`"
        )
    elif event_type == "launch_decision_changed":
        title = "Launch decision updated"
        body = (
            f"*Agent:* `{payload.get('agent_id')}`\n"
            f"*Decision:* `{payload.get('decision')}`\n"
            f"*Reason:* {payload.get('reason') or 'n/a'}\n"
            f"*Decision ID:* `{_short_id(payload.get('decision_id'))}`"
        )
        blockers = payload.get("blockers") or []
        if isinstance(blockers, list) and blockers:
            body += f"\n*Blockers:* {', '.join(str(x) for x in blockers[:5])}"
    elif event_type == "remediation_verified":
        title = "Remediation verified"
        body = (
            f"*Agent:* `{payload.get('agent_id')}`\n"
            f"*Runs:* `{_short_id(payload.get('baseline_run_id'))}` -> `{_short_id(payload.get('candidate_run_id'))}`\n"
            f"*Pattern updates:* `{payload.get('updated_patterns')}`\n"
            f"*Resolved SLO violations:* `{payload.get('resolved_slo_violations')}`"
        )
    else:
        title = f"Greenlight event: {event_type}"
        body = json.dumps(payload, ensure_ascii=True)

    return {
        "text": f"[Greenlight] {title}",
        "username": "Greenlight",
        "icon_emoji": ":rotating_light:",
        "blocks": [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"Greenlight: {title}"},
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": body},
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": f"event: `{event_type}`"},
                    {"type": "mrkdwn", "text": f"at: `{sent_at}`"},
                ],
            },
        ],
    }


def _build_request_body(event_type: str, payload: Dict[str, Any], sent_at: str) -> Dict[str, Any]:
    fmt = _notify_format()
    if fmt == "slack":
        return _slack_message(event_type, payload, sent_at)
    return {
        "event_type": event_type,
        "sent_at": sent_at,
        "payload": payload,
    }


def send_webhook_event(
    event_type: str,
    payload: Dict[str, Any],
    timeout_seconds: int = 10,
    delivery_id: Optional[str] = None,
) -> Optional[str]:
    webhook_url = os.getenv("NOTIFY_WEBHOOK_URL", "").strip()
    if not webhook_url:
        return None
    if not webhook_is_enabled(event_type):
        return None

    signature_secret = os.getenv("NOTIFY_WEBHOOK_SECRET", "").strip()
    sent_at = datetime.now(timezone.utc).isoformat()
    body = _build_request_body(event_type, payload, sent_at)
    if delivery_id:
        body["delivery_id"] = delivery_id
    body_bytes = json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if delivery_id:
        headers["X-Greenlight-Delivery-Id"] = str(delivery_id)
    if signature_secret:
        headers.update(build_webhook_signature_headers(body=body_bytes, secret=signature_secret))
        # Backward compatibility for existing receivers.
        headers["X-Greenlight-Webhook-Secret"] = signature_secret

    req = request.Request(
        url=webhook_url,
        method="POST",
        headers=headers,
        data=body_bytes,
    )
    try:
        ssl_ctx = ssl.create_default_context(cafile=certifi.where())
        with request.urlopen(req, timeout=timeout_seconds, context=ssl_ctx):
            return None
    except error.HTTPError as exc:
        return f"HTTP {exc.code}"
    except Exception as exc:  # pragma: no cover - defensive runtime branch
        return str(exc)
