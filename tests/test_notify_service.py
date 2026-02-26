from __future__ import annotations

import json
from typing import Any, Dict

from src.api.services import notify


def test_webhook_is_disabled_without_url(monkeypatch):
    monkeypatch.delenv("NOTIFY_WEBHOOK_URL", raising=False)
    monkeypatch.delenv("NOTIFY_WEBHOOK_EVENTS", raising=False)
    assert notify.webhook_is_enabled("regression_detected") is False


def test_webhook_respects_event_allowlist(monkeypatch):
    monkeypatch.setenv("NOTIFY_WEBHOOK_URL", "https://example.com/hook")
    monkeypatch.setenv("NOTIFY_WEBHOOK_EVENTS", "regression_detected,pattern_status_changed")
    assert notify.webhook_is_enabled("regression_detected") is True
    assert notify.webhook_is_enabled("other_event") is False


def test_send_webhook_event_posts_payload(monkeypatch):
    captured: Dict[str, Any] = {}
    monkeypatch.setenv("NOTIFY_WEBHOOK_URL", "https://example.com/hook")
    monkeypatch.setenv("NOTIFY_WEBHOOK_EVENTS", "regression_detected")

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def fake_urlopen(req, timeout=10, context=None):
        captured["url"] = req.full_url
        captured["headers"] = dict(req.header_items())
        captured["timeout"] = timeout
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return _Resp()

    monkeypatch.setattr(notify.request, "urlopen", fake_urlopen)
    err = notify.send_webhook_event("regression_detected", {"a": 1})
    assert err is None
    assert captured["url"] == "https://example.com/hook"
    assert captured["body"]["event_type"] == "regression_detected"
    assert captured["body"]["payload"] == {"a": 1}


def test_send_webhook_event_includes_delivery_id(monkeypatch):
    captured: Dict[str, Any] = {}
    monkeypatch.setenv("NOTIFY_WEBHOOK_URL", "https://example.com/hook")
    monkeypatch.setenv("NOTIFY_WEBHOOK_EVENTS", "regression_detected")

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def fake_urlopen(req, timeout=10, context=None):
        captured["headers"] = {k.lower(): v for k, v in req.header_items()}
        captured["body"] = json.loads(req.data.decode("utf-8"))
        return _Resp()

    monkeypatch.setattr(notify.request, "urlopen", fake_urlopen)
    err = notify.send_webhook_event("regression_detected", {"a": 1}, delivery_id="deliv-123")
    assert err is None
    assert captured["headers"]["x-greenlight-delivery-id"] == "deliv-123"
    assert captured["body"]["delivery_id"] == "deliv-123"


def test_send_webhook_event_adds_hmac_signature_headers(monkeypatch):
    captured: Dict[str, Any] = {}
    monkeypatch.setenv("NOTIFY_WEBHOOK_URL", "https://example.com/hook")
    monkeypatch.setenv("NOTIFY_WEBHOOK_EVENTS", "regression_detected")
    monkeypatch.setenv("NOTIFY_WEBHOOK_SECRET", "test-secret")

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

    def fake_urlopen(req, timeout=10, context=None):
        captured["headers"] = {k.lower(): v for k, v in req.header_items()}
        captured["body_raw"] = req.data
        return _Resp()

    monkeypatch.setattr(notify.request, "urlopen", fake_urlopen)
    err = notify.send_webhook_event("regression_detected", {"a": 1})
    assert err is None

    assert "x-greenlight-timestamp" in captured["headers"]
    assert "x-greenlight-signature" in captured["headers"]
    ok, reason = notify.verify_webhook_signature(
        body=captured["body_raw"],
        signature_header=captured["headers"]["x-greenlight-signature"],
        timestamp_header=captured["headers"]["x-greenlight-timestamp"],
        secret="test-secret",
    )
    assert ok is True
    assert reason is None


def test_verify_webhook_signature_rejects_replay_window(monkeypatch):
    body = b'{"event_type":"x"}'
    headers = notify.build_webhook_signature_headers(body=body, secret="test-secret", timestamp=1000)
    ok, reason = notify.verify_webhook_signature(
        body=body,
        signature_header=headers["X-Greenlight-Signature"],
        timestamp_header=headers["X-Greenlight-Timestamp"],
        secret="test-secret",
        now_timestamp=2000,
        tolerance_seconds=60,
    )
    assert ok is False
    assert reason == "timestamp_out_of_window"


def test_slack_format_auto_detect(monkeypatch):
    monkeypatch.setenv("NOTIFY_WEBHOOK_URL", "https://hooks.slack.com/services/T/B/X")
    monkeypatch.delenv("NOTIFY_WEBHOOK_FORMAT", raising=False)
    assert notify._notify_format() == "slack"


def test_build_slack_payload(monkeypatch):
    monkeypatch.setenv("NOTIFY_WEBHOOK_FORMAT", "slack")
    body = notify._build_request_body(
        "pattern_status_changed",
        {
            "pattern_id": "p1",
            "from_status": "detected",
            "to_status": "assigned",
            "owner": "pm_owner",
            "priority": "high",
        },
        "2026-02-24T00:00:00Z",
    )
    assert "text" in body
    assert "blocks" in body
    assert body["blocks"][0]["type"] == "header"
