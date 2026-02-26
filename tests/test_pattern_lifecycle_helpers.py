from src.api.main import _append_status_history, _is_allowed_pattern_transition


def test_append_status_history_appends_when_status_changes():
    history = [{"from": None, "to": "detected", "at": "2026-02-24T00:00:00Z"}]
    out = _append_status_history(history, old_status="detected", new_status="assigned", note="owner assigned")
    assert len(out) == 2
    assert out[-1]["from"] == "detected"
    assert out[-1]["to"] == "assigned"
    assert out[-1]["note"] == "owner assigned"


def test_append_status_history_noop_when_status_unchanged():
    history = [{"from": None, "to": "detected", "at": "2026-02-24T00:00:00Z"}]
    out = _append_status_history(history, old_status="detected", new_status="detected", note=None)
    assert out == history


def test_pattern_transition_matrix_allows_expected_path():
    assert _is_allowed_pattern_transition("detected", "assigned") is True
    assert _is_allowed_pattern_transition("in_progress", "fixed") is True
    assert _is_allowed_pattern_transition("verifying", "resolved") is True


def test_pattern_transition_matrix_blocks_invalid_jump():
    assert _is_allowed_pattern_transition("detected", "resolved") is False
    assert _is_allowed_pattern_transition("assigned", "resolved") is False
