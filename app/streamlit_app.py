from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from urllib import error, parse, request

import pandas as pd
import streamlit as st

st.set_page_config(page_title="ai-agent-platform", layout="wide")

PATTERN_ALLOWED_TRANSITIONS: Dict[str, list[str]] = {
    "detected": ["diagnosed", "assigned", "wont_fix"],
    "diagnosed": ["assigned", "in_progress", "wont_fix"],
    "assigned": ["in_progress", "diagnosed", "wont_fix"],
    "in_progress": ["fixed", "regressed", "wont_fix"],
    "fixed": ["verifying", "regressed"],
    "verifying": ["resolved", "regressed", "in_progress"],
    "resolved": ["regressed"],
    "regressed": ["assigned", "in_progress", "fixed", "wont_fix"],
    "wont_fix": ["regressed"],
}


def api_call(
    base_url: str,
    api_key: str,
    method: str,
    path: str,
    payload: Optional[Dict[str, Any]] = None,
    extra_headers: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    url = f"{base_url.rstrip('/')}{path}"
    body = None
    headers = {"Authorization": f"Bearer {api_key}"}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if extra_headers:
        headers.update(extra_headers)

    req = request.Request(url=url, method=method, headers=headers, data=body)
    try:
        with request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except error.HTTPError as e:
        raw = e.read().decode("utf-8")
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"ok": False, "error": {"code": "HTTP_ERROR", "message": raw or str(e)}}
    except Exception as e:  # pragma: no cover - UI defensive path
        return {"ok": False, "error": {"code": "REQUEST_FAILED", "message": str(e)}}


def results_df(items: list[Dict[str, Any]]) -> pd.DataFrame:
    rows = []
    for c in items:
        rows.append(
            {
                "id": c.get("id"),
                "case_id": c.get("case_id"),
                "evaluation_mode": c.get("evaluation_mode"),
                "answer_correct": c.get("answer_correct"),
                "source_correct": c.get("source_correct"),
                "response_quality": c.get("response_quality"),
                "overall_score": c.get("overall_score"),
                "tester": c.get("tester"),
                "eval_date": c.get("eval_date"),
                "actual_response": c.get("actual_response"),
            }
        )
    return pd.DataFrame(rows)


def log_activity(event_type: str, title: str, details: str = "", severity: str = "info") -> None:
    events = st.session_state.get("activity_events", [])
    events.append(
        {
            "at": datetime.now(timezone.utc).isoformat(),
            "severity": severity,
            "event_type": event_type,
            "title": title,
            "details": details,
        }
    )
    # Keep recent 200 events to avoid unbounded session growth.
    st.session_state["activity_events"] = events[-200:]


st.title("ai-agent-platform")

st.sidebar.header("API Connection")
base_url = st.sidebar.text_input("Base URL", value="http://127.0.0.1:8001")
api_key = st.sidebar.text_input("API Key", type="password")
admin_api_key = st.sidebar.text_input("Admin API Key (optional)", type="password")
org_id = st.sidebar.text_input("Org ID", value="23cdb862-a12f-4b6c-84ee-5cb648f9b5bb")

if st.sidebar.button("Load Agents"):
    if not api_key.strip():
        st.sidebar.error("API key is required.")
    else:
        query = parse.urlencode({"org_id": org_id})
        resp = api_call(base_url, api_key, "GET", f"/api/agents?{query}")
        if resp.get("ok"):
            items = resp.get("data", {}).get("items", [])
            st.session_state["agents"] = items
            st.session_state.pop("selected_agent_id", None)
            st.session_state.pop("selected_golden_set_id", None)
            st.session_state.pop("latest_run_id", None)
        else:
            st.sidebar.error(resp.get("error", {}).get("message", "Failed to load agents"))

agents = st.session_state.get("agents", [])
if not agents:
    st.info("Load agents from API to begin.")
    st.stop()

st.subheader("1) Select Agent")
agent_options = {f"{a['name']} ({a['id'][:8]})": a["id"] for a in agents}
agent_label = st.selectbox("Agent", list(agent_options.keys()))
selected_agent_id = agent_options[agent_label]
st.session_state["selected_agent_id"] = selected_agent_id
selected_agent = next((a for a in agents if a.get("id") == selected_agent_id), {})
selected_agent_type = selected_agent.get("agent_type")

gate_card = api_call(base_url, api_key, "GET", f"/api/agents/{selected_agent_id}/launch-gate")
if gate_card.get("ok"):
    gate_data = gate_card.get("data", {})
    can_launch = bool(gate_data.get("can_launch"))
    c_gate_a, c_gate_b, c_gate_c, c_gate_d = st.columns(4)
    c_gate_a.metric("Launch Gate", "PASS" if can_launch else "BLOCKED")
    c_gate_b.metric("Critical Issues", int(gate_data.get("active_critical_issues", 0)))
    c_gate_c.metric("Open SLO Violations", int(gate_data.get("open_slo_violations", 0)))
    c_gate_d.metric("Readiness Pending", int(gate_data.get("readiness_pending_items", 0)))
    if can_launch:
        st.success("Launch readiness summary: all gate checks passing.")
    else:
        blockers = gate_data.get("blockers") or []
        if blockers:
            st.warning("Launch readiness summary: blockers detected.")
            st.caption(" | ".join(str(x) for x in blockers[:3]))

st.subheader("1A) Health + Portfolio Snapshot")


def _fmt_rate(v: Any) -> str:
    if v is None:
        return "n/a"
    try:
        return f"{float(v):.2%}"
    except Exception:
        return "n/a"


agent_health_resp = api_call(base_url, api_key, "GET", f"/api/agents/{selected_agent_id}/health")
if agent_health_resp.get("ok"):
    ah = agent_health_resp.get("data", {})
    h1, h2, h3, h4, h5, h6 = st.columns(6)
    h1.metric("Agent Launch", "PASS" if ah.get("can_launch") else "BLOCKED")
    h2.metric("Active Issues", int(ah.get("active_issue_count", 0)))
    h3.metric("Critical Issues", int(ah.get("active_critical_issues", 0)))
    h4.metric("Open SLO", int(ah.get("open_slo_violations", 0)))
    h5.metric("Readiness Pending", int(ah.get("readiness_pending_items", 0)))
    h6.metric("Latest Run", str(ah.get("latest_run_status") or "n/a"))

    r1, r2, r3 = st.columns(3)

    r1.metric("Answer Yes Rate", _fmt_rate(ah.get("answer_yes_rate")))
    r2.metric("Source Yes Rate", _fmt_rate(ah.get("source_yes_rate")))
    r3.metric("Quality Good Rate", _fmt_rate(ah.get("quality_good_rate")))
    blockers = ah.get("blockers") or []
    if blockers:
        st.caption("Agent blockers: " + " | ".join(str(x) for x in blockers[:5]))
else:
    st.warning(agent_health_resp.get("error", {}).get("message", "Failed to load agent health"))

trend_resp = api_call(
    base_url,
    api_key,
    "GET",
    f"/api/agents/{selected_agent_id}/score-trend?window_days=30&limit=20&offset=0",
)
if trend_resp.get("ok"):
    trend_items = trend_resp.get("data", {}).get("items", [])
    if trend_items:
        trend_df = pd.DataFrame(
            [
                {
                    "created_at": i.get("created_at"),
                    "answer_yes_rate": float(i.get("answer_yes_rate") or 0.0),
                    "source_yes_rate": float(i.get("source_yes_rate") or 0.0),
                    "quality_good_rate": float(i.get("quality_good_rate") or 0.0),
                }
                for i in trend_items
            ]
        )
        trend_df["created_at"] = pd.to_datetime(trend_df["created_at"], errors="coerce")
        trend_df = trend_df.sort_values("created_at", ascending=True).set_index("created_at")
        st.caption("Score trend (last 30 days)")
        st.line_chart(trend_df, use_container_width=True)

run_list_resp = api_call(
    base_url,
    api_key,
    "GET",
    f"/api/eval/runs?org_id={org_id}&agent_id={selected_agent_id}&limit=20&offset=0",
)
if run_list_resp.get("ok"):
    run_items = run_list_resp.get("data", {}).get("items", [])
    if run_items:
        run_df = pd.DataFrame(run_items)
        run_display_cols = [
            c
            for c in [
                "id",
                "name",
                "type",
                "status",
                "created_at",
                "completed_at",
                "result_count",
                "answer_yes_rate",
                "source_yes_rate",
                "quality_good_rate",
            ]
            if c in run_df.columns
        ]
        st.caption("Recent eval runs (agent)")
        st.dataframe(run_df[run_display_cols], use_container_width=True)

portfolio_resp = api_call(base_url, api_key, "GET", f"/api/orgs/{org_id}/portfolio-health?limit=100&offset=0")
if portfolio_resp.get("ok"):
    ph = portfolio_resp.get("data", {})
    p1, p2, p3, p4, p5, p6 = st.columns(6)
    p1.metric("Total Agents", int(ph.get("total_agents", 0)))
    p2.metric("Healthy", int(ph.get("healthy_agents", 0)))
    p3.metric("Blocked", int(ph.get("blocked_agents", 0)))
    p4.metric("Avg Answer", _fmt_rate(ph.get("avg_answer_yes_rate")))
    p5.metric("Avg Source", _fmt_rate(ph.get("avg_source_yes_rate")))
    p6.metric("Avg Quality", _fmt_rate(ph.get("avg_quality_good_rate")))
    portfolio_items = ph.get("items", [])
    if portfolio_items:
        portfolio_df = pd.DataFrame(portfolio_items)
        portfolio_cols = [
            c
            for c in [
                "agent_id",
                "name",
                "status",
                "can_launch",
                "latest_run_status",
                "active_critical_issues",
                "open_slo_violations",
                "readiness_pending_items",
                "answer_yes_rate",
                "source_yes_rate",
                "quality_good_rate",
            ]
            if c in portfolio_df.columns
        ]
        with st.expander("Portfolio agent table"):
            st.dataframe(portfolio_df[portfolio_cols], use_container_width=True)

c_load_gs, c_load_latest, c_load_templates = st.columns(3)
with c_load_gs:
    if st.button("Load Golden Sets"):
        resp = api_call(base_url, api_key, "GET", f"/api/agents/{selected_agent_id}/golden-sets")
        if resp.get("ok"):
            st.session_state["golden_sets"] = resp.get("data", {}).get("items", [])
        else:
            st.error(resp.get("error", {}).get("message", "Failed to load golden sets"))
with c_load_latest:
    if st.button("Load Latest Run"):
        resp = api_call(base_url, api_key, "GET", f"/api/agents/{selected_agent_id}/latest")
        if resp.get("ok"):
            latest = resp.get("data", {}).get("latest_run")
            if latest:
                st.session_state["latest_run_id"] = latest["run_id"]
                log_activity("run_latest_loaded", "Loaded latest run", f"run_id={latest['run_id'][:8]}")
            else:
                st.session_state["latest_run_id"] = None
        else:
            st.error(resp.get("error", {}).get("message", "Failed to load latest run"))
with c_load_templates:
    if st.button("Load Eval Templates"):
        params = {"org_id": org_id, "include_inactive": "false"}
        if selected_agent_type:
            params["agent_type"] = str(selected_agent_type)
        query = parse.urlencode(params)
        resp = api_call(base_url, api_key, "GET", f"/api/eval/templates?{query}")
        if resp.get("ok"):
            st.session_state["eval_templates"] = resp.get("data", {}).get("items", [])
        else:
            st.error(resp.get("error", {}).get("message", "Failed to load eval templates"))

st.subheader("2) Create Golden Set (Optional)")
with st.expander("Upload canonical JSON golden set"):
    gs_name = st.text_input("Golden set name", value="Acme Retrieval GS v2")
    gs_description = st.text_input("Description", value="Streamlit-created golden set")
    gs_method = st.selectbox(
        "Generation method",
        ["manual", "documents", "prd_schema", "data_fixtures", "clone", "prod_logs"],
        index=0,
    )
    gs_sources = st.text_input("Source files (comma-separated)", value="acme-kb-v2.pdf")
    gs_cases_json = st.text_area(
        "Cases JSON array",
        value=json.dumps(
            [
                {
                    "input": "What is Acme remote policy?",
                    "expected_output": "Acme uses a hybrid policy with three in-office days.",
                    "acceptable_sources": "HR Policy 2026",
                    "evaluation_mode": "answer",
                    "difficulty": "easy",
                    "capability": "retrieval",
                    "scenario_type": "straightforward",
                    "domain": "hr",
                    "verification_status": "unverified",
                }
            ],
            indent=2,
        ),
        height=220,
    )
    if st.button("Create Golden Set"):
        try:
            parsed_cases = json.loads(gs_cases_json)
            if not isinstance(parsed_cases, list) or len(parsed_cases) == 0:
                st.error("Cases JSON must be a non-empty array.")
            else:
                payload = {
                    "org_id": org_id,
                    "agent_id": selected_agent_id,
                    "name": gs_name,
                    "description": gs_description,
                    "generation_method": gs_method,
                    "source_files": [x.strip() for x in gs_sources.split(",") if x.strip()],
                    "cases": parsed_cases,
                }
                resp = api_call(base_url, api_key, "POST", "/api/golden-sets/upload", payload=payload)
                if resp.get("ok"):
                    st.success(f"Golden set created: {resp['data']['golden_set_id']}")
                    reload_resp = api_call(base_url, api_key, "GET", f"/api/agents/{selected_agent_id}/golden-sets")
                    if reload_resp.get("ok"):
                        st.session_state["golden_sets"] = reload_resp.get("data", {}).get("items", [])
                else:
                    st.error(resp.get("error", {}).get("message", "Failed to create golden set"))
        except json.JSONDecodeError as e:
            st.error(f"Invalid JSON: {e}")

golden_sets = st.session_state.get("golden_sets", [])
if golden_sets:
    st.subheader("3) Select Golden Set")
    gs_options = {f"{g['name']} ({g['case_count']} cases)": g["id"] for g in golden_sets}
    gs_label = st.selectbox("Golden Set", list(gs_options.keys()))
    selected_golden_set_id = gs_options[gs_label]
    st.session_state["selected_golden_set_id"] = selected_golden_set_id

    st.subheader("4) Create + Execute Run")
    run_name = st.text_input("Run name", value="streamlit-run")
    loaded_templates = st.session_state.get("eval_templates", [])
    template_options: Dict[str, Optional[str]] = {"(none)": None}
    for t in loaded_templates:
        template_options[f"{t.get('name')} ({str(t.get('id'))[:8]})"] = t.get("id")
    selected_template_label = st.selectbox("Eval Template (optional)", list(template_options.keys()))
    selected_template_id = template_options[selected_template_label]
    judge_mode = st.selectbox("Judge mode", ["deterministic", "provider"], index=0)
    judge_model = st.text_input("Judge model", value="gpt-4.1-mini")
    judge_prompt_version = st.text_input("Judge prompt version", value="v1")
    c_create, c_execute = st.columns(2)
    with c_create:
        if st.button("Create Run"):
            run_config = {"sample_size": "all", "judge_mode": judge_mode}
            if judge_mode == "provider":
                run_config["judge_model"] = judge_model
                run_config["judge_prompt_version"] = judge_prompt_version
            payload = {
                "org_id": org_id,
                "agent_id": selected_agent_id,
                "golden_set_id": selected_golden_set_id,
                "template_id": selected_template_id,
                "name": run_name,
                "type": "eval",
                "config": run_config,
                "design_context": {"reason": "streamlit-ui"},
            }
            resp = api_call(base_url, api_key, "POST", "/api/eval/runs", payload=payload)
            if resp.get("ok"):
                st.session_state["latest_run_id"] = resp["data"]["run_id"]
                st.success(f"Created run: {resp['data']['run_id']}")
                log_activity("run_created", "Created eval run", f"run_id={resp['data']['run_id'][:8]}")
            else:
                st.error(resp.get("error", {}).get("message", "Failed to create run"))
    with c_execute:
        if st.button("Execute Current Run"):
            run_id = st.session_state.get("latest_run_id")
            if not run_id:
                st.warning("Create or load a run first.")
            else:
                resp = api_call(base_url, api_key, "POST", f"/api/eval/runs/{run_id}/execute")
                if resp.get("ok"):
                    st.success("Run executed.")
                    log_activity("run_executed", "Executed eval run", f"run_id={run_id[:8]}")
                else:
                    st.error(resp.get("error", {}).get("message", "Failed to execute run"))

run_id = st.session_state.get("latest_run_id")
if run_id:
    st.subheader("5) Run Summary")
    run_resp = api_call(base_url, api_key, "GET", f"/api/eval/runs/{run_id}")
    run_data = run_resp.get("data", {}) if run_resp.get("ok") else {}
    summary_resp = api_call(base_url, api_key, "GET", f"/api/eval/runs/{run_id}/summary")
    if summary_resp.get("ok"):
        summary = summary_resp["data"]
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Run ID", run_id[:8])
        c2.metric("Status", summary.get("status", "unknown"))
        c3.metric("Total Results", summary.get("total_results", 0))
        c4.metric("Answer Yes Rate", f"{summary.get('answer_yes_rate', 0.0):.2%}")
        c5.metric("Judge Mode", str((run_data.get("config") or {}).get("judge_mode", "deterministic")))
        slo_resp = api_call(base_url, api_key, "GET", f"/api/agents/{selected_agent_id}/slo-status?limit_violations=5")
        if slo_resp.get("ok"):
            slo_data = slo_resp.get("data", {})
            st.caption(f"SLO status: {slo_data.get('slo_status')} (violations: {slo_data.get('open_violation_count', 0)})")
        with st.expander("Run Config"):
            st.json(run_data.get("config") or {})
    else:
        st.error(summary_resp.get("error", {}).get("message", "Failed to load summary"))

    st.subheader("6) Policy Contract Status")
    run_status = str(run_data.get("status", "unknown"))
    failure_reason = run_data.get("failure_reason")
    if run_status == "failed":
        msg = str(failure_reason or "")
        if "violates profile scale" in msg or "Missing required dimension_scores keys" in msg:
            st.error("Policy contract violation detected.")
            st.code(msg, language="text")
        else:
            st.warning("Run failed for a non-policy reason.")
            st.code(msg or "No failure reason provided.", language="text")
    else:
        st.success("No policy contract violations on current run.")

    st.subheader("7) Result Details")
    results_resp = api_call(base_url, api_key, "GET", f"/api/eval/runs/{run_id}/results?limit=200")
    if results_resp.get("ok"):
        items = results_resp.get("data", {}).get("items", [])
        if items:
            df = results_df(items)
            st.dataframe(
                df[
                    [
                        "id",
                        "case_id",
                        "evaluation_mode",
                        "answer_correct",
                        "source_correct",
                        "response_quality",
                        "overall_score",
                        "tester",
                        "eval_date",
                    ]
                ],
                use_container_width=True,
            )
            selected_result = st.selectbox("Select result row", list(df["id"].values))
            row = df[df["id"] == selected_result].iloc[0]
            st.markdown("**Actual Response**")
            st.code(row["actual_response"] or "", language="text")
        else:
            st.info("No results yet. Execute the run first.")
    else:
        st.error(results_resp.get("error", {}).get("message", "Failed to load results"))

    st.subheader("7A) Run Artifacts")
    artifacts_resp = api_call(base_url, api_key, "GET", f"/api/eval/runs/{run_id}/artifacts?limit=200")
    if artifacts_resp.get("ok"):
        artifact_items = artifacts_resp.get("data", {}).get("items", [])
        if artifact_items:
            art_df = pd.DataFrame(
                [
                    {
                        "id": a.get("id"),
                        "case_id": a.get("case_id"),
                        "evaluation_mode": a.get("evaluation_mode"),
                        "judge_mode": a.get("judge_mode"),
                        "judge_model": a.get("judge_model"),
                        "executor_mode": a.get("executor_mode"),
                        "judge_prompt_hash": a.get("judge_prompt_hash"),
                        "case_latency_ms": a.get("case_latency_ms"),
                        "execution_latency_ms": a.get("execution_latency_ms"),
                        "judge_latency_ms": a.get("judge_latency_ms"),
                        "created_at": a.get("created_at"),
                    }
                    for a in artifact_items
                ]
            )
            st.dataframe(art_df, use_container_width=True)
            artifact_options = {f"{str(a.get('id'))[:8]} | case {str(a.get('case_id'))[:8]}": a for a in artifact_items}
            selected_artifact_label = st.selectbox("Select artifact", list(artifact_options.keys()))
            selected_artifact = artifact_options[selected_artifact_label]
            with st.expander("Artifact Detail"):
                st.json(selected_artifact)
        else:
            st.info("No artifacts yet. Execute a run first.")
    else:
        st.error(artifacts_resp.get("error", {}).get("message", "Failed to load artifacts"))

    st.subheader("7B) Human Review Queue")
    review_queue_resp = api_call(
        base_url,
        api_key,
        "GET",
        f"/api/eval/runs/{run_id}/review-queue?include_reviewed=false&only_actionable=true&limit=100&offset=0",
    )
    if review_queue_resp.get("ok"):
        review_items = review_queue_resp.get("data", {}).get("items", [])
        if review_items:
            review_df = pd.DataFrame(
                [
                    {
                        "id": i.get("id"),
                        "case_id": i.get("case_id"),
                        "evaluation_mode": i.get("evaluation_mode"),
                        "answer_correct": i.get("answer_correct"),
                        "source_correct": i.get("source_correct"),
                        "response_quality": i.get("response_quality"),
                        "overall_score": i.get("overall_score"),
                        "review_status": i.get("review_status"),
                    }
                    for i in review_items
                ]
            )
            st.dataframe(review_df, use_container_width=True)
            review_options = {f"{str(i.get('id'))[:8]} | {str(i.get('case_id'))[:8]}": i for i in review_items}
            review_label = st.selectbox("Select review item", list(review_options.keys()))
            selected_review = review_options[review_label]
            decision = st.selectbox("Decision", ["accept", "override"])
            reason = st.text_input("Review reason", value="Reviewed by human")
            override_text = st.text_area(
                "Override JSON (for decision=override)",
                value=json.dumps(
                    {"answer_correct": "yes", "source_correct": "yes", "response_quality": "good"},
                    indent=2,
                ),
                height=120,
            )
            if st.button("Submit Review Decision"):
                payload: Dict[str, Any] = {
                    "decision": decision,
                    "reason": reason if reason.strip() else None,
                }
                if decision == "override":
                    try:
                        payload["override"] = json.loads(override_text)
                    except json.JSONDecodeError as exc:
                        st.error(f"Invalid override JSON: {exc}")
                        payload = {}
                if payload:
                    rr = api_call(
                        base_url,
                        api_key,
                        "PATCH",
                        f"/api/eval/runs/{run_id}/results/{selected_review.get('id')}/review",
                        payload=payload,
                    )
                    if rr.get("ok"):
                        st.success(f"Review submitted: {rr.get('data', {}).get('review_status')}")
                        with st.expander("Review response"):
                            st.json(rr.get("data", {}))
                    else:
                        st.error(rr.get("error", {}).get("message", "Failed to submit review"))
        else:
            st.info("No actionable unreviewed items in this run.")
    else:
        st.error(review_queue_resp.get("error", {}).get("message", "Failed to load review queue"))
else:
    st.info("Create or load a run to view summary and results.")

st.subheader("8) Regression Compare")
default_baseline = st.session_state.get("baseline_run_id") or run_id or ""
default_candidate = st.session_state.get("candidate_run_id") or run_id or ""
default_baseline_ref = st.session_state.get("baseline_ref") or "active"
default_candidate_ref = st.session_state.get("candidate_ref") or "latest"
auto_create_pattern = st.checkbox("Auto-create Issue Pattern on regression", value=False)
if run_id:
    st.caption(f"Current run: {run_id}")
else:
    st.caption("Current run: none loaded")

c_ref1, c_ref2 = st.columns(2)
with c_ref1:
    if st.button("Set Baseline Ref from current run"):
        if not run_id:
            st.warning("No current run loaded. Create or load a run first.")
        else:
            payload = {
                "kind": "baseline",
                "name": "default",
                "run_id": run_id,
                "is_active": True,
                "notes": "Set from Streamlit current run",
                "metadata": {"source": "streamlit", "action": "set_baseline_from_current_run"},
            }
            ref_resp = api_call(
                base_url,
                api_key,
                "POST",
                f"/api/agents/{selected_agent_id}/run-registry",
                payload=payload,
            )
            if ref_resp.get("ok"):
                st.session_state["baseline_ref"] = "active"
                st.success("Baseline reference set to active current run.")
            else:
                st.error(ref_resp.get("error", {}).get("message", "Failed to set baseline reference"))
with c_ref2:
    if st.button("Set Candidate Ref from current run"):
        if not run_id:
            st.warning("No current run loaded. Create or load a run first.")
        else:
            payload = {
                "kind": "candidate",
                "name": "default",
                "run_id": run_id,
                "is_active": True,
                "notes": "Set from Streamlit current run",
                "metadata": {"source": "streamlit", "action": "set_candidate_from_current_run"},
            }
            ref_resp = api_call(
                base_url,
                api_key,
                "POST",
                f"/api/agents/{selected_agent_id}/run-registry",
                payload=payload,
            )
            if ref_resp.get("ok"):
                st.session_state["candidate_ref"] = "active"
                st.success("Candidate reference set to active current run.")
            else:
                st.error(ref_resp.get("error", {}).get("message", "Failed to set candidate reference"))

compare_mode = st.radio(
    "Compare Mode",
    ["Run IDs", "Run References"],
    horizontal=True,
    help="Run IDs compares explicit UUIDs. Run References compares named baseline/candidate refs for this agent.",
)
c_base, c_cand, c_go = st.columns([2, 2, 1])
if compare_mode == "Run IDs":
    with c_base:
        baseline_run_id = st.text_input("Baseline Run ID", value=default_baseline, key="baseline_run_id")
    with c_cand:
        candidate_run_id = st.text_input("Candidate Run ID", value=default_candidate, key="candidate_run_id")
else:
    with c_base:
        baseline_ref = st.text_input(
            "Baseline Ref (active/current/<name>/latest)",
            value=default_baseline_ref,
            key="baseline_ref",
        )
    with c_cand:
        candidate_ref = st.text_input(
            "Candidate Ref (active/current/<name>/latest)",
            value=default_candidate_ref,
            key="candidate_ref",
        )
with c_go:
    if st.button("Compare Runs"):
        if compare_mode == "Run IDs" and (not baseline_run_id.strip() or not candidate_run_id.strip()):
            st.warning("Both baseline and candidate run IDs are required.")
        elif compare_mode == "Run References" and (not baseline_ref.strip() or not candidate_ref.strip()):
            st.warning("Both baseline_ref and candidate_ref are required.")
        else:
            query_params: Dict[str, str] = {
                "auto_create_pattern": str(auto_create_pattern).lower(),
            }
            if compare_mode == "Run IDs":
                query_params["baseline_run_id"] = baseline_run_id.strip()
                query_params["candidate_run_id"] = candidate_run_id.strip()
            else:
                query_params["agent_id"] = selected_agent_id
                query_params["baseline_ref"] = baseline_ref.strip()
                query_params["candidate_ref"] = candidate_ref.strip()
            query = parse.urlencode(query_params)
            resp = api_call(base_url, api_key, "GET", f"/api/eval/compare?{query}")
            if resp.get("ok"):
                st.session_state["run_compare"] = resp.get("data", {})
                rc = int(resp.get("data", {}).get("regression_count", 0))
                compare_baseline = str(resp.get("data", {}).get("baseline_run_id", ""))[:8]
                compare_candidate = str(resp.get("data", {}).get("candidate_run_id", ""))[:8]
                log_activity(
                    "regression_compare",
                    "Compared runs",
                    f"baseline={compare_baseline}, candidate={compare_candidate}, regressions={rc}",
                    severity="error" if rc > 0 else "info",
                )
                notify = resp.get("data", {}).get("notification") or {}
                if notify.get("sent"):
                    log_activity("notification", "Sent Slack notification", "event=regression_detected")
                elif notify.get("error"):
                    log_activity(
                        "notification",
                        "Slack notification failed",
                        f"event=regression_detected, error={notify.get('error')}",
                        severity="warning",
                    )
            else:
                st.error(resp.get("error", {}).get("message", "Failed to compare runs"))

compare_data = st.session_state.get("run_compare")
if compare_data:
    regression_count = int(compare_data.get("regression_count", 0))
    total_cases = int(compare_data.get("total_compared_cases", 0))
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Compared Cases", total_cases)
    c2.metric("Regressions", regression_count)
    c3.metric("Answer Delta", f"{float(compare_data.get('answer_yes_rate_delta', 0.0)):+.2%}")
    c4.metric("Quality Delta", f"{float(compare_data.get('quality_good_rate_delta', 0.0)):+.2%}")

    if regression_count > 0:
        st.error("Regression detected between baseline and candidate.")
    else:
        st.success("No regression detected between baseline and candidate.")
        promoted_note = st.text_input(
            "Promotion note",
            value="Auto-promoted after clean compare",
            key="promote_note",
        )
        if st.button("Promote Candidate -> Baseline"):
            promote_payload = {
                "candidate_run_id": compare_data.get("candidate_run_id"),
                "baseline_run_id": compare_data.get("baseline_run_id"),
                "baseline_name": "default",
                "require_clean_compare": True,
                "clean_compare_window_minutes": 120,
                "notes": promoted_note if promoted_note.strip() else None,
                "metadata": {
                    "source": "streamlit",
                    "action": "promote_after_clean_compare",
                    "baseline_run_id": compare_data.get("baseline_run_id"),
                },
            }
            promote_resp = api_call(
                base_url,
                api_key,
                "POST",
                f"/api/agents/{selected_agent_id}/run-registry/promote-candidate",
                payload=promote_payload,
            )
            if promote_resp.get("ok"):
                st.success("Candidate promoted to baseline.")
                st.session_state["baseline_ref"] = "active"
                log_activity(
                    "run_registry_promoted",
                    "Promoted candidate to baseline",
                    f"candidate={str(compare_data.get('candidate_run_id', ''))[:8]}",
                )
            else:
                st.error(promote_resp.get("error", {}).get("message", "Failed to promote candidate to baseline"))

    auto_pattern = compare_data.get("auto_pattern") or {}
    if auto_pattern.get("enabled"):
        if auto_pattern.get("created"):
            st.info(f"Issue Pattern created: {auto_pattern.get('pattern_id')}")
        elif auto_pattern.get("pattern_id"):
            st.info(f"Existing Issue Pattern reused: {auto_pattern.get('pattern_id')}")

    notification = compare_data.get("notification") or {}
    if notification.get("event_type") == "regression_detected":
        if notification.get("sent"):
            st.caption("Notification sent: regression_detected")
        elif notification.get("error"):
            st.warning(f"Notification failed: {notification.get('error')}")

    remediation = compare_data.get("remediation") or {}
    if remediation:
        st.markdown("**Remediation Auto-Close**")
        c_r1, c_r2, c_r3 = st.columns(3)
        c_r1.metric("Auto-Close Triggered", "YES" if remediation.get("auto_closed") else "NO")
        c_r2.metric("Patterns Updated", int(remediation.get("updated_patterns", 0)))
        c_r3.metric("SLO Violations Resolved", int(remediation.get("resolved_slo_violations", 0)))
        if remediation.get("auto_closed") and (int(remediation.get("updated_patterns", 0)) > 0 or int(remediation.get("resolved_slo_violations", 0)) > 0):
            st.success("Remediation closure actions were applied for this compare.")
        elif remediation.get("auto_closed"):
            st.info("Auto-close was evaluated; no matching open remediation items were found.")

    regressions = compare_data.get("regressions", [])
    if regressions:
        st.dataframe(pd.DataFrame(regressions), use_container_width=True)
    with st.expander("Comparison Details"):
        st.json(compare_data)

st.subheader("9) Calibration")
c_cal_latest, c_cal_create = st.columns(2)
with c_cal_latest:
    if st.button("Load Latest Calibration"):
        resp = api_call(base_url, api_key, "GET", f"/api/agents/{selected_agent_id}/calibration/latest")
        if resp.get("ok"):
            st.session_state["latest_calibration"] = resp.get("data", {}).get("latest_calibration")
        else:
            st.error(resp.get("error", {}).get("message", "Failed to load latest calibration"))

with c_cal_create:
    with st.expander("Create Calibration Run"):
        cal_prompt_version = st.text_input("Calibration prompt version", value="judge_prompt_v1")
        cal_model = st.text_input("Calibration judge model", value="gpt-4.1-mini")
        cal_cases_json = st.text_area(
            "Per-case comparison JSON array",
            value=json.dumps(
                [
                    {"human_label": "yes", "judge_label": "yes", "is_clean": True},
                    {"human_label": "partially", "judge_label": "no", "is_clean": False},
                ],
                indent=2,
            ),
            height=180,
        )
        if st.button("Create Calibration"):
            try:
                parsed = json.loads(cal_cases_json)
                if not isinstance(parsed, list) or len(parsed) == 0:
                    st.error("Comparison JSON must be a non-empty array.")
                else:
                    payload = {
                        "org_id": org_id,
                        "agent_id": selected_agent_id,
                        "prompt_version": cal_prompt_version,
                        "judge_model": cal_model,
                        "per_case_comparison": parsed,
                    }
                    resp = api_call(base_url, api_key, "POST", "/api/calibration/runs", payload=payload)
                    if resp.get("ok"):
                        st.session_state["latest_calibration"] = resp.get("data")
                        st.success(f"Created calibration: {resp['data']['id']}")
                    else:
                        st.error(resp.get("error", {}).get("message", "Failed to create calibration"))
            except json.JSONDecodeError as e:
                st.error(f"Invalid JSON: {e}")

latest_cal = st.session_state.get("latest_calibration")
if latest_cal:
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Calibration ID", str(latest_cal.get("id", ""))[:8])
    c2.metric("Overall Agreement", f"{float(latest_cal.get('overall_agreement', 0.0)):.2%}")
    clean = latest_cal.get("clean_agreement")
    c3.metric("Clean Agreement", f"{float(clean):.2%}" if clean is not None else "n/a")
    c4.metric("Judge Model", str(latest_cal.get("judge_model", "")))
    with st.expander("Calibration Details"):
        st.json(latest_cal)
else:
    st.info("Load or create a calibration run to view metrics.")

st.subheader("10) Issue Pattern Lifecycle")
c_pat_load, c_pat_refresh = st.columns(2)
with c_pat_load:
    if st.button("Load Patterns"):
        resp = api_call(base_url, api_key, "GET", f"/api/agents/{selected_agent_id}/patterns")
        if resp.get("ok"):
            st.session_state["patterns"] = resp.get("data", {}).get("items", [])
        else:
            st.error(resp.get("error", {}).get("message", "Failed to load patterns"))
with c_pat_refresh:
    if st.button("Refresh Patterns"):
        resp = api_call(base_url, api_key, "GET", f"/api/agents/{selected_agent_id}/patterns")
        if resp.get("ok"):
            st.session_state["patterns"] = resp.get("data", {}).get("items", [])
        else:
            st.error(resp.get("error", {}).get("message", "Failed to refresh patterns"))

patterns = st.session_state.get("patterns", [])
if patterns:
    all_status_options = [
        "detected",
        "diagnosed",
        "assigned",
        "in_progress",
        "fixed",
        "verifying",
        "resolved",
        "regressed",
        "wont_fix",
    ]
    priority_options = ["critical", "high", "medium", "low"]
    pattern_options = {f"{p['title']} ({p['id'][:8]})": p for p in patterns}
    pattern_label = st.selectbox("Pattern", list(pattern_options.keys()))
    selected_pattern = pattern_options[pattern_label]
    pattern_id = selected_pattern["id"]
    current_status = selected_pattern["status"]
    allowed_next = PATTERN_ALLOWED_TRANSITIONS.get(current_status, [])
    status_options = [current_status, *[s for s in allowed_next if s != current_status]]
    if not status_options:
        status_options = all_status_options

    c1, c2, c3 = st.columns(3)
    with c1:
        status_value = st.selectbox(
            "Pattern Status",
            status_options,
            index=0,
        )
    with c2:
        priority_value = st.selectbox(
            "Pattern Priority",
            priority_options,
            index=priority_options.index(selected_pattern["priority"]),
        )
    with c3:
        owner_value = st.text_input("Pattern Owner", value=selected_pattern.get("owner") or "")

    if status_value == current_status:
        st.caption(f"Current status: `{current_status}`. Allowed transitions: {', '.join(allowed_next) if allowed_next else 'none'}")
    else:
        st.caption(f"Transition preview: `{current_status}` -> `{status_value}`")

    force_override = st.checkbox("Force transition override (admin keys only)", value=False)
    status_note = st.text_input("Status Note")
    if st.button("Update Pattern"):
        payload: Dict[str, Any] = {
            "status": status_value,
            "priority": priority_value,
            "owner": owner_value if owner_value.strip() else None,
            "status_note": status_note if status_note.strip() else None,
            "force": force_override,
        }
        resp = api_call(
            base_url,
            api_key,
            "PATCH",
            f"/api/agents/{selected_agent_id}/patterns/{pattern_id}",
            payload=payload,
        )
        if resp.get("ok"):
            st.success("Pattern updated.")
            log_activity(
                "pattern_transition",
                "Updated pattern",
                f"pattern={pattern_id[:8]}, {current_status}->{status_value}",
                severity="info",
            )
            notify = resp.get("data", {}).get("notification") or {}
            if notify.get("sent"):
                st.caption("Notification sent: pattern_status_changed")
                log_activity("notification", "Sent Slack notification", "event=pattern_status_changed")
            elif notify.get("error"):
                st.warning(f"Notification failed: {notify.get('error')}")
                log_activity(
                    "notification",
                    "Slack notification failed",
                    f"event=pattern_status_changed, error={notify.get('error')}",
                    severity="warning",
                )
            refresh_resp = api_call(base_url, api_key, "GET", f"/api/agents/{selected_agent_id}/patterns")
            if refresh_resp.get("ok"):
                st.session_state["patterns"] = refresh_resp.get("data", {}).get("items", [])
        else:
            st.error(resp.get("error", {}).get("message", "Failed to update pattern"))

    st.markdown("**Quick Actions**")
    quick_action_map = {
        "Move to In Progress": "in_progress",
        "Mark Fixed": "fixed",
        "Move to Verifying": "verifying",
        "Resolve": "resolved",
    }
    q1, q2, q3, q4 = st.columns(4)
    quick_cols = [q1, q2, q3, q4]
    for idx, (label, target_status) in enumerate(quick_action_map.items()):
        is_allowed = target_status in status_options and target_status != current_status
        with quick_cols[idx]:
            if st.button(label, disabled=not is_allowed):
                quick_payload: Dict[str, Any] = {
                    "status": target_status,
                    "priority": selected_pattern.get("priority"),
                    "owner": selected_pattern.get("owner"),
                    "status_note": f"Quick action: {label}",
                    "force": False,
                }
                quick_resp = api_call(
                    base_url,
                    api_key,
                    "PATCH",
                    f"/api/agents/{selected_agent_id}/patterns/{pattern_id}",
                    payload=quick_payload,
                )
                if quick_resp.get("ok"):
                    st.success(f"Pattern updated via quick action: {target_status}")
                    log_activity(
                        "pattern_transition",
                        "Quick action transition",
                        f"pattern={pattern_id[:8]}, {current_status}->{target_status}",
                        severity="info",
                    )
                    notify = quick_resp.get("data", {}).get("notification") or {}
                    if notify.get("sent"):
                        st.caption("Notification sent: pattern_status_changed")
                        log_activity("notification", "Sent Slack notification", "event=pattern_status_changed")
                    elif notify.get("error"):
                        st.warning(f"Notification failed: {notify.get('error')}")
                        log_activity(
                            "notification",
                            "Slack notification failed",
                            f"event=pattern_status_changed, error={notify.get('error')}",
                            severity="warning",
                        )
                    refresh_resp = api_call(base_url, api_key, "GET", f"/api/agents/{selected_agent_id}/patterns")
                    if refresh_resp.get("ok"):
                        st.session_state["patterns"] = refresh_resp.get("data", {}).get("items", [])
                else:
                    st.error(quick_resp.get("error", {}).get("message", "Quick action failed"))

    if st.button("Load Pattern History"):
        history_resp = api_call(
            base_url,
            api_key,
            "GET",
            f"/api/agents/{selected_agent_id}/patterns/{pattern_id}/history",
        )
        if history_resp.get("ok"):
            st.session_state["pattern_history"] = history_resp.get("data", {})
            log_activity("pattern_history_loaded", "Loaded pattern history", f"pattern={pattern_id[:8]}")
        else:
            st.error(history_resp.get("error", {}).get("message", "Failed to load pattern history"))

    pattern_history = st.session_state.get("pattern_history")
    if pattern_history and str(pattern_history.get("pattern_id")) == str(pattern_id):
        st.markdown("**Pattern History**")
        st.caption(f"Current status: {pattern_history.get('status')} | Updated: {pattern_history.get('updated_at')}")
        history_items = pattern_history.get("status_history") or []
        if history_items:
            hist_df = pd.DataFrame(history_items)
            if "at" in hist_df.columns:
                hist_df = hist_df.sort_values("at", ascending=False)
            st.dataframe(hist_df, use_container_width=True)
        else:
            st.info("No status history entries yet.")

    with st.expander("Pattern Details"):
        status_color = {
            "detected": "#6b7280",
            "diagnosed": "#2563eb",
            "assigned": "#7c3aed",
            "in_progress": "#d97706",
            "fixed": "#0d9488",
            "verifying": "#0891b2",
            "resolved": "#15803d",
            "regressed": "#dc2626",
            "wont_fix": "#374151",
        }.get(str(selected_pattern.get("status")), "#6b7280")
        st.markdown(
            f"<span style='display:inline-block;padding:4px 8px;border-radius:999px;background:{status_color};color:white;font-weight:600;'>"
            f"{selected_pattern.get('status')}"
            f"</span>",
            unsafe_allow_html=True,
        )
        c_meta1, c_meta2, c_meta3 = st.columns(3)
        c_meta1.write(f"**Priority:** {selected_pattern.get('priority')}")
        c_meta2.write(f"**Owner:** {selected_pattern.get('owner') or 'unassigned'}")
        c_meta3.write(f"**Updated:** {selected_pattern.get('updated_at')}")
        st.write(f"**Title:** {selected_pattern.get('title')}")
        st.write(f"**Root Cause Type:** {selected_pattern.get('root_cause_type') or 'n/a'}")
        st.write(f"**Suggested Fix:** {selected_pattern.get('suggested_fix') or 'n/a'}")
        st.write("**Pattern ID (copy):**")
        st.code(str(selected_pattern.get("id")), language="text")
        st.write("**Agent ID (copy):**")
        st.code(str(selected_pattern.get("agent_id")), language="text")
        linked = selected_pattern.get("linked_case_ids") or []
        if linked:
            st.write("**Linked Case IDs (copy):**")
            st.code("\n".join(str(x) for x in linked), language="text")
else:
    st.info("No patterns loaded yet. Click 'Load Patterns'.")

st.subheader("11) Gate Contracts")
c_gate_defs_load, c_gate_bindings_load = st.columns(2)
with c_gate_defs_load:
    if st.button("Load Gate Definitions"):
        query = parse.urlencode({"org_id": org_id, "include_builtin": "true", "active_only": "true", "limit": 200, "offset": 0})
        resp = api_call(base_url, api_key, "GET", f"/api/gate-definitions?{query}")
        if resp.get("ok"):
            st.session_state["gate_definitions"] = resp.get("data", {}).get("items", [])
        else:
            st.error(resp.get("error", {}).get("message", "Failed to load gate definitions"))
with c_gate_bindings_load:
    if st.button("Load Agent Gate Bindings"):
        resp = api_call(base_url, api_key, "GET", f"/api/agents/{selected_agent_id}/gate-bindings?limit=200&offset=0")
        if resp.get("ok"):
            st.session_state["gate_bindings"] = resp.get("data", {}).get("items", [])
        else:
            st.error(resp.get("error", {}).get("message", "Failed to load gate bindings"))

gate_definitions = st.session_state.get("gate_definitions", [])
if gate_definitions:
    defs_df = pd.DataFrame(
        [
            {
                "id": d.get("id"),
                "key": d.get("key"),
                "name": d.get("name"),
                "evaluator_key": d.get("evaluator_key"),
                "contract_version": d.get("contract_version"),
                "is_builtin": d.get("is_builtin"),
                "active": d.get("active"),
                "org_id": d.get("org_id"),
            }
            for d in gate_definitions
        ]
    )
    st.dataframe(defs_df, use_container_width=True)
else:
    st.info("No gate definitions loaded yet. Click 'Load Gate Definitions'.")

with st.expander("Create Org Gate Definition"):
    gate_key = st.text_input("Gate key", value="custom_quality_gate")
    gate_name = st.text_input("Gate name", value="Custom Quality Gate")
    gate_description = st.text_input("Gate description", value="Org-scoped gate definition")
    gate_evaluator_key = st.selectbox(
        "Evaluator key",
        ["calibration_freshness", "golden_set_quality"],
        index=0,
    )
    gate_contract_version = st.text_input("Gate contract version", value="1.0.0")
    gate_run_types = st.multiselect(
        "Applies to run types",
        ["eval", "regression", "ab_comparison", "calibration"],
        default=["eval", "regression", "ab_comparison"],
    )
    gate_default_config_text = st.text_area(
        "Default config JSON",
        value=json.dumps({"min_overall_agreement": 0.75, "max_age_days": 14}, indent=2),
        height=120,
    )
    gate_schema_text = st.text_area(
        "Config schema JSON",
        value=json.dumps(
            {
                "type": "object",
                "properties": {
                    "min_overall_agreement": {"type": "number", "minimum": 0, "maximum": 1},
                    "max_age_days": {"type": "integer", "minimum": 1, "maximum": 3650},
                },
                "additionalProperties": False,
            },
            indent=2,
        ),
        height=160,
    )
    if st.button("Create Gate Definition"):
        try:
            default_cfg = json.loads(gate_default_config_text)
            schema_cfg = json.loads(gate_schema_text)
            if not isinstance(default_cfg, dict) or not isinstance(schema_cfg, dict):
                st.error("Config schema and default config must be JSON objects.")
            elif not gate_run_types:
                st.error("Select at least one run type.")
            else:
                payload = {
                    "org_id": org_id,
                    "key": gate_key.strip(),
                    "name": gate_name.strip(),
                    "description": gate_description.strip() or None,
                    "evaluator_key": gate_evaluator_key,
                    "contract_version": gate_contract_version.strip() or "1.0.0",
                    "config_schema": schema_cfg,
                    "default_config": default_cfg,
                    "applies_to_run_types": gate_run_types,
                    "active": True,
                }
                resp = api_call(base_url, api_key, "POST", "/api/gate-definitions", payload=payload)
                if resp.get("ok"):
                    st.success(f"Created gate definition: {resp.get('data', {}).get('id')}")
                    log_activity("gate_definition_created", "Created gate definition", f"key={gate_key}")
                    query = parse.urlencode({"org_id": org_id, "include_builtin": "true", "active_only": "true", "limit": 200, "offset": 0})
                    reload_resp = api_call(base_url, api_key, "GET", f"/api/gate-definitions?{query}")
                    if reload_resp.get("ok"):
                        st.session_state["gate_definitions"] = reload_resp.get("data", {}).get("items", [])
                else:
                    st.error(resp.get("error", {}).get("message", "Failed to create gate definition"))
        except json.JSONDecodeError as exc:
            st.error(f"Invalid JSON: {exc}")

gate_bindings = st.session_state.get("gate_bindings", [])
if gate_bindings:
    bindings_df = pd.DataFrame(
        [
            {
                "id": b.get("id"),
                "gate_key": b.get("gate_key"),
                "gate_name": b.get("gate_name"),
                "evaluator_key": b.get("evaluator_key"),
                "definition_contract_version": b.get("definition_contract_version"),
                "enabled": b.get("enabled"),
                "updated_at": b.get("updated_at"),
            }
            for b in gate_bindings
        ]
    )
    st.dataframe(bindings_df, use_container_width=True)
else:
    st.info("No gate bindings loaded yet. Click 'Load Agent Gate Bindings'.")

if gate_definitions:
    gate_option_map = {f"{d.get('name')} ({str(d.get('id'))[:8]})": d for d in gate_definitions}
    selected_gate_label = st.selectbox("Gate Definition for Binding", list(gate_option_map.keys()))
    selected_gate = gate_option_map[selected_gate_label]
    binding_enabled = st.checkbox("Binding enabled", value=True)
    default_binding_config = selected_gate.get("default_config") or {}
    binding_cfg_text = st.text_area(
        "Binding config JSON (overrides default config)",
        value=json.dumps(default_binding_config, indent=2),
        height=120,
    )
    if st.button("Upsert Agent Gate Binding"):
        try:
            binding_cfg = json.loads(binding_cfg_text)
            if not isinstance(binding_cfg, dict):
                st.error("Binding config must be a JSON object.")
            else:
                payload = {
                    "gate_definition_id": selected_gate.get("id"),
                    "enabled": bool(binding_enabled),
                    "config": binding_cfg,
                }
                resp = api_call(base_url, api_key, "POST", f"/api/agents/{selected_agent_id}/gate-bindings", payload=payload)
                if resp.get("ok"):
                    st.success("Gate binding saved.")
                    log_activity(
                        "gate_binding_upserted",
                        "Upserted gate binding",
                        f"agent={selected_agent_id[:8]}, gate={str(selected_gate.get('key'))}",
                    )
                    reload_resp = api_call(base_url, api_key, "GET", f"/api/agents/{selected_agent_id}/gate-bindings?limit=200&offset=0")
                    if reload_resp.get("ok"):
                        st.session_state["gate_bindings"] = reload_resp.get("data", {}).get("items", [])
                else:
                    st.error(resp.get("error", {}).get("message", "Failed to save gate binding"))
        except json.JSONDecodeError as exc:
            st.error(f"Invalid JSON: {exc}")

st.markdown("**Evaluator Contracts**")
c_eval_defs_load, c_eval_bindings_load = st.columns(2)
with c_eval_defs_load:
    if st.button("Load Evaluator Definitions"):
        query = parse.urlencode({"org_id": org_id, "include_builtin": "true", "active_only": "true", "limit": 200, "offset": 0})
        resp = api_call(base_url, api_key, "GET", f"/api/evaluator-definitions?{query}")
        if resp.get("ok"):
            st.session_state["evaluator_definitions"] = resp.get("data", {}).get("items", [])
        else:
            st.error(resp.get("error", {}).get("message", "Failed to load evaluator definitions"))
with c_eval_bindings_load:
    if st.button("Load Agent Evaluator Bindings"):
        resp = api_call(base_url, api_key, "GET", f"/api/agents/{selected_agent_id}/evaluator-bindings?limit=200&offset=0")
        if resp.get("ok"):
            st.session_state["evaluator_bindings"] = resp.get("data", {}).get("items", [])
        else:
            st.error(resp.get("error", {}).get("message", "Failed to load evaluator bindings"))

evaluator_definitions = st.session_state.get("evaluator_definitions", [])
if evaluator_definitions:
    eval_defs_df = pd.DataFrame(
        [
            {
                "id": d.get("id"),
                "key": d.get("key"),
                "name": d.get("name"),
                "evaluation_mode": d.get("evaluation_mode"),
                "evaluator_kind": d.get("evaluator_kind"),
                "contract_version": d.get("contract_version"),
                "is_builtin": d.get("is_builtin"),
                "active": d.get("active"),
                "org_id": d.get("org_id"),
            }
            for d in evaluator_definitions
        ]
    )
    st.dataframe(eval_defs_df, use_container_width=True)

with st.expander("Create Org Evaluator Definition"):
    eval_key = st.text_input("Evaluator key", value="custom_answer_eval")
    eval_name = st.text_input("Evaluator name", value="Custom Answer Evaluator")
    eval_description = st.text_input("Evaluator description", value="Org-scoped evaluator definition")
    eval_mode = st.selectbox("Evaluation mode", ["answer", "criteria"], index=0)
    eval_kind = st.selectbox("Evaluator kind", ["judge_service"], index=0)
    eval_contract_version = st.text_input("Evaluator contract version", value="1.0.0")
    eval_default_config_text = st.text_area(
        "Evaluator default config JSON",
        value=json.dumps({"judge_mode": "deterministic"}, indent=2),
        height=100,
    )
    if st.button("Create Evaluator Definition"):
        try:
            eval_default_cfg = json.loads(eval_default_config_text)
            if not isinstance(eval_default_cfg, dict):
                st.error("Evaluator default config must be a JSON object.")
            else:
                payload = {
                    "org_id": org_id,
                    "key": eval_key.strip(),
                    "name": eval_name.strip(),
                    "description": eval_description.strip() or None,
                    "evaluation_mode": eval_mode,
                    "evaluator_kind": eval_kind,
                    "contract_version": eval_contract_version.strip() or "1.0.0",
                    "default_config": eval_default_cfg,
                    "active": True,
                }
                resp = api_call(base_url, api_key, "POST", "/api/evaluator-definitions", payload=payload)
                if resp.get("ok"):
                    st.success(f"Created evaluator definition: {resp.get('data', {}).get('id')}")
                    log_activity("evaluator_definition_created", "Created evaluator definition", f"key={eval_key}")
                else:
                    st.error(resp.get("error", {}).get("message", "Failed to create evaluator definition"))
        except json.JSONDecodeError as exc:
            st.error(f"Invalid JSON: {exc}")

evaluator_bindings = st.session_state.get("evaluator_bindings", [])
if evaluator_bindings:
    eval_bind_df = pd.DataFrame(
        [
            {
                "id": b.get("id"),
                "evaluation_mode": b.get("evaluation_mode"),
                "evaluator_key": b.get("evaluator_key"),
                "evaluator_name": b.get("evaluator_name"),
                "definition_contract_version": b.get("definition_contract_version"),
                "enabled": b.get("enabled"),
                "updated_at": b.get("updated_at"),
            }
            for b in evaluator_bindings
        ]
    )
    st.dataframe(eval_bind_df, use_container_width=True)

if evaluator_definitions:
    eval_option_map = {f"{d.get('name')} ({str(d.get('id'))[:8]})": d for d in evaluator_definitions}
    selected_eval_label = st.selectbox("Evaluator Definition for Binding", list(eval_option_map.keys()))
    selected_eval = eval_option_map[selected_eval_label]
    evaluator_binding_enabled = st.checkbox("Evaluator binding enabled", value=True)
    eval_binding_cfg_text = st.text_area(
        "Evaluator binding config JSON",
        value=json.dumps(selected_eval.get("default_config") or {}, indent=2),
        height=100,
    )
    if st.button("Upsert Agent Evaluator Binding"):
        try:
            eval_binding_cfg = json.loads(eval_binding_cfg_text)
            if not isinstance(eval_binding_cfg, dict):
                st.error("Evaluator binding config must be a JSON object.")
            else:
                payload = {
                    "evaluator_definition_id": selected_eval.get("id"),
                    "evaluation_mode": selected_eval.get("evaluation_mode"),
                    "enabled": bool(evaluator_binding_enabled),
                    "config": eval_binding_cfg,
                }
                resp = api_call(
                    base_url,
                    api_key,
                    "POST",
                    f"/api/agents/{selected_agent_id}/evaluator-bindings",
                    payload=payload,
                )
                if resp.get("ok"):
                    st.success("Evaluator binding saved.")
                    log_activity(
                        "evaluator_binding_upserted",
                        "Upserted evaluator binding",
                        f"agent={selected_agent_id[:8]}, mode={selected_eval.get('evaluation_mode')}",
                    )
                else:
                    st.error(resp.get("error", {}).get("message", "Failed to save evaluator binding"))
        except json.JSONDecodeError as exc:
            st.error(f"Invalid JSON: {exc}")

st.markdown("**Run Type Contracts**")
c_rt_defs_load, c_rt_bindings_load = st.columns(2)
with c_rt_defs_load:
    if st.button("Load Run Type Definitions"):
        query = parse.urlencode({"org_id": org_id, "include_builtin": "true", "active_only": "true", "limit": 200, "offset": 0})
        resp = api_call(base_url, api_key, "GET", f"/api/run-type-definitions?{query}")
        if resp.get("ok"):
            st.session_state["run_type_definitions"] = resp.get("data", {}).get("items", [])
        else:
            st.error(resp.get("error", {}).get("message", "Failed to load run type definitions"))
with c_rt_bindings_load:
    if st.button("Load Agent Run Type Bindings"):
        resp = api_call(base_url, api_key, "GET", f"/api/agents/{selected_agent_id}/run-type-bindings?limit=200&offset=0")
        if resp.get("ok"):
            st.session_state["run_type_bindings"] = resp.get("data", {}).get("items", [])
        else:
            st.error(resp.get("error", {}).get("message", "Failed to load run type bindings"))

run_type_definitions = st.session_state.get("run_type_definitions", [])
if run_type_definitions:
    rt_defs_df = pd.DataFrame(
        [
            {
                "id": d.get("id"),
                "run_type": d.get("run_type"),
                "key": d.get("key"),
                "name": d.get("name"),
                "handler_key": d.get("handler_key"),
                "contract_version": d.get("contract_version"),
                "is_builtin": d.get("is_builtin"),
                "active": d.get("active"),
                "org_id": d.get("org_id"),
            }
            for d in run_type_definitions
        ]
    )
    st.dataframe(rt_defs_df, use_container_width=True)

with st.expander("Create Org Run Type Definition"):
    rt_type = st.selectbox("Run type", ["eval", "regression", "ab_comparison", "calibration"], index=0)
    rt_key = st.text_input("Run type definition key", value="custom_eval_handler")
    rt_name = st.text_input("Run type definition name", value="Custom Eval Handler")
    rt_description = st.text_input("Run type definition description", value="Org-scoped run type handler")
    rt_handler_key = st.selectbox("Handler key", ["default", "sync_only", "async_only"], index=0)
    rt_contract_version = st.text_input("Run type contract version", value="1.0.0")
    rt_default_config_text = st.text_area(
        "Run type default config JSON",
        value=json.dumps({"allow_start": True, "allow_execute": True}, indent=2),
        height=100,
    )
    if st.button("Create Run Type Definition"):
        try:
            rt_default_cfg = json.loads(rt_default_config_text)
            if not isinstance(rt_default_cfg, dict):
                st.error("Run type default config must be a JSON object.")
            else:
                payload = {
                    "org_id": org_id,
                    "run_type": rt_type,
                    "key": rt_key.strip(),
                    "name": rt_name.strip(),
                    "description": rt_description.strip() or None,
                    "handler_key": rt_handler_key,
                    "contract_version": rt_contract_version.strip() or "1.0.0",
                    "default_config": rt_default_cfg,
                    "active": True,
                }
                resp = api_call(base_url, api_key, "POST", "/api/run-type-definitions", payload=payload)
                if resp.get("ok"):
                    st.success(f"Created run type definition: {resp.get('data', {}).get('id')}")
                    log_activity("run_type_definition_created", "Created run type definition", f"key={rt_key}, type={rt_type}")
                else:
                    st.error(resp.get("error", {}).get("message", "Failed to create run type definition"))
        except json.JSONDecodeError as exc:
            st.error(f"Invalid JSON: {exc}")

run_type_bindings = st.session_state.get("run_type_bindings", [])
if run_type_bindings:
    rt_bind_df = pd.DataFrame(
        [
            {
                "id": b.get("id"),
                "run_type": b.get("run_type"),
                "definition_key": b.get("definition_key"),
                "definition_name": b.get("definition_name"),
                "handler_key": b.get("handler_key"),
                "definition_contract_version": b.get("definition_contract_version"),
                "enabled": b.get("enabled"),
                "updated_at": b.get("updated_at"),
            }
            for b in run_type_bindings
        ]
    )
    st.dataframe(rt_bind_df, use_container_width=True)

if run_type_definitions:
    rt_option_map = {f"{d.get('name')} ({str(d.get('id'))[:8]})": d for d in run_type_definitions}
    selected_rt_label = st.selectbox("Run Type Definition for Binding", list(rt_option_map.keys()))
    selected_rt = rt_option_map[selected_rt_label]
    run_type_binding_enabled = st.checkbox("Run type binding enabled", value=True)
    rt_binding_cfg_text = st.text_area(
        "Run type binding config JSON",
        value=json.dumps(selected_rt.get("default_config") or {}, indent=2),
        height=100,
    )
    if st.button("Upsert Agent Run Type Binding"):
        try:
            rt_binding_cfg = json.loads(rt_binding_cfg_text)
            if not isinstance(rt_binding_cfg, dict):
                st.error("Run type binding config must be a JSON object.")
            else:
                payload = {
                    "run_type_definition_id": selected_rt.get("id"),
                    "run_type": selected_rt.get("run_type"),
                    "enabled": bool(run_type_binding_enabled),
                    "config": rt_binding_cfg,
                }
                resp = api_call(
                    base_url,
                    api_key,
                    "POST",
                    f"/api/agents/{selected_agent_id}/run-type-bindings",
                    payload=payload,
                )
                if resp.get("ok"):
                    st.success("Run type binding saved.")
                    log_activity(
                        "run_type_binding_upserted",
                        "Upserted run type binding",
                        f"agent={selected_agent_id[:8]}, run_type={selected_rt.get('run_type')}",
                    )
                else:
                    st.error(resp.get("error", {}).get("message", "Failed to save run type binding"))
        except json.JSONDecodeError as exc:
            st.error(f"Invalid JSON: {exc}")

st.markdown("**Contract Preflight**")
preflight_run_type = st.selectbox(
    "Preflight run type",
    ["eval", "regression", "ab_comparison", "calibration"],
    index=0,
)
preflight_entrypoint = st.selectbox(
    "Preflight entrypoint",
    ["start", "execute"],
    index=0,
)
preflight_use_selected_gs = st.checkbox(
    "Use currently selected golden set for preflight",
    value=bool(st.session_state.get("selected_golden_set_id")),
)
preflight_golden_set_id = ""
if preflight_use_selected_gs:
    preflight_golden_set_id = str(st.session_state.get("selected_golden_set_id") or "")
else:
    preflight_golden_set_id = st.text_input("Preflight golden set ID (optional)", value="")

if st.button("Run Contract Preflight"):
    params = {
        "run_type": preflight_run_type,
        "entrypoint": preflight_entrypoint,
    }
    gs_id = preflight_golden_set_id.strip()
    if gs_id:
        params["golden_set_id"] = gs_id
    query = parse.urlencode(params)
    resp = api_call(base_url, api_key, "GET", f"/api/agents/{selected_agent_id}/contract-status?{query}")
    if resp.get("ok"):
        st.session_state["contract_preflight"] = resp.get("data", {})
        status_val = str(resp.get("data", {}).get("status", "fail"))
        log_activity(
            "contract_preflight",
            "Ran agent contract preflight",
            f"agent={selected_agent_id[:8]}, run_type={preflight_run_type}, entrypoint={preflight_entrypoint}, status={status_val}",
            severity="info" if status_val == "pass" else "warning",
        )
    else:
        st.error(resp.get("error", {}).get("message", "Failed to run contract preflight"))

preflight_data = st.session_state.get("contract_preflight")
if preflight_data:
    status_value = str(preflight_data.get("status", "fail")).lower()
    c_pf1, c_pf2, c_pf3, c_pf4 = st.columns(4)
    c_pf1.metric("Status", status_value.upper())
    c_pf2.metric("Resolved Handler", str(preflight_data.get("resolved_handler_key", "default")))
    c_pf3.metric("Enabled Gates", int(preflight_data.get("enabled_gate_binding_count", 0)))
    c_pf4.metric("Enabled Evaluators", int(preflight_data.get("enabled_evaluator_binding_count", 0)))
    issues = preflight_data.get("issues") or []
    if status_value == "pass":
        st.success("Preflight passed. No blocking contract issues detected.")
    else:
        st.error("Preflight failed. Blocking contract issues detected.")
    if issues:
        issues_df = pd.DataFrame(issues)
        st.dataframe(issues_df, use_container_width=True)
    with st.expander("Preflight Details"):
        st.json(preflight_data)

st.markdown("**Contract Upgrade Workflow**")
contract_type = st.selectbox("Definition type", ["gate", "evaluator", "run_type"], index=0)
defs_by_type = {
    "gate": st.session_state.get("gate_definitions", []),
    "evaluator": st.session_state.get("evaluator_definitions", []),
    "run_type": st.session_state.get("run_type_definitions", []),
}
selected_defs = defs_by_type.get(contract_type, [])
definition_id_value = st.text_input("Definition ID", value="")
if selected_defs:
    contract_option_map = {f"{d.get('name')} ({str(d.get('id'))[:8]})": d for d in selected_defs}
    selected_contract_label = st.selectbox("Pick loaded definition", list(contract_option_map.keys()))
    selected_contract = contract_option_map[selected_contract_label]
    definition_id_value = str(selected_contract.get("id"))
    st.caption(
        f"Current version: {str(selected_contract.get('contract_version') or '1.0.0')} | key: {selected_contract.get('key')}"
    )

target_contract_version = st.text_input("Target contract version", value="1.1.0")
rollout_mode = st.selectbox("Rollout mode", ["definition_only", "sync_bindings"], index=0)
c_upgrade_preview, c_upgrade_apply = st.columns(2)
with c_upgrade_preview:
    if st.button("Preview Upgrade Impact"):
        payload = {
            "definition_type": contract_type,
            "definition_id": definition_id_value.strip(),
            "target_contract_version": target_contract_version.strip(),
            "include_items": True,
            "max_items": 200,
        }
        resp = api_call(base_url, api_key, "POST", "/api/contracts/upgrade-preview", payload=payload)
        if resp.get("ok"):
            st.session_state["contract_upgrade_preview"] = resp.get("data", {})
            p = resp.get("data", {})
            log_activity(
                "contract_upgrade_preview",
                "Previewed contract upgrade impact",
                (
                    f"type={contract_type}, id={definition_id_value[:8]}, target={target_contract_version}, "
                    f"status={p.get('status')}, breaking={p.get('breaking_count')}"
                ),
                severity="warning" if int(p.get("breaking_count", 0) or 0) > 0 else "info",
            )
        else:
            st.error(resp.get("error", {}).get("message", "Failed to preview contract upgrade"))
with c_upgrade_apply:
    if st.button("Apply Contract Upgrade"):
        payload = {
            "definition_type": contract_type,
            "definition_id": definition_id_value.strip(),
            "target_contract_version": target_contract_version.strip(),
            "rollout_mode": rollout_mode,
        }
        resp = api_call(base_url, api_key, "POST", "/api/contracts/apply-upgrade", payload=payload)
        if resp.get("ok"):
            st.success("Contract upgrade applied.")
            preview_data = resp.get("data", {}).get("preview") or {}
            st.session_state["contract_upgrade_preview"] = preview_data
            log_activity(
                "contract_upgrade_apply",
                "Applied contract upgrade",
                (
                    f"type={contract_type}, id={definition_id_value[:8]}, target={target_contract_version}, "
                    f"rollout={rollout_mode}, bindings_updated={resp.get('data', {}).get('bindings_updated', 0)}"
                ),
                severity="info",
            )
        else:
            st.error(resp.get("error", {}).get("message", "Failed to apply contract upgrade"))

upgrade_preview = st.session_state.get("contract_upgrade_preview")
if upgrade_preview:
    u1, u2, u3, u4, u5 = st.columns(5)
    u1.metric("Upgrade Status", str(upgrade_preview.get("status", "safe")).upper())
    u2.metric("Impacted Bindings", int(upgrade_preview.get("impacted_binding_count", 0)))
    u3.metric("Breaking", int(upgrade_preview.get("breaking_count", 0)))
    u4.metric("Warnings", int(upgrade_preview.get("warning_count", 0)))
    u5.metric("Invalid", int(upgrade_preview.get("invalid_count", 0)))
    if int(upgrade_preview.get("breaking_count", 0)) > 0 or int(upgrade_preview.get("invalid_count", 0)) > 0:
        st.error("Upgrade is risky. Review impacts before rollout.")
    else:
        st.success("Upgrade is safe for current bindings.")
    preview_items = upgrade_preview.get("items") or []
    if preview_items:
        st.dataframe(pd.DataFrame(preview_items), use_container_width=True)
    with st.expander("Upgrade Preview Details"):
        st.json(upgrade_preview)

st.markdown("**Contract Drift Monitor**")
drift_include_healthy = st.checkbox("Include healthy bindings", value=False)
drift_limit = st.number_input("Agent scan limit", min_value=1, max_value=1000, value=200, step=1)
drift_promote_min = st.selectbox("Promote minimum drift", ["breaking", "invalid", "warning"], index=0)
drift_promote_dry_run = st.checkbox("Promote dry run", value=False)
if st.button("Load Contract Drift"):
    query = parse.urlencode(
        {
            "org_id": org_id,
            "include_healthy": "true" if drift_include_healthy else "false",
            "limit": int(drift_limit),
        }
    )
    resp = api_call(base_url, api_key, "GET", f"/api/contracts/drift?{query}")
    if resp.get("ok"):
        st.session_state["contract_drift"] = resp.get("data", {})
        d = resp.get("data", {})
        log_activity(
            "contract_drift_scan",
            "Loaded contract drift monitor",
            (
                f"org={org_id[:8]}, agents={d.get('checked_agent_count', 0)}, "
                f"breaking={d.get('breaking_count', 0)}, warning={d.get('warning_count', 0)}, invalid={d.get('invalid_count', 0)}"
            ),
            severity="warning" if int(d.get("breaking_count", 0) or 0) > 0 else "info",
        )
    else:
        st.error(resp.get("error", {}).get("message", "Failed to load contract drift"))

if st.button("Promote Drift To Issue Patterns"):
    payload = {
        "org_id": org_id,
        "agent_id": selected_agent_id,
        "min_drift": drift_promote_min,
        "dry_run": bool(drift_promote_dry_run),
        "limit": int(drift_limit),
    }
    resp = api_call(base_url, api_key, "POST", "/api/contracts/drift/promote-patterns", payload=payload)
    if resp.get("ok"):
        promote_data = resp.get("data", {})
        st.session_state["contract_drift_promote"] = promote_data
        st.success(
            f"Promote complete: eligible={promote_data.get('eligible_item_count', 0)}, "
            f"created={promote_data.get('created_pattern_count', 0)}, reused={promote_data.get('reused_pattern_count', 0)}"
        )
        notify = promote_data.get("notification") or {}
        if notify.get("sent"):
            st.caption("Notification sent: contract_drift_patterns_promoted")
        elif notify.get("queued"):
            st.caption("Notification queued: contract_drift_patterns_promoted")
        elif notify.get("error"):
            st.warning(f"Notification failed: {notify.get('error')}")
        log_activity(
            "contract_drift_promoted",
            "Promoted contract drift to issue patterns",
            (
                f"agent={selected_agent_id[:8]}, min={drift_promote_min}, dry_run={drift_promote_dry_run}, "
                f"eligible={promote_data.get('eligible_item_count', 0)}, created={promote_data.get('created_pattern_count', 0)}"
            ),
            severity="warning",
        )
    else:
        st.error(resp.get("error", {}).get("message", "Failed to promote drift to patterns"))

drift_data = st.session_state.get("contract_drift")
if drift_data:
    d1, d2, d3, d4, d5 = st.columns(5)
    d1.metric("Checked Agents", int(drift_data.get("checked_agent_count", 0)))
    d2.metric("Drift Items", int(drift_data.get("item_count", 0)))
    d3.metric("Breaking", int(drift_data.get("breaking_count", 0)))
    d4.metric("Warnings", int(drift_data.get("warning_count", 0)))
    d5.metric("Invalid", int(drift_data.get("invalid_count", 0)))
    drift_items = drift_data.get("items") or []
    if drift_items:
        st.dataframe(pd.DataFrame(drift_items), use_container_width=True)
    with st.expander("Drift Details"):
        st.json(drift_data)

drift_promote_data = st.session_state.get("contract_drift_promote")
if drift_promote_data:
    with st.expander("Drift Promote Details"):
        st.json(drift_promote_data)

st.subheader("12) SLO Guardrails")
c_slo_load, c_slo_save = st.columns(2)
with c_slo_load:
    if st.button("Load SLO Policy"):
        resp = api_call(base_url, api_key, "GET", f"/api/agents/{selected_agent_id}/slo-policy")
        if resp.get("ok"):
            st.session_state["slo_policy"] = resp.get("data", {}).get("slo_policy")
        else:
            st.error(resp.get("error", {}).get("message", "Failed to load SLO policy"))

cal_gate_resp = api_call(base_url, api_key, "GET", f"/api/agents/{selected_agent_id}/calibration-gate-status")
if cal_gate_resp.get("ok"):
    cg = cal_gate_resp.get("data", {})
    cg1, cg2, cg3 = st.columns(3)
    cg1.metric("Calibration Gate", str(cg.get("status", "disabled")).upper())
    cg2.metric("Min Agreement", f"{float(cg.get('min_overall_agreement', 0.7)):.2f}")
    cg3.metric("Max Age Days", int(cg.get("max_age_days", 14)))
    if cg.get("reasons"):
        st.caption("Calibration gate reasons: " + " | ".join(str(x) for x in (cg.get("reasons") or [])[:3]))

golden_set_gate_resp = None
if selected_golden_set_id:
    golden_set_gate_resp = api_call(base_url, api_key, "GET", f"/api/golden-sets/{selected_golden_set_id}/quality-gate-status")
if golden_set_gate_resp and golden_set_gate_resp.get("ok"):
    gg = golden_set_gate_resp.get("data", {})
    gg1, gg2, gg3, gg4 = st.columns(4)
    gg1.metric("GS Quality Gate", str(gg.get("status", "disabled")).upper())
    gg2.metric("Verified Ratio", f"{float(gg.get('verified_case_ratio', 0.0)):.2f}")
    gg3.metric("Active Cases", int(gg.get("active_case_count", 0)))
    gg4.metric("Verified Cases", int(gg.get("verified_case_count", 0)))
    if gg.get("reasons"):
        st.caption("Golden set gate reasons: " + " | ".join(str(x) for x in (gg.get("reasons") or [])[:3]))

existing_slo = st.session_state.get("slo_policy") or {}
min_answer_yes_rate = st.number_input("Min Answer Yes Rate", min_value=0.0, max_value=1.0, value=float(existing_slo.get("min_answer_yes_rate") or 0.8), step=0.01)
min_source_yes_rate = st.number_input("Min Source Yes Rate", min_value=0.0, max_value=1.0, value=float(existing_slo.get("min_source_yes_rate") or 0.8), step=0.01)
min_quality_good_rate = st.number_input("Min Quality Good Rate", min_value=0.0, max_value=1.0, value=float(existing_slo.get("min_quality_good_rate") or 0.8), step=0.01)
max_run_duration_ms = st.number_input("Max Run Duration (ms)", min_value=1, max_value=600000, value=int(existing_slo.get("max_run_duration_ms") or 120000), step=1000)
max_regression_count = st.number_input("Max Regression Count", min_value=0, max_value=10000, value=int(existing_slo.get("max_regression_count") or 0), step=1)
require_calibration_gate = st.checkbox("Require Calibration Gate", value=bool(existing_slo.get("require_calibration_gate") or False))
min_calibration_overall_agreement = st.number_input(
    "Min Calibration Overall Agreement",
    min_value=0.0,
    max_value=1.0,
    value=float(existing_slo.get("min_calibration_overall_agreement") or 0.7),
    step=0.01,
)
max_calibration_age_days = st.number_input(
    "Max Calibration Age (days)",
    min_value=1,
    max_value=3650,
    value=int(existing_slo.get("max_calibration_age_days") or 14),
    step=1,
)
require_golden_set_quality_gate = st.checkbox(
    "Require Golden Set Quality Gate",
    value=bool(existing_slo.get("require_golden_set_quality_gate") or False),
)
min_verified_case_ratio = st.number_input(
    "Min Verified Case Ratio",
    min_value=0.0,
    max_value=1.0,
    value=float(existing_slo.get("min_verified_case_ratio") or 0.7),
    step=0.01,
)
min_active_case_count = st.number_input(
    "Min Active Case Count",
    min_value=1,
    max_value=1000000,
    value=int(existing_slo.get("min_active_case_count") or 20),
    step=1,
)

with c_slo_save:
    if st.button("Save SLO Policy"):
        payload = {
            "min_answer_yes_rate": float(min_answer_yes_rate),
            "min_source_yes_rate": float(min_source_yes_rate),
            "min_quality_good_rate": float(min_quality_good_rate),
            "max_run_duration_ms": int(max_run_duration_ms),
            "max_regression_count": int(max_regression_count),
            "require_calibration_gate": bool(require_calibration_gate),
            "min_calibration_overall_agreement": float(min_calibration_overall_agreement),
            "max_calibration_age_days": int(max_calibration_age_days),
            "require_golden_set_quality_gate": bool(require_golden_set_quality_gate),
            "min_verified_case_ratio": float(min_verified_case_ratio),
            "min_active_case_count": int(min_active_case_count),
        }
        resp = api_call(base_url, api_key, "POST", f"/api/agents/{selected_agent_id}/slo-policy", payload=payload)
        if resp.get("ok"):
            st.session_state["slo_policy"] = resp.get("data", {}).get("slo_policy")
            st.success("SLO policy saved.")
        else:
            st.error(resp.get("error", {}).get("message", "Failed to save SLO policy"))

st.subheader("13) Launch Gate")
c_gate1, c_gate2 = st.columns(2)
with c_gate1:
    if st.button("Evaluate Launch Gate"):
        resp = api_call(base_url, api_key, "GET", f"/api/agents/{selected_agent_id}/launch-gate")
        if resp.get("ok"):
            st.session_state["launch_gate"] = resp.get("data", {})
        else:
            st.error(resp.get("error", {}).get("message", "Failed to evaluate launch gate"))
with c_gate2:
    if st.button("Load Launch Decisions"):
        resp = api_call(base_url, api_key, "GET", f"/api/agents/{selected_agent_id}/launch-decisions?limit=20")
        if resp.get("ok"):
            st.session_state["launch_decisions"] = resp.get("data", {}).get("items", [])
        else:
            st.error(resp.get("error", {}).get("message", "Failed to load launch decisions"))

gate = st.session_state.get("launch_gate")
if gate:
    can_launch = bool(gate.get("can_launch"))
    if can_launch:
        st.success("Can Launch: YES")
    else:
        st.error("Can Launch: NO")
    blockers = gate.get("blockers") or []
    if blockers:
        st.markdown("**Blockers**")
        for b in blockers:
            st.write(f"- {b}")

decision_choice = st.selectbox("Launch decision", ["go", "no_go", "deferred"])
decision_reason = st.text_input("Decision reason")
if st.button("Submit Launch Decision"):
    payload = {"decision": decision_choice, "reason": decision_reason if decision_reason.strip() else None}
    resp = api_call(base_url, api_key, "POST", f"/api/agents/{selected_agent_id}/launch-decision", payload=payload)
    if resp.get("ok"):
        st.success("Launch decision recorded.")
        st.session_state["launch_gate"] = resp.get("data", {}).get("gate")
        decision = resp.get("data", {}).get("decision", {})
        notify = decision.get("notification") or {}
        if notify.get("sent"):
            st.caption("Notification sent: launch_decision_changed")
        elif notify.get("error"):
            st.warning(f"Notification failed: {notify.get('error')}")
    else:
        err = resp.get("error", {}).get("message", "Failed to submit launch decision")
        st.error(err)
        details = resp.get("error", {}).get("details")
        if details:
            st.json(details)

decisions = st.session_state.get("launch_decisions", [])
if decisions:
    st.markdown("**Launch Decision History**")
    st.dataframe(pd.DataFrame(decisions), use_container_width=True)

st.subheader("14) Queue Ops")
effective_admin_key = admin_api_key.strip() or api_key.strip()
c_q1, c_q2 = st.columns(2)
with c_q1:
    if st.button("Load Queue Stats"):
        if not effective_admin_key:
            st.error("Admin API key (or API key) is required.")
        else:
            resp = api_call(base_url, effective_admin_key, "GET", f"/api/system/queue/stats?org_id={org_id}")
            if resp.get("ok"):
                st.session_state["queue_stats"] = resp.get("data", {})
            else:
                st.error(resp.get("error", {}).get("message", "Failed to load queue stats"))
with c_q2:
    if st.button("Load Failed Queue Jobs"):
        if not effective_admin_key:
            st.error("Admin API key (or API key) is required.")
        else:
            resp = api_call(base_url, effective_admin_key, "GET", f"/api/system/queue/jobs/failed?org_id={org_id}&limit=100")
            if resp.get("ok"):
                st.session_state["failed_queue_jobs"] = resp.get("data", {}).get("items", [])
            else:
                st.error(resp.get("error", {}).get("message", "Failed to load failed queue jobs"))

queue_stats = st.session_state.get("queue_stats") or {}
if queue_stats:
    q_a, q_b, q_c, q_d = st.columns(4)
    q_a.metric("Queued", int(queue_stats.get("queued_count", 0)))
    q_b.metric("Running", int(queue_stats.get("running_count", 0)))
    q_c.metric("Failed", int(queue_stats.get("failed_count", 0)))
    q_d.metric("Retry Backlog", int(queue_stats.get("retry_backlog_count", 0)))
    st.caption(
        f"Oldest queued age: {queue_stats.get('oldest_queued_age_seconds')}s | Checked at: {queue_stats.get('checked_at')}"
    )

failed_jobs = st.session_state.get("failed_queue_jobs", [])
if failed_jobs:
    st.markdown("**Failed Jobs**")
    failed_df = pd.DataFrame(failed_jobs)
    display_cols = [
        c for c in [
            "job_id",
            "run_id",
            "run_name",
            "job_status",
            "attempt_count",
            "max_attempts",
            "error_message",
            "updated_at",
        ] if c in failed_df.columns
    ]
    st.dataframe(failed_df[display_cols], use_container_width=True)

    job_options = {f"{j.get('job_id', '')[:8]} | run {str(j.get('run_id', ''))[:8]} | {j.get('error_message', '')[:40]}": j for j in failed_jobs}
    selected_job_label = st.selectbox("Failed Job", list(job_options.keys()))
    selected_job = job_options[selected_job_label]
    selected_job_id = str(selected_job.get("job_id"))
    retry_delay_seconds = st.number_input("Retry delay seconds", min_value=0, max_value=86400, value=0, step=1)
    c_act1, c_act2 = st.columns(2)
    with c_act1:
        if st.button("Retry Selected Job"):
            resp = api_call(
                base_url,
                effective_admin_key,
                "POST",
                f"/api/system/queue/jobs/{selected_job_id}/retry?delay_seconds={int(retry_delay_seconds)}",
            )
            if resp.get("ok"):
                st.success("Job re-queued.")
            else:
                st.error(resp.get("error", {}).get("message", "Retry failed"))
    with c_act2:
        if st.button("Cancel Selected Job"):
            resp = api_call(
                base_url,
                effective_admin_key,
                "POST",
                f"/api/system/queue/jobs/{selected_job_id}/cancel",
            )
            if resp.get("ok"):
                if resp.get("data", {}).get("cancelled"):
                    st.success("Job cancelled.")
                else:
                    st.info(f"Job not active; status={resp.get('data', {}).get('status')}")
            else:
                st.error(resp.get("error", {}).get("message", "Cancel failed"))
else:
    st.caption("No failed jobs loaded yet.")

st.subheader("15) Contract Drift Automation")
c_cd1, c_cd2 = st.columns(2)
with c_cd1:
    if st.button("Load Drift Policy"):
        if not effective_admin_key:
            st.error("Admin API key (or API key) is required.")
        else:
            query = parse.urlencode({"org_id": org_id})
            resp = api_call(base_url, effective_admin_key, "GET", f"/api/system/contracts/drift-policy?{query}")
            if resp.get("ok"):
                st.session_state["contract_drift_policy"] = resp.get("data", {})
            else:
                st.error(resp.get("error", {}).get("message", "Failed to load drift policy"))
with c_cd2:
    if st.button("Load Drift Monitor"):
        if not effective_admin_key:
            st.error("Admin API key (or API key) is required.")
        else:
            query = parse.urlencode({"org_id": org_id, "limit": 200})
            resp = api_call(base_url, effective_admin_key, "GET", f"/api/contracts/drift?{query}")
            if resp.get("ok"):
                st.session_state["contract_drift"] = resp.get("data", {})
            else:
                st.error(resp.get("error", {}).get("message", "Failed to load contract drift"))
    if st.button("Load Drift Trigger Summary"):
        if not effective_admin_key:
            st.error("Admin API key (or API key) is required.")
        else:
            query = parse.urlencode({"org_id": org_id, "schedule_name": cd_schedule_name if "cd_schedule_name" in locals() else "daily", "window_days": 30, "limit": 50})
            resp = api_call(base_url, effective_admin_key, "GET", f"/api/system/contracts/drift/trigger-summary?{query}")
            if resp.get("ok"):
                st.session_state["contract_drift_trigger_summary"] = resp.get("data", {})
            else:
                st.error(resp.get("error", {}).get("message", "Failed to load drift trigger summary"))

policy = st.session_state.get("contract_drift_policy") or {}
default_enabled = bool(policy.get("enabled", False))
default_min_drift = str(policy.get("min_drift", "breaking"))
default_promote = bool(policy.get("promote_to_patterns", True))
default_scan_limit = int(policy.get("scan_limit", 200))
default_schedule_name = str(policy.get("schedule_name", "daily"))
default_schedule_window = int(policy.get("schedule_window_minutes", 1440))
default_alert_enabled = bool(policy.get("alert_enabled", False))
default_alert_max_dedupe = float(policy.get("alert_max_dedupe_hit_rate", 0.7))
default_alert_min_exec = float(policy.get("alert_min_execution_rate", 0.5))
default_alert_cooldown = int(policy.get("alert_cooldown_minutes", 60))

cd_enabled = st.checkbox("Policy enabled", value=default_enabled)
cd_min_drift = st.selectbox("Policy min drift", ["warning", "breaking", "invalid"], index=["warning", "breaking", "invalid"].index(default_min_drift) if default_min_drift in {"warning", "breaking", "invalid"} else 1)
cd_promote = st.checkbox("Promote to patterns", value=default_promote)
cd_scan_limit = st.number_input("Policy scan limit", min_value=1, max_value=1000, value=default_scan_limit, step=1)
cd_schedule_name = st.text_input("Policy schedule name", value=default_schedule_name)
cd_schedule_window = st.number_input("Policy schedule window (minutes)", min_value=5, max_value=10080, value=default_schedule_window, step=5)
cd_alert_enabled = st.checkbox("Alert enabled", value=default_alert_enabled)
cd_alert_max_dedupe = st.slider(
    "Alert max dedupe hit rate",
    min_value=0.0,
    max_value=1.0,
    value=float(default_alert_max_dedupe),
    step=0.01,
)
cd_alert_min_exec = st.slider(
    "Alert min execution rate",
    min_value=0.0,
    max_value=1.0,
    value=float(default_alert_min_exec),
    step=0.01,
)
cd_alert_cooldown = st.number_input(
    "Alert cooldown (minutes)",
    min_value=0,
    max_value=10080,
    value=default_alert_cooldown,
    step=5,
)

c_cd3, c_cd4 = st.columns(2)
with c_cd3:
    if st.button("Save Drift Policy"):
        if not effective_admin_key:
            st.error("Admin API key (or API key) is required.")
        else:
            payload = {
                "org_id": org_id,
                "enabled": bool(cd_enabled),
                "min_drift": cd_min_drift,
                "promote_to_patterns": bool(cd_promote),
                "scan_limit": int(cd_scan_limit),
                "schedule_name": cd_schedule_name.strip() or "daily",
                "schedule_window_minutes": int(cd_schedule_window),
                "alert_enabled": bool(cd_alert_enabled),
                "alert_max_dedupe_hit_rate": float(cd_alert_max_dedupe),
                "alert_min_execution_rate": float(cd_alert_min_exec),
                "alert_cooldown_minutes": int(cd_alert_cooldown),
            }
            resp = api_call(base_url, effective_admin_key, "POST", "/api/system/contracts/drift-policy", payload=payload)
            if resp.get("ok"):
                st.session_state["contract_drift_policy"] = resp.get("data", {})
                st.success("Drift policy saved.")
            else:
                st.error(resp.get("error", {}).get("message", "Failed to save drift policy"))
with c_cd4:
    trigger_force = st.checkbox("Trigger force", value=False)
    trigger_dry_run = st.checkbox("Trigger dry run", value=False)
    if st.button("Trigger Drift Policy Run"):
        if not effective_admin_key:
            st.error("Admin API key (or API key) is required.")
        else:
            idempotency_key = f"streamlit-contract-drift-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
            payload = {
                "org_id": org_id,
                "schedule_name": cd_schedule_name.strip() or "manual",
                "window_minutes": int(cd_schedule_window),
                "dry_run": bool(trigger_dry_run),
                "force": bool(trigger_force),
            }
            resp = api_call(
                base_url,
                effective_admin_key,
                "POST",
                "/api/system/contracts/drift/trigger",
                payload=payload,
                extra_headers={"Idempotency-Key": idempotency_key},
            )
            if resp.get("ok"):
                st.session_state["contract_drift_trigger"] = resp.get("data", {})
                st.success("Drift trigger executed.")
            else:
                st.error(resp.get("error", {}).get("message", "Failed to trigger drift policy run"))

c_cd5, c_cd6 = st.columns(2)
with c_cd5:
    drift_alert_dry_run = st.checkbox("Drift alert dry run", value=True)
    drift_alert_force = st.checkbox("Drift alert force notify", value=False)
    if st.button("Notify Drift Trigger Summary"):
        if not effective_admin_key:
            st.error("Admin API key (or API key) is required.")
        else:
            idempotency_key = f"streamlit-contract-drift-notify-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
            payload = {
                "org_id": org_id,
                "schedule_name": cd_schedule_name.strip() or "daily",
                "window_days": 30,
                "dry_run": bool(drift_alert_dry_run),
                "force_notify": bool(drift_alert_force),
            }
            resp = api_call(
                base_url,
                effective_admin_key,
                "POST",
                "/api/system/contracts/drift/trigger-summary/notify",
                payload=payload,
                extra_headers={"Idempotency-Key": idempotency_key},
            )
            if resp.get("ok"):
                st.session_state["contract_drift_trigger_notify"] = resp.get("data", {})
                st.success("Drift trigger summary notify handled.")
            else:
                st.error(resp.get("error", {}).get("message", "Failed to notify drift trigger summary"))
with c_cd6:
    if st.button("Load Drift Alert Delivery"):
        if not effective_admin_key:
            st.error("Admin API key (or API key) is required.")
        else:
            query = parse.urlencode({"org_id": org_id, "schedule_name": cd_schedule_name.strip() or "daily", "window_days": 30})
            resp = api_call(base_url, effective_admin_key, "GET", f"/api/system/contracts/drift/trigger-alert-delivery?{query}")
            if resp.get("ok"):
                st.session_state["contract_drift_trigger_alert_delivery"] = resp.get("data", {})
            else:
                st.error(resp.get("error", {}).get("message", "Failed to load drift alert delivery"))

c_cd7, c_cd8 = st.columns(2)
with c_cd7:
    schedule_run_dry = st.checkbox("Schedule run dry run", value=True)
    schedule_run_force = st.checkbox("Schedule run force trigger", value=False)
    schedule_run_force_notify = st.checkbox("Schedule run force notify", value=False)
    if st.button("Run Drift Schedule Cycle"):
        if not effective_admin_key:
            st.error("Admin API key (or API key) is required.")
        else:
            idempotency_key = f"streamlit-contract-drift-schedule-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
            payload = {
                "org_id": org_id,
                "schedule_name": cd_schedule_name.strip() or "daily",
                "window_minutes": int(cd_schedule_window),
                "summary_window_days": 30,
                "dry_run": bool(schedule_run_dry),
                "force": bool(schedule_run_force),
                "force_notify": bool(schedule_run_force_notify),
            }
            resp = api_call(
                base_url,
                effective_admin_key,
                "POST",
                "/api/system/contracts/drift/schedule-run",
                payload=payload,
                extra_headers={"Idempotency-Key": idempotency_key},
            )
            if resp.get("ok"):
                st.session_state["contract_drift_schedule_run"] = resp.get("data", {})
                st.success("Drift schedule cycle executed.")
            else:
                st.error(resp.get("error", {}).get("message", "Failed to run drift schedule cycle"))
with c_cd8:
    st.caption("Runs trigger + anomaly notify in one call.")

trigger_data = st.session_state.get("contract_drift_trigger")
if trigger_data:
    t1, t2, t3, t4 = st.columns(4)
    t1.metric("Executed", "YES" if bool(trigger_data.get("executed")) else "NO")
    t2.metric("Deduped", "YES" if bool(trigger_data.get("deduped")) else "NO")
    t3.metric("Policy Enabled", "YES" if bool(trigger_data.get("policy_enabled")) else "NO")
    t4.metric("Min Drift", str(trigger_data.get("min_drift", "n/a")).upper())
    promote_result = trigger_data.get("promote_result") or {}
    if promote_result:
        p1, p2, p3 = st.columns(3)
        p1.metric("Eligible", int(promote_result.get("eligible_item_count", 0)))
        p2.metric("Created", int(promote_result.get("created_pattern_count", 0)))
        p3.metric("Reused", int(promote_result.get("reused_pattern_count", 0)))
    with st.expander("Drift Trigger Details"):
        st.json(trigger_data)

trigger_summary = st.session_state.get("contract_drift_trigger_summary")
if trigger_summary:
    s1, s2, s3, s4, s5 = st.columns(5)
    s1.metric("Triggers", int(trigger_summary.get("trigger_count", 0)))
    s2.metric("Executed", int(trigger_summary.get("executed_count", 0)))
    s3.metric("Deduped", int(trigger_summary.get("deduped_count", 0)))
    s4.metric("Policy Disabled", int(trigger_summary.get("policy_disabled_count", 0)))
    s5.metric("Promotion Disabled", int(trigger_summary.get("promotion_disabled_count", 0)))
    st.caption(
        f"Execution rate={float(trigger_summary.get('execution_rate', 0.0)):.2f} | "
        f"Dedupe hit rate={float(trigger_summary.get('dedupe_hit_rate', 0.0)):.2f}"
    )
    summary_items = trigger_summary.get("items") or []
    if summary_items:
        st.dataframe(pd.DataFrame(summary_items), use_container_width=True)
    with st.expander("Trigger Summary Details"):
        st.json(trigger_summary)

trigger_notify = st.session_state.get("contract_drift_trigger_notify")
if trigger_notify:
    n1, n2, n3 = st.columns(3)
    n1.metric("Drift Anomaly", "YES" if bool(trigger_notify.get("anomaly_detected")) else "NO")
    n2.metric("Notified", "YES" if bool(trigger_notify.get("notified")) else "NO")
    n3.metric("Dry Run", "YES" if bool(trigger_notify.get("dry_run")) else "NO")
    notify_result = trigger_notify.get("notification") or {}
    if notify_result.get("sent"):
        st.success("Drift trigger alert sent.")
    elif notify_result.get("suppressed"):
        st.info("Drift trigger alert suppressed by cooldown.")
    with st.expander("Drift Trigger Notify Details"):
        st.json(trigger_notify)

trigger_alert_delivery = st.session_state.get("contract_drift_trigger_alert_delivery")
if trigger_alert_delivery:
    d1, d2, d3, d4, d5, d6 = st.columns(6)
    d1.metric("Notify Events", int(trigger_alert_delivery.get("total_notify_events", 0)))
    d2.metric("Sent", int(trigger_alert_delivery.get("sent_count", 0)))
    d3.metric("Failed", int(trigger_alert_delivery.get("failed_count", 0)))
    d4.metric("Suppressed", int(trigger_alert_delivery.get("suppressed_count", 0)))
    d5.metric("Skipped", int(trigger_alert_delivery.get("skipped_count", 0)))
    d6.metric("Dry Runs", int(trigger_alert_delivery.get("dry_run_count", 0)))
    with st.expander("Drift Alert Delivery Details"):
        st.json(trigger_alert_delivery)

schedule_run_data = st.session_state.get("contract_drift_schedule_run")
if schedule_run_data:
    sr1, sr2, sr3 = st.columns(3)
    sr1.metric("Schedule Triggered", "YES" if bool(schedule_run_data.get("trigger", {}).get("executed")) else "NO")
    sr2.metric("Anomaly", "YES" if bool(schedule_run_data.get("notify", {}).get("anomaly_detected")) else "NO")
    sr3.metric("Notified", "YES" if bool(schedule_run_data.get("notify", {}).get("notified")) else "NO")
    with st.expander("Drift Schedule Run Details"):
        st.json(schedule_run_data)

st.subheader("16) Activity Feed")
feed_source = st.radio("Feed Source", ["Session", "Server"], horizontal=True)
c_feed_a, c_feed_b, c_feed_c = st.columns([1, 1, 4])
with c_feed_a:
    if st.button("Clear Feed"):
        st.session_state["activity_events"] = []
with c_feed_b:
    if st.button("Load Server Feed"):
        resp = api_call(base_url, api_key, "GET", f"/api/agents/{selected_agent_id}/activity?limit=100")
        if resp.get("ok"):
            st.session_state["server_activity_events"] = resp.get("data", {}).get("items", [])
        else:
            st.error(resp.get("error", {}).get("message", "Failed to load server activity feed"))
with c_feed_c:
    st.caption("Recent regressions, pattern transitions, and notification events.")

if feed_source == "Session":
    feed_items = st.session_state.get("activity_events", [])
else:
    feed_items = st.session_state.get("server_activity_events", [])

if feed_items:
    feed_df = pd.DataFrame(feed_items)
    sort_col = "at" if "at" in feed_df.columns else ("created_at" if "created_at" in feed_df.columns else None)
    if sort_col:
        feed_df = feed_df.sort_values(sort_col, ascending=False).reset_index(drop=True)

    if "severity" in feed_df.columns:
        def _severity_badge(value: Any) -> str:
            v = str(value or "").lower()
            color = {"error": "#dc2626", "warning": "#d97706", "info": "#2563eb"}.get(v, "#6b7280")
            return f"<span style='display:inline-block;padding:2px 8px;border-radius:999px;background:{color};color:white;font-weight:600'>{v or 'n/a'}</span>"

        feed_df["severity_badge"] = feed_df["severity"].apply(_severity_badge)

    display_cols = [c for c in ["created_at", "at", "severity", "event_type", "title", "details"] if c in feed_df.columns]
    if "severity_badge" in feed_df.columns and "severity" in display_cols:
        display_df = feed_df[display_cols].copy()
        display_df["severity"] = feed_df["severity_badge"]
        st.write(display_df.to_html(escape=False, index=False), unsafe_allow_html=True)
    else:
        st.dataframe(feed_df[display_cols], use_container_width=True)

    if feed_source == "Server":
        st.markdown("**Server Event Detail**")
        event_labels = [
            f"{idx}: {row.get('event_type', 'event')} ({str(row.get('created_at', ''))[:19]})"
            for idx, row in feed_df.iterrows()
        ]
        selected_event_label = st.selectbox("Select event", event_labels)
        selected_idx = int(selected_event_label.split(":")[0])
        selected = feed_df.iloc[selected_idx].to_dict()
        st.write(f"**Title:** {selected.get('title')}")
        st.write(f"**Severity:** {selected.get('severity')}")
        st.write(f"**Details:** {selected.get('details')}")
        st.write("**Metadata:**")
        raw_meta = selected.get("metadata")
        if isinstance(raw_meta, str):
            try:
                raw_meta = json.loads(raw_meta)
            except Exception:
                pass
        st.json(raw_meta if raw_meta is not None else {})
else:
    st.info("No activity events yet. Run compare or update a pattern to populate the feed.")
