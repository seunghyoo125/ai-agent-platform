from __future__ import annotations

import json
from typing import Any, Dict, Optional
from urllib import error, parse, request

import pandas as pd
import streamlit as st

st.set_page_config(page_title="ai-agent-platform", layout="wide")


def api_call(
    base_url: str,
    api_key: str,
    method: str,
    path: str,
    payload: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    url = f"{base_url.rstrip('/')}{path}"
    body = None
    headers = {"Authorization": f"Bearer {api_key}"}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

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


st.title("ai-agent-platform")

st.sidebar.header("API Connection")
base_url = st.sidebar.text_input("Base URL", value="http://127.0.0.1:8001")
api_key = st.sidebar.text_input("API Key", type="password")
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

c_load_gs, c_load_latest = st.columns(2)
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
            else:
                st.session_state["latest_run_id"] = None
        else:
            st.error(resp.get("error", {}).get("message", "Failed to load latest run"))

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
                "name": run_name,
                "type": "eval",
                "config": run_config,
                "design_context": {"reason": "streamlit-ui"},
            }
            resp = api_call(base_url, api_key, "POST", "/api/eval/runs", payload=payload)
            if resp.get("ok"):
                st.session_state["latest_run_id"] = resp["data"]["run_id"]
                st.success(f"Created run: {resp['data']['run_id']}")
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
        with st.expander("Run Config"):
            st.json(run_data.get("config") or {})
    else:
        st.error(summary_resp.get("error", {}).get("message", "Failed to load summary"))

    st.subheader("6) Result Details")
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
else:
    st.info("Create or load a run to view summary and results.")

st.subheader("7) Calibration")
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
