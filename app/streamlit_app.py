from __future__ import annotations

import json
from typing import Any, Dict

import pandas as pd
import streamlit as st

st.set_page_config(page_title="ai-agent-platform", layout="wide")


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def cases_df(run: Dict[str, Any]) -> pd.DataFrame:
    rows = []
    for c in run.get("cases", []):
        tags = c.get("tags", {}) or {}
        rows.append(
            {
                "id": c.get("id"),
                "overall": c.get("overall"),
                "capability": tags.get("capability"),
                "difficulty": tags.get("difficulty"),
                "test_type": tags.get("test_type"),
                "behavior": ", ".join(tags.get("behavior") or []),
                "answer_correct": c.get("rubric", {}).get("answer_correct"),
                "sources_correct": c.get("rubric", {}).get("sources_correct"),
                "response_appropriate": c.get("rubric", {}).get("response_appropriate"),
                "prompt": c.get("prompt"),
                "generated": c.get("generated"),
            }
        )
    return pd.DataFrame(rows)


st.title("ai-agent-platform")

st.sidebar.header("Load evaluation artifacts")
run_a_path = st.sidebar.text_input("Run A JSON path", value="output/run_a.json")
run_b_path = st.sidebar.text_input("Run B JSON path (optional)", value="output/run_b.json")

if st.sidebar.button("Load"):
    run_a = load_json(run_a_path)
    df_a = cases_df(run_a)
    st.session_state["run_a"] = run_a
    st.session_state["df_a"] = df_a

    if run_b_path.strip():
        run_b = load_json(run_b_path)
        df_b = cases_df(run_b)
        st.session_state["run_b"] = run_b
        st.session_state["df_b"] = df_b
    else:
        st.session_state.pop("run_b", None)
        st.session_state.pop("df_b", None)

if "df_a" not in st.session_state:
    st.info("Load a run artifact to begin.")
    st.stop()

run_a = st.session_state["run_a"]
df_a = st.session_state["df_a"]

summary = run_a.get("summary", {})

c1, c2, c3 = st.columns(3)
c1.metric("Total cases", summary.get("total", 0))
c2.metric("Strict pass rate", f"{summary.get('pass_rate_strict', 0.0):.2%}")
c3.metric("Lenient pass rate", f"{summary.get('pass_rate_lenient', 0.0):.2%}")

st.subheader("Cases")
st.dataframe(
    df_a[["id", "overall", "capability", "difficulty", "test_type", "behavior"]],
    use_container_width=True,
)

st.subheader("Case detail")
selected = st.selectbox("Select case id", list(df_a["id"].values))
row_a = df_a[df_a["id"] == selected].iloc[0]

st.markdown("**Prompt**")
st.code(row_a["prompt"] or "", language="text")

st.markdown("**Generated (Run A)**")
st.code(row_a["generated"] or "", language="text")

if "df_b" in st.session_state:
    df_b = st.session_state["df_b"]
    row_b = df_b[df_b["id"] == selected].iloc[0]

    st.markdown("**Generated (Run B)**")
    st.code(row_b["generated"] or "", language="text")

    st.markdown(f"**Overall change:** {row_a['overall']} → {row_b['overall']}")
