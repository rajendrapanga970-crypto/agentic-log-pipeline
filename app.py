"""
Agentic Log Pipeline — Streamlit Dashboard
Auto-connects to agents API and Qdrant
"""

import os
import time
import requests
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from datetime import datetime

AGENTS_HOST = os.getenv("AGENTS_HOST", "agents")
AGENTS_PORT = os.getenv("AGENTS_PORT", "8000")
AGENTS_URL  = f"http://{AGENTS_HOST}:{AGENTS_PORT}"

st.set_page_config(
    page_title="Agentic Log Pipeline",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ─── Custom CSS ───────────────────────────────────────────────────────────────
st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;700;800&display=swap');
  html, body, [class*="css"] { font-family: 'Syne', sans-serif; }
  .metric-card {
    background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
    border: 1px solid #334155; border-radius: 12px;
    padding: 1.2rem 1.5rem; margin-bottom: 0.5rem;
  }
  .metric-value { font-size: 2.5rem; font-weight: 800; font-family: 'JetBrains Mono', monospace; }
  .metric-label { color: #94a3b8; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.1em; }
  .log-row { font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; }
  .badge-malicious { background: #450a0a; color: #fca5a5; padding: 2px 8px; border-radius: 4px; }
  .badge-deny      { background: #431407; color: #fdba74; padding: 2px 8px; border-radius: 4px; }
  .badge-allowed   { background: #052e16; color: #86efac; padding: 2px 8px; border-radius: 4px; }
  .stApp { background: #020617; color: #e2e8f0; }
</style>
""", unsafe_allow_html=True)

# ─── Sidebar ─────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ Log Pipeline")
    st.markdown("---")
    auto_refresh = st.toggle("Auto-refresh (10s)", value=False)
    if st.button("🔄 Refresh Now"):
        st.rerun()
    st.markdown("---")
    st.markdown("### Query Logs (RAG)")
    query = st.text_area("Ask about logs...", placeholder="Any SQL injection attempts?")
    if st.button("🔍 Search"):
        st.session_state["run_query"] = query
    st.markdown("---")
    st.markdown("### Test Agent")
    test_log = st.text_input("Log message", "Failed login attempt from 10.0.0.1")
    test_level = st.selectbox("Level", ["INFO", "WARN", "ERROR", "CRITICAL"])
    if st.button("⚡ Classify"):
        st.session_state["run_classify"] = {"message": test_log, "level": test_level}

# ─── Helpers ─────────────────────────────────────────────────────────────────
def api(path, method="get", json=None):
    try:
        fn = requests.get if method == "get" else requests.post
        r = fn(f"{AGENTS_URL}{path}", json=json, timeout=10)
        return r.json()
    except Exception as e:
        return {"error": str(e)}

# ─── Main content ─────────────────────────────────────────────────────────────
st.markdown("# 🛡️ Agentic Log Pipeline Dashboard")
st.markdown(f"*Last updated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}*")

# Stats
stats = api("/stats")
if "error" in stats:
    st.warning(f"⚠️ Agents service not reachable: {stats['error']}")
    st.info("Make sure the full stack is running: `docker compose up --build`")
else:
    cols = st.columns(4)
    with cols[0]:
        st.markdown(f"""<div class="metric-card">
          <div class="metric-value" style="color:#60a5fa">{stats.get('total_logs',0)}</div>
          <div class="metric-label">Total Logs</div></div>""", unsafe_allow_html=True)
    with cols[1]:
        st.markdown(f"""<div class="metric-card">
          <div class="metric-value" style="color:#f87171">{stats.get('malicious',0)}</div>
          <div class="metric-label">🔴 Malicious</div></div>""", unsafe_allow_html=True)
    with cols[2]:
        st.markdown(f"""<div class="metric-card">
          <div class="metric-value" style="color:#fb923c">{stats.get('deny',0)}</div>
          <div class="metric-label">🟠 Deny/Error</div></div>""", unsafe_allow_html=True)
    with cols[3]:
        st.markdown(f"""<div class="metric-card">
          <div class="metric-value" style="color:#4ade80">{stats.get('allowed',0)}</div>
          <div class="metric-label">🟢 Allowed</div></div>""", unsafe_allow_html=True)

    # Charts
    col_a, col_b = st.columns(2)
    with col_a:
        fig = go.Figure(go.Pie(
            labels=["Malicious", "Deny", "Allowed"],
            values=[stats.get("malicious",1), stats.get("deny",1), stats.get("allowed",1)],
            hole=0.6,
            marker=dict(colors=["#ef4444","#f97316","#22c55e"]),
        ))
        fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                          font_color="#e2e8f0", title="Log Classification")
        st.plotly_chart(fig, use_container_width=True)
    with col_b:
        st.markdown("### Pipeline Architecture")
        st.markdown("""
        | Layer | Component | Status |
        |-------|-----------|--------|
        | 7 | Streamlit Dashboard | ✅ Running |
        | 6 | n8n Orchestration | 🔄 Auto-configured |
        | 5 | LangGraph Agents | ✅ Running |
        | 4 | Ollama (Mistral) | 🔄 Pulling model |
        | 3 | Qdrant Vector DB | ✅ Running |
        | 2 | Apache NiFi | 🔄 Auto-configured |
        | 1 | Docker Infrastructure | ✅ Running |
        """)

# Recent Logs
st.markdown("---")
st.markdown("### 📋 Recent Log Events")
logs_resp = api("/logs/recent?limit=20")
if "logs" in logs_resp and logs_resp["logs"]:
    rows = []
    for l in logs_resp["logs"]:
        cls = l.get("classification","allowed")
        badge = f'<span class="badge-{cls}">{cls}</span>'
        rows.append({
            "Time": l.get("timestamp","")[:19],
            "Level": l.get("level",""),
            "Source": l.get("source",""),
            "Message": l.get("message","")[:80],
            "Classification": cls,
        })
    df = pd.DataFrame(rows)
    st.dataframe(df, use_container_width=True, hide_index=True,
                 column_config={"Classification": st.column_config.TextColumn(width="medium")})

# RAG Query result
if "run_query" in st.session_state and st.session_state["run_query"]:
    st.markdown("---")
    st.markdown("### 🔍 RAG Query Result")
    with st.spinner("Searching logs..."):
        result = api("/query", method="post", json={"query": st.session_state["run_query"]})
    if "answer" in result:
        st.success(result["answer"])
        with st.expander("Source logs"):
            for s in result.get("sources", []):
                st.code(s.get("text",""), language="text")
    st.session_state["run_query"] = None

# Classify test
if "run_classify" in st.session_state and st.session_state["run_classify"]:
    st.markdown("---")
    st.markdown("### ⚡ Classification Result")
    data = st.session_state["run_classify"]
    with st.spinner("Classifying..."):
        result = api("/agent/classify", method="post",
                     json={"log_data": f'{{"level":"{data["level"]}","message":"{data["message"]}"}}'})
    if "classification" in result:
        cls = result["classification"]
        color = {"malicious":"🔴","deny":"🟠","allowed":"🟢"}.get(cls,"⚪")
        st.markdown(f"**{color} {cls.upper()}** — {result.get('explanation','')}")
    st.session_state["run_classify"] = None

# Auto-refresh
if auto_refresh:
    time.sleep(10)
    st.rerun()
