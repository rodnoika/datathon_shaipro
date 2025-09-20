import os
import pandas as pd
import streamlit as st
from datetime import datetime, timezone
from detector import run_detection
from chat import intent_to_filter
from storage import load_blocklist, block_ip, filter_by_time

st.set_page_config(page_title="Shai.pro MVP", layout="wide")
st.title("Shai.pro — DevSecOps AI Assistant (MVP)")

DATA_PATH = st.sidebar.text_input("CSV logs path", value="data/sample_logs.csv")
window_minutes = st.sidebar.slider("Rolling window (minutes)", 1, 15, 5)
fail_threshold = st.sidebar.slider("Fail threshold (rule)", 3, 50, 10)
contamination = st.sidebar.slider("IF contamination", 0.01, 0.2, 0.02, step=0.01)

st.sidebar.markdown("---")
st.sidebar.write("**Blocklist**")
blocked = load_blocklist()
st.sidebar.code("\\n".join(sorted(blocked)) or "(empty)")

logs, findings, incidents = run_detection(DATA_PATH, window_minutes, fail_threshold, contamination)

incidents_view = incidents[~incidents["src_ip"].isin(blocked)].copy()

tab1, tab2, tab3 = st.tabs(["📊 Dashboard", "💬 Chat", "⚙️ Incidents"])

with tab1:
    col1, col2 = st.columns([2,1], gap="large")
    with col1:
        st.subheader("Top suspicious IPs")
        st.dataframe(incidents_view, use_container_width=True)
    with col2:
        st.subheader("Actions")
        ip_to_block = st.selectbox("Block IP", [""] + incidents_view["src_ip"].tolist())
        if st.button("🚫 Block IP"):
            if ip_to_block:
                block_ip(ip_to_block)
                st.success(f"IP {ip_to_block} added to blocklist (simulation). Refresh to update views.")
        st.caption("Blocking is simulated: the IP disappears from tables but no real firewall changes are made.")

with tab2:
    st.subheader("Ask in natural language")
    user_q = st.text_input("Например: 'покажи все неудачные логины за час'")
    if st.button("Ask"):
        if not user_q.strip():
            st.warning("Введите запрос.")
        else:
            filt = intent_to_filter(user_q)
            st.write("Parsed filter:", filt)
            logs["timestamp"] = pd.to_datetime(logs["timestamp"], utc=True)
            sub = logs.copy()
            if filt["start"] and filt["end"]:
                sub = sub[(sub["timestamp"] >= filt["start"]) & (sub["timestamp"] <= filt["end"])]
            if filt["event"]:
                sub = sub[sub["event"] == filt["event"]]
            if filt["status"]:
                sub = sub[sub["status"] == filt["status"]]
            st.write(f"Found {len(sub)} events")
            st.dataframe(sub.head(200), use_container_width=True)

with tab3:
    st.subheader("Minute-level findings")
    st.dataframe(findings.head(500), use_container_width=True)

st.markdown("---")
st.caption("MVP demo: rules + Isolation Forest for anomalies, simple NL parsing instead of a full LLM. Replace 'intent_to_filter' with an LLM call for production.")
