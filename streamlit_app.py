import os
import pandas as pd
import streamlit as st
from datetime import datetime, timezone
from detector import run_detection
from chat import intent_to_filter
from storage import load_blocklist, block_ip, filter_by_time
from forecast import build_series, simple_linear_forecast
import altair as alt

st.set_page_config(page_title="Shai.pro MVP", layout="wide")
st.title("Shai.pro — DevSecOps AI Assistant (MVP)")
st.sidebar.title("Log Source")
log_source = st.sidebar.selectbox(
    "Выбери источник логов",
    ["SSH Logs (sample_logs.csv)", "Firewall Logs (firewall_logs.csv)"]
)

if log_source.startswith("SSH"):
    DATA_PATH = "data/sample_logs.csv"
    log_type = "ssh"
else:
    DATA_PATH = "data/firewall_logs.csv"
    log_type = "firewall"

st.sidebar.write("CSV logs path:", DATA_PATH)
window_minutes = st.sidebar.slider("Rolling window (minutes)", 1, 15, 5)
fail_threshold = st.sidebar.slider("Fail threshold (rule)", 3, 50, 10)
contamination = st.sidebar.slider("IF contamination", 0.01, 0.2, 0.02, step=0.01)

st.sidebar.markdown("---")
st.sidebar.write("**Blocklist**")
blocked = load_blocklist()
st.sidebar.code("\\n".join(sorted(blocked)) or "(empty)")

logs, findings, incidents = run_detection(
    DATA_PATH, window_minutes, fail_threshold, contamination, log_type=log_type
)

incidents_view = incidents[~incidents["src_ip"].isin(blocked)].copy()

tab1, tab2, tab3 = st.tabs(["📊 Dashboard", "💬 Chat", "⚙️ Incidents"])

with tab1:
    if log_type == "ssh":
        col1, col2 = st.columns([2,1], gap="large")
        with col1:
            st.subheader("Top suspicious IPs (with risk & severity)")
            st.dataframe(incidents_view, use_container_width=True)

            st.markdown("**Anomaly timeline (fails/min & anomalies)**")
            if not findings.empty:
                series_df = build_series(findings, window_minutes)
                st.line_chart(series_df.set_index("minute")[["fails_per_min"]])
                st.bar_chart(series_df.set_index("minute")[["anomalies"]])
            else:
                st.info("Нет minute-level данных для визуализации.")

            st.markdown("**Forecast (next 60 min)**")
            if not findings.empty:
                fdf = simple_linear_forecast(build_series(findings, window_minutes), horizon_minutes=60)
                if not fdf.empty:
                    st.line_chart(fdf.set_index("minute"))
                else:
                    st.caption("Недостаточно данных для прогноза.")
        with col2:
            st.subheader("Actions")
            ip_to_block = st.selectbox("Block IP", [""] + incidents_view["src_ip"].astype(str).tolist())
            if st.button("🚫 Block IP"):
                if ip_to_block:
                    block_ip(ip_to_block)
                    st.success(f"IP {ip_to_block} added to blocklist (simulation). Refresh to update views.")
            st.caption("Blocking is simulated: the IP disappears from tables but no real firewall changes are made.")

            fw_path = "data/firewall_logs.csv"
            if os.path.exists(fw_path):
                try:
                    fw = pd.read_csv(fw_path)
                    fw["timestamp"] = pd.to_datetime(fw["timestamp"], utc=True)
                    fw_denies = fw[fw["action"].astype(str).str.lower() == "deny"]
                    fw_counts = fw_denies.groupby("src_ip").size().reset_index(name="fw_denies")
                    corr = incidents_view.merge(fw_counts, on="src_ip", how="left").fillna({"fw_denies":0})
                    corr["corr_boosted_severity"] = corr.apply(
                        lambda r: "High" if (r.get("severity","Low") in ["Medium","High"] and r["fw_denies"]>0) else r.get("severity","Low"),
                        axis=1
                    )
                    st.subheader("Cross-source correlation (SSH × Firewall)")
                    st.dataframe(corr[["src_ip","risk","severity","fw_denies","corr_boosted_severity"]], use_container_width=True)
                except Exception as e:
                    st.caption(f"Correlation skipped: {e}")
    else:
        st.subheader("Firewall Events Overview")
        st.dataframe(logs.head(50), use_container_width=True)

        blocked = logs[logs.get("action","").astype(str).str.lower() == "deny"]
        if not blocked.empty:
            top_blocked = blocked["src_ip"].value_counts().head(5).reset_index()
            top_blocked.columns = ["src_ip","denies"]
            st.write("Топ IP по блокировкам:")
            st.bar_chart(top_blocked.set_index("src_ip"))
        else:
            st.info("Нет deny-событий в текущем файле.")
with tab2:
    st.subheader("Ask in natural language")

    if log_type == "ssh":
        user_q = st.text_input(
            "Например: 'самый частый юзер который неудачно логинился за час' / 'топ 5 ip с неудачными входами за 5 минут' / 'сколько неудачных логинов за день'"
        )
        if st.button("Ask", key="ask_ssh"):
            if not user_q.strip():
                st.warning("Введите запрос.")
            else:
                from chat import intent_to_query  
                intent = intent_to_query(user_q)
                st.write("Parsed intent:", {
                    "start": intent["start"].isoformat(),
                    "end": intent["end"].isoformat(),
                    "event": intent["event"],
                    "status": intent["status"],
                    "op": intent["op"],
                    "limit": intent["limit"],
                })

                logs["timestamp"] = pd.to_datetime(logs["timestamp"], utc=True)
                sub = logs[(logs["timestamp"] >= intent["start"]) & (logs["timestamp"] <= intent["end"])].copy()

                if intent.get("event") and "event" in sub.columns:
                    sub = sub[sub["event"] == intent["event"]]
                if intent.get("status") and "status" in sub.columns:
                    sub = sub[sub["status"] == intent["status"]]

                if sub.empty:
                    sub = logs[(logs["timestamp"] >= intent["end"] - pd.Timedelta(days=1)) & (logs["timestamp"] <= intent["end"])].copy()
                    if intent.get("event") and "event" in sub.columns:
                        sub = sub[sub["event"] == intent["event"]]
                    if intent.get("status") and "status" in sub.columns:
                        sub = sub[sub["status"] == intent["status"]]
                    st.caption("Ничего не нашли за выбранный период. Показаны данные за последние 24 часа.")

                op = intent["op"]; limit = intent["limit"]
                if sub.empty:
                    st.info("Нет событий под запрос.")
                else:
                    if op == "top_users":
                        ans = (sub.groupby("user").size().reset_index(name="events")
                               .sort_values("events", ascending=False).head(limit))
                        st.write(f"Топ {len(ans)} пользователей:")
                        st.dataframe(ans, use_container_width=True)
                    elif op == "top_ips":
                        ans = (sub.groupby("src_ip").size().reset_index(name="events")
                               .sort_values("events", ascending=False).head(limit))
                        st.write(f"Топ {len(ans)} IP-адресов:")
                        st.dataframe(ans, use_container_width=True)
                    elif op == "count":
                        st.write(f"Количество событий: **{len(sub)}**")
                    else:
                        st.write(f"Найдено {len(sub)} событий (первые 200):")
                        st.dataframe(sub.head(200), use_container_width=True)

    else:
        user_q_fw = st.text_input(
            "Firewall: например 'топ 10 IP по deny за день' / 'сколько deny за 5 минут' / 'покажи deny за час'"
        )
        if st.button("Ask", key="ask_fw"):
            if not user_q_fw.strip():
                st.warning("Введите запрос.")
            else:
                q = user_q_fw.lower()
                from datetime import timedelta
                now = datetime.now(timezone.utc)
                if "за 5 минут" in q or "за пять минут" in q:
                    start, end = now - timedelta(minutes=5), now
                elif "за день" in q or "сегодня" in q:
                    start, end = now - timedelta(days=1), now
                elif "за час" in q or "последний час" in q:
                    start, end = now - timedelta(hours=1), now
                else:
                    start, end = now - timedelta(hours=1), now

                limit = 10
                import re
                m = re.search(r"\b(\d{1,3})\b", q)
                if m:
                    try:
                        limit = max(1, min(1000, int(m.group(1))))
                    except:
                        pass
                if "топ" in q or "самый частый" in q:
                    op = "top_ips"
                elif "сколько" in q or "количеств" in q or "count" in q:
                    op = "count"
                else:
                    op = "list"

                logs["timestamp"] = pd.to_datetime(logs["timestamp"], utc=True)
                sub = logs[(logs["timestamp"] >= start) & (logs["timestamp"] <= end)].copy()

                if "deny" in q or "заблок" in q or "блок" in q:
                    if "action" in sub.columns:
                        sub = sub[sub["action"].astype(str).str.lower() == "deny"]

                if sub.empty:
                    st.info("Нет событий под запрос.")
                else:
                    if op == "top_ips":
                        ans = (sub.groupby("src_ip").size().reset_index(name="events")
                               .sort_values("events", ascending=False).head(limit))
                        st.write(f"Топ {len(ans)} IP по событиям (в т.ч. deny, если указан):")
                        st.dataframe(ans, use_container_width=True)
                    elif op == "count":
                        st.write(f"Количество событий: **{len(sub)}**")
                    else:
                        st.write(f"Найдено {len(sub)} событий (первые 200):")
                        st.dataframe(sub.head(200), use_container_width=True)
with tab3:
    if log_type == "ssh":
        st.subheader("Minute-level findings")
        st.dataframe(findings.head(500), use_container_width=True)
    else:
        st.subheader("Firewall incidents (top denied sources)")
        st.dataframe(incidents.head(50), use_container_width=True)



st.markdown("---")
st.caption("MVP demo: rules + Isolation Forest for anomalies, simple NL parsing instead of a full LLM. Replace 'intent_to_filter' with an LLM call for production.")
