# dashboard/app.py

import streamlit as st
import pandas as pd
import os

st.set_page_config(page_title="Threat Detection Dashboard", layout="wide")
st.title("🛡️ Threat Detection Suite Dashboard")

with st.sidebar:
    st.markdown("### 📊 Navigation")
    selected = st.radio("Choose a View:", [
        "🔌 Port Scan Results",
        "🌐 Web Scan Results",
        "🚨 Intrusion Alerts"
    ])

def load_data(filepath, columns=None):
    if not os.path.exists(filepath):
        st.warning(f"⚠️ No data found at `{filepath}`.")
        return pd.DataFrame()

    return pd.read_csv(filepath, names=columns) if columns else pd.read_csv(filepath)

# Port Scanner View
if selected == "🔌 Port Scan Results":
    st.subheader("🔍 TCP Port Scanner Logs")
    df = load_data("logs/port_scan_results.csv")

    if not df.empty:
        df = df.sort_values(by="Timestamp", ascending=False)
        st.dataframe(df)

        with st.expander("📈 Port Scan Summary"):
            st.write("Total Records:", len(df))
            st.write("Unique Targets:", df['Target'].nunique())

# Web Scanner View
elif selected == "🌐 Web Scan Results":
    st.subheader("🌐 Web Vulnerability Scanner Logs")
    df = load_data("logs/web_scan_results.csv")

    if not df.empty:
        df = df.sort_values(by="Timestamp", ascending=False)
        st.dataframe(df.style.applymap(
            lambda val: 'background-color: #ffe0e0' if val is True else ''
        ))

        with st.expander("📊 Web Scan Summary"):
            st.write("Total Scans:", len(df))
            st.write("Unique URLs:", df['URL'].nunique())

# IDS Alerts View
elif selected == "🚨 Intrusion Alerts":
    st.subheader("🛑 IDS Alerts (e.g., SYN Flood)")
    df = load_data("logs/alerts.csv", columns=["Timestamp", "Source IP", "Alert"])

    if not df.empty:
        df = df.sort_values(by="Timestamp", ascending=False)
        st.dataframe(df.style.applymap(
            lambda val: 'background-color: #ffcccc' if isinstance(val, str) and "SYN" in val else ''
        ))

        with st.expander("📊 Alert Summary"):
            st.write("Total Alerts:", len(df))
            st.write("Unique Source IPs:", df['Source IP'].nunique())
