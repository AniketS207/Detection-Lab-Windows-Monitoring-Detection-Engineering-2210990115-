import streamlit as st
import pandas as pd
import json
import os
import time

ALERT_FILE = "../alerts/alerts.json"

st.set_page_config(
    page_title="Detection Lab Dashboard",
    page_icon="🚨",
    layout="wide"
)

# =========================
# Styling
# =========================

st.markdown("""
    <style>
    .critical {
        background-color: #ff4b4b;
        color: white;
        padding: 10px;
        border-radius: 10px;
    }

    .high {
        background-color: #ff914d;
        color: white;
        padding: 10px;
        border-radius: 10px;
    }

    .medium {
        background-color: #ffd93d;
        color: black;
        padding: 10px;
        border-radius: 10px;
    }

    .low {
        background-color: #4caf50;
        color: white;
        padding: 10px;
        border-radius: 10px;
    }
    </style>
""", unsafe_allow_html=True)

# =========================
# Header
# =========================

st.title("🚨 Detection Lab Dashboard")
st.caption("Real-time Sigma Detection Alerts")

# =========================
# Auto Refresh
# =========================

refresh = st.sidebar.slider(
    "Refresh interval (seconds)",
    1,
    10,
    2
)

# =========================
# Load Alerts
# =========================

def load_alerts():

    if not os.path.exists(ALERT_FILE):
        return []

    try:

        with open(ALERT_FILE, "r", encoding="utf-8") as f:
            return json.load(f)

    except:
        return []

alerts = load_alerts()

# =========================
# Metrics
# =========================

col1, col2, col3, col4 = st.columns(4)

critical_count = sum(
    1 for a in alerts
    if a.get("severity", "").lower() == "critical"
)

high_count = sum(
    1 for a in alerts
    if a.get("severity", "").lower() == "high"
)

medium_count = sum(
    1 for a in alerts
    if a.get("severity", "").lower() == "medium"
)

total_count = len(alerts)

col1.metric("Total Alerts", total_count)
col2.metric("Critical", critical_count)
col3.metric("High", high_count)
col4.metric("Medium", medium_count)

st.divider()

# =========================
# Alerts Table
# =========================

if alerts:

    df = pd.DataFrame(alerts)

    st.subheader("📋 Alert Table")

    st.dataframe(
        df,
        use_container_width=True,
        height=400
    )

    st.divider()

    # =========================
    # Individual Alert Cards
    # =========================

    st.subheader("🚨 Latest Alerts")

    for alert in reversed(alerts):

        severity = alert.get("severity", "unknown").lower()

        css_class = severity

        st.markdown(
            f"""
            <div class="{css_class}">
                <h4>{alert.get("rule_name", "Unknown Rule")}</h4>

                <b>Severity:</b> {severity.upper()}<br>

                <b>Image:</b><br>
                {alert.get("image", "")}<br><br>

                <b>Command Line:</b><br>
                {alert.get("command_line", "")}<br><br>

                <b>Timestamp:</b>
                {alert.get("timestamp", "")}
            </div>
            <br>
            """,
            unsafe_allow_html=True
        )

else:

    st.warning("No alerts found.")

# =========================
# Auto Refresh
# =========================

time.sleep(refresh)
st.rerun()