"""Streamlit UI for ioc-enricher. Run: streamlit run app.py"""
import io
import os

import pandas as pd
import streamlit as st
from dotenv import load_dotenv

import enricher

load_dotenv()
st.set_page_config(page_title="IOC Enricher", page_icon="🛡️", layout="wide")
st.title("🛡️ IOC Enricher")
st.caption("Paste IPs or raw log text. IPs are extracted automatically and checked against AbuseIPDB.")

api_key = os.environ.get("ABUSEIPDB_KEY", "")
with st.sidebar:
    st.header("Settings")
    if not api_key:
        api_key = st.text_input("AbuseIPDB API key", type="password")
    skip_private = st.checkbox("Skip private/reserved IPs", value=True)
    min_score = st.slider("Only show score ≥", 0, 100, 0)

text = st.text_area("Paste IPs or log lines", height=160, placeholder="8.8.8.8\n185.220.101.4")
upload = st.file_uploader("...or upload a .txt / .log file", type=["txt", "log", "csv"])
if upload:
    text += "\n" + enricher.decode_bytes(upload.getvalue())

if st.button("Enrich", type="primary"):
    ips = enricher.parse_ips(text, skip_private)
    if not api_key:
        st.error("Add your AbuseIPDB API key (sidebar or .env).")
    elif not ips:
        st.warning("No valid IPs found.")
    else:
        bar = st.progress(0.0, text="Starting...")
        results, errors = enricher.enrich_many(
            ips, api_key, on_progress=lambda i, n, ip: bar.progress(i / n, text=f"{ip} ({i}/{n})")
        )
        bar.empty()
        st.session_state["results"], st.session_state["errors"] = results, errors

results = st.session_state.get("results")
if results:
    df = pd.DataFrame(results).sort_values("score", ascending=False)
    df = df[df["score"] >= min_score]
    counts = df["verdict"].value_counts()
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Checked", len(df))
    c2.metric("🔴 Malicious", int(counts.get("malicious", 0)))
    c3.metric("🟠 Suspicious", int(counts.get("suspicious", 0)))
    c4.metric("🟢 Clean", int(counts.get("clean", 0)))

    st.dataframe(
        df, use_container_width=True, hide_index=True,
        column_config={"score": st.column_config.ProgressColumn("score", min_value=0, max_value=100, format="%d")},
    )

    buf = io.StringIO(newline="")
    enricher.write_csv(df.to_dict("records"), buf)
    d1, d2 = st.columns(2)
    d1.download_button("⬇️ Download CSV", buf.getvalue(), "results.csv", "text/csv")
    d2.download_button("⬇️ Download JSON", df.to_json(orient="records", indent=2), "results.json", "application/json")

for ip, msg in st.session_state.get("errors", []):
    st.warning(f"{ip}: {msg}")
