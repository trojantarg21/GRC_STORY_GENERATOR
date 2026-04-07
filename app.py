import streamlit as st
from log_parser import parse_log_file
from translator import translate_logs
from story_generator import generate_story, generate_summary, group_events, build_clean_sentences
from risk_engine import assess_risk, explain_risk, get_recommendations
import tempfile

st.set_page_config(page_title="Cyber Incident Story Generator", layout="wide")

st.title("🛡️ Cyber Incident Story Generator")

st.write("Upload a log file to analyze security events and generate a report.")

uploaded_file = st.file_uploader("Upload your log file", type=["txt"])

if uploaded_file:
    # Save uploaded file temporarily
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(uploaded_file.read())
        file_path = tmp.name

    # Process pipeline
    logs = parse_log_file(file_path)
    translated = translate_logs(logs)

    messages = [log["translated"] for log in translated]
    groups = group_events(messages)
    cleaned_messages = build_clean_sentences(groups)

    story = generate_story(cleaned_messages)
    summary = generate_summary(translated)

    risk = assess_risk(translated)
    meaning = explain_risk(risk)
    actions = get_recommendations(risk)

    st.success("Analysis Complete ✅")

    # Summary
    st.subheader("🚨 Summary")
    st.write(summary)

    # Story
    st.subheader("📖 Incident Story")
    st.write(story)

    # Risk
    st.subheader("⚠️ Risk Analysis")
    if risk == "HIGH":
       st.error(f"RISK LEVEL: {risk}")
    elif risk == "MEDIUM":
       st.warning(f"RISK LEVEL: {risk}")
    else:
       st.success(f"RISK LEVEL: {risk}")
    st.write(f"**What this means:** {meaning}")

    # Actions
    st.subheader("🛠️ Recommended Actions")
    for action in actions:
        st.write(f"- {action}")