"""Run with: streamlit run app.py"""
import json

import streamlit as st

from promptshield import analyze
from promptshield.detector import MAX_INPUT_LENGTH

st.set_page_config(page_title="PromptShield", page_icon="🛡️", layout="centered")
st.title("🛡️ PromptShield")
st.caption("Local • Rule-based • Explainable")
st.write("Check text for common prompt injection signals before passing it to an assistant.")
st.info("Scores reflect matched rules, not attack probability. Review context before taking action.")
with st.sidebar:
    st.header("How scoring works")
    st.write("Each rule counts once. Each category contributes up to 50 points; the total is capped at 100.")
    st.write("Low: 0–29 · Medium: 30–59 · High: 60–100")
    st.caption("Text is processed locally. PromptShield does not call external APIs or save prompts.")

with st.form("scan"):
    prompt = st.text_area("Text to inspect", height=230, max_chars=MAX_INPUT_LENGTH,
                          placeholder="Paste a prompt, retrieved document, or assistant input…")
    submitted = st.form_submit_button("Analyze text", type="primary")

if submitted:
    if not prompt.strip():
        st.warning("Enter some text to analyze.")
    else:
        try:
            result = analyze(prompt)
        except ValueError as error:
            st.error(str(error))
            st.stop()
        st.metric("Risk score", f"{result.score} / 100", delta=result.level + " risk", delta_color="off")
        st.progress(result.score / 100)
        st.subheader("Matched patterns")
        if not result.matches:
            st.success("No configured patterns matched. This does not guarantee the text is safe.")
        for match in result.matches:
            with st.expander(f"{match.category} · {match.rule_id} · weight {match.weight}", expanded=True):
                st.write(match.explanation)
                st.code(match.evidence, language=None)
        st.download_button("Download JSON report", json.dumps(result.to_dict(), indent=2),
                           "promptshield-report.json", "application/json")

st.divider()
st.caption("Heuristics can miss obfuscated attacks and flag benign quotations. Use alongside other safeguards.")
