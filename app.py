import streamlit as st
import ipaddress
from urllib.parse import urlparse

def analyze_url(url):
    url = url.strip()

    if not url:
        return 0, ["Please enter a URL"]

    if "://" not in url:
        url = "http://" + url

    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()

    score = 0
    findings = []

    if parsed.scheme != "https":
        score += 1
        findings.append("No HTTPS")

    if "@" in parsed.netloc:
        score += 2
        findings.append("Contains @ symbol")

    try:
        ipaddress.ip_address(host)
        score += 2
        findings.append("Uses IP address")
    except ValueError:
        pass

    if len(url) > 75:
        score += 1
        findings.append("Long URL")

    if host.count(".") >= 3:
        score += 1
        findings.append("Multiple subdomains")

    keywords = ["login", "verify", "update", "secure", "account", "password"]

    if any(word in url.lower() for word in keywords):
        score += 1
        findings.append("Suspicious keywords")

    if not findings:
        findings.append("No tested warning indicators")

    return score, findings


st.set_page_config(page_title="PhishGuard", page_icon="🛡️")

st.title("🛡️ PhishGuard")
st.subheader("Phishing URL Detection System")
st.write("Enter a website URL to analyze.")

url = st.text_input("Enter URL")

if st.button("Analyze URL"):
    if not url.strip():
        st.error("Please enter a URL")
    else:
        score, findings = analyze_url(url)

        st.write("Risk Score:", score, "/8")

        for item in findings:
            st.write("•", item)

        if score >= 4:
            st.error("High Risk Indicators Detected")
        elif score >= 2:
            st.warning("Suspicious Indicators Detected")
        else:
            st.success("Few Warning Indicators Found")

st.caption("Educational prototype. Not a guarantee of website safety.")
