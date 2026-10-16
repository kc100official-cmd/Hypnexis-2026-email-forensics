import streamlit as st
import pandas as pd
import json
from datetime import datetime

from core.triage_engine import analyze_email_threat
from data.sample_emails import SAMPLE_EMAILS
from core.geolocation import FORENSIC_DISCLAIMER

st.set_page_config(
    page_title="SIH26106 | Email Threat & Forensic Intelligence",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for dark/cyber modern look matching the hackathon theme
st.markdown("""
<style>
    .main-header {
        font-size: 2.1rem;
        font-weight: 700;
        color: #1E3A8A;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 1.05rem;
        color: #4B5563;
        margin-bottom: 1.2rem;
    }
    .badge-sih {
        background-color: #2563EB;
        color: white;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.85rem;
        display: inline-block;
        margin-right: 8px;
    }
    .badge-theme {
        background-color: #059669;
        color: white;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.85rem;
        display: inline-block;
        margin-right: 8px;
    }
    .badge-offline {
        background-color: #6366F1;
        color: white;
        padding: 4px 10px;
        border-radius: 6px;
        font-weight: 600;
        font-size: 0.85rem;
        display: inline-block;
    }
    .priority-card {
        padding: 1.2rem;
        border-radius: 10px;
        color: white;
        text-align: center;
        font-weight: 700;
        font-size: 1.4rem;
        margin-bottom: 1rem;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    }
    .evidence-item {
        background: #F8FAFC;
        border-left: 4px solid #3B82F6;
        padding: 10px 14px;
        margin-bottom: 8px;
        border-radius: 4px;
    }
    .evidence-item-high {
        background: #FEF2F2;
        border-left: 4px solid #EF4444;
        padding: 10px 14px;
        margin-bottom: 8px;
        border-radius: 4px;
    }
    .evidence-item-medium {
        background: #FFFBEB;
        border-left: 4px solid #F59E0B;
        padding: 10px 14px;
        margin-bottom: 8px;
        border-radius: 4px;
    }
    .disclaimer-box {
        background: #EFF6FF;
        border: 1px solid #BFDBFE;
        border-radius: 8px;
        padding: 12px;
        font-size: 0.88rem;
        color: #1E40AF;
        margin-top: 10px;
    }
</style>
""", unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.image("https://img.icons8.com/color/96/000000/shield.png", width=64)
    st.markdown("### SIH 2026 Submission")
    st.markdown("**Problem ID:** `SIH26106`")
    st.markdown("**Theme:** Blockchain & Cybersecurity")
    st.markdown("**Team:** `<Hypnexis '26>`")
    st.markdown("**Institution:** Manipal University Jaipur")
    st.markdown("---")

    st.subheader("⚡ Quick Load Test Samples")
    selected_sample = st.selectbox(
        "Choose a pre-configured synthetic scenario:",
        ["-- Select a Sample --"] + list(SAMPLE_EMAILS.keys())
    )

    st.markdown("---")
    st.markdown("#### ⚙️ Engine Status")
    st.markdown("✅ **ML Text Classifier:** Ready (TF-IDF + LogReg)")
    st.markdown("✅ **Domain & Spoof Rules:** Active")
    st.markdown("✅ **PhishTank Intel Cache:** Loaded")
    st.markdown("✅ **GeoIP Relay Resolver:** Active")
    st.markdown("---")
    st.caption("Software-only prototype for human-in-the-loop email threat triage.")

# Main Application Header
col_title, col_badges = st.columns([0.7, 0.3])
with col_title:
    st.markdown('<div class="main-header">🛡️ Email Threat & Forensic Intelligence Platform</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-header">AI-Powered Phishing Detection, Hop-by-Hop Relay GeoLocation, and Explainable Forensic Triage</div>', unsafe_allow_html=True)

with col_badges:
    st.markdown("""
        <div style="text-align: right; padding-top: 10px;">
            <span class="badge-sih">SIH26106</span>
            <span class="badge-theme">Cybersecurity</span>
            <span class="badge-offline">Offline Demo Ready</span>
        </div>
    """, unsafe_allow_html=True)

st.divider()

# Session State for Email Content
if "email_input" not in st.session_state:
    st.session_state["email_input"] = SAMPLE_EMAILS["1. High Risk: Spoofed PayPal Security Suspension (Full Headers)"]

if selected_sample != "-- Select a Sample --":
    st.session_state["email_input"] = SAMPLE_EMAILS[selected_sample]

# Tabs for Navigation
tab_input, tab_triage, tab_geo, tab_urls, tab_export = st.tabs([
    "📥 1. Email Input & Inspection",
    "📊 2. AI Threat Assessment",
    "🌍 3. Relay GeoLocation & Headers",
    "🔗 4. URL Threat Intelligence",
    "📑 5. SOC Incident Report"
])

# ----------------- TAB 1: INPUT & INSPECTION -----------------
with tab_input:
    st.subheader("Input Message (Headers + Body or Plain Text)")
    email_text = st.text_area(
        "Paste email source (supports full RFC 822 format or simple email body):",
        value=st.session_state["email_input"],
        height=240,
        key="main_text_input"
    )

    col_btn1, col_btn2 = st.columns([0.2, 0.8])
    with col_btn1:
        run_analysis = st.button("🚀 Analyze Email Threat", type="primary", use_container_width=True)
    with col_btn2:
        if st.button("🧹 Clear Input", use_container_width=False):
            st.session_state["email_input"] = ""
            st.rerun()

    # Run Analysis
    analysis = analyze_email_threat(email_text)
    parsed = analysis["parsed"]

    st.markdown("#### 🔎 Parsed Header Structure")
    col_p1, col_p2, col_p3 = st.columns(3)
    with col_p1:
        st.metric("From (Display Name)", parsed.get("sender_name") or "(None detected)")
        st.metric("Sender Address", parsed.get("sender_email") or "(Not specified)")
    with col_p2:
        st.metric("Sender Domain", parsed.get("sender_domain") or "(None)")
        st.metric("Reply-To Domain", parsed.get("reply_to_domain") or "Same as Sender")
    with col_p3:
        st.metric("Subject", parsed.get("subject") or "(No subject)")
        st.metric("Extracted Origin IP", parsed.get("origin_ip") or "(No public IP in headers)")

# ----------------- TAB 2: AI THREAT ASSESSMENT -----------------
with tab_triage:
    st.subheader("Human-in-the-Loop Review Priority")
    
    # Priority Banner
    p_color = analysis["priority_color"]
    p_label = analysis["priority_label"]
    score = analysis["threat_score"]

    st.markdown(f"""
        <div class="priority-card" style="background-color: {p_color};">
            {p_label}
            <div style="font-size: 1rem; font-weight: 400; margin-top: 4px;">
                Overall Threat Index: <strong>{score} / 100</strong>
            </div>
        </div>
    """, unsafe_allow_html=True)

    # Score Metrics Breakdown
    m_col1, m_col2, m_col3, m_col4 = st.columns(4)
    with m_col1:
        st.metric("Overall Threat Index", f"{score}/100")
    with m_col2:
        st.metric("AI Classifier Score", f"{analysis['score_breakdown']['ml_score']}/100", 
                  help="TF-IDF + Logistic Regression classification on language cues")
    with m_col3:
        st.metric("Domain & Heuristic Score", f"{analysis['score_breakdown']['rule_score']}/100",
                  help="Brand impersonation, urgency triggers, credential requests")
    with m_col4:
        st.metric("URL Risk Score", f"{analysis['score_breakdown']['url_score']}/100",
                  help="PhishTank matches, naked IPs, deceptive paths, shorteners")

    st.markdown("---")

    # Plain Language Evidence
    col_ev, col_steps = st.columns([0.6, 0.4])

    with col_ev:
        st.markdown("### 🔍 Evidence Behind The Review Priority")
        st.caption("Plain-language findings synthesized for rapid human verification:")
        for ev in analysis["evidence"]:
            sev = ev.get("severity", "INFO")
            css_class = "evidence-item-high" if sev in ("HIGH", "MALICIOUS") else ("evidence-item-medium" if sev in ("MEDIUM", "SUSPICIOUS") else "evidence-item")
            st.markdown(f"""
                <div class="{css_class}">
                    <strong>[{ev['source']}]</strong> — <span style="font-weight:600;">{sev}</span>: {ev['detail']}
                </div>
            """, unsafe_allow_html=True)

        # AI Classifier Keywords
        if analysis["ml_results"]["top_keywords"]:
            st.markdown("##### 🧠 Influential Linguistic Tokens (AI Model Feature Weights)")
            kw_data = [{"Token": k, "Feature Contribution": v} for k, v in analysis["ml_results"]["top_keywords"]]
            st.dataframe(pd.DataFrame(kw_data), use_container_width=True, hide_index=True)

    with col_steps:
        st.markdown("### 🛡️ Recommended Safe Next Steps")
        st.caption("Actionable guidance for the recipient / security analyst:")
        for idx, step in enumerate(analysis["safe_steps"], 1):
            st.checkbox(f"**Step {idx}:** {step}", value=False, key=f"step_{idx}")

        st.markdown("""
            <div class="disclaimer-box">
                <strong>Human-Centric Review:</strong> This tool assists your decision-making. 
                Automatic blocking is disabled to prevent false positives on business-critical emails.
            </div>
        """, unsafe_allow_html=True)

# ----------------- TAB 3: RELAY GEOLOCATION & HEADERS -----------------
with tab_geo:
    st.subheader("Origin IP GeoLocation & Intermediate Relays")
    
    geo = analysis["geo_results"]
    if geo and geo.get("status") in ("success", "approximate"):
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.metric("Relay IP", geo.get("ip", "Unknown"))
        with c2:
            st.metric("Approx. Country", geo.get("country", "Unknown"))
        with c3:
            st.metric("City / Region", f"{geo.get('city', 'N/A')}, {geo.get('region', 'N/A')}")
        with c4:
            st.metric("ISP / Network ASN", f"{geo.get('isp', 'Unknown')} ({geo.get('asn', 'N/A')})")

        # Map display if coordinates available
        lat, lon = geo.get("lat"), geo.get("lon")
        if lat and lon and (lat != 0.0 or lon != 0.0):
            st.markdown("##### 📍 Approximate Geographic Location of Originating Mail Relay")
            map_df = pd.DataFrame([{"lat": lat, "lon": lon}])
            st.map(map_df, zoom=4)

        st.markdown(f"""
            <div class="disclaimer-box">
                ⚖️ <strong>CISA / Forensic Safe Use Notice:</strong><br>
                {FORENSIC_DISCLAIMER}
            </div>
        """, unsafe_allow_html=True)

    else:
        st.info("No public IP address was found in the provided email headers. If testing, select a sample with Received headers.")

    # Received Header Hop Trace
    st.markdown("---")
    st.markdown("#### 🔀 Received: Header Hop-by-Hop Trace")
    hops = parsed.get("received_hops", [])
    if hops:
        hop_rows = []
        for i, h in enumerate(hops, 1):
            hop_rows.append({
                "Hop #": i,
                "Public IP(s) Detected": ", ".join(h["public_ips"]) if h["public_ips"] else "Private/None",
                "Raw Received Snippet": h["raw"]
            })
        st.dataframe(pd.DataFrame(hop_rows), use_container_width=True, hide_index=True)
    else:
        st.caption("No intermediate Received headers detected (pasted text was plain body).")

# ----------------- TAB 4: URL THREAT INTELLIGENCE -----------------
with tab_urls:
    st.subheader("Extracted Hyperlinks & Reputation Intelligence")
    url_res = analysis["url_results"]
    
    if url_res["total_urls"] > 0:
        st.write(f"Total extracted URLs: **{url_res['total_urls']}**")
        url_table = []
        for item in url_res["url_details"]:
            url_table.append({
                "Target URL": item["url"],
                "Hostname": item["hostname"],
                "Status": item["status"],
                "Risk Score": f"{item['risk_score']}/100",
                "Flags & Threat Intel Matches": "; ".join(item["flags"]) if item["flags"] else "Clean / No known flags"
            })
        st.dataframe(pd.DataFrame(url_table), use_container_width=True, hide_index=True)
    else:
        st.success("✅ No external URLs found in the analyzed email message.")

    st.markdown("---")
    st.markdown("#### 📚 Reference Threat Intel Databases")
    st.markdown("- **PhishTank** (phishtank.org): Community-verified phishing URL feeds & cached signatures.")
    st.markdown("- **CISA Secure Our World**: Recognized patterns for deceptive credential collection.")

# ----------------- TAB 5: SOC INCIDENT REPORT EXPORT -----------------
with tab_export:
    st.subheader("SOC Incident Triage Report")
    st.caption("Standardized forensic summary formatted for incident response teams and ticketing systems.")

    incident_report = {
        "incident_id": f"INC-SIH26106-{int(datetime.now().timestamp())}",
        "timestamp": datetime.now().isoformat(),
        "platform": "SIH26106 Email Threat Detection & Forensic Intelligence",
        "team": "Hypnexis '26 (Manipal University Jaipur)",
        "review_priority": analysis["priority"],
        "threat_score": analysis["threat_score"],
        "sender": {
            "name": parsed.get("sender_name"),
            "email": parsed.get("sender_email"),
            "domain": parsed.get("sender_domain")
        },
        "subject": parsed.get("subject"),
        "origin_ip": analysis.get("geo_results", {}),
        "evidence_log": analysis["evidence"],
        "extracted_urls": analysis["url_results"]["url_details"],
        "recommended_actions": analysis["safe_steps"],
        "forensic_notice": FORENSIC_DISCLAIMER
    }

    report_json = json.dumps(incident_report, indent=2)

    col_exp1, col_exp2 = st.columns(2)
    with col_exp1:
        st.download_button(
            label="💾 Download JSON Incident Report",
            data=report_json,
            file_name=f"triage_report_{analysis['priority'].lower()}_{int(datetime.now().timestamp())}.json",
            mime="application/json",
            use_container_width=True
        )
    with col_exp2:
        markdown_summary = f"""# SIH26106 Security Incident Triage Summary
- **Incident ID:** {incident_report['incident_id']}
- **Review Priority:** {analysis['priority']} ({analysis['threat_score']}/100)
- **Subject:** {parsed.get('subject')}
- **Sender:** {parsed.get('sender_name')} <{parsed.get('sender_email')}>
- **Origin Relay IP:** {parsed.get('origin_ip') or 'N/A'}

## Evidence Summary
{chr(10).join([f"- [{e['source']}] {e['detail']}" for e in analysis['evidence']])}

## Recommended Actions
{chr(10).join([f"- [ ] {s}" for s in analysis['safe_steps']])}
"""
        st.download_button(
            label="📝 Download Markdown Incident Summary",
            data=markdown_summary,
            file_name=f"incident_summary_{analysis['priority'].lower()}.md",
            mime="text/markdown",
            use_container_width=True
        )

    st.code(report_json, language="json")
