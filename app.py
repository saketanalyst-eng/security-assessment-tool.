import streamlit as st
import os
import time
from dotenv import load_dotenv

# Import your backend modules
from virus_total_client import scan_url, scan_ip, scan_file, extract_stats
from risk_engine import calculate_risk
from ai_report import generate_ai_report

# Load environment variables (for local development)
load_dotenv()

# ---------- PAGE CONFIG ----------
st.set_page_config(
    page_title="AI Security Assessment Tool",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ---------- CUSTOM CSS (ENHANCED) ----------
st.markdown("""
    <style>
    .main-title {
        font-size: 3rem;
        font-weight: 700;
        background: linear-gradient(135deg, #00ff88, #00b4d8);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        text-align: center;
        margin-bottom: 0.5rem;
    }
    .sub-title {
        text-align: center;
        color: #aaa;
        font-size: 1.1rem;
        margin-bottom: 2rem;
    }
    .result-card {
        background-color: #1e1e1e;
        padding: 1.5rem;
        border-radius: 12px;
        border-left: 5px solid #00ff88;
        margin: 1rem 0;
    }
    .risk-score {
        font-size: 4rem;
        font-weight: 800;
        text-align: center;
    }
    .risk-level {
        font-size: 1.5rem;
        font-weight: 600;
        text-align: center;
        padding: 0.3rem 1rem;
        border-radius: 50px;
        display: inline-block;
        margin: 0 auto;
    }
    .stat-box {
        background-color: #2d2d2d;
        padding: 0.8rem;
        border-radius: 8px;
        text-align: center;
    }
    .stat-number {
        font-size: 2rem;
        font-weight: 700;
    }
    .footer {
        text-align: center;
        color: #666;
        margin-top: 3rem;
        font-size: 0.9rem;
    }
    
    /* ===== ENHANCED AI REPORT STYLING ===== */
    .ai-report-container {
        background: linear-gradient(145deg, #1a1a2e, #16213e);
        padding: 2rem;
        border-radius: 16px;
        border: 1px solid #00b4d8;
        box-shadow: 0 8px 32px rgba(0, 180, 216, 0.15);
        margin: 1rem 0;
        position: relative;
        overflow: hidden;
    }
    
    .ai-report-container::before {
        content: '';
        position: absolute;
        top: -50%;
        left: -50%;
        width: 200%;
        height: 200%;
        background: radial-gradient(circle at 30% 50%, rgba(0, 180, 216, 0.03), transparent 70%);
        pointer-events: none;
    }
    
    .ai-report-container::after {
        content: '🤖';
        position: absolute;
        top: 10px;
        right: 20px;
        font-size: 2.5rem;
        opacity: 0.1;
    }
    
    .ai-report-content {
        position: relative;
        z-index: 1;
        color: #e0e0e0;
        font-size: 1.05rem;
        line-height: 1.8;
    }
    
    .ai-report-content strong {
        color: #00b4d8;
    }
    
    .ai-report-content h3, 
    .ai-report-content h4 {
        color: #00ff88;
        margin-top: 0.5rem;
        margin-bottom: 0.3rem;
    }
    
    .ai-report-content ul {
        list-style-type: none;
        padding-left: 0;
    }
    
    .ai-report-content li {
        padding: 0.4rem 0 0.4rem 1.8rem;
        position: relative;
        border-bottom: 1px solid rgba(255,255,255,0.05);
    }
    
    .ai-report-content li::before {
        content: '▸';
        position: absolute;
        left: 0;
        color: #00ff88;
        font-weight: bold;
    }
    
    .ai-executive-summary {
        background: rgba(0, 255, 136, 0.05);
        padding: 1.2rem 1.5rem;
        border-radius: 10px;
        border-left: 4px solid #00ff88;
        margin: 0.8rem 0;
    }
    
    .ai-recommendations {
        background: rgba(0, 180, 216, 0.05);
        padding: 1.2rem 1.5rem;
        border-radius: 10px;
        border-left: 4px solid #00b4d8;
        margin: 0.8rem 0;
    }
    
    .ai-report-badge {
        display: inline-block;
        background: linear-gradient(135deg, #00ff88, #00b4d8);
        color: #0a0a1a;
        padding: 0.2rem 1rem;
        border-radius: 20px;
        font-size: 0.7rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.5px;
        margin-bottom: 0.5rem;
    }
    </style>
""", unsafe_allow_html=True)

# ---------- HEADER ----------
st.markdown('<div class="main-title">🛡️ AI Security Assessment Tool</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-title">Scan URLs, IP Addresses, and Files for security threats</div>', unsafe_allow_html=True)

# ---------- SIDEBAR ----------
with st.sidebar:
    st.image("https://via.placeholder.com/200x60/000000/00ff88?text=AnantNetra", use_container_width=True)
    st.markdown("---")
    st.markdown("### 🔑 API Status")
    
    vt_key = os.getenv("VIRUSTOTAL_API_KEY")
    groq_key = os.getenv("GROQ_API_KEY")
    
    if vt_key:
        st.success("✅ VirusTotal: Connected")
    else:
        st.error("❌ VirusTotal: Missing key")
    
    if groq_key:
        st.success("✅ Groq AI: Connected")
    else:
        st.warning("⚠️ Groq AI: Using template fallback")
    
    st.markdown("---")
    st.markdown("### 📖 About")
    st.markdown("""
    This tool integrates:
    - **VirusTotal API** for threat intelligence
    - **Risk Engine** for scoring
    - **Groq AI** (Llama 3.3) for reports
    """)
    st.markdown("---")
    st.markdown("### 🚀 Quick Tips")
    st.markdown("""
    - URLs: `example.com` or `https://example.com`
    - IPs: `8.8.8.8` or `192.168.1.1`
    - Files: Supports EXE, ZIP, PDF, and more
    """)

# ---------- INITIALIZE SESSION STATE ----------
if 'results' not in st.session_state:
    st.session_state.results = None

# ---------- MAIN INPUT TABS ----------
tab1, tab2, tab3 = st.tabs(["🌐 Scan URL", "🔢 Scan IP", "📁 Scan File"])

# ==========================================
# TAB 1: URL SCAN
# ==========================================
with tab1:
    st.markdown("### Enter a URL to scan")
    url_input = st.text_input(
        "URL",
        placeholder="e.g., example.com or https://example.com",
        label_visibility="collapsed",
        key="url_input"
    )
    
    col1, col2, col3 = st.columns([1, 1, 4])
    with col1:
        scan_url_btn = st.button("🔍 Scan URL", type="primary", use_container_width=True)
    
    if scan_url_btn and url_input:
        with st.spinner("🔄 Scanning URL... This may take 20-30 seconds."):
            report = scan_url(url_input)
            if report:
                stats = extract_stats(report)
                if stats:
                    risk = calculate_risk(stats)
                    ai_report = generate_ai_report("url", url_input, risk)
                    st.session_state.results = {
                        "input_type": "URL",
                        "input_value": url_input,
                        "stats": stats,
                        "risk": risk,
                        "ai_report": ai_report
                    }
                else:
                    st.error("❌ Could not extract statistics from VirusTotal report.")
            else:
                st.error("❌ Scan failed. Please check the URL and try again.")
    elif scan_url_btn and not url_input:
        st.warning("⚠️ Please enter a URL.")

# ==========================================
# TAB 2: IP SCAN
# ==========================================
with tab2:
    st.markdown("### Enter an IP Address to scan")
    ip_input = st.text_input(
        "IP Address",
        placeholder="e.g., 8.8.8.8",
        label_visibility="collapsed",
        key="ip_input"
    )
    
    col1, col2, col3 = st.columns([1, 1, 4])
    with col1:
        scan_ip_btn = st.button("🔍 Scan IP", type="primary", use_container_width=True)
    
    if scan_ip_btn and ip_input:
        with st.spinner("🔄 Checking IP reputation..."):
            report = scan_ip(ip_input)
            if report:
                stats = extract_stats(report)
                if stats:
                    risk = calculate_risk(stats)
                    ai_report = generate_ai_report("ip", ip_input, risk)
                    st.session_state.results = {
                        "input_type": "IP",
                        "input_value": ip_input,
                        "stats": stats,
                        "risk": risk,
                        "ai_report": ai_report
                    }
                else:
                    st.error("❌ Could not extract statistics from VirusTotal report.")
            else:
                st.error("❌ IP scan failed. Please check the IP address.")
    elif scan_ip_btn and not ip_input:
        st.warning("⚠️ Please enter an IP address.")

# ==========================================
# TAB 3: FILE SCAN
# ==========================================
with tab3:
    st.markdown("### Upload a file to scan")
    uploaded_file = st.file_uploader(
        "Choose a file (EXE, ZIP, PDF, etc.)",
        type=None,
        label_visibility="collapsed",
        key="file_uploader"
    )
    
    if uploaded_file is not None:
        file_size = uploaded_file.size / 1024  # KB
        st.success(f"✅ File '{uploaded_file.name}' uploaded ({file_size:.1f} KB)")
        
        # Save temporarily
        temp_path = f"temp_{uploaded_file.name}"
        with open(temp_path, "wb") as f:
            f.write(uploaded_file.getbuffer())
        
        col1, col2, col3 = st.columns([1, 1, 4])
        with col1:
            scan_file_btn = st.button("🔍 Scan File", type="primary", use_container_width=True)
        
        if scan_file_btn:
            with st.spinner("🔄 Uploading and scanning file... This may take up to 30 seconds."):
                report = scan_file(temp_path)
                if report:
                    stats = extract_stats(report)
                    if stats:
                        risk = calculate_risk(stats)
                        ai_report = generate_ai_report("file", uploaded_file.name, risk)
                        st.session_state.results = {
                            "input_type": "File",
                            "input_value": uploaded_file.name,
                            "stats": stats,
                            "risk": risk,
                            "ai_report": ai_report
                        }
                    else:
                        st.error("❌ Could not extract statistics from VirusTotal report.")
                else:
                    st.error("❌ File scan failed. Please try again.")
                # Clean up temp file
                if os.path.exists(temp_path):
                    os.remove(temp_path)

# ==========================================
# DISPLAY RESULTS
# ==========================================
if st.session_state.results:
    results = st.session_state.results
    stats = results["stats"]
    risk = results["risk"]
    ai_report = results["ai_report"]
    
    st.markdown("---")
    st.markdown("## 📊 Scan Results")
    
    # ---------- Row 1: Summary ----------
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Input Type", results["input_type"])
    with col2:
        st.metric("Input Value", results["input_value"])
    with col3:
        st.metric("☢️ Malicious", stats.get('malicious', 0))
    with col4:
        st.metric("⚠️ Suspicious", stats.get('suspicious', 0))
    
    # ---------- Row 2: Risk Score ----------
    st.markdown("### 🎯 Risk Assessment")
    col1, col2, col3 = st.columns([1, 1, 1])
    
    score = risk["score"]
    level = risk["level"]
    
    # Color mapping
    if score == 0:
        color = "#00ff88"
        bg_color = "#00ff8820"
    elif score <= 20:
        color = "#90ee90"
        bg_color = "#90ee9020"
    elif score <= 40:
        color = "#ffff00"
        bg_color = "#ffff0020"
    elif score <= 70:
        color = "#ffa500"
        bg_color = "#ffa50020"
    else:
        color = "#ff4444"
        bg_color = "#ff444420"
    
    with col1:
        st.markdown(f"""
        <div style="background-color:{bg_color}; padding:1.5rem; border-radius:12px; text-align:center; border:1px solid {color};">
            <div style="font-size:0.9rem; color:#aaa;">Risk Score</div>
            <div style="font-size:4rem; font-weight:800; color:{color};">{score}</div>
            <div style="font-size:1.2rem; font-weight:600; color:{color};">{level}</div>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("#### 📊 Detection Summary")
        st.markdown(f"""
        - ✅ **Harmless:** {stats.get('harmless', 0)}
        - ⚠️ **Suspicious:** {stats.get('suspicious', 0)}
        - ☢️ **Malicious:** {stats.get('malicious', 0)}
        - 🛑 **Undetected:** {stats.get('undetected', 0)}
        """)
    
    with col3:
        st.markdown("#### 📈 Risk Interpretation")
        if score == 0:
            st.info("✅ No threats detected. The input is safe.")
        elif score <= 20:
            st.info("🟢 Low risk. Minor suspicious indicators.")
        elif score <= 40:
            st.warning("🟡 Medium risk. Proceed with caution.")
        elif score <= 70:
            st.warning("🟠 High risk. Strong indicators of threats.")
        else:
            st.error("🔴 Critical risk. Severe threats detected!")
    
    # ---------- Row 3: AI Report (ENHANCED) ----------
    st.markdown("### 🤖 AI-Generated Security Report")
    
    # Parse the AI report to separate Summary and Recommendations
    report_lines = ai_report.split('\n')
    summary = ""
    recommendations = ""
    current_section = ""
    
    for line in report_lines:
        if "Executive Summary" in line or "**Executive Summary:**" in line:
            current_section = "summary"
            clean_line = line.replace("**Executive Summary:**", "").strip()
            if clean_line:
                summary += clean_line + " "
        elif "Recommendations" in line or "**Recommendations:**" in line:
            current_section = "recommendations"
        elif current_section == "summary" and line.strip():
            if not line.startswith('**'):
                summary += line.strip() + " "
        elif current_section == "recommendations" and line.strip():
            if line.strip().startswith('-') or line.strip().startswith('*'):
                recommendations += line.strip() + "\n"
            elif line.strip() and not line.startswith('**'):
                recommendations += "- " + line.strip() + "\n"
    
    # If parsing failed, use the raw report
    if not summary and not recommendations:
        summary = "The submitted input appears to be safe based on security vendor analysis."
        recommendations = "- No immediate action required.\n- Continue normal monitoring."
    
    # Format recommendations as HTML list items
    rec_items = []
    for rec in recommendations.split('\n'):
        if rec.strip():
            clean_rec = rec.strip().lstrip('-').lstrip('*').strip()
            rec_items.append(f'<li>{clean_rec}</li>')
    rec_html = ''.join(rec_items)
    
    # Display using st.markdown with HTML rendering enabled
    html_content = f"""
    <div class="ai-report-container">
        <div class="ai-report-content">
            <div class="ai-report-badge">🤖 AI Generated • Security Analysis</div>
            
            <div class="ai-executive-summary">
                <strong style="color: #00ff88;">📋 Executive Summary</strong>
                <p style="margin: 0.5rem 0 0 0;">{summary}</p>
            </div>
            
            <div class="ai-recommendations">
                <strong style="color: #00b4d8;">💡 Recommendations</strong>
                <ul style="margin: 0.5rem 0 0 0; padding-left: 0; list-style-type: none;">
                    {rec_html}
                </ul>
            </div>
            
            <div style="margin-top: 1rem; font-size: 0.8rem; color: #666; text-align: right; border-top: 1px solid rgba(255,255,255,0.08); padding-top: 0.5rem;">
                ⚡ Powered by Groq AI • Llama 3.3 70B
            </div>
        </div>
    </div>
    """
    
    st.markdown(html_content, unsafe_allow_html=True)
    
    # ---------- Row 4: Raw Data (Expandable) ----------
    with st.expander("📋 View Raw Scan Data (JSON)"):
        st.json({
            "input_type": results["input_type"],
            "input_value": results["input_value"],
            "stats": stats,
            "risk": risk
        })
    
    # ---------- Clear Button ----------
    if st.button("🗑️ Clear Results", type="secondary"):
        st.session_state.results = None
        st.rerun()

# ==========================================
# FOOTER
# ==========================================
st.markdown("""
<div class="footer">
    Built with ❤️ for AnantNetra Technologies • 
    <a href="#" style="color:#00ff88;">GitHub</a> • 
    <a href="#" style="color:#00ff88;">Documentation</a>
</div>
""", unsafe_allow_html=True)
