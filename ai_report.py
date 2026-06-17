import os
import streamlit as st
from dotenv import load_dotenv

# ---------- SECRET HANDLING (Works Locally + Cloud) ----------
def get_secret(key):
    """Try st.secrets first (cloud), fallback to os.getenv (local)."""
    try:
        return st.secrets[key]
    except:
        return os.getenv(key)

# Load environment variables (for local development)
load_dotenv()

# Get API key using the hybrid method
GROQ_API_KEY = get_secret("GROQ_API_KEY")


def generate_ai_report(input_type, input_value, risk_data):
    """
    Generate a security report using Groq (fast, free, reliable).
    Falls back to template if Groq fails.
    """
    
    # Build the prompt
    prompt = build_prompt(input_type, input_value, risk_data)
    
    # --- Try Groq ---
    if GROQ_API_KEY:
        try:
            from groq import Groq
            
            # Initialize Groq client
            client = Groq(api_key=GROQ_API_KEY)
            
            # Send request to Groq
            chat_completion = client.chat.completions.create(
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert. Provide concise, professional security assessments."
                    },
                    {
                        "role": "user",
                        "content": prompt,
                    }
                ],
                model="llama-3.3-70b-versatile",
                temperature=0.3,
                max_tokens=500,
            )
            
            # Extract the response
            ai_report = chat_completion.choices[0].message.content
            print("✅ Successfully used Groq AI (Llama 3.3 70B)")
            return ai_report
            
        except ImportError:
            print("⚠️ Groq SDK not installed. Run: pip install groq")
        except Exception as e:
            print(f"⚠️ Groq error: {e}")
    
    # --- Fallback to template ---
    print("📝 Using template fallback...")
    return generate_template_report(input_type, input_value, risk_data)


def build_prompt(input_type, input_value, risk_data):
    """Build the prompt for the LLM."""
    return f"""
Based on the following security scan results, write a concise Executive Summary 
and clear Recommendations.

Input type: {input_type}
Input value: {input_value}
Risk score: {risk_data['score']}/100
Risk level: {risk_data['level']}

Scan details:
- Malicious detections: {risk_data['details']['malicious']}
- Suspicious detections: {risk_data['details']['suspicious']}
- Harmless detections: {risk_data['details']['harmless']}
- Undetected: {risk_data['details']['undetected']}

Format your response exactly like this:

**Executive Summary:**
[Write 2-3 sentences summarizing the risk]

**Recommendations:**
- [Recommendation 1]
- [Recommendation 2]
- [Recommendation 3]
"""


def generate_template_report(input_type, input_value, risk_data):
    """Fallback template based on risk score."""
    score = risk_data['score']
    
    if score == 0:
        summary = f"The submitted {input_type} ('{input_value}') appears to be safe. No malicious or suspicious activity was detected by any of the security vendors."
        recs = [
            "No action required. The input is considered safe.",
            "Continue normal operations."
        ]
    elif score <= 20:
        summary = f"The submitted {input_type} ('{input_value}') shows low-risk indicators. A small number of vendors flagged it as suspicious, but no direct malware was detected."
        recs = [
            "Monitor the input for any changes in reputation.",
            "No immediate action required, but keep logging enabled."
        ]
    elif score <= 40:
        summary = f"The submitted {input_type} ('{input_value}') shows medium-risk indicators due to suspicious reputation and some security vendor detections."
        recs = [
            "Avoid interacting with this input if possible.",
            "Enable additional monitoring and logging.",
            "Review the reputation and consider blocking access."
        ]
    elif score <= 70:
        summary = f"The submitted {input_type} ('{input_value}') shows high-risk indicators. Multiple vendors have flagged it as malicious or suspicious."
        recs = [
            "Do not interact with this input. Treat as suspicious.",
            "Enable thorough security monitoring.",
            "Consider blocking this input at the network level.",
            "Report to your security team for investigation."
        ]
    else:
        summary = f"The submitted {input_type} ('{input_value}') shows critical-risk indicators. Strong evidence of malware or malicious activity was detected."
        recs = [
            "Immediately block and isolate this input.",
            "Do not access or execute this input.",
            "Notify your security team and incident response immediately.",
            "Perform a full security sweep of your environment if exposure occurred."
        ]
    
    summary_text = f"**Executive Summary:**\n{summary}\n\n**Recommendations:**\n"
    for rec in recs:
        summary_text += f"- {rec}\n"
    return summary_text


# --- Quick test ---
if __name__ == "__main__":
    test_risk = {
        "score": 0,
        "level": "✅ Safe",
        "details": {"malicious": 0, "suspicious": 0, "harmless": 70, "undetected": 1}
    }
    print(generate_ai_report("url", "google.com", test_risk))
