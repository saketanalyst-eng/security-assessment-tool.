# 🛡️ AI-Powered Security Assessment Tool

An intelligent cybersecurity application that scans **URLs**, **IP addresses**, and **files** using the VirusTotal API, calculates security risk scores, and generates **AI-powered threat assessment reports** using **Groq's Llama 3.3 70B model**.

Built with **Python** and **Streamlit**, the application provides a clean and interactive web interface for rapid security analysis and threat intelligence reporting.

---

## 🚀 Features

### 🔍 Multi-Input Security Scanning

* Scan URLs for malicious content and phishing threats
* Analyze IP addresses for reputation and abuse indicators
* Upload and scan files (EXE, ZIP, PDF, DOCX, etc.)

### 🛡️ VirusTotal Integration

* Leverages VirusTotal v3 API
* Checks artifacts against 70+ antivirus engines
* Retrieves threat intelligence and detection statistics

### 📊 Dynamic Risk Assessment Engine

Automatically calculates:

* Risk Score (0–100)
* Detection Percentage
* Threat Severity Level

Risk Categories:

* ✅ Safe
* 🟢 Low Risk
* 🟡 Medium Risk
* 🟠 High Risk
* 🔴 Critical

### 🤖 AI-Powered Security Reports

Generates:

* Executive Summary
* Threat Analysis
* Risk Interpretation
* Security Recommendations

Powered by:

* Groq (Llama 3.3 70B)
* Intelligent fallback template when AI service is unavailable

### 🎨 Interactive Streamlit Interface

* Clean and responsive UI
* Real-time analysis feedback
* Easy-to-understand security insights

### ☁️ Cloud Deployment Ready

* Streamlit Cloud compatible
* Secure environment variable management
* GitHub integration

---

# 🛠️ Tech Stack

| Layer                  | Technology              |
| ---------------------- | ----------------------- |
| Frontend               | Streamlit               |
| Backend                | Python 3.9+             |
| Threat Intelligence    | VirusTotal API v3       |
| AI Report Generation   | Groq (Llama 3.3 70B)    |
| Environment Management | python-dotenv           |
| Deployment             | Streamlit Cloud, GitHub |

---

# 📦 Installation & Setup

## 1️⃣ Clone the Repository

```bash
git clone https://github.com/saketanalyst-eng/security-assessment-tool.git
cd security-assessment-tool
```

## 2️⃣ Create a Virtual Environment

### Linux / macOS

```bash
python -m venv venv
source venv/bin/activate
```

### Windows

```bash
python -m venv venv
venv\Scripts\activate
```

---

## 3️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 4️⃣ Configure API Keys

Create a `.env` file in the project root:

```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key
GROQ_API_KEY=your_groq_api_key
```

### Obtain API Keys

#### VirusTotal API Key

1. Create a free account at https://www.virustotal.com
2. Navigate to your profile settings
3. Copy your API key

#### Groq API Key

1. Create an account at https://console.groq.com
2. Generate a free API key
3. Add it to your `.env` file

---

## 5️⃣ Run the Application

```bash
streamlit run app.py
```

Application URL:

```text
http://localhost:8501
```

---

# ☁️ Deploy to Streamlit Cloud

## Step 1

Push your project to GitHub.

> Ensure `.env` is included in `.gitignore`.

## Step 2

Log in to Streamlit Cloud.

## Step 3

Click **New App** and select:

* Repository
* Branch
* Main File: `app.py`

## Step 4

Add Secrets

Navigate to:

```text
Settings → Secrets
```

Add:

```toml
VIRUSTOTAL_API_KEY="your_virustotal_key"
GROQ_API_KEY="your_groq_key"
```

## Step 5

Deploy

Click **Deploy**.

Your application will be available at:

```text
https://your-app-name.streamlit.app
```

---

# 🧠 System Architecture

```text
User Input (URL / IP / File)
            │
            ▼
      Streamlit UI
          (app.py)
            │
            ▼
   VirusTotal Client
 (virus_total_client.py)
            │
            ▼
      Risk Engine
    (risk_engine.py)
            │
            ▼
      AI Reporter
    (ai_report.py)
      ├── Groq API
      └── Template Fallback
            │
            ▼
      Results Display
```

---

# 📁 Project Structure

```text
security-assessment-tool/
│
├── app.py
├── virus_total_client.py
├── risk_engine.py
├── ai_report.py
├── requirements.txt
├── .env
├── .gitignore
├── README.md
│
└── assets/
    └── screenshots/
```

### File Descriptions

| File                  | Purpose                    |
| --------------------- | -------------------------- |
| app.py                | Streamlit frontend         |
| virus_total_client.py | VirusTotal API integration |
| risk_engine.py        | Risk score calculation     |
| ai_report.py          | AI report generation       |
| requirements.txt      | Python dependencies        |
| .env                  | API credentials            |
| README.md             | Project documentation      |

---

# 🎯 Usage Examples

## 🌐 Scan a URL

1. Enter a URL:

   ```text
   https://example.com
   ```

2. Click:

   ```text
   Scan URL
   ```

3. Review:

   * Detection results
   * Risk score
   * AI-generated security report

---

## 🌍 Scan an IP Address

1. Enter:

   ```text
   8.8.8.8
   ```

2. Click:

   ```text
   Scan IP
   ```

3. View:

   * Reputation data
   * Detection metrics
   * Threat assessment

---

## 📄 Scan a File

1. Upload:

   * EXE
   * ZIP
   * PDF
   * DOCX
   * Any supported file

2. Click:

   ```text
   Scan File
   ```

3. Review:

   * VirusTotal detections
   * Risk score
   * AI-powered analysis

---

# 📸 Screenshots

Add screenshots to showcase:

* Home Page
* URL Scan Results
* IP Scan Results
* File Analysis
* AI Security Report

Example:

```markdown
![Dashboard](assets/screenshots/dashboard.png)
```

---

# 🎥 Demo Video

Watch the complete walkthrough:

```text
https://youtu.be/YOUR_VIDEO_ID
```

The demo includes:

* Project Overview
* VirusTotal Integration
* Risk Scoring Logic
* AI Report Generation
* Live Demonstration
* Deployment Process

---

# 🧪 Sample Output

```text
Risk Score: 82/100

Threat Level: HIGH RISK

Detections:
18/92 Security Engines Flagged This Resource

AI Summary:
The scanned URL exhibits multiple malicious indicators,
including detections from reputable antivirus vendors.
Users should avoid interacting with the resource and
block it within enterprise environments.
```

---

# 🔒 Security Notes

* API keys are stored securely using environment variables.
* Sensitive credentials are excluded via `.gitignore`.
* File uploads are processed through VirusTotal's secure scanning infrastructure.
* No uploaded files are permanently stored by the application.

---

# 🤝 Contributing

Contributions are welcome.

1. Fork the repository
2. Create a feature branch

```bash
git checkout -b feature/new-feature
```

3. Commit changes

```bash
git commit -m "Add new feature"
```

4. Push branch

```bash
git push origin feature/new-feature
```

5. Open a Pull Request

---

# 📜 License

This project is licensed under the MIT License.

See the `LICENSE` file for details.

---

# 🙏 Acknowledgments

* VirusTotal for providing industry-leading threat intelligence APIs
* Groq for ultra-fast LLM inference
* Streamlit for rapid web application development
* Python open-source community for the supporting ecosystem

---

## 👨‍💻 Author

**Saket Pandey**

AI Engineer | Data Scientist | Machine Learning Enthusiast

GitHub: https://github.com/saketanalyst-eng

LinkedIn: https://linkedin.com/in/saketpandey

---

⭐ If you found this project useful, consider giving it a star on GitHub!
