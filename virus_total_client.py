import requests
import time
import os
import sys
import hashlib  # <-- NEW: For calculating file hashes
from dotenv import load_dotenv
from risk_engine import calculate_risk
from ai_report import generate_ai_report   

# Load the API key from .env file
load_dotenv()
API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# VirusTotal API base URL
VT_API_URL = "https://www.virustotal.com/api/v3/"


# ---------- HELPER: Fetch analysis results by ID ----------
def get_analysis_results(analysis_id):
    """Poll VirusTotal for analysis results using the analysis ID."""
    url = VT_API_URL + f"analyses/{analysis_id}"
    headers = {"x-apikey": API_KEY}
    
    print("⏳ Waiting 20 seconds for analysis to complete...")
    time.sleep(20)
    
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        print(f"❌ Error fetching analysis: {response.text}")
        return None
    
    return response.json()


# ---------- PART 1: SCAN URL ----------
def scan_url(url):
    """Submit a URL to VirusTotal and get the scan results."""
    submit_url = VT_API_URL + "urls"
    headers = {"x-apikey": API_KEY}
    data = {"url": url}
    
    print(f"📤 Submitting URL: {url}")
    response = requests.post(submit_url, headers=headers, data=data)
    
    if response.status_code != 200:
        print(f"❌ Error submitting URL: {response.text}")
        return None
    
    scan_id = response.json()["data"]["id"]
    print(f"✅ Scan ID received: {scan_id}")
    
    report_data = get_analysis_results(scan_id)
    return report_data


# ---------- PART 2: SCAN IP ADDRESS ----------
def scan_ip(ip_address):
    """Check an IP address against VirusTotal's database."""
    url = VT_API_URL + f"ip_addresses/{ip_address}"
    headers = {"x-apikey": API_KEY}
    
    print(f"📤 Checking IP: {ip_address}")
    response = requests.get(url, headers=headers)
    
    if response.status_code == 404:
        print(f"ℹ️ IP {ip_address} not found in VirusTotal database (no history).")
        return {"data": {"attributes": {"last_analysis_stats": {"harmless": 0, "malicious": 0, "suspicious": 0, "undetected": 0}}}}
    elif response.status_code != 200:
        print(f"❌ Error checking IP: {response.text}")
        return None
    
    print("✅ IP report retrieved successfully!")
    return response.json()


# ---------- PART 3: SCAN FILE (FIXED - Handles Duplicates) ----------
def scan_file(file_path):
    """Upload and scan a file (EXE, ZIP, PDF, etc.) with VirusTotal.
       Handles duplicates gracefully using SHA-256 hash checking.
    """
    if not os.path.exists(file_path):
        print(f"❌ File not found: {file_path}")
        return None
    
    file_size = os.path.getsize(file_path)
    if file_size > 650 * 1024 * 1024:
        print(f"❌ File too large ({file_size / 1024 / 1024:.1f}MB). Max size is 650MB.")
        return None
    
    # --- STEP 1: Calculate SHA-256 hash of the file ---
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    file_hash = sha256_hash.hexdigest()
    print(f"🔑 File SHA-256: {file_hash}")
    
    headers = {"x-apikey": API_KEY}
    file_name = os.path.basename(file_path)
    
    # --- STEP 2: Check if VirusTotal already knows this file ---
    get_url = VT_API_URL + f"files/{file_hash}"
    print(f"📤 Checking if file already exists in VirusTotal...")
    response = requests.get(get_url, headers=headers)
    
    if response.status_code == 200:
        # Found in cache! Return the report immediately.
        print("✅ File found in VirusTotal cache. Retrieving report...")
        return response.json()
    
    elif response.status_code == 404:
        # Not found. Upload it.
        print("📤 File not in cache. Uploading...")
        upload_url = VT_API_URL + "files"
        with open(file_path, "rb") as f:
            files = {"file": (file_name, f, "application/octet-stream")}
            response = requests.post(upload_url, headers=headers, files=files)
        
        # Handle the "Already Submitted" error (409)
        if response.status_code == 409:
            print("⏳ File is already being scanned by VirusTotal. Waiting and retrying...")
            # Wait a bit and then try to fetch the report again
            time.sleep(30)
            retry_response = requests.get(get_url, headers=headers)
            if retry_response.status_code == 200:
                print("✅ Report retrieved after waiting.")
                return retry_response.json()
            else:
                print(f"❌ Retry failed: {retry_response.text}")
                return None
        
        elif response.status_code == 200:
            # Upload successful, get the analysis ID
            analysis_id = response.json()["data"]["id"]
            print(f"✅ File uploaded. Analysis ID: {analysis_id}")
            return get_analysis_results(analysis_id)
        
        else:
            print(f"❌ Error uploading file: {response.text}")
            return None
    
    else:
        print(f"❌ Error checking file existence: {response.text}")
        return None


# ---------- EXTRACT STATISTICS (Handles both URLs/Files AND IPs) ----------
def extract_stats(report_data):
    """Extract key threat stats from the VirusTotal report."""
    if not report_data:
        return None
    
    try:
        attributes = report_data["data"]["attributes"]
        
        # IMPORTANT: Check for both 'stats' (URLs/Files) and 'last_analysis_stats' (IPs)
        if 'stats' in attributes:
            stats = attributes['stats']
        elif 'last_analysis_stats' in attributes:
            stats = attributes['last_analysis_stats']
        else:
            print("❌ No statistics found in the report.")
            return None
        
        print("\n📊 Scan Statistics:")
        print(f"   ✅ Harmless: {stats.get('harmless', 0)}")
        print(f"   ⚠️ Suspicious: {stats.get('suspicious', 0)}")
        print(f"   ☢️ Malicious: {stats.get('malicious', 0)}")
        print(f"   🛑 Undetected: {stats.get('undetected', 0)}")
        return stats
        
    except KeyError as e:
        print(f"❌ Error parsing report: {e}")
        return None


# ---------- MAIN DISPATCHER ----------
def run_scan(input_type, input_value):
    """Run the appropriate scan based on input type."""
    print("\n" + "="*50)
    print(f"🔍 SCANNING {input_type.upper()}: {input_value}")
    print("="*50)
    
    if input_type == "url":
        report = scan_url(input_value)
    elif input_type == "ip":
        report = scan_ip(input_value)
    elif input_type == "file":
        report = scan_file(input_value)
    else:
        print(f"❌ Invalid input type: {input_type}")
        return
    
    if not report:
        print("❌ Scan failed. Please try again.")
        return
    
    stats = extract_stats(report)
    if stats:
        risk_result = calculate_risk(stats)
        print("\n🎯 RISK ASSESSMENT:")
        print(f"   Score: {risk_result['score']}/100")
        print(f"   Level: {risk_result['level']}")
        print(f"   Details: {risk_result['details']}")
    else:
        print("❌ Could not extract statistics from the report.")
            # --- GENERATE AI REPORT ---
    print("\n🤖 Generating AI-powered security report...")
    ai_report = generate_ai_report(input_type, input_value, risk_result)
    print("\n" + "="*50)
    print("📄 AI-GENERATED SECURITY REPORT")
    print("="*50)
    print(ai_report)    


# ---------- COMMAND LINE ARGUMENTS ----------
if __name__ == "__main__":
    print("🚀 VirusTotal Multi-Scanner")
    print(f"🔑 API Key loaded: {'✅' if API_KEY else '❌ Not found!'}")
    
    if not API_KEY:
        print("❌ Error: API key not found. Please check your .env file.")
        sys.exit(1)
    
    if len(sys.argv) >= 3:
        input_type = sys.argv[1].lower()
        input_value = sys.argv[2]
        run_scan(input_type, input_value)
    else:
        # --- DEMO MODE ---
        print("\n📋 No arguments provided. Running DEMO with all 3 test cases:\n")
        
        run_scan("url", "google.com")
        run_scan("ip", "8.8.8.8")
        
        test_file_path = "test_scan.txt"
        if not os.path.exists(test_file_path):
            with open(test_file_path, "w") as f:
                f.write("This is a test file for VirusTotal scanning.")
            print(f"📄 Created dummy test file: {test_file_path}")
        
        run_scan("file", test_file_path)
        
        print("\n✅ Demo complete! To scan your own inputs, run:")
        print("   python virus_total_client.py url example.com")
        print("   python virus_total_client.py ip 192.168.1.1")
        print("   python virus_total_client.py file C:/path/to/your/file.exe")