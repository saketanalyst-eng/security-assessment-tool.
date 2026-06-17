def calculate_risk(scan_stats):
    """
    Calculate risk score and level based on VirusTotal scan statistics.
    
    Args:
        scan_stats (dict): Contains 'malicious', 'suspicious', 'harmless', 'undetected' counts
        
    Returns:
        dict: Contains 'score' (0-100) and 'level' (string)
    """
    # Extract numbers from the stats
    malicious = scan_stats.get('malicious', 0)
    suspicious = scan_stats.get('suspicious', 0)
    harmless = scan_stats.get('harmless', 0)
    undetected = scan_stats.get('undetected', 0)
    
    # Start with a score of 0
    score = 0
    
    # Rule 1: Malware Detection (+40 points)
    # If any antivirus flagged it as malicious, it's serious
    if malicious > 0:
        score += 40
    
    # Rule 2: Phishing Detection (+30 points)
    # We don't have a dedicated "phishing" count from the basic stats,
    # but if it's suspicious AND not harmful, we treat it as phishing-like
    if suspicious > 0 and harmless == 0:
        score += 30
    
    # Rule 3: Malicious Domain (+20 points)
    # If more than 3 engines flag it as malicious, it's definitely a bad domain
    if malicious >= 3:
        score += 20
    elif malicious >= 1:
        score += 10  # Partial for just 1-2 detections
    
    # Rule 4: Suspicious Reputation (+10 points)
    # If there are suspicious flags but no malicious ones
    if suspicious > 0 and malicious == 0:
        score += 10
    
    # Rule 5: If it's completely clean (no malicious, no suspicious), score stays 0
    # Safety check: Cap the score at 100 so it doesn't exceed 100
    final_score = min(score, 100)
    
    # Determine Risk Level based on final score
    if final_score == 0:
        level = "✅ Safe"
    elif final_score <= 20:
        level = "🟢 Low Risk"
    elif final_score <= 40:
        level = "🟡 Medium Risk"
    elif final_score <= 70:
        level = "🟠 High Risk"
    else:
        level = "🔴 Critical"
    
    return {
        "score": final_score,
        "level": level,
        "details": {
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected
        }
    }


# -------- TEST THE RISK ENGINE ----------
if __name__ == "__main__":
    # Simulate a safe scan (like Google.com)
    safe_stats = {"harmless": 70, "malicious": 0, "suspicious": 0, "undetected": 1}
    print("Test 1 - Safe Website:")
    result1 = calculate_risk(safe_stats)
    print(f"Score: {result1['score']} | Level: {result1['level']}")
    
    # Simulate a suspicious scan (some detections)
    suspicious_stats = {"harmless": 40, "malicious": 2, "suspicious": 5, "undetected": 3}
    print("\nTest 2 - Suspicious Website:")
    result2 = calculate_risk(suspicious_stats)
    print(f"Score: {result2['score']} | Level: {result2['level']}")
    
    # Simulate a dangerous scan (many detections)
    dangerous_stats = {"harmless": 10, "malicious": 15, "suspicious": 20, "undetected": 5}
    print("\nTest 3 - Dangerous Website:")
    result3 = calculate_risk(dangerous_stats)
    print(f"Score: {result3['score']} | Level: {result3['level']}")