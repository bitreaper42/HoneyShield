import math

def calculate_unified_threat_score(incident_record: dict) -> tuple:
    """
    Calculates a Unified Threat Score (0-100) using a Normalized Weighted Percentage Model
    by reading directly from the MongoDB incident record schema.
    """
    apk_data = incident_record.get("apk_analysis", {})
    osint_data = incident_record.get("osint_analysis", {})
    scanner_report = apk_data.get("scanner_json_report", {})
    
    # --- Extracted Fields ---
    permissions = scanner_report.get("permissions", [])
    base64_strings = scanner_report.get("suspicious_base64_strings", [])
    hardcoded_urls = scanner_report.get("hardcoded_urls", [])
    evasion_tactics = apk_data.get("evasion_tactics", [])
    
    # Dynamic/OSINT fields
    sandbox_behaviors = osint_data.get("sandbox_behaviors", [])
    c2_endpoints = osint_data.get("c2_endpoints_discovered", [])
    
    # --- 1. Permissions Percentage (P_perm) - Weight: 40% (0.40) ---
    perm_raw = 0
    if "android.permission.BIND_ACCESSIBILITY_SERVICE" in permissions: perm_raw += 20
    if "android.permission.SYSTEM_ALERT_WINDOW" in permissions: perm_raw += 15
    if any(p in permissions for p in ["android.permission.RECEIVE_SMS", "android.permission.READ_SMS", "android.permission.SEND_SMS"]): perm_raw += 15
    if "android.permission.READ_PHONE_STATE" in permissions: perm_raw += 10
    if "android.permission.RECEIVE_BOOT_COMPLETED" in permissions: perm_raw += 5
    if "android.permission.READ_CONTACTS" in permissions: perm_raw += 5
    if "android.permission.ACCESS_FINE_LOCATION" in permissions: perm_raw += 5
    
    p_perm = min((perm_raw / 75) * 100, 100)
    
    # --- 2. Network & C2 Percentage (P_net) - Weight: 35% (0.35) ---
    net_raw = 0
    if len(c2_endpoints) > 0: net_raw += 25
    
    # Check for Telegram/Firebase in signatures/tactics
    combined_sigs = " ".join(sandbox_behaviors + evasion_tactics).upper()
    if "TELEGRAM" in combined_sigs: net_raw += 25
    if "FIREBASE" in combined_sigs: net_raw += 15
    
    p_net = min((net_raw / 65) * 100, 100)
    
    # --- 3. Brand Impersonation Percentage (P_brand) - Weight: 15% (0.15) ---
    brand_spoofed = bool(apk_data.get("impersonated_brand")) or "SPOOF" in combined_sigs
    p_brand = 100 if brand_spoofed else 0
    
    # --- 4. Heuristics & Obfuscation Percentage (P_heur) - Weight: 10% (0.10) ---
    h_raw = (3 * len(base64_strings)) + (1 * len(hardcoded_urls))
    p_heur = (1 - math.exp(-h_raw / 10)) * 100
    
    # --- Master Formula Calculation ---
    master_score = (0.40 * p_perm) + (0.35 * p_net) + (0.15 * p_brand) + (0.10 * p_heur)
    rounded_score = round(master_score)
    
    # --- Determine Unified Verdict based on Score ---
    if rounded_score >= 75: verdict = "CRITICAL"
    elif rounded_score >= 50: verdict = "HIGH"
    elif rounded_score >= 25: verdict = "MEDIUM"
    else: verdict = "LOW"
        
    return rounded_score, verdict
