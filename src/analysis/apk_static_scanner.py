#!/usr/bin/env python3
# apk_static_scanner.py
# Standalone static analyzer for suspicious APKs.
# Scans AndroidManifest.xml, DEX files, and resources for indicators of compromise.

import os
import sys
import re
import zipfile
import json
import base64
import argparse

# Colors for terminal output
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
PURPLE = '\033[0;35m'
CYAN = '\033[0;36m'
NC = '\033[0m' # No Color
BOLD = '\033[1m'

# Target Regex Patterns
URL_PATTERN = re.compile(r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[a-zA-Z0-9_.-]*)*')
IP_PATTERN = re.compile(r'\b(?:[1-9][0-9]{0,2}\.){3}[0-9]{1,3}\b')
FIREBASE_PATTERN = re.compile(r'[a-zA-Z0-9-]+\.firebaseio\.com', re.IGNORECASE)
TELEGRAM_TOKEN_PATTERN = re.compile(r'[0-9]{8,10}:[a-zA-Z0-9_-]{35}')
BASE64_PATTERN = re.compile(r'\b[a-zA-Z0-9+/]{20,80}={0,2}\b')

# Exclusion list for standard framework domains
EXCLUDED_DOMAINS = [
    'schemas.android.com', 'w3.org', 'google.com', 'android.com', 
    'github.com', 'googleapis.com', 'apple.com', 'oracle.com'
]

# Dangerous Permissions List
DANGEROUS_PERMISSIONS = {
    'android.permission.READ_SMS': 'Allows app to read incoming SMS messages (commonly used for OTP theft).',
    'android.permission.SEND_SMS': 'Allows app to send SMS silently, causing billing costs or spam.',
    'android.permission.RECEIVE_SMS': 'Allows app to intercept incoming SMS (SMS Stealer).',
    'android.permission.READ_PHONE_STATE': 'Allows app to retrieve device unique IDs (IMEI/IMSI).',
    'android.permission.RECEIVE_BOOT_COMPLETED': 'Allows app to start automatically upon device boot (persistence).',
    'android.permission.SYSTEM_ALERT_WINDOW': 'Allows drawing overlays (used for fake login screens/credential harvesting).',
    'android.permission.READ_CONTACTS': 'Allows harvesting user contacts.',
    'android.permission.ACCESS_FINE_LOCATION': 'Allows tracking precise GPS location.'
}

def extract_strings_from_bytes(data, min_len=4):
    """Native string extraction supporting both UTF-8/ASCII and UTF-16LE binary XML formats."""
    strings = []
    
    # Try UTF-8 / ASCII
    try:
        text_utf8 = data.decode('utf-8', errors='ignore')
        words_utf8 = re.findall(r'[\x20-\x7E]{' + str(min_len) + ',}', text_utf8)
        strings.extend(words_utf8)
    except Exception:
        pass
        
    # Try UTF-16LE (very common in compiled Android XML/resource binaries)
    try:
        text_utf16 = data.decode('utf-16le', errors='ignore')
        words_utf16 = re.findall(r'[\x20-\x7E]{' + str(min_len) + ',}', text_utf16)
        strings.extend(words_utf16)
    except Exception:
        pass
        
    return list(set(s.strip() for s in strings))

def extract_package_name(manifest_strings):
    """Heuristic helper to resolve the main Android package name from binary XML string pool."""
    # Package names typically follow the format: com.example.app
    package_pattern = re.compile(r'^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+$')
    candidates = [s for s in manifest_strings if package_pattern.match(s)]
    
    if not candidates:
        return "unknown.package"
        
    # Heuristic: Sort by length (the main package name is typically the shortest base prefix)
    candidates.sort(key=len)
    for c in candidates:
        if c.startswith(('com.', 'org.', 'net.', 'io.', 'co.', 'in.', 'in_.')):
            return c
    return candidates[0]

def load_brands(config_path="config/monitored_brands.json", custom_brands_str=None):
    """Loads brand profiles (brand name mapped to allowed package substrings)."""
    # Default fallback profiles
    brands = {
        "sbi": ["sbi", "statebank"],
        "yono": ["sbi", "yono"],
        "paypal": ["paypal"],
        "chase": ["chase"],
        "hdfc": ["hdfc"],
        "icici": ["icici"],
        "binance": ["binance"],
        "coinbase": ["coinbase"],
        "stripe": ["stripe"],
        "hsbc": ["hsbc"]
    }
    
    # Try loading from configuration JSON
    if config_path and os.path.exists(config_path):
        try:
            with open(config_path, 'r') as f:
                data = json.load(f)
                if isinstance(data, dict) and "brands" in data:
                    brands = data["brands"]
                    print(f"[*] Loaded {len(brands)} brand definitions from: {config_path}")
        except Exception as e:
            print(f"{YELLOW}[!] Warning: Failed to parse brand config JSON ({str(e)}). Using default list.{NC}")
            
    # Apply CLI custom overrides (Format: brand1:pkg1,pkg2;brand2:pkg3)
    if custom_brands_str:
        try:
            for pair in custom_brands_str.split(';'):
                if not pair or ':' not in pair:
                    continue
                brand_name, pkgs_str = pair.split(':', 1)
                brands[brand_name.strip().lower()] = [p.strip().lower() for p in pkgs_str.split(',')]
            print(f"[*] Applied custom --brands override. Total monitored brands: {len(brands)}")
        except Exception as e:
            print(f"{YELLOW}[!] Warning: Failed to parse custom --brands flag ({str(e)}).{NC}")
            
    return brands

def scan_apk(apk_path, config_path="config/monitored_brands.json", custom_brands=None):
    if not os.path.exists(apk_path):
        print(f"{RED}[!] Error: File not found at {apk_path}{NC}")
        sys.exit(1)
        
    print(f"{CYAN}{BOLD}======================================================================{NC}")
    print(f"{CYAN}{BOLD}              HoneyShield Static APK Threat Analyzer                  {NC}")
    print(f"{CYAN}{BOLD}======================================================================{NC}")
    print(f"[*] Target APK: {BOLD}{os.path.basename(apk_path)}{NC}")
    
    results = {
        "file_name": os.path.basename(apk_path),
        "file_size_mb": round(os.path.getsize(apk_path) / (1024 * 1024), 2),
        "package_name": "unknown.package",
        "detections": {
            "permissions": [],
            "brand_mismatch_warnings": [],
            "brand_matches": [],
            "urls": [],
            "firebase": [],
            "telegram": [],
            "ips": [],
            "base64": []
        },
        "risk_score": 0,
        "risk_level": "LOW"
    }
    
    try:
        with zipfile.ZipFile(apk_path, 'r') as zip_ref:
            namelist = zip_ref.namelist()
            
            # Read AndroidManifest.xml strings
            manifest_strings = []
            if 'AndroidManifest.xml' in namelist:
                manifest_data = zip_ref.read('AndroidManifest.xml')
                manifest_strings = extract_strings_from_bytes(manifest_data)
                
            # Read DEX files
            dex_strings = []
            for name in namelist:
                if name.endswith('.dex'):
                    print(f"[*] Extracting strings from classes container: {name}...")
                    dex_data = zip_ref.read(name)
                    dex_strings.extend(extract_strings_from_bytes(dex_data))
            
            # Read resources
            resources_strings = []
            if 'resources.arsc' in namelist:
                res_data = zip_ref.read('resources.arsc')
                resources_strings = extract_strings_from_bytes(res_data)
                
            all_strings = list(set(manifest_strings + dex_strings + resources_strings))
            
            # Extract main package name
            package_name = extract_package_name(manifest_strings)
            print(f"[*] Detected Android Package Name: {BOLD}{package_name}{NC}")
            results["package_name"] = package_name
            
            # --- 1. SCAN PERMISSIONS ---
            print(f"\n{BLUE}[*] Auditing Android Permissions...{NC}")
            found_permissions = []
            for s in all_strings:
                if s in DANGEROUS_PERMISSIONS:
                    found_permissions.append(s)
            
            if found_permissions:
                for perm in found_permissions:
                    desc = DANGEROUS_PERMISSIONS[perm]
                    print(f"  {RED}[!] Dangerous Permission found:{NC} {perm}")
                    print(f"      Description: {desc}")
                    results["detections"]["permissions"].append({"permission": perm, "description": desc})
                    results["risk_score"] += 15
            else:
                print(f"  {GREEN}[✔] No highly dangerous permissions flagged in manifest.{NC}")
                
            # --- 2. GENERALIZED BRAND AUDIT (IMPERSONATION DETECTION) ---
            print(f"\n{BLUE}[*] Auditing Brand References & Package Mismatch...{NC}")
            brands_dict = load_brands(config_path, custom_brands)
            detected_brand_warnings = []
            detected_brand_matches = []
            
            for brand_keyword, allowed_packages in brands_dict.items():
                brand_found = False
                brand_regex = re.compile(r'\b' + re.escape(brand_keyword) + r'\b', re.IGNORECASE)
                
                for s in all_strings:
                    # Filter out excessively long class declarations
                    if len(s) < 50 and brand_regex.search(s):
                        brand_found = True
                        break
                        
                if brand_found:
                    # Check package name match
                    package_match = any(pkg_sub in package_name.lower() for pkg_sub in allowed_packages)
                    
                    if package_match:
                        detected_brand_matches.append({
                            "brand": brand_keyword,
                            "allowed_substrings": allowed_packages
                        })
                        print(f"  {GREEN}[✔] Brand Reference Match:{NC} Brand \"{brand_keyword}\" referenced, package name is \"{package_name}\".")
                    else:
                        detected_brand_warnings.append({
                            "brand": brand_keyword,
                            "allowed_substrings": allowed_packages
                        })
                        print(f"  {RED}[!] BRAND IMPERSONATION WARNING: Brand \"{brand_keyword}\" referenced in strings, but package name \"{package_name}\" does not match expected patterns ({', '.join(allowed_packages)}).{NC}")
                        results["risk_score"] += 30
            
            results["detections"]["brand_mismatch_warnings"] = detected_brand_warnings
            results["detections"]["brand_matches"] = detected_brand_matches
            
            if not detected_brand_warnings and not detected_brand_matches:
                print(f"  {GREEN}[✔] No monitored brand references detected.{NC}")
                
            # --- 3. SCAN TELEGRAM BOT TOKENS ---
            print(f"\n{BLUE}[*] Auditing Telegram Bot API Tokens...{NC}")
            found_telegram = []
            for s in all_strings:
                match = TELEGRAM_TOKEN_PATTERN.search(s)
                if match:
                    token = match.group(0)
                    if token not in found_telegram:
                        found_telegram.append(token)
                        
            if found_telegram:
                print(f"  {RED}[!] CRITICAL: Hardcoded Telegram Bot Token(s) Detected (indicators of spyware/exfiltration):{NC}")
                for token in found_telegram:
                    print(f"      - {token}")
                    results["detections"]["telegram"].append(token)
                results["risk_score"] += 35
            else:
                print(f"  {GREEN}[✔] No Telegram Bot API tokens found.{NC}")
                
            # --- 4. SCAN FIREBASE ENDPOINTS ---
            print(f"\n{BLUE}[*] Checking for Firebase Endpoints...{NC}")
            found_firebase = []
            for s in all_strings:
                match = FIREBASE_PATTERN.search(s)
                if match:
                    fb = match.group(0)
                    if fb not in found_firebase:
                        found_firebase.append(fb)
                        
            if found_firebase:
                print(f"  {RED}[!] Firebase Backend Endpoints Detected (potential exfiltration point):{NC}")
                for fb in found_firebase:
                    print(f"      - https://{fb}")
                    results["detections"]["firebase"].append(fb)
                results["risk_score"] += 15
            else:
                print(f"  {GREEN}[✔] No Firebase endpoints detected.{NC}")
                
            # --- 5. SCAN HARDCODED URLS ---
            print(f"\n{BLUE}[*] Checking for Hardcoded HTTP/HTTPS URLs...{NC}")
            found_urls = []
            for s in all_strings:
                match = URL_PATTERN.search(s)
                if match:
                    url = match.group(0)
                    is_excluded = any(domain in url.lower() for domain in EXCLUDED_DOMAINS)
                    if not is_excluded and url not in found_urls:
                        found_urls.append(url)
                        
            if found_urls:
                print(f"  {YELLOW}[!] Hardcoded third-party URLs detected:{NC}")
                for url in found_urls:
                    print(f"      - {url}")
                    results["detections"]["urls"].append(url)
                results["risk_score"] += 5
            else:
                print(f"  {GREEN}[✔] No suspicious hardcoded URLs found.{NC}")
                
            # --- 6. SCAN HARDCODED IP ADDRESSES ---
            print(f"\n{BLUE}[*] Checking for Hardcoded IPv4 Addresses...{NC}")
            found_ips = []
            for s in all_strings:
                match = IP_PATTERN.search(s)
                if match:
                    ip = match.group(0)
                    if ip not in ['127.0.0.1', '0.0.0.0', '255.255.255.255'] and not ip.startswith('192.168.') and ip not in found_ips:
                        try:
                            octets = list(map(int, ip.split('.')))
                            if all(0 <= o <= 255 for o in octets):
                                found_ips.append(ip)
                        except ValueError:
                            pass
                            
            if found_ips:
                print(f"  {RED}[!] Hardcoded Public IP Addresses Detected (often used for direct C2 connections):{NC}")
                for ip in found_ips:
                    print(f"      - {ip}")
                    results["detections"]["ips"].append(ip)
                results["risk_score"] += 15
            else:
                print(f"  {GREEN}[✔] No hardcoded public IP addresses found.{NC}")
                
            # --- 7. SCAN SUSPICIOUS BASE64 PAYLOADS ---
            print(f"\n{BLUE}[*] Analyzing Suspicious Base64 Strings...{NC}")
            found_b64 = []
            for s in all_strings:
                match = BASE64_PATTERN.search(s)
                if match:
                    b64_str = match.group(0)
                    try:
                        decoded = base64.b64decode(b64_str).decode('utf-8', errors='ignore')
                        indicators = ['http://', 'https://', 'chmod', 'system/bin', 'sh', 'apk', 'curl', 'wget', 'android/']
                        if any(ind in decoded.lower() for ind in indicators) and b64_str not in found_b64:
                            found_b64.append((b64_str, decoded.strip()))
                    except Exception:
                        pass
                        
            if found_b64:
                print(f"  {RED}[!] ALERT: Decoded suspicious Base64 encoded payload:{NC}")
                for original, decoded in found_b64:
                    print(f"      - Original: \"{original}\"")
                    print(f"        Decoded:  \"{decoded}\"")
                    results["detections"]["base64"].append({"raw": original, "decoded": decoded})
                results["risk_score"] += 20
            else:
                print(f"  {GREEN}[✔] No suspicious Base64 encoded payloads detected.{NC}")
                
        # --- RISK SCORE EVALUATION ---
        results["risk_score"] = min(results["risk_score"], 100)
        
        if results["risk_score"] >= 60:
            results["risk_level"] = "CRITICAL / HIGH RISK"
            color = RED
        elif results["risk_score"] >= 25:
            results["risk_level"] = "MEDIUM RISK"
            color = YELLOW
        else:
            results["risk_level"] = "LOW RISK"
            color = GREEN
            
        print(f"\n{CYAN}{BOLD}======================================================================{NC}")
        print(f"{BOLD}Scan Summary for {results['file_name']}:{NC}")
        print(f"  Risk Score: {color}{BOLD}{results['risk_score']}/100{NC}")
        print(f"  Risk Level: {color}{BOLD}{results['risk_level']}{NC}")
        print(f"{CYAN}{BOLD}======================================================================{NC}")
        
        output_json_path = "data/outputs/apk_scan_results.json"
        with open(output_json_path, "w") as jf:
            json.dump(results, jf, indent=4)
        print(f"[+] Static scan JSON results saved to: {output_json_path}\n")
        
    except zipfile.BadZipFile:
        print(f"{RED}[!] Error: File is not a valid zip container (corrupt APK).{NC}")
        sys.exit(1)
    except Exception as e:
        print(f"{RED}[!] Error during static analysis: {str(e)}{NC}")
        sys.exit(1)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HoneyShield Static APK Threat Analyzer")
    parser.add_argument("apk_path", help="Path to the target APK file to analyze")
    parser.add_argument("--brands-config", default="config/monitored_brands.json", help="Path to the JSON brands config file (default: config/monitored_brands.json)")
    parser.add_argument("--brands", help="Custom brand specifications override. Format: 'brand1:pkg1,pkg2;brand2:pkg3'")
    
    args = parser.parse_args()
    scan_apk(args.apk_path, args.brands_config, args.brands)
    
    # Trigger next pipeline step: apk_dynamic_sandbox.py
    import subprocess
    print(f"\n[*] Triggering next pipeline step: apk_dynamic_sandbox.py...")
    subprocess.run([sys.executable, "src/analysis/apk_dynamic_sandbox.py", args.apk_path], check=True)

