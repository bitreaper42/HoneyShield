#!/usr/bin/env python3
# apk_static_scanner.py
# Standalone static analyzer for suspicious APKs.
# Scans AndroidManifest.xml, DEX files, and resources for indicators of compromise.

import os
import sys
import re
import subprocess
import zipfile
import json
import base64
import argparse

# Shared utilities (colours, path bootstrap, string extractor)
from src.analysis import (extract_strings_from_bytes)
from src.Database_manager.db_manager import update_incident_record

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
            print(f" Warning: Failed to parse brand config JSON ({str(e)}). Using default list.")
            
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
            print(f" Warning: Failed to parse custom --brands flag {str(e)}.")
            
    return brands

def scan_apk(apk_path, config_path="config/monitored_brands.json", custom_brands=None):
    if not os.path.exists(apk_path):
        raise Exception(f"File not found at {apk_path}")
    print(f"[*] Target APK: os.path.basename(apk_path)")
    
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
        "accessibility_abuse_detected": False,
        "evasion_tactics": []
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
            print(f"[*] Detected Android Package Name: {package_name}")
            results["package_name"] = package_name
            
            # --- 1. SCAN PERMISSIONS ---
            print(f"\n Auditing Android Permissions..")
            found_permissions = []
            for s in all_strings:
                if s == 'android.permission.BIND_ACCESSIBILITY_SERVICE':
                    print(f"[!] ATTACKER EVASION DETECTED:BIND_ACCESSIBILITY_SERVICE found!")
                    results["accessibility_abuse_detected"] = True
                    if "BIND_ACCESSIBILITY_SERVICE" not in results["evasion_tactics"]:
                        results["evasion_tactics"].append("BIND_ACCESSIBILITY_SERVICE")
                
                if s in DANGEROUS_PERMISSIONS:
                    found_permissions.append(s)
            
            if found_permissions:
                for perm in found_permissions:
                    desc = DANGEROUS_PERMISSIONS[perm]
                    print(f"  [!] Dangerous Permission found: {perm}")
                    print(f"      Description: {desc}")
                    results["detections"]["permissions"].append({"permission": perm, "description": desc})
                
            # --- 2. GENERALIZED BRAND AUDIT (IMPERSONATION DETECTION) ---
            print(f" Auditing Brand References & Package Mismatch...")
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
                        print(f"   Brand Reference Match: Brand \"{brand_keyword}\" referenced, package name is \"{package_name}\".")
                    else:
                        detected_brand_warnings.append({
                            "brand": brand_keyword,
                            "allowed_substrings": allowed_packages
                        })
            
            results["detections"]["brand_mismatch_warnings"] = detected_brand_warnings
            results["detections"]["brand_matches"] = detected_brand_matches
                
            # --- 3. SCAN TELEGRAM BOT TOKENS ---
            print(f"\n Auditing Telegram Bot API Tokens...")
            found_telegram = []
            for s in all_strings:
                match = TELEGRAM_TOKEN_PATTERN.search(s)
                if match:
                    token = match.group(0)
                    if token not in found_telegram:
                        found_telegram.append(token)
                        
            if found_telegram:
                print(f"  CRITICAL: Hardcoded Telegram Bot Token(s) Detected (indicators of spyware/exfiltration)")
                for token in found_telegram:
                    print(f"      - {token}")
                    results["detections"]["telegram"].append(token)
                
            # --- 4. SCAN FIREBASE ENDPOINTS ---
            print(f"\n Checking for Firebase Endpoints...")
            found_firebase = []
            for s in all_strings:
                match = FIREBASE_PATTERN.search(s)
                if match:
                    fb = match.group(0)
                    if fb not in found_firebase:
                        found_firebase.append(fb)
                        
            if found_firebase:
                print(f" Firebase Backend Endpoints Detected (potential exfiltration point):")
                for fb in found_firebase:
                    print(f"      - https://{fb}")
                    results["detections"]["firebase"].append(fb)
                
            # --- 5. SCAN HARDCODED URLS ---
            print(f"\n Checking for Hardcoded HTTP/HTTPS URLs...")
            found_urls = []
            for s in all_strings:
                match = URL_PATTERN.search(s)
                if match:
                    url = match.group(0)
                    is_excluded = any(domain in url.lower() for domain in EXCLUDED_DOMAINS)
                    if not is_excluded and url not in found_urls:
                        found_urls.append(url)
                        
            if found_urls:
                print(f"  [!] Hardcoded third-party URLs detected:")
                for url in found_urls:
                    print(f"      - {url}")
                    results["detections"]["urls"].append(url)
            else:
                print(f" No suspicious hardcoded URLs found.")
                
            # --- 6. SCAN HARDCODED IP ADDRESSES ---
            print(f"Checking for Hardcoded IPv4 Addresses...")
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
                print(f"  [!] Hardcoded Public IP Addresses Detected (often used for direct C2 connections):")
                for ip in found_ips:
                    print(f"      - {ip}")
                    results["detections"]["ips"].append(ip)
            else:
                print(f"  [✔] No hardcoded public IP addresses found.")
                
            # --- 7. SCAN SUSPICIOUS BASE64 PAYLOADS ---
            print(f"\n[*] Analyzing Suspicious Base64 Strings...")
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
                print(f"  [!] ALERT: Decoded suspicious Base64 encoded payload:")
                for original, decoded in found_b64:
                    print(f"      - Original: \"{original}\"")
                    print(f"        Decoded:  \"{decoded}\"")
                    results["detections"]["base64"].append({"raw": original, "decoded": decoded})
            else:
                print(f"  [✔] No suspicious Base64 encoded payloads detected.")
        
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
        output_json_path = os.path.join(project_root, "data/outputs/apk_scan_results.json")
        with open(output_json_path, "w") as jf:
            json.dump(results, jf, indent=4)
        print(f"[+] Static scan JSON results saved to: {output_json_path}\n")
        
        return results
        
    except zipfile.BadZipFile:
        raise Exception("File is not a valid zip container (corrupt APK).")
    except Exception as e:
        raise Exception(f"Error during static analysis: {str(e)}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HoneyShield Static APK Threat Analyzer")
    parser.add_argument("apk_path", help="Path to the target APK file to analyze")
    parser.add_argument("--brands-config", default="config/monitored_brands.json", help="Path to the JSON brands config file (default: config/monitored_brands.json)")
    parser.add_argument("--brands", help="Custom brand specifications override. Format: 'brand1:pkg1,pkg2;brand2:pkg3'")
    
    args = parser.parse_args()
    
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
    brands_config_abs = os.path.join(project_root, args.brands_config) if not os.path.isabs(args.brands_config) else args.brands_config
    
    try:
        results = scan_apk(args.apk_path, brands_config_abs, args.brands)
        print("Static analysis completed successfully.")
    except Exception as e:
        print(f"Error: {e}")

