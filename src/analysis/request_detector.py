#!/usr/bin/env python3
# request_detector.py
# Programmatically detects the request method, endpoints, and parameters 
# associated with the suspicious C2 domain in the HoneyShield project.

import os
import sys
import re
import zipfile
import json
import requests
import hashlib
from urllib.parse import urlparse

# Ensure correct package import path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))
from src.analysis.credential_store import get_or_create_credentials

# Colors for terminal output
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
CYAN = '\033[0;36m'
NC = '\033[0m'
BOLD = '\033[1m'

URL_PATTERN = re.compile(r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::\d+)?(?:/(?:(?!https?://)[^\s<>"\'\]{}();,])*)?', re.IGNORECASE)

def extract_strings_from_bytes(data):
    """Extract printable ASCII strings from binary byte files."""
    try:
        text = data.decode('utf-8', errors='ignore')
        return re.findall(r'[\x20-\x7E]{3,100}', text)
    except Exception:
        return []

def scan_bundle_for_url_and_params(apk_path, suspicious_domains):
    """Scans the APK assets for suspicious URLs and parameter references."""
    print(f"[*] Analyzing APK file: {apk_path}")
    if not os.path.exists(apk_path):
        raise FileNotFoundError(f"APK file not found at {apk_path}")
        
    extracted_urls = []
    
    with zipfile.ZipFile(apk_path, 'r') as zip_ref:
        namelist = zip_ref.namelist()
        
        # Focus on the javascript bundle asset
        bundle_path = 'assets/index.android.bundle'
        if bundle_path not in namelist:
            raise FileNotFoundError(f"React Native asset bundle {bundle_path} not found in the APK.")
            
        data = zip_ref.read(bundle_path)
        strings = extract_strings_from_bytes(data)
        
        for s in strings:
            # Extract URLs matching the pattern
            urls = URL_PATTERN.findall(s)
            for url in urls:
                for sd in suspicious_domains:
                    if sd in url:
                        extracted_urls.append(url)
                        break
                        
    # Resolve unique URLs
    extracted_urls = sorted(list(set(extracted_urls)))
    return extracted_urls

def probe_endpoint(base_url, path, credentials=None):
    """Probes a candidate endpoint path with GET and POST requests to detect routes."""
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    print(f"\n[*] Probing candidate route: {url}")
    
    detected_method = None
    response_payload = None
    
    # 1. Probe with POST (common for logins)
    try:
        headers = {"Content-Type": "application/json"}
        # Send dynamic credentials if available, otherwise use default mock credentials
        test_payload = credentials if credentials else {"username": "test_user", "password": "test_password"}
        resp = requests.post(url, json=test_payload, headers=headers, timeout=8)
        
        print(f"    [POST] Status Code: {resp.status_code}")
        # Express route mismatch typically yields a 404 with "Cannot POST /route"
        if resp.status_code == 200:
            print(f"    {GREEN}[✔] Success response received on POST!{NC}")
            detected_method = "POST"
            response_payload = resp.text
        elif "Cannot POST" in resp.text:
            print(f"    [POST] Route rejected (Cannot POST error).")
    except Exception as e:
        print(f"    [POST] Connection failed: {e}")
        
    # 2. Probe with GET (fallback/check)
    try:
        resp = requests.get(url, timeout=8)
        print(f"    [GET] Status Code: {resp.status_code}")
        if resp.status_code == 200 and detected_method is None:
            print(f"    {GREEN}[✔] Success response received on GET!{NC}")
            detected_method = "GET"
            response_payload = resp.text
        elif "Cannot GET" in resp.text:
            print(f"    [GET] Route rejected (Cannot GET error).")
    except Exception as e:
        print(f"    [GET] Connection failed: {e}")
        
    return detected_method, response_payload, test_payload if detected_method == "POST" else None

def main():
    print(f"{CYAN}======================================================================{NC}")
    print(f"{CYAN}               HoneyShield C2 Request Detector Tool                   {NC}")
    print(f"{CYAN}======================================================================{NC}")
    
    apk_path = "data/inputs/sample.apk"
    if len(sys.argv) > 1:
        apk_path = sys.argv[1]
        
    hunted_report = "data/outputs/hunted_domains.json"
    if not os.path.exists(hunted_report):
        print(f"{RED}[!] Error: Hunted domains report not found at {hunted_report}.{NC}")
        print(f"[*] Please run 'python3 src/analysis/domain_hunter.py {apk_path}' first to identify suspicious domains.")
        sys.exit(1)
        
    try:
        with open(hunted_report, 'r') as f:
            report_data = json.load(f)
            suspicious_domains = report_data.get("suspicious_domains", [])
    except Exception as e:
        print(f"{RED}[!] Error reading {hunted_report}: {e}{NC}")
        sys.exit(1)
        
    if not suspicious_domains:
        print(f"{RED}[!] No suspicious domains found in {hunted_report}.{NC}")
        sys.exit(1)
        
    print(f"[*] Loaded suspicious domains from hunted report: {suspicious_domains}")
    
    try:
        # Calculate SHA-256 hash of the target APK to fetch/generate unique credentials
        credentials = None
        try:
            sha256 = hashlib.sha256()
            with open(apk_path, 'rb') as f:
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    sha256.update(chunk)
            apk_hash = sha256.hexdigest()
            print(f"[*] Target APK SHA-256: {apk_hash}")
            credentials = get_or_create_credentials(apk_hash)
            print(f"[*] Loaded threat credentials: {credentials}")
        except Exception as e:
            print(f"{YELLOW}[!] Failed to load credentials from Redis: {e}. Using defaults.{NC}")

        urls = scan_bundle_for_url_and_params(apk_path, suspicious_domains)
        
        if not urls:
            print(f"{RED}[!] No URLs matching suspicious domains extracted from the APK.{NC}")
            sys.exit(1)
            
        print(f"{GREEN}[✔] Extracted C2 URL String from Bundle: {urls[0]}{NC}")
        
        # De-concatenate and extract base domain
        parsed_url = urlparse(urls[0])
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        print(f"[*] Isolated Base C2 Server: {base_url}")
        
        # Define candidate endpoint paths to test
        # We test both the parsed path and the common API login paths
        candidates = ["login", "login-variant", "auth", "otp"]
        parsed_path = parsed_url.path.lstrip('/')
        if parsed_path and parsed_path not in candidates:
            candidates.insert(0, parsed_path)
            
        # Clean candidates list
        candidates = sorted(list(set([c.split('arrow')[0].split('tps')[0].strip() for c in candidates if c])))
        
        print(f"[*] Candidate endpoints to probe: {candidates}")
        
        detection_results = {
            "c2_base_url": base_url,
            "probed_endpoints": []
        }
        
        # Probe all candidate endpoints to detect method and active routes
        for path in candidates:
            method, payload, params = probe_endpoint(base_url, path, credentials)
            if method:
                endpoint_info = {
                    "endpoint": f"/{path}",
                    "method": method,
                    "status": "ACTIVE",
                    "response": payload
                }
                if method == "POST" and params:
                    endpoint_info["params"] = params
                detection_results["probed_endpoints"].append(endpoint_info)
                
        print(f"\n{CYAN}======================================================================{NC}")
        print(f"Detections Analysis Summary:")
        if not detection_results["probed_endpoints"]:
            print(f"  {RED}[!] No active endpoints detected during API probes.{NC}")
        else:
            for endpoint in detection_results["probed_endpoints"]:
                print(f"  {GREEN}[✔] Active Endpoint:{NC} {base_url}{endpoint['endpoint']}")
                print(f"      Method: {BOLD}{endpoint['method']}{NC}")
                if "params" in endpoint:
                    print(f"      Parameters: {BOLD}{json.dumps(endpoint['params'])}{NC}")
                print(f"      Response Template: {endpoint['response']}")
        print(f"{CYAN}======================================================================{NC}")
        
        # Save results
        output_path = "data/outputs/c2_detection_report.json"
        with open(output_path, "w") as f:
            json.dump(detection_results, f, indent=4)
        print(f"[+] Detection report saved to: {output_path}\n")
        
    except Exception as e:
        print(f"{RED}[!] Error during detection: {e}{NC}")
        sys.exit(1)

if __name__ == "__main__":
    main()
