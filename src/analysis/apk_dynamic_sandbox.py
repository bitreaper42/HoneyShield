#!/usr/bin/env python3
# apk_dynamic_sandbox.py
# Dynamically analyzes suspicious APKs using the VirusTotal API v3.
# Extracts live dynamic network telemetry (IP connections, DNS query domains, HTTP calls, behavior flags).

import os
import sys
import time
import json
import hashlib
import requests

# Colors for terminal output
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
PURPLE = '\033[0;35m'
CYAN = '\033[0;36m'
NC = '\033[0m' # No Color
BOLD = '\033[1m'

VT_API_URL = "https://www.virustotal.com/api/v3"

def load_env_key():
    """Reads the VirusTotal API key from environment variables or .env file."""
    key = os.environ.get('VT_API_KEY')
    if key:
        return key
        
    if os.path.exists('.env'):
        try:
            with open('.env', 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith('VT_API_KEY='):
                        parts = line.split('=', 1)
                        if len(parts) > 1:
                            return parts[1].strip().strip('"').strip("'")
        except Exception:
            pass
    return None

def calculate_sha256(filepath):
    """Calculates the SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()

def get_file_info(sha256, api_key):
    """Queries basic file metadata from VirusTotal."""
    print(f"[*] Querying VirusTotal database for file metadata: {sha256}...")
    url = f"{VT_API_URL}/files/{sha256}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            return response.json().get("data", {}).get("attributes", {})
        elif response.status_code == 404:
            print("[INFO] File hash not yet indexed in VirusTotal database.")
            return None
        else:
            response.raise_for_status()
    except Exception as e:
        print(f"{YELLOW}[!] Error searching database by file hash: {str(e)}{NC}")
        raise e
    return None

def get_behaviour_summary(sha256, api_key):
    """Fetches the consolidated behaviour summary for a file hash from VirusTotal."""
    print(f"[*] Fetching consolidated behaviour summary for: {sha256}...")
    url = f"{VT_API_URL}/files/{sha256}/behaviour_summary"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }
    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json().get("data")
            if data is not None and isinstance(data, dict):
                return data.get("attributes", {})
            return {}
        elif response.status_code in [204, 404]:
            print("[INFO] No behaviour summary reports found for this file.")
            return {}
        else:
            response.raise_for_status()
    except Exception as e:
        print(f"{YELLOW}[!] Error retrieving behaviour summary: {str(e)}{NC}")
        raise e
    return {}

def upload_file_to_vt(apk_path, api_key):
    """Uploads an APK to VirusTotal, handling files larger than 32MB."""
    file_size = os.path.getsize(apk_path)
    headers = {
        "x-apikey": api_key
    }
    
    if file_size < 32 * 1024 * 1024:
        print(f"[*] Uploading file directly to VT (size: {file_size / (1024 * 1024):.2f} MB)...")
        url = f"{VT_API_URL}/files"
    else:
        print(f"[*] File size >= 32MB ({file_size / (1024 * 1024):.2f} MB). Requesting dedicated large file upload URL...")
        upload_url_endpoint = f"{VT_API_URL}/files/upload_url"
        resp = requests.get(upload_url_endpoint, headers=headers, timeout=15)
        resp.raise_for_status()
        url = resp.json().get("data")
        if not url:
            raise Exception("Failed to retrieve dynamic upload URL from VirusTotal.")
        print(f"[*] Dedicated upload URL retrieved successfully.")
        
    with open(apk_path, "rb") as f:
        files = {"file": (os.path.basename(apk_path), f, "application/octet-stream")}
        response = requests.post(url, headers=headers, files=files, timeout=180)
        
    response.raise_for_status()
    analysis_data = response.json().get("data", {})
    analysis_id = analysis_data.get("id")
    if not analysis_id:
        raise Exception("Upload succeeded but no analysis ID was returned by VirusTotal.")
    return analysis_id

def poll_analysis_status(analysis_id, api_key, max_wait_sec=360, poll_interval=45):
    """Polls the status of a VT analysis until completed or timed out."""
    url = f"{VT_API_URL}/analyses/{analysis_id}"
    headers = {
        "x-apikey": api_key
    }
    
    start_time = time.time()
    print(f"[*] Monitoring dynamic analysis progress (polling every {poll_interval}s)...")
    
    while time.time() - start_time < max_wait_sec:
        time.sleep(poll_interval)
        print(f"    Checking status at {time.strftime('%H:%M:%S')}...")
        try:
            resp = requests.get(url, headers=headers, timeout=15)
            resp.raise_for_status()
            data = resp.json().get("data", {})
            status = data.get("attributes", {}).get("status")
            
            print(f"    Current status: {status}")
            if status == "completed":
                return True
            elif status == "failed":
                print(f"{RED}[!] VirusTotal analysis failed on the server side.{NC}")
                return False
        except Exception as e:
            print(f"    {YELLOW}[Warning] Error polling status: {e}{NC}")
            
    print(f"{RED}[!] Dynamic analysis polling timed-out after {max_wait_sec}s.{NC}")
    return False

def parse_behaviour_report(file_attr, behaviour_attr, sha256):
    """Parses VT file metadata and behaviour summary into standard HoneyShield JSON format."""
    stats = file_attr.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected
    
    threat_score = 0
    if total > 0:
        threat_score = int(((malicious + suspicious) / total) * 100)
        
    if malicious > 3:
        verdict = "MALICIOUS"
    elif malicious > 0 or suspicious > 0:
        verdict = "SUSPICIOUS"
    else:
        verdict = "UNDETECTED"
        
    # Extract IP Traffic
    ips = set()
    ip_traffic = behaviour_attr.get("ip_traffic", [])
    for conn in ip_traffic:
        ip = conn.get("destination_ip")
        port = conn.get("destination_port")
        if ip:
            if port:
                ips.add(f"{ip}:{port}")
            else:
                ips.add(ip)
                
    # Extract DNS Lookups (Domains)
    domains = set()
    dns_lookups = behaviour_attr.get("dns_lookups", [])
    for query in dns_lookups:
        domain = query.get("hostname")
        if domain:
            domains.add(domain)
            
    # Extract HTTP conversations
    http_calls = []
    http_conversations = behaviour_attr.get("http_conversations", [])
    for conv in http_conversations:
        url = conv.get("url")
        method = conv.get("request_method")
        status = conv.get("response_status_code")
        if url:
            http_calls.append({
                "method": method or "UNKNOWN",
                "url": url,
                "status": status
            })
            
    # Extract signature/behavior attributes
    signatures = []
    signatures.extend(behaviour_attr.get("calls_highlighted", []))
    for alert in behaviour_attr.get("ids_alerts", []):
        context = alert.get("alert_context", {})
        alert_name = context.get("alert_name") or alert.get("rule_msg")
        if alert_name:
            signatures.append(alert_name)
            
    signatures = sorted(list(set(signatures)))
    
    return {
        "verdict": verdict,
        "threat_score": threat_score,
        "sha256": sha256,
        "domains": sorted(list(domains)),
        "ips": sorted(list(ips)),
        "http_calls": http_calls,
        "signatures_triggered": signatures
    }

def run_real_sandbox(target, api_key):
    """Orchestrates the dynamic VT pipeline for the APK path or SHA-256 hash."""
    print(f"{CYAN}{BOLD}======================================================================{NC}")
    print(f"{CYAN}{BOLD}              HoneyShield Dynamic APK Threat Analyzer                 {NC}")
    print(f"{CYAN}{BOLD}======================================================================{NC}")
    
    is_hash = len(target) == 64 and all(c in "0123456789abcdefABCDEF" for c in target)
    
    if is_hash:
        sha256 = target.lower()
        print(f"[*] Target SHA-256 Hash: {BOLD}{sha256}{NC}")
    else:
        print(f"[*] Target APK: {BOLD}{os.path.basename(target)}{NC}")
        sha256 = calculate_sha256(target)
        print(f"[*] Calculated SHA-256: {sha256}")
        
    # Step 1: Query the database by hash first
    file_attr = get_file_info(sha256, api_key)
    behaviour_attr = {}
    
    if file_attr is not None:
        print(f"{GREEN}[✔] File found in VirusTotal database!{NC}")
        behaviour_attr = get_behaviour_summary(sha256, api_key)
    else:
        if is_hash:
            raise Exception("File hash not found in VirusTotal database. Cannot perform dynamic analysis on a hash alone.")
        # Step 2: Detonate file
        print(f"[*] Dynamic logs missing. Initiating file upload and sandbox detonation...")
        analysis_id = upload_file_to_vt(target, api_key)
        print(f"{GREEN}[+] Upload Successful! Analysis ID: {analysis_id}{NC}")
        
        # Step 3: Polling loop
        completed = poll_analysis_status(analysis_id, api_key)
        if not completed:
            raise Exception("Dynamic sandbox analysis did not complete in the allowed time.")
            
        # Re-fetch attributes once complete
        file_attr = get_file_info(sha256, api_key)
        if not file_attr:
            raise Exception("File info could not be fetched after analysis completed.")
            
        behaviour_attr = get_behaviour_summary(sha256, api_key)
        if not behaviour_attr:
            # If still no behaviour, construct an empty template to allow basic stats
            print(f"{YELLOW}[!] Dynamic run completed but no consolidated network behaviours returned.{NC}")
            behaviour_attr = {}

    # Step 4: Parse and print summary
    results = parse_behaviour_report(file_attr, behaviour_attr, sha256)
    
    color = GREEN
    if results["verdict"] in ["MALICIOUS", "SUSPICIOUS"]:
        color = RED if results["verdict"] == "MALICIOUS" else YELLOW
        
    print(f"\n{CYAN}{BOLD}======================================================================{NC}")
    print(f"Dynamic Analysis Summary:")
    print(f"  Verdict: {color}{BOLD}{results['verdict']}{NC}")
    print(f"  Threat Score: {color}{BOLD}{results['threat_score']}/100{NC}")
    print(f"  IP Connections (C2): {len(results['ips'])}")
    print(f"  Domain Connections (DNS): {len(results['domains'])}")
    print(f"  HTTP Calls Logged: {len(results['http_calls'])}")
    print(f"  Behaviors Matched: {len(results['signatures_triggered'])}")
    print(f"{CYAN}{BOLD}======================================================================{NC}")
    
    if results["signatures_triggered"]:
        print(f"\n{BLUE}[*] Triggered Behavior Signatures:{NC}")
        for sig in results["signatures_triggered"]:
            print(f"  - {sig}")
            
    # Output to standard JSON results file
    output_path = "data/outputs/apk_dynamic_results.json"
    with open(output_path, "w") as f:
        json.dump(results, f, indent=4)
    print(f"\n[+] Dynamic analysis JSON results saved to: {output_path}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 apk_dynamic_sandbox.py <path_to_apk_or_sha256>")
        sys.exit(1)
        
    target = sys.argv[1]
    
    is_hash = len(target) == 64 and all(c in "0123456789abcdefABCDEF" for c in target)
    if not is_hash and not os.path.exists(target):
        print(f"{RED}[!] Error: File not found at {target}{NC}")
        sys.exit(1)
        
    key = load_env_key()
    if not key:
        print(f"{RED}[!] Error: VT_API_KEY environment variable is not configured.{NC}")
        print("    Please set VT_API_KEY in your .env file or environment.")
        sys.exit(1)
        
    try:
        run_real_sandbox(target, key)
        
        # Trigger next pipeline step if we analyzed a file path: domain_hunter.py
        if not is_hash:
            import subprocess
            print(f"\n[*] Triggering next pipeline step: domain_hunter.py...")
            subprocess.run([sys.executable, "src/analysis/domain_hunter.py", target], check=True)
    except Exception as e:
        print(f"\n{RED}[!] Sandbox Detonation Execution Failed: {e}{NC}")
        sys.exit(1)

