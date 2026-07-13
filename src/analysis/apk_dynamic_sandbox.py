#!/usr/bin/env python3
# apk_dynamic_sandbox.py
# Dynamically analyzes suspicious APKs using the VirusTotal API v3.
# Extracts live dynamic network telemetry (IP connections, DNS query domains, HTTP calls, behavior flags).

import os
import time
import json
import hashlib
import requests
import argparse
import math


# Shared utilities (colours, path bootstrap)


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
        print(f" Error searching database by file hash: {str(e)}")
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
        print(f" Error retrieving behaviour summary: {str(e)}")
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
                print(f"[!] VirusTotal analysis failed on the server side.")
                return False
        except Exception as e:
            print(f"    [Warning] Error polling status: {e}")
            
    print(f"[!] Dynamic analysis polling timed-out after {max_wait_sec}s.")
    return False

def parse_behaviour_report(file_attr, behaviour_attr, sha256):
    """Parses VT file metadata and behaviour summary into standard HoneyShield JSON format."""
    stats = file_attr.get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
        
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
        "sha256": sha256,
        "domains": sorted(list(domains)),
        "ips": sorted(list(ips)),
        "http_calls": http_calls,
        "signatures_triggered": signatures
    }

def run_real_sandbox(target, api_key):
    """Orchestrates the dynamic VT pipeline for the APK path or SHA-256 hash."""
    
    is_hash = len(target) == 64 and all(c in "0123456789abcdefABCDEF" for c in target)
    
    if is_hash:
        sha256 = target.lower()
        print(f"[*] Target SHA-256 Hash: {sha256}")
    else:
        print(f"[*] Target APK: {os.path.basename(target)}")
        sha256 = calculate_sha256(target)
        print(f"[*] Calculated SHA-256: {sha256}")
        
    # Step 1: Query the database by hash first
    file_attr = get_file_info(sha256, api_key)
    behaviour_attr = {}
    
    if file_attr is not None:
        print(f"[✔] File found in VirusTotal database!")
        behaviour_attr = get_behaviour_summary(sha256, api_key)
    else:
        if is_hash:
            raise Exception("File hash not found in VirusTotal database. Cannot perform dynamic analysis on a hash alone.")
        # Step 2: Detonate file
        print(f"[*] Dynamic logs missing. Initiating file upload and sandbox detonation...")
        analysis_id = upload_file_to_vt(target, api_key)
        print(f"[+] Upload Successful! Analysis ID: {analysis_id}")
        
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
            print(f" Dynamic run completed but no consolidated network behaviours returned.")
            behaviour_attr = {}

    # Step 4: Parse and print summary
    results = parse_behaviour_report(file_attr, behaviour_attr, sha256)
    
    
        
    print(f"\n======================================================================")
    print(f"Dynamic Analysis Summary:")
    print(f"  Verdict: {results['verdict']}")
    print(f"  IP Connections (C2): {len(results['ips'])}")
    print(f"  Domain Connections (DNS): {len(results['domains'])}")
    print(f"  HTTP Calls Logged: {len(results['http_calls'])}")
    print(f"  Behaviors Matched: {len(results['signatures_triggered'])}")
    print(f"======================================================================")
    
    if results["signatures_triggered"]:
        print(f"\n[*] Triggered Behavior Signatures:")
        for sig in results["signatures_triggered"]:
            print(f"  - {sig}")
            
    # Output to standard JSON results file
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
    output_path = os.path.join(project_root, "data/outputs/apk_dynamic_results.json")
    with open(output_path, "w") as f:
        json.dump(results, f, indent=4)
    print(f"\n[+] Dynamic analysis JSON results saved to: {output_path}\n")
    
    return results

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HoneyShield Dynamic Sandbox")
    parser.add_argument("target", help="Path to APK or SHA-256 hash")
    parser.add_argument("--record-id", type=str, help="MongoDB tracking record ID", default=None)
    
    args = parser.parse_args()
    target = args.target
    
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
    
    is_hash = len(target) == 64 and all(c in "0123456789abcdefABCDEF" for c in target)
    if not is_hash and not os.path.exists(target):
        raise Exception(f"File not found at {target}")
        
    key = load_env_key()
    if not key:
        raise Exception("VT_API_KEY environment variable is not configured. Please set VT_API_KEY in your .env file or environment.")
        
    try:
        results = run_real_sandbox(target, key)
        print("Dynamic sandbox completed successfully.")
    except Exception as e:
        print(f"Error: {e}")

