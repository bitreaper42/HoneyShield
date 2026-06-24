import subprocess
import os
import requests
import base64
from dotenv import load_dotenv
from db_manager import update_incident_record
from db_manager import generate_and_assign_honeytokens

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

def run_sandbox(apk_url, record_id=None):
    # Perform URL sanity check and parameter analysis first
    tokens = generate_and_assign_honeytokens(record_id)

    subprocess.run(
        ["bash", "url_sanity_check.sh", apk_url],
        check=True
    )
    
    # Safely download the APK and calculate its SHA-256 hash
    subprocess.run(
        ["python3", "apk_analyzer.py", apk_url],
        check=True
    )
    
    # Perform the interactive network sandbox analysis
    subprocess.run(
        ["bash", "interactive_analysis.sh", apk_url],
        check=True
    )
    
    if record_id:
        update_incident_record(
            record_id=record_id,
            incident_status="SANDBOX_ANALYZED"
        )
        print(f"[+] Updated incident {record_id} to SANDBOX_ANALYZED")

def analyze_url(url_to_scan, record_id=None):
    """Encodes and checks a text URL via the VirusTotal API."""
    print(f"\n[THREAT_ANALYSIS] Analyzing URL: {url_to_scan}")
    
    if record_id:
        update_incident_record(
            record_id=record_id,
            osint_analysis={"extracted_url": url_to_scan}
        )
        
    if not VT_API_KEY:
        print("[THREAT_ANALYSIS] [!] VirusTotal API key missing from configuration.")
        return

    url_id = base64.urlsafe_b64encode(url_to_scan.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }
    
    try:
        response = requests.get(api_url, headers=headers)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            malicious_votes = stats['malicious']
            total_votes = sum(stats.values())
            vt_score = f"{malicious_votes}/{total_votes}"
            
            print(f"[THREAT_ANALYSIS] VIRUSTOTAL RESULTS: {malicious_votes} malicious engines")
            
            if record_id:
                update_incident_record(
                    record_id=record_id,
                    osint_analysis={"virustotal_score": vt_score}
                )
            
            if malicious_votes > 0:
                print("[THREAT_ANALYSIS] ACTION: High Threat Detected! Preparing payload for isolated MobSF Sandbox detonation.")
            else:
                print("[THREAT_ANALYSIS] ACTION: Unknown/New Threat. Pushing to MobSF Sandbox for Deep Dive Analysis.")
            
            run_sandbox(url_to_scan, record_id)
                
        else:
            print("[THREAT_ANALYSIS] URL not yet in VirusTotal database. Pushing to Sandbox...")
            run_sandbox(url_to_scan, record_id)
            
    except Exception as e:
        print(f"[THREAT_ANALYSIS] [!] Error connecting to VirusTotal: {e}")
        run_sandbox(url_to_scan, record_id)