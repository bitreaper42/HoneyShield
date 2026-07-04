import os
import requests
import base64
import threading
from dotenv import load_dotenv

from src.Database_manager.db_manager import update_incident_record, generate_and_assign_honeytokens, remove_incident_ttl
from src.analysis.apk_analyzer import download_and_hash_apk
from src.analysis.apk_static_scanner import scan_apk
from src.analysis.apk_dynamic_sandbox import run_real_sandbox, load_env_key
from src.analysis.domain_hunter import hunt_domains
from src.analysis.request_detector import run_detection
# Cross-platform Python replacement for scripts/url_sanity_check.sh
from src.analysis.url_sanity_check import perform_url_sanity_check

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

def run_sandbox_pipeline(apk_url, record_id=None):
    try:
        print(f"\n[PIPELINE] Starting orchestration for URL: {apk_url}")
        
        # Pre-requisite: Generate Honeytokens and run URL sanity check
        tokens = generate_and_assign_honeytokens(record_id)

        # --- URL Sanity Check (native Python — cross-platform) ---
        # Replaces the old bash subprocess call to scripts/url_sanity_check.sh.
        # The original shell script is kept intact under scripts/ for reference.
        sanity_report = {}
        try:
            print("\n[PIPELINE] -> Pre-flight: Running URL Sanity Check...")
            sanity_report = perform_url_sanity_check(apk_url)
            print("[PIPELINE] URL Sanity Check completed.")
        except Exception as e:
            print(f"\n[PIPELINE] [!] Warning: URL sanity check raised an exception: {e}")
            print("[PIPELINE] Continuing pipeline execution...")
        
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
        out_file_abs = os.path.join(project_root, "data/inputs/sample.apk")
        hash_out_abs = os.path.join(project_root, "data/inputs/sample_apk_hash.txt")
        brands_config_abs = os.path.join(project_root, "config/monitored_brands.json")
        
        # --- PHASE 1: Download & Hash ---
        print("\n[PIPELINE] -> Phase 1: Downloading APK")
        apk_path, file_hash = download_and_hash_apk(apk_url, out_file_abs, hash_out_abs)
        if record_id:
            update_incident_record(
                record_id=record_id,
                incident_status="APK_DOWNLOADED",
                apk_analysis={"apk_hash": file_hash}
            )
            print(f"[PIPELINE] DB updated to APK_DOWNLOADED")
            
        # --- PHASE 2: Static Scanner ---
        print("\n[PIPELINE] -> Phase 2: Static Scanning")
        static_results = scan_apk(apk_path, brands_config_abs)
        if record_id:
            update_incident_record(
                record_id=record_id,
                incident_status="STATIC_ANALYSIS_COMPLETED",
                apk_analysis={
                    "risk_score": static_results.get("risk_score"),
                    "scanner_json_report": static_results,
                    "accessibility_abuse_detected": static_results.get("accessibility_abuse_detected", False),
                    "evasion_tactics": static_results.get("evasion_tactics", [])
                }
            )
            print(f"[PIPELINE] DB updated to STATIC_ANALYSIS_COMPLETED")
            
            if static_results.get('accessibility_abuse_detected'):
                remove_incident_ttl(record_id)
            
        # --- PHASE 3: Dynamic Sandbox ---
        print("\n[PIPELINE] -> Phase 3: Dynamic Sandbox")
        vt_key = load_env_key()
        if not vt_key:
            raise Exception("VT_API_KEY missing.")
        dynamic_results = run_real_sandbox(apk_path, vt_key)
        if record_id:
            update_incident_record(
                record_id=record_id,
                incident_status="DYNAMIC_ANALYSIS_COMPLETED",
                osint_analysis={
                    "virustotal_score": f"{dynamic_results.get('threat_score', 0)}/100",
                    "sandbox_behaviors": dynamic_results.get("signatures_triggered", [])
                }
            )
            print(f"[PIPELINE] DB updated to DYNAMIC_ANALYSIS_COMPLETED")
            
        # --- PHASE 4: C2 Domain Hunter ---
        print("\n[PIPELINE] -> Phase 4: Domain Hunter")
        domain_results = hunt_domains(apk_path)
        if record_id:
            update_incident_record(
                record_id=record_id,
                incident_status="C2_DOMAINS_ISOLATED",
                osint_analysis={
                    "infrastructure_audit": domain_results,
                    "c2_endpoints_discovered": domain_results.get("suspicious_domains", [])
                }
            )
            print(f"[PIPELINE] DB updated to C2_DOMAINS_ISOLATED")
            
        # --- PHASE 5: Request Detector (Trap Arming) ---
        print("\n[PIPELINE] -> Phase 5: Request Detector (Probing)")
        detection_results = run_detection(apk_path, record_id)
        if record_id:
            endpoints = detection_results.get("probed_endpoints", [])
            final_status = "TRAP_READY" if endpoints else "C2_PROBED_SUCCESSFULLY"
            update_incident_record(
                record_id=record_id,
                incident_status=final_status,
                osint_analysis={
                    "c2_base_url": detection_results.get("c2_base_url"),
                    "active_endpoints": endpoints
                }
            )
            print(f"[PIPELINE] DB updated to {final_status}")

        print("\n[PIPELINE] [✔] Full HoneyShield Detonation Pipeline Completed Successfully!")

    except Exception as e:
        print(f"\n[PIPELINE] [!] Pipeline Execution Failed: {e}")
        if record_id:
            update_incident_record(record_id=record_id, incident_status="PIPELINE_FAILED")


def run_sandbox_from_file(file_path, record_id=None):
    """
    Direct Detonation Pipeline for APK files saved locally (e.g., from direct upload or ZIP extraction).
    Bypasses URL Sanity Checks and the Download Phase.
    """
    try:
        print(f"\n[PIPELINE] Starting direct file detonation orchestration for: {file_path}")
        
        # Pre-requisite: Generate Honeytokens
        tokens = generate_and_assign_honeytokens(record_id)

        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
        brands_config_abs = os.path.join(project_root, "config/monitored_brands.json")
        
        # DB Update Phase 1 Bypass
        if record_id:
            update_incident_record(
                record_id=record_id,
                incident_status="APK_DOWNLOADED"
            )
            print(f"[PIPELINE] DB updated to APK_DOWNLOADED (File already local)")

        # --- PHASE 2: Static Scanner ---
        print("\n[PIPELINE] -> Phase 2: Static Scanning")
        static_results = scan_apk(file_path, brands_config_abs)
        if record_id:
            update_incident_record(
                record_id=record_id,
                incident_status="STATIC_ANALYSIS_COMPLETED",
                apk_analysis={
                    "risk_score": static_results.get("risk_score"),
                    "scanner_json_report": static_results,
                    "accessibility_abuse_detected": static_results.get("accessibility_abuse_detected", False),
                    "evasion_tactics": static_results.get("evasion_tactics", [])
                }
            )
            print(f"[PIPELINE] DB updated to STATIC_ANALYSIS_COMPLETED")
            
            if static_results.get('accessibility_abuse_detected'):
                remove_incident_ttl(record_id)
            
        # --- PHASE 3: Dynamic Sandbox ---
        print("\n[PIPELINE] -> Phase 3: Dynamic Sandbox")
        vt_key = load_env_key()
        if not vt_key:
            raise Exception("VT_API_KEY missing.")
        dynamic_results = run_real_sandbox(file_path, vt_key)
        if record_id:
            update_incident_record(
                record_id=record_id,
                incident_status="DYNAMIC_ANALYSIS_COMPLETED",
                osint_analysis={
                    "virustotal_score": f"{dynamic_results.get('threat_score', 0)}/100",
                    "sandbox_behaviors": dynamic_results.get("signatures_triggered", [])
                }
            )
            print(f"[PIPELINE] DB updated to DYNAMIC_ANALYSIS_COMPLETED")
            
        # --- PHASE 4: C2 Domain Hunter ---
        print("\n[PIPELINE] -> Phase 4: Domain Hunter")
        domain_results = hunt_domains(file_path)
        if record_id:
            update_incident_record(
                record_id=record_id,
                incident_status="C2_DOMAINS_ISOLATED",
                osint_analysis={
                    "infrastructure_audit": domain_results,
                    "c2_endpoints_discovered": domain_results.get("suspicious_domains", [])
                }
            )
            print(f"[PIPELINE] DB updated to C2_DOMAINS_ISOLATED")
            
        # --- PHASE 5: Request Detector (Trap Arming) ---
        print("\n[PIPELINE] -> Phase 5: Request Detector (Probing)")
        detection_results = run_detection(file_path, record_id)
        if record_id:
            endpoints = detection_results.get("probed_endpoints", [])
            final_status = "TRAP_READY" if endpoints else "C2_PROBED_SUCCESSFULLY"
            update_incident_record(
                record_id=record_id,
                incident_status=final_status,
                osint_analysis={
                    "c2_base_url": detection_results.get("c2_base_url"),
                    "active_endpoints": endpoints
                }
            )
            print(f"[PIPELINE] DB updated to {final_status}")

        print("\n[PIPELINE] [+] Full HoneyShield Local File Detonation Pipeline Completed Successfully!")

    except Exception as e:
        print(f"\n[PIPELINE] [!] Pipeline Execution Failed: {e}")
        if record_id:
            update_incident_record(record_id=record_id, incident_status="PIPELINE_FAILED")


def run_sandbox(apk_url, record_id=None):
    """Wrapper to maintain backward compatibility, runs pipeline directly."""
    run_sandbox_pipeline(apk_url, record_id)


def _analyze_url_worker(url_to_scan, record_id):
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
                print("[THREAT_ANALYSIS] ACTION: High Threat Detected! Preparing payload for pipeline detonation.")
            else:
                print("[THREAT_ANALYSIS] ACTION: Unknown/New Threat. Pushing to Pipeline for Deep Dive Analysis.")
            
            run_sandbox_pipeline(url_to_scan, record_id)
                
        else:
            print("[THREAT_ANALYSIS] URL not yet in VirusTotal database. Pushing to Sandbox pipeline...")
            run_sandbox_pipeline(url_to_scan, record_id)
            
    except Exception as e:
        print(f"[THREAT_ANALYSIS] [!] Error connecting to VirusTotal: {e}")
        run_sandbox_pipeline(url_to_scan, record_id)


def analyze_url(url_to_scan, record_id=None):
    """Starts the URL analysis and orchestration pipeline in a background thread."""
    thread = threading.Thread(target=_analyze_url_worker, args=(url_to_scan, record_id))
    thread.daemon = True
    thread.start()