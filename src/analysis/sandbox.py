import os
import requests
import base64
import threading
from dotenv import load_dotenv

from src.Database_manager.db_manager import update_incident_record, generate_and_assign_honeytokens, remove_incident_ttl, get_incident_record, push_to_sdk_database
from src.analysis.apk_analyzer import download_and_hash_apk
from src.analysis.apk_static_scanner import scan_apk
from src.analysis.apk_dynamic_sandbox import run_real_sandbox, load_env_key
from src.analysis.domain_hunter import hunt_domains
from src.analysis.request_detector import run_detection
from src.analysis.url_sanity_check import perform_url_sanity_check
from src.analysis.scoring_engine import calculate_unified_threat_score

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")

def run_sandbox_pipeline(target, record_id=None, is_local_file=False):
    """
    Unified Detonation Pipeline. 
    If is_local_file=True, 'target' is a local file path.
    Otherwise, 'target' is a URL to download.
    """
    try:
        print(f"\n[PIPELINE] Starting orchestration for: {target}")
        
        # Pre-requisite: Generate Honeytokens
        tokens = generate_and_assign_honeytokens(record_id)
        
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
        brands_config_abs = os.path.join(project_root, "config/monitored_brands.json")
        
        # --- PHASE 1: Download & Hash (or just Hash if local) ---
        if is_local_file:
            apk_path = target
            if record_id:
                update_incident_record(record_id, incident_status="APK_READY_LOCAL")
                print(f"[PIPELINE] DB updated to APK_READY_LOCAL (File already local)")
        else:
            try:
                print("\n[PIPELINE] -> Pre-flight: Running URL Sanity Check...")
                perform_url_sanity_check(target)
                print("[PIPELINE] URL Sanity Check completed.")
            except Exception as e:
                print(f"\n[PIPELINE] [!] Warning: URL sanity check issue: {e}")
                print("[PIPELINE] Continuing pipeline execution...")
                
            print("\n[PIPELINE] -> Phase 1: Downloading APK")
            out_file_abs = os.path.join(project_root, "data/inputs/sample.apk")
            hash_out_abs = os.path.join(project_root, "data/inputs/sample_apk_hash.txt")
            apk_path, file_hash = download_and_hash_apk(target, out_file_abs, hash_out_abs)
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
        if vt_key:
            dynamic_results = run_real_sandbox(apk_path, vt_key)
            if record_id:
                update_incident_record(
                    record_id=record_id, 
                    incident_status="DYNAMIC_ANALYSIS_COMPLETED", 
                    osint_analysis={"sandbox_behaviors": dynamic_results.get("signatures_triggered", [])}
                )
                print(f"[PIPELINE] DB updated to DYNAMIC_ANALYSIS_COMPLETED")
        else:
            print("[!] Skipping Phase 3: VT_API_KEY missing.")

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

        # --- PHASE 5: Request Detector ---
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

        # --- PHASE 6: Unified Threat Scoring (DB Aggregation) ---
        if record_id:
            print("\n[PIPELINE] -> Phase 6: Calculating Unified Threat Score")
            record = get_incident_record(record_id)
            if record:
                score, verdict = calculate_unified_threat_score(record)
                update_incident_record(
                    record_id=record_id,
                    incident_status=f"PIPELINE_COMPLETE_{verdict}",
                    apk_analysis={
                        "unified_threat_score": score,
                        "verdict": verdict
                    }
                )
                print(f"[PIPELINE] FINAL SCORE: {score}/100 | VERDICT: {verdict}")
                
                # Push to secondary SDK Database if score meets threshold
                if score >= 60:
                    print(f"[PIPELINE] Score ({score}) meets threshold. Pushing to SDK Database...")
                    push_to_sdk_database(record, score, verdict)
                
        print("\n[PIPELINE] [+] Full HoneyShield Pipeline Completed Successfully!")

    except Exception as e:
        print(f"\n[PIPELINE] [!] Pipeline Execution Failed: {e}")
        if record_id:
            update_incident_record(record_id=record_id, incident_status="PIPELINE_FAILED")


# ==============================================================
# WRAPPERS TO MAINTAIN BACKWARD COMPATIBILITY
# ==============================================================

def run_sandbox_from_file(file_path, record_id=None):
    """Wrapper for backward compatibility. Detonates a local file directly."""
    run_sandbox_pipeline(file_path, record_id, is_local_file=True)

def run_sandbox(apk_url, record_id=None):
    """Wrapper for backward compatibility. Downloads URL then detonates."""
    run_sandbox_pipeline(apk_url, record_id, is_local_file=False)


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