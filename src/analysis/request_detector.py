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
import secrets
import string
from urllib.parse import urlparse

# Shared utilities (colours, path bootstrap, string extractor)
from src.analysis import (
    RED, GREEN, YELLOW, BLUE, CYAN, NC, BOLD,
    extract_strings_from_bytes
)
from src.Database_manager.db_manager import update_incident_record, get_incident_record




URL_PATTERN = re.compile(
    r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::\d+)?(?:/(?:(?!https?://)[^\s<>"\'\\]{}();,])*)?',
    re.IGNORECASE
)




def scan_bundle_for_url_and_params(apk_path, suspicious_domains):
    """Scans the APK assets for suspicious URLs and parameter references.
    Supports React Native (index.android.bundle), Flutter (assets/), and
    generic native APKs by scanning all text-like asset files."""
    print(f"[*] Analyzing APK file: {apk_path}")
    if not os.path.exists(apk_path):
        raise FileNotFoundError(f"APK file not found at {apk_path}")

    extracted_urls = []

    # Candidate bundle paths to try, in priority order
    BUNDLE_CANDIDATES = [
        "assets/index.android.bundle",    # React Native
        "assets/flutter_assets/main.dart.snapshot",  # Flutter
    ]

    with zipfile.ZipFile(apk_path, 'r') as zip_ref:
        namelist = zip_ref.namelist()

        # Determine which files to scan
        files_to_scan = []
        for candidate in BUNDLE_CANDIDATES:
            if candidate in namelist:
                files_to_scan.append(candidate)
                print(f"[*] Found bundle: {candidate}")

        # If no known bundle found, scan all .js and .txt files in assets/
        if not files_to_scan:
            files_to_scan = [
                f for f in namelist
                if f.startswith("assets/") and (
                    f.endswith(".js") or f.endswith(".txt") or f.endswith(".bundle")
                )
            ]
            if files_to_scan:
                print(f"[*] No standard bundle found. Scanning {len(files_to_scan)} asset file(s) for URLs.")
            else:
                print("[!] No scannable bundle or asset files found in this APK. Skipping URL extraction.")
                return []

        for bundle_path in files_to_scan:
            try:
                data = zip_ref.read(bundle_path)
                strings = extract_strings_from_bytes(data)
                for s in strings:
                    urls = URL_PATTERN.findall(s)
                    for url in urls:
                        for sd in suspicious_domains:
                            if sd in url:
                                extracted_urls.append(url)
                                break
            except Exception as e:
                print(f"[!] Could not read {bundle_path}: {e}")

    extracted_urls = sorted(list(set(extracted_urls)))
    return extracted_urls


def probe_endpoint(base_url, path, credentials=None):
    """Probes a candidate endpoint path with GET and POST requests to detect routes."""
    url = f"{base_url.rstrip('/')}/{path.lstrip('/')}"
    print(f"\n[*] Probing candidate route: {url}")

    detected_method = None
    response_payload = None
    test_payload = credentials if credentials else {"username": "test_user", "password": "test_password"}

    # 1. Probe with POST (common for logins)
    try:
        headers = {"Content-Type": "application/json"}
        resp = requests.post(url, json=test_payload, headers=headers, timeout=8)
        print(f"    [POST] Status Code: {resp.status_code}")
        if resp.status_code == 200:
            print(f"    {GREEN}[+] Success response received on POST!{NC}")
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
            print(f"    {GREEN}[+] Success response received on GET!{NC}")
            detected_method = "GET"
            response_payload = resp.text
        elif "Cannot GET" in resp.text:
            print(f"    [GET] Route rejected (Cannot GET error).")
    except Exception as e:
        print(f"    [GET] Connection failed: {e}")

    return detected_method, response_payload, test_payload if detected_method == "POST" else None


def run_detection(apk_path, record_id=None):

    print(f"{CYAN}======================================================================{NC}")
    print(f"{CYAN}               HoneyShield C2 Request Detector Tool                   {NC}")
    print(f"{CYAN}======================================================================{NC}")

    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
    apk_path = os.path.join(project_root, apk_path) if not os.path.isabs(apk_path) else apk_path
    hunted_report = os.path.join(project_root, "data/outputs/hunted_domains.json")

    if not os.path.exists(hunted_report):
        raise Exception(f"Hunted domains report not found at {hunted_report}. Please run domain_hunter.py first.")

    try:
        with open(hunted_report, 'r') as f:
            report_data = json.load(f)
            suspicious_domains = report_data.get("suspicious_domains", [])
    except Exception as e:
        raise Exception(f"Error reading {hunted_report}: {e}")

    if not suspicious_domains:
        raise Exception(f"No suspicious domains found in {hunted_report}.")

    print(f"[*] Loaded suspicious domains from hunted report: {suspicious_domains}")

    try:
        # ── Resolve Honeypot Credentials ──────────────────────────────────────
        # Priority 1: Retrieve pre-generated MongoDB honeytokens tied to this incident.
        # Priority 2: Fall back to inline random dummy credentials for standalone testing.
        credentials = None

        if record_id:
            try:
                print(f"[*] Fetching honeytokens from MongoDB for record: {record_id}")
                incident_doc = get_incident_record(record_id)
                if incident_doc:
                    raw_tokens = incident_doc.get("honeytokens", {})
                    username = raw_tokens.get("username")
                    password = raw_tokens.get("password")
                    if username and password:
                        credentials = {
                            "username": username,
                            "password": password,
                            "otp": raw_tokens.get("virtual_otp_number")
                        }
                        print(f"    {GREEN}[+] Honeytokens loaded from MongoDB.{NC}")
                    else:
                        print(f"    {YELLOW}[!] Honeytoken fields missing in record. "
                              f"Falling back to generated credentials.{NC}")
                else:
                    print(f"    {YELLOW}[!] Incident record not found in MongoDB. "
                          f"Falling back to generated credentials.{NC}")
            except Exception as e:
                print(f"    {YELLOW}[!] MongoDB honeytoken lookup failed: {e}. "
                      f"Falling back to generated credentials.{NC}")

        if credentials is None:
            # Inline dummy credential generator — mirrors the banking-style format
            # from generate_and_assign_honeytokens() for consistency.
            prefix = secrets.choice(["sbi_", "yono_", "user_"])
            suffix = ''.join(
                secrets.choice(string.ascii_lowercase + string.digits) for _ in range(7)
            )
            dummy_user = f"{prefix}{suffix}"

            mandatory = [
                secrets.choice(string.ascii_uppercase),
                secrets.choice(string.ascii_lowercase),
                secrets.choice(string.digits),
                secrets.choice("!@#$%^&*"),
            ]
            pool = string.ascii_letters + string.digits + "!@#$%^&*"
            pw_chars = mandatory + [secrets.choice(pool) for _ in range(8)]
            for i in range(len(pw_chars) - 1, 0, -1):
                j = secrets.randbelow(i + 1)
                pw_chars[i], pw_chars[j] = pw_chars[j], pw_chars[i]
            dummy_pass = ''.join(pw_chars)

            first_digit = secrets.choice(["8", "9"])
            dummy_otp = f"+91{first_digit}{''.join(secrets.choice(string.digits) for _ in range(9))}"

            credentials = {"username": dummy_user, "password": dummy_pass, "otp": dummy_otp}
            print(f"    {YELLOW}[!] Using generated standalone dummy credentials for probe.{NC}")

        print(f"[*] Probe credential username: {credentials['username']}")

        # ── URL Extraction ────────────────────────────────────────────────────
        urls = scan_bundle_for_url_and_params(apk_path, suspicious_domains)

        if not urls:
            print(f"{YELLOW}[!] No URLs matching suspicious domains extracted from the APK. Skipping probes.{NC}")
            return {"c2_base_url": None, "probed_endpoints": []}

        print(f"{GREEN}[+] Extracted C2 URL String from Bundle: {urls[0]}{NC}")

        # De-concatenate and extract base domain
        parsed_url = urlparse(urls[0])
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        print(f"[*] Isolated Base C2 Server: {base_url}")

        # ── Endpoint Probing ──────────────────────────────────────────────────
        candidates = ["login", "login-variant", "auth", "otp"]
        parsed_path = parsed_url.path.lstrip('/')
        if parsed_path and parsed_path not in candidates:
            candidates.insert(0, parsed_path)

        # Clean candidates list
        candidates = sorted(list(set(
            [c.split('arrow')[0].split('tps')[0].strip() for c in candidates if c]
        )))
        print(f"[*] Candidate endpoints to probe: {candidates}")

        detection_results = {
            "c2_base_url": base_url,
            "probed_endpoints": []
        }

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

        # ── Summary ───────────────────────────────────────────────────────────
        print(f"\n{CYAN}======================================================================{NC}")
        print(f"Detections Analysis Summary:")
        if not detection_results["probed_endpoints"]:
            print(f"  {RED}[!] No active endpoints detected during API probes.{NC}")
        else:
            for endpoint in detection_results["probed_endpoints"]:
                print(f"  {GREEN}[+] Active Endpoint:{NC} {base_url}{endpoint['endpoint']}")
                print(f"      Method: {BOLD}{endpoint['method']}{NC}")
                if "params" in endpoint:
                    print(f"      Parameters: {BOLD}{json.dumps(endpoint['params'])}{NC}")
                print(f"      Response Template: {endpoint['response']}")
        print(f"{CYAN}======================================================================{NC}")

        # ── Save Results (file closed atomically before any next stage) ───────
        output_path = os.path.join(project_root, "data/outputs/c2_detection_report.json")
        with open(output_path, "w") as f:
            json.dump(detection_results, f, indent=4)
        print(f"[+] Detection report saved to: {output_path}\n")

        return detection_results

    except Exception as e:
        raise Exception(f"Error during detection: {e}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="HoneyShield C2 Request Detector")
    parser.add_argument("apk_path", nargs="?", default="data/inputs/sample.apk", help="Path to APK")
    parser.add_argument("--record-id", type=str, help="MongoDB tracking record ID", default=None)
    args = parser.parse_args()
    try:
        results = run_detection(args.apk_path, args.record_id)
        print("Detection completed successfully.")
    except Exception as e:
        print(f"Error: {e}")
