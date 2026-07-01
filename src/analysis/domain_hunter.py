#!/usr/bin/env python3
# domain_hunter.py
# Hunt for hardcoded domains, URLs, and C2 IP addresses inside compiled APK files.
# Extracts strings from classes.dex, AndroidManifest.xml, and resources.arsc.

import os
import re
import zipfile
import json
from urllib.parse import urlparse
import argparse

# Shared utilities (colours, path bootstrap, string extractor)
from src.analysis import (
    RED, GREEN, YELLOW, BLUE, PURPLE, CYAN, NC, BOLD,
    extract_strings_from_bytes
)
from src.Database_manager.db_manager import update_incident_record

# Regular expressions
URL_PATTERN = re.compile(r'https?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::\d+)?(?:/(?:(?!https?://)[^\s<>"\'\]{}();,])*)?', re.IGNORECASE)
IP_PATTERN = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

# Exclusion list of benign/framework domains to minimize noise
BENIGN_DOMAINS = {
    'schemas.android.com', 'android.com', 'google.com', 'googleapis.com', 
    'apple.com', 'w3.org', 'xml.org', 'xmlpull.org', 'facebook.com', 
    'reactnative.dev', 'expo.dev', 'expo.io', 'github.com', 'kotlinlang.org', 
    'jetbrains.com', 'stackoverflow.com', 'example.com', 'sqlite.org', 
    'adobe.com', 'ns.adobe.com', 'swmansion.com', 'youtrack.jetbrains.com'
}

# Suspicious keywords that might indicate fraud/phishing targeting banks
SUSPICIOUS_KEYWORDS = ['sbi', 'yono', 'statebank', 'kyc', 'bank', 'login', 'secure', 'verification', 'otp', 'card']

# Extensions of media/binary files to skip during search to keep execution fast
EXCLUDED_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.webp', '.gif', '.mp3', '.mp4', 
    '.wav', '.ttf', '.otf', '.woff', '.woff2', '.svg', '.pdf',
    '.zip', '.tar', '.gz', '.rar'
}


def clean_domain(domain_str):
    """Normalize domain strings by stripping subdomains and whitespace."""
    if not domain_str:
        return ""
    # Strip port if present
    domain_str = domain_str.split(':')[0]
    return domain_str.strip().lower()

def is_benign(domain):
    """Checks if a domain belongs to the benign/framework exclusion list."""
    cleaned = clean_domain(domain)
    if cleaned in BENIGN_DOMAINS:
        return True
    # Check parent domain exclusions (e.g. sub.google.com)
    for benign in BENIGN_DOMAINS:
        if cleaned.endswith('.' + benign):
            return True
    return False

def check_suspicious(domain):
    """Checks if a domain contains any suspicious keywords indicating bank phishing."""
    cleaned = clean_domain(domain)
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in cleaned:
            return True
    return False

def hunt_domains(apk_path):
    print(f"{CYAN}{BOLD}======================================================================{NC}")
    print(f"{CYAN}{BOLD}                   HoneyShield Hardcoded Domain Hunter                {NC}")
    print(f"{CYAN}{BOLD}======================================================================{NC}")
    print(f"[*] Target APK: {BOLD}{os.path.basename(apk_path)}{NC}")
    
    if not os.path.exists(apk_path):
        raise Exception(f"File not found at {apk_path}")
        
    found_urls = set()
    found_ips = set()
    found_domains = set()
    
    try:
        with zipfile.ZipFile(apk_path, 'r') as zip_ref:
            namelist = zip_ref.namelist()
            
            # Identify targets inside the zip package, skipping directories and media assets
            targets = []
            for name in namelist:
                if name.endswith('/') or any(name.lower().endswith(ext) for ext in EXCLUDED_EXTENSIONS):
                    continue
                targets.append(name)
            
            for target_name in targets:
                print(f"[*] Scanning file: {target_name}...")
                try:
                    data = zip_ref.read(target_name)
                    strings = extract_strings_from_bytes(data)
                    
                    for s in strings:
                        # Extract URLs
                        urls = URL_PATTERN.findall(s)
                        for url in urls:
                            found_urls.add(url)
                            try:
                                parsed = urlparse(url)
                                if parsed.netloc:
                                    found_domains.add(parsed.netloc)
                            except Exception:
                                pass
                                
                        # Extract Raw IP Addresses
                        ips = IP_PATTERN.findall(s)
                        for ip in ips:
                            # Filter out local loopback or standard system IPs (like 0.0.0.0, 255.255.255.255)
                            if ip not in ['0.0.0.0', '255.255.255.255', '127.0.0.1']:
                                found_ips.add(ip)
                                
                except Exception as e:
                    print(f"{YELLOW}[!] Error reading {target_name}: {e}{NC}")
                    
    except Exception as e:
        raise Exception(f"Error opening APK zip package: {e}")
        
    # Process and filter findings
    final_ips = sorted(list(found_ips))
    
    raw_domains = [clean_domain(d) for d in found_domains if d]
    
    # Classify domains
    benign_list = []
    suspicious_list = []
    general_list = []
    
    for d in sorted(list(set(raw_domains))):
        if not d:
            continue
        if is_benign(d):
            benign_list.append(d)
        elif check_suspicious(d):
            suspicious_list.append(d)
        else:
            general_list.append(d)
            
    # Print results
    print(f"\n{RED}{BOLD}=== SUSPICIOUS / FRAUDULENT DOMAINS & IPS ==={NC}")
    if not suspicious_list and not final_ips:
        print("  None detected.")
    else:
        for domain in suspicious_list:
            print(f"  {RED}[!] SUSPICIOUS DOMAIN:{NC} {BOLD}{domain}{NC}")
        for ip in final_ips:
            print(f"  {RED}[!] OUTBOUND IP (C2 candidate):{NC} {BOLD}{ip}{NC}")
            
    print(f"\n{YELLOW}{BOLD}=== OTHER EXTERNAL DOMAINS ==={NC}")
    if not general_list:
        print("  None detected.")
    else:
        for domain in general_list:
            print(f"  - {domain}")
            
    print(f"\n{GREEN}{BOLD}=== BENIGN FRAMEWORK/SYSTEM DOMAINS (Filtered) ==={NC}")
    print(f"  Filtered out {len(benign_list)} common utility/framework domains (Google, Android, Expo, etc.)")
    
    # Save to JSON
    output_data = {
        "apk_file": os.path.basename(apk_path),
        "suspicious_domains": suspicious_list,
        "outbound_ips": final_ips,
        "general_domains": general_list,
        "benign_domains": benign_list,
        "all_extracted_urls": sorted(list(found_urls))
    }
    
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
    output_path = os.path.join(project_root, "data/outputs/hunted_domains.json")
    with open(output_path, "w") as f:
        json.dump(output_data, f, indent=4)
        
    print(f"\n{CYAN}[+] Hunt complete. JSON results exported to: {output_path}{NC}\n")
    return output_data

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HoneyShield Domain Hunter")
    parser.add_argument("apk_path", help="Path to the target APK")
    
    args = parser.parse_args()
    
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
    
    try:
        results = hunt_domains(args.apk_path)
        print("Domain hunting completed successfully.")
    except Exception as e:
        print(f"Error: {e}")

