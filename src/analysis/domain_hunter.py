#!/usr/bin/env python3
# domain_hunter.py
# Hunt for hardcoded domains, URLs, and C2 IP addresses inside compiled APK files.
# Extracts strings from classes.dex, AndroidManifest.xml, and resources.arsc.

import os
import sys
import re
import zipfile
import json
from urllib.parse import urlparse

# Colors for terminal output
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE = '\033[0;34m'
PURPLE = '\033[0;35m'
CYAN = '\033[0;36m'
NC = '\033[0m' # No Color
BOLD = '\033[1m'

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

def extract_strings_from_bytes(data, min_len=4):
    """Extract readable strings using UTF-8/ASCII and UTF-16LE mappings from binary files."""
    strings = []
    
    # Try UTF-8 / ASCII
    try:
        text_utf8 = data.decode('utf-8', errors='ignore')
        words_utf8 = re.findall(r'[\x20-\x7E]{' + str(min_len) + ',}', text_utf8)
        strings.extend(words_utf8)
    except Exception:
        pass
        
    # Try UTF-16LE (common in compiled Android resources/binary XMLs)
    try:
        text_utf16 = data.decode('utf-16le', errors='ignore')
        words_utf16 = re.findall(r'[\x20-\x7E]{' + str(min_len) + ',}', text_utf16)
        strings.extend(words_utf16)
    except Exception:
        pass
        
    return list(set(s.strip() for s in strings))

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
        print(f"{RED}[!] Error: File not found at {apk_path}{NC}")
        sys.exit(1)
        
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
        print(f"{RED}[!] Error opening APK zip package: {e}{NC}")
        sys.exit(1)
        
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
    
    output_path = "data/outputs/hunted_domains.json"
    with open(output_path, "w") as f:
        json.dump(output_data, f, indent=4)
        
    print(f"\n{CYAN}[+] Hunt complete. JSON results exported to: {output_path}{NC}\n")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 domain_hunter.py <path_to_apk>")
        sys.exit(1)
        
    hunt_domains(sys.argv[1])
    
    # Trigger next pipeline step: request_detector.py
    import subprocess
    print(f"\n[*] Triggering next pipeline step: request_detector.py...")
    subprocess.run([sys.executable, "src/analysis/request_detector.py", sys.argv[1]], check=True)

