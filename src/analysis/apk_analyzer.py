#!/usr/bin/env python3
# apk_analyzer.py
# Safely downloads a suspicious APK and calculates its SHA-256 hash.

import os
import sys
import subprocess
import hashlib
import urllib.request
import argparse
from urllib.error import URLError, HTTPError

# Path bootstrap and DB import (sys.path resolved by src.analysis package __init__)
from src.analysis import RED, GREEN, YELLOW, CYAN, NC, BOLD
from src.Database_manager.db_manager import update_incident_record



# Configurable limits
MAX_FILE_SIZE = 200 * 1024 * 1024  # 200 MB limit
TIMEOUT = 15  # seconds
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

def download_and_hash_apk(url, output_path="data/inputs/sample.apk", hash_output_path="data/inputs/sample_apk_hash.txt"):
    print(f"[*] Starting defensive APK download from: {url}")
    
    # Configure request with a custom user-agent
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    sha256 = hashlib.sha256()
    bytes_downloaded = 0
    
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
            # Check content length header if present
            content_length = response.headers.get("Content-Length")
            if content_length:
                size_in_bytes = int(content_length)
                if size_in_bytes > MAX_FILE_SIZE:
                    raise Exception(f"File size exceeds the maximum limit ({size_in_bytes / (1024*1024):.2f}MB > {MAX_FILE_SIZE / (1024*1024)}MB).")
            
            # Stream download in chunks of 1MB
            with open(output_path, "wb") as f:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    
                    bytes_downloaded += len(chunk)
                    if bytes_downloaded > MAX_FILE_SIZE:
                        f.close()
                        os.remove(output_path)
                        raise Exception(f"File size limit exceeded during transfer ({bytes_downloaded / (1024*1024):.2f}MB > {MAX_FILE_SIZE / (1024*1024)}MB).")
                    
                    f.write(chunk)
                    sha256.update(chunk)
                    
        # Successfully downloaded
        file_hash = sha256.hexdigest()
        print(f"[+] Safe download complete. File saved to: {output_path} ({bytes_downloaded / (1024*1024):.2f} MB)")
        print(f"[+] Computed SHA-256: {file_hash}")
        
        
        # Write hash to local output file
        with open(hash_output_path, "w") as hf:
            hf.write(file_hash + "\n")
        print(f"[+] SHA-256 hash saved to: {hash_output_path}")
        
        return output_path, file_hash
        
    except HTTPError as e:
        error_body = e.read().decode('utf-8', errors='ignore')
        raise Exception(f"HTTP Error downloading APK: {e.code} - {e.reason}. Response: {error_body}")
    except URLError as e:
        raise Exception(f"Connection Error downloading APK: {e.reason}")
    except Exception as e:
        if os.path.exists(output_path):
            os.remove(output_path)
        raise e

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="HoneyShield APK Analyzer")
    parser.add_argument("target_url", help="URL to download APK from")
    parser.add_argument("out_file", nargs='?', default="data/inputs/sample.apk", help="Output APK path")
    parser.add_argument("hash_out", nargs='?', default="data/inputs/sample_apk_hash.txt", help="Output hash path")
    
    args = parser.parse_args()
    
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
    out_file_abs = os.path.join(project_root, args.out_file) if not os.path.isabs(args.out_file) else args.out_file
    hash_out_abs = os.path.join(project_root, args.hash_out) if not os.path.isabs(args.hash_out) else args.hash_out
    
    try:
        apk_path, file_hash = download_and_hash_apk(args.target_url, out_file_abs, hash_out_abs)
        print(f"Success: {apk_path} - {file_hash}")
    except Exception as e:
        print(f"Error: {e}")

