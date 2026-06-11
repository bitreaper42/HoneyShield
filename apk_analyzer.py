#!/usr/bin/env python3
# apk_analyzer.py
# Safely downloads a suspicious APK and calculates its SHA-256 hash.

import os
import sys
import hashlib
import urllib.request
from urllib.error import URLError, HTTPError

# Configurable limits
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB limit
TIMEOUT = 15  # seconds
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

def download_and_hash_apk(url, output_path="sample.apk", hash_output_path="apk_hash.txt"):
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
                    print(f"[!] Error: File size exceeds the maximum limit ({size_in_bytes / (1024*1024):.2f}MB > {MAX_FILE_SIZE / (1024*1024)}MB). Aborting download.")
                    sys.exit(2)
            
            # Stream download in chunks of 1MB
            with open(output_path, "wb") as f:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    
                    bytes_downloaded += len(chunk)
                    if bytes_downloaded > MAX_FILE_SIZE:
                        print(f"[!] Error: File size limit exceeded during transfer ({bytes_downloaded / (1024*1024):.2f}MB > {MAX_FILE_SIZE / (1024*1024)}MB). Deleting partial file.")
                        f.close()
                        os.remove(output_path)
                        sys.exit(2)
                    
                    f.write(chunk)
                    sha256.update(chunk)
                    
        # Successfully downloaded
        file_hash = sha256.hexdigest()
        print(f"[✔] Safe download complete. File saved to: {output_path} ({bytes_downloaded / (1024*1024):.2f} MB)")
        print(f"[✔] Computed SHA-256: {file_hash}")
        
        # Write hash to local output file
        with open(hash_output_path, "w") as hf:
            hf.write(file_hash + "\n")
        print(f"[+] SHA-256 hash saved to: {hash_output_path}")
        
        return file_hash
        
    except HTTPError as e:
        print(f"[!] HTTP Error downloading APK: {e.code} - {e.reason}")
        sys.exit(1)
    except URLError as e:
        print(f"[!] Connection Error downloading APK: {e.reason}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Unexpected Error during download: {str(e)}")
        if os.path.exists(output_path):
            os.remove(output_path)
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 apk_analyzer.py <APK_URL> [output_file] [hash_output_file]")
        sys.exit(1)
        
    target_url = sys.argv[1]
    out_file = sys.argv[2] if len(sys.argv) > 2 else "sample.apk"
    hash_out = sys.argv[3] if len(sys.argv) > 3 else "apk_hash.txt"
    
    download_and_hash_apk(target_url, out_file, hash_out)
