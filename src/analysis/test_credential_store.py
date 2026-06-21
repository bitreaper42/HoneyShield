# test_credential_store.py
# Unit tests for the Redis-based threat credential store.

import sys
import os
import time
import json

# Ensure correct package import path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from src.analysis.credential_store import get_or_create_credentials, get_redis_client, CREDENTIAL_TTL

def run_tests():
    print("[*] Connecting to Redis to check availability...")
    try:
        r = get_redis_client()
        print("[✔] Connected to Redis successfully.")
    except Exception as e:
        print(f"[!] Redis connection failed: {e}")
        sys.exit(1)
        
    print("\n[*] Running Test 1: Generate credentials for a new APK hash...")
    test_hash = "abc1239999999999999999999999999999999999999999999999999999999abc"
    
    # Ensure key doesn't exist
    key = f"apk_cred:{test_hash}"
    r.delete(key)
    
    creds1 = get_or_create_credentials(test_hash)
    print(f"    Generated credentials: {creds1}")
    assert "username" in creds1
    assert "password" in creds1
    assert not creds1["username"].startswith("SBI_")
    print("[✔] Test 1 passed.")
    
    print("\n[*] Running Test 2: Fetch credentials again (should map 1-to-1)...")
    creds2 = get_or_create_credentials(test_hash)
    print(f"    Fetched credentials: {creds2}")
    assert creds1["username"] == creds2["username"]
    assert creds1["password"] == creds2["password"]
    print("[✔] Test 2 passed.")
    
    print("\n[*] Running Test 3: Check TTL on stored key...")
    ttl = r.ttl(key)
    print(f"    TTL of key: {ttl} seconds (expected close to {CREDENTIAL_TTL})")
    assert ttl > 0 and ttl <= CREDENTIAL_TTL
    print("[✔] Test 3 passed.")
    
    print("\n[*] Running Test 4: Verify key expiration / replacement behavior...")
    # Artificially set a low TTL of 2 seconds
    r.set(key, json.dumps(creds1), ex=2)
    print("    Waiting 3 seconds for key to expire...")
    time.sleep(3)
    
    # Try fetching again. It should generate a new set of credentials
    creds3 = get_or_create_credentials(test_hash)
    print(f"    Regenerated credentials after expiry: {creds3}")
    assert creds1["username"] != creds3["username"] or creds1["password"] != creds3["password"]
    print("[✔] Test 4 passed.")
    
    # Clean up test hash
    r.delete(key)
    print("\n[✔] All credential store tests completed successfully!")

if __name__ == "__main__":
    run_tests()
