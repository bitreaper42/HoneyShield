# credential_store.py
# Manages threat credentials mapped to APK hashes using Redis with a 72-hour TTL.

import os
import json
import random
import string
import redis
from dotenv import load_dotenv

# Load env variables from .env
load_dotenv()

# Colors for terminal output
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
CYAN = '\033[0;36m'
NC = '\033[0m'

REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
REDIS_DB = int(os.environ.get("REDIS_DB", 0))
REDIS_PASSWORD = os.environ.get("REDIS_PASSWORD") or None

# 72 hours in seconds
CREDENTIAL_TTL = 72 * 60 * 60

def get_redis_client():
    """Returns a connected Redis client instance."""
    try:
        r = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            db=REDIS_DB,
            password=REDIS_PASSWORD,
            socket_timeout=5,
            decode_responses=True
        )
        # Ping to test connection
        r.ping()
        return r
    except redis.ConnectionError as e:
        print(f"{RED}[!] Error connecting to Redis at {REDIS_HOST}:{REDIS_PORT}. Ensure the Redis service/container is running.{NC}")
        raise e

def generate_random_credentials():
    """Generates realistic-looking random username and password strings."""
    first_names = ["alex", "jordan", "taylor", "morgan", "sam", "jamie", "robin", "casey", "skyler", "ryan", "priya", "amit", "rahul", "neha", "rohit"]
    last_names = ["smith", "jones", "miller", "davis", "garcia", "rodriguez", "wilson", "thomas", "taylor", "lee", "sharma", "verma", "gupta", "kumar"]
    
    # Prefix-free, natural username
    username = f"{random.choice(first_names)}_{random.choice(last_names)}{random.randint(10, 999)}"
    
    # Alphanumeric password (length 10)
    chars = string.ascii_letters + string.digits
    password = "".join(random.choice(chars) for _ in range(10))
    
    return {
        "username": username,
        "password": password
    }

def get_or_create_credentials(apk_hash):
    """
    Retrieves the unique threat credentials for an APK hash.
    If the key is missing or expired, new credentials are generated and saved with a 72-hour TTL.
    """
    if not apk_hash:
        raise ValueError("Invalid or empty APK hash provided.")
        
    apk_hash = apk_hash.lower().strip()
    key = f"apk_cred:{apk_hash}"
    
    r = get_redis_client()
    
    # Check if exists in Redis
    cred_json = r.get(key)
    if cred_json:
        try:
            return json.loads(cred_json)
        except json.JSONDecodeError:
            # If malformed, regenerate
            pass
            
    # If not found or malformed, generate new ones
    creds = generate_random_credentials()
    
    # Store with TTL (72 hours)
    r.set(key, json.dumps(creds), ex=CREDENTIAL_TTL)
    print(f"{GREEN}[+] Generated and cached credentials for {apk_hash} in Redis (TTL: 72h).{NC}")
    
    return creds
