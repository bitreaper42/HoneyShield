import os
import secrets
import string
from datetime import datetime, timezone
from dotenv import load_dotenv
from pymongo import MongoClient, ASCENDING
from pymongo.errors import ConnectionFailure, OperationFailure

# Load environment variables from .env file
load_dotenv()

# MongoDB Configuration
# MONGODB_URI is fetched from the .env file.
# Make sure to replace the placeholder in your .env with the actual connection string.
MONGODB_URI = os.getenv('MONGODB_URI', 'mongodb+srv://<username>:<password>@cluster-placeholder.mongodb.net/?retryWrites=true&w=majority')
DB_NAME = 'threat_intel'
COLLECTION_NAME = 'honey_credentials'

def get_database():
    """
    Establish a connection to the MongoDB cluster and return the database object.
    """
    try:
        # Connect to the MongoDB cluster
        client = MongoClient(MONGODB_URI)
        
        # Ping the server to verify connection
        client.admin.command('ping')
        print("Successfully connected to MongoDB.")
        
        return client[DB_NAME]
    except ConnectionFailure as e:
        print(f"Failed to connect to MongoDB: {e}")
        return None
    except Exception as e:
        print(f"An error occurred while connecting: {e}")
        return None

def setup_database():
    """
    Creates a TTL index on the 'createdAt' field so that unused records 
    automatically drop after exactly 3 days (259200 seconds).
    """
    db = get_database()
    if db is None:
        print("Database connection not established. Skipping setup.")
        return

    collection = db[COLLECTION_NAME]
    
    try:
        # Create a TTL index on the 'createdAt' field
        # expireAfterSeconds is set to 259200 seconds (3 days)
        collection.create_index(
            [("createdAt", ASCENDING)],
            expireAfterSeconds=259200,
            name="ttl_createdAt"
        )
        print("TTL index on 'createdAt' successfully created/verified (expires after 3 days).")
    except OperationFailure as e:
        print(f"Failed to create TTL index: {e}")
    except Exception as e:
        print(f"An unexpected error occurred while setting up the index: {e}")

def create_incident_record(**kwargs):
    """
    Inserts a new document enforcing a strictly structured, nested dictionary schema.
    
    Keyword Arguments:
        incident_status (str): Current status of the incident (default: "LURE_CAPTURED")
        attacker_contact (str): Contact info of attacker
        channel (str): Source channel
        extracted_url (str): Extracted malicious URL
        virustotal_score (str): Score from VT
        domain_age_days (int): Age of domain in days
        infrastructure_ip (str): IP address of infrastructure
        infrastructure_asn (str): ASN
        infrastructure_hosting (str): Hosting provider
        tls_issuer (str): TLS issuer name
        tls_expiry (str): TLS expiration date
        apk_hash (str): Hash of the APK
        impersonated_brand (str): Brand impersonated
        risk_score (float): Calculated risk score
        scanner_json_report (dict): Full scanner report
        honeytoken_username (str): Honeytoken username
        honeytoken_password (str): Honeytoken password
        honeytoken_virtual_otp (str): Honeytoken OTP
        triggeredAt (datetime): Time the honeytoken was triggered (default: None)
        attacker_real_ip (str): Real IP of attacker (default: None)
        device_fingerprint (str): Attacker device fingerprint (default: None)
    """
    db = get_database()
    if db is None:
        print("Database connection not established. Cannot insert record.")
        return None

    collection = db[COLLECTION_NAME]

    # Construct the document adhering to the requested strictly typed schema
    document = {
        "incident_status": kwargs.get("incident_status", "LURE_CAPTURED"),
        "createdAt": datetime.now(timezone.utc),
        
        "ingress_data": {
            "attacker_contact": kwargs.get("attacker_contact"),
            "channel": kwargs.get("channel")
        },
        
        "osint_analysis": {
            "extracted_url": kwargs.get("extracted_url"),
            "virustotal_score": kwargs.get("virustotal_score"),
            "domain_age_days": kwargs.get("domain_age_days"),
            "infrastructure_audit": {
                "ip": kwargs.get("infrastructure_ip"),
                "asn": kwargs.get("infrastructure_asn"),
                "hosting": kwargs.get("infrastructure_hosting")
            },
            "tls_certificate": {
                "issuer": kwargs.get("tls_issuer"),
                "expiry": kwargs.get("tls_expiry")
            }
        },
        
        "apk_analysis": {
            "apk_hash": kwargs.get("apk_hash"),
            "impersonated_brand": kwargs.get("impersonated_brand"),
            "risk_score": kwargs.get("risk_score"),
            "scanner_json_report": kwargs.get("scanner_json_report", {})
        },
        
        "honeytokens": {
            "username": kwargs.get("honeytoken_username"),
            "password": kwargs.get("honeytoken_password"),
            "virtual_otp_number": kwargs.get("honeytoken_virtual_otp")
        },
        
        "forensic_intercept": {
            "triggeredAt": kwargs.get("triggeredAt", None),
            "attacker_real_ip": kwargs.get("attacker_real_ip", None),
            "device_fingerprint": kwargs.get("device_fingerprint", None)
        }
    }

    try:
        result = collection.insert_one(document)
        print(f"Successfully inserted incident record with ID: {result.inserted_id}")
        return result.inserted_id
    except Exception as e:
        print(f"Failed to insert incident record: {e}")
        return None

def update_incident_record(record_id, **kwargs):
    """
    Updates an existing incident record using MongoDB's $set operator.
    Flattens nested dictionaries in kwargs to dot-notation so that
    nested fields are updated without overwriting the parent dictionary.
    """
    db = get_database()
    if db is None:
        print("Database connection not established. Cannot update record.")
        return False
        
    collection = db[COLLECTION_NAME]
    
    # Helper function to flatten nested dictionaries to dot-notation
    def flatten_dict(d, parent_key='', sep='.'):
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(flatten_dict(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        return dict(items)
        
    update_fields = flatten_dict(kwargs)
    
    if not update_fields:
        print("No fields provided for update.")
        return False
        
    try:
        from bson.objectid import ObjectId
        # Convert string ID to ObjectId if necessary
        if isinstance(record_id, str):
            record_id = ObjectId(record_id)
            
        result = collection.update_one(
            {"_id": record_id},
            {"$set": update_fields}
        )
        
        if result.matched_count == 0:
            print(f"No record found with ID: {record_id}")
            return False
            
        print(f"Successfully updated record {record_id}. Modified count: {result.modified_count}")
        return True
    except Exception as e:
        print(f"Failed to update incident record: {e}")
        return False

def get_incident_record(record_id):
    """
    Retrieves a full incident document from the honey_credentials collection
    by its MongoDB ObjectId.

    Args:
        record_id (str | ObjectId): The string or ObjectId of the incident document.

    Returns:
        dict: The full document dictionary if found, or None if the record does
              not exist or the database connection fails.
    """
    db = get_database()
    if db is None:
        print("Database connection not established. Cannot retrieve record.")
        return None

    collection = db[COLLECTION_NAME]

    try:
        from bson.objectid import ObjectId
        # Normalize to ObjectId whether a string or ObjectId was passed in
        if isinstance(record_id, str):
            record_id = ObjectId(record_id)

        document = collection.find_one({"_id": record_id})

        if document is None:
            print(f"[get_incident_record] No record found with ID: {record_id}")
            return None

        print(f"[get_incident_record] Successfully retrieved record: {record_id}")
        return document

    except Exception as e:
        print(f"[get_incident_record] Failed to retrieve incident record: {e}")
        return None

def generate_and_assign_honeytokens(record_id):

    """
    Generates realistic synthetic Indian banking credentials for honeytoken
    injection during dynamic sandbox analysis, persists them to the incident
    record, and returns them for ADB-based UI automation.

    Credential Spec:
        - Username : Indian banking-style ID (sbi_/yono_/user_ + 6-8 alphanumeric)
        - Password : 12-char, high-entropy, meets banking complexity rules
        - OTP Number: Synthetic Indian mobile (+91, starts with 8 or 9)

    Args:
        record_id: MongoDB ObjectId (or its string representation) of the
                   incident document to update.

    Returns:
        dict: {"username": str, "password": str, "virtual_otp_number": str}
              or None if the database update fails.
    """

    # ── 1. Generate Username ──────────────────────────────────────────
    prefix = secrets.choice(["sbi_", "yono_", "user_"])
    suffix_length = secrets.choice(range(6, 9))  # 6, 7, or 8 chars
    suffix = ''.join(secrets.choice(string.ascii_lowercase + string.digits)
                     for _ in range(suffix_length))
    username = f"{prefix}{suffix}"

    # ── 2. Generate Password (12-char, banking-compliant) ─────────────
    # Guarantee at least one of each required character class
    mandatory = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*"),
    ]
    # Fill remaining 8 characters from the full character pool
    full_pool = string.ascii_letters + string.digits + "!@#$%^&*"
    remaining = [secrets.choice(full_pool) for _ in range(8)]
    # Combine and shuffle to eliminate positional bias
    password_chars = mandatory + remaining
    # Fisher-Yates shuffle using secrets for uniform randomness
    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]
    password = ''.join(password_chars)

    # ── 3. Generate Virtual OTP Number (+91 Indian mobile) ────────────
    first_digit = secrets.choice(["8", "9"])
    remaining_digits = ''.join(secrets.choice(string.digits) for _ in range(9))
    virtual_otp_number = f"+91{first_digit}{remaining_digits}"

    # ── 4. Persist to Database ────────────────────────────────────────
    print(f"[HONEYTOKEN] Generated credentials for incident {record_id}")
    print(f"[HONEYTOKEN]   Username : {username}")
    print(f"[HONEYTOKEN]   Password : {'*' * len(password)}")
    print(f"[HONEYTOKEN]   OTP No.  : {virtual_otp_number}")

    success = update_incident_record(
        record_id=record_id,
        incident_status="CREDENTIALS_READY_FOR_INJECTION",
        honeytokens={
            "username": username,
            "password": password,
            "virtual_otp_number": virtual_otp_number
        }
    )

    if not success:
        print(f"[HONEYTOKEN] [!] Failed to persist honeytokens for {record_id}")
        return None

    print(f"[HONEYTOKEN] Credentials persisted. Ready for ADB injection.")
    return {
        "username": username,
        "password": password,
        "virtual_otp_number": virtual_otp_number
    }

if __name__ == '__main__':
    print("--- Threat Intel Database Manager Executing ---")
    
    # 1. Setup Database (Create TTL Index)
    print("\n--- Setting up TTL Index ---")
    setup_database()

    # 2. Insert a Dummy Record
    print("\n--- Inserting Dummy Record ---")
    record_id = create_incident_record(
        incident_status="LURE_CAPTURED",
        attacker_contact="@scammer_telegram_id",
        channel="Telegram",
        extracted_url="http://malicious-honey-domain.com/login",
        virustotal_score="34/89",
        domain_age_days=2,
        infrastructure_ip="198.51.100.14",
        infrastructure_asn="AS64496",
        infrastructure_hosting="Bulletproof Hosting Example",
        tls_issuer="Let's Encrypt",
        tls_expiry="2024-09-01T00:00:00Z",
        apk_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        impersonated_brand="TargetBank",
        risk_score=9.5,
        scanner_json_report={"malware_family": "FakeBanker", "detected_permissions": ["SMS_READ"]},
        honeytoken_username="honey_user_1337",
        honeytoken_password="Password123!",
        honeytoken_virtual_otp="883399"
    )

    if record_id:
        print(f"\nTest completed successfully. Document ID: {record_id}")
        print("Note: The 'forensic_intercept' fields are correctly set to None per requirements.")
    else:
        print("\nTest failed. Could not insert document.")
