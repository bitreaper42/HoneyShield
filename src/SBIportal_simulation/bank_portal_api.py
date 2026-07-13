from flask import Flask, request, jsonify
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure
from datetime import datetime, timezone
from dotenv import load_dotenv
import os
import time

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# MongoDB Configuration
MONGODB_URI = os.getenv('MONGODB_URI')
DB_NAME = os.getenv('DB_NAME', 'threat_intel')
COLLECTION_NAME = os.getenv('COLLECTION_NAME', 'honey_credentials')

def get_database():
    """
    Establish a connection to the MongoDB cluster and return the collection object.
    """
    try:
        client = MongoClient(MONGODB_URI)
        # Ping to verify connection
        client.admin.command('ping')
        return client[DB_NAME][COLLECTION_NAME]
    except ConnectionFailure as e:
        print(f"Failed to connect to MongoDB: {e}")
        return None
    except Exception as e:
        print(f"An error occurred while connecting: {e}")
        return None

# Initialize database collection
collection = get_database()

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS')
    return response

@app.route('/api/login', methods=['POST', 'OPTIONS'])
def api_login():
    if request.method == 'OPTIONS':
        return '', 200

    if collection is None:
        return jsonify({"error": "Database connection error."}), 500

    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid request. JSON payload required."}), 400

    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"error": "Username and password are required."}), 400

    # 1. Query MongoDB for exact honeytoken match
    query = {
        "honeytokens.username": username,
        "honeytokens.password": password
    }
    
    incident = collection.find_one(query)

    # 2. TRAP TRIGGER LOGIC
    if incident:
        # Extract attacker footprint
        attacker_ip = request.remote_addr
        # Fallback to X-Forwarded-For if behind a reverse proxy (useful for production)
        if request.headers.get('X-Forwarded-For'):
            attacker_ip = request.headers.get('X-Forwarded-For').split(',')[0]
            
        user_agent = request.headers.get('User-Agent', 'Unknown')
        
        print(f"\n[ALERT] TRAP TRIGGERED! Honeytoken matched for incident: {incident['_id']}")
        print(f"[ALERT] Attacker IP: {attacker_ip} | Device: {user_agent}")

        # Update MongoDB: Set forensics and Unset TTL index to save permanently
        update_operation = {
            "$set": {
                "incident_status": "TRAP_TRIGGERED",
                "forensic_intercept.triggeredAt": datetime.now(timezone.utc),
                "forensic_intercept.attacker_real_ip": attacker_ip,
                "forensic_intercept.device_fingerprint": user_agent,
                "apk_analysis.unified_threat_score": 100,
                "apk_analysis.verdict": "CRITICAL"
            },
            "$unset": {
                "createdAt": ""  # CRITICAL: Removes the TTL flag, saving the document forever for law enforcement
            }
        }
        
        collection.update_one({"_id": incident["_id"]}, update_operation)
        
        # Simulating a slow response tarpit to waste attacker resources and seem like a natural bank error
        time.sleep(3)
        return jsonify({
            "error": "Temporary service disruption. Please try again later.",
            "status": "fail"
        }), 503

    # 3. NORMAL LOGIC
    else:
        # No honeytoken match; return standard generic invalid response immediately
        return jsonify({
            "error": "Invalid username or password.",
            "status": "fail"
        }), 401


def start_bank_portal():
    """Entry point for launching the Bank Portal API from main.py as a background thread."""
    print("--- HoneyShield Bank Portal API Active on Port 8080 ---")
    if collection is None:
        print("[!] Warning: MongoDB connection failed on startup. Please check your .env file.")
    app.run(host='0.0.0.0', port=8080, use_reloader=False)

if __name__ == '__main__':
    start_bank_portal()

