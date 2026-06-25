from flask import Flask, request
import requests
import base64
import re
import os
import io
import hashlib
import threading
from pypdf import PdfReader
from dotenv import load_dotenv

from src.lures.reply_engine import classify_branch, engine_status, get_lure_reply
from src.analysis.sandbox import analyze_url
from src.analysis.pdfparser import extract_payload_from_pdf, extract_payload_from_generic_media
from src.Database_manager.db_manager import generate_and_assign_honeytokens
from src.Database_manager.db_manager import create_incident_record, update_incident_record

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
VT_API_KEY = os.getenv("VT_API_KEY")
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")



def twiml_reply(message: str) -> str:
    """Return TwiML with XML-safe message text."""
    safe = (
        message.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )
    return f"<Response><Message>{safe}</Message></Response>"


def download_twilio_media(media_url: str):
    """
    Twilio media URLs require HTTP Basic Auth (Account SID + Auth Token).
    Without this, downloads return HTTP 401.
    """
    if not TWILIO_ACCOUNT_SID or not TWILIO_AUTH_TOKEN:
        print("[!] Missing TWILIO_ACCOUNT_SID or TWILIO_AUTH_TOKEN in .env")
        return None
    return requests.get(
        media_url,
        auth=(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN),
        timeout=30,
    )





@app.route('/webhook', methods=['POST'])
def incoming_message():
    incoming_msg = request.form.get('Body', '').lower()
    sender_number = request.form.get('From', '')
    num_media = int(request.form.get('NumMedia', 0))
    
    print(f"\n[WEBHOOK] New message from {sender_number}: {incoming_msg}")
    
    urls = re.findall(r'(https?://[^\s]+)', incoming_msg)
    record_id = None
    
    if num_media > 0 or urls:
        record_id = create_incident_record(
            incident_status="LURE_CAPTURED",
            attacker_contact=sender_number,
            channel="Twilio"
        )
        if record_id:
            record_id = str(record_id)
            print(f"[+] Incident recorded. Tracking ID: {record_id}")
        else:
            print("[-] Failed to initialize incident record.")
    # ========================================================
    # FEATURE: MEDIA & FILE INTERCEPTION & EXTRACTION STAGE
    # ========================================================
    if num_media > 0:
        media_url = request.form.get('MediaUrl0')
        media_type = request.form.get('MediaContentType0', '')
        
        print(f"[MEDIA] Attachment detected. MIME type: {media_type}")
        print(f"[MEDIA] Twilio asset URL: {media_url}")
        
        media_reply_branch = "media_other"
        try:
            print("[MEDIA] Downloading media payload from Twilio URL (authenticated).")
            download_response = download_twilio_media(media_url)
            if download_response is None:
                return twiml_reply(
                    get_lure_reply(
                        incoming_msg,
                        branch="media_other",
                        sender_id=sender_number,
                    )
                )

            if download_response.status_code == 200:
                file_bytes = download_response.content

                base_name = f"captured_{sender_number.replace('+', '')}"
                if "pdf" in media_type:
                    filename = f"{base_name}.pdf"
                    media_reply_branch = "media_pdf"
                elif "android" in media_type or "octet-stream" in media_type:
                    filename = f"{base_name}.apk"
                    media_reply_branch = "media_apk"
                    
                    # Calculate SHA-256 hash and pre-generate unique threat credentials
                    file_hash = hashlib.sha256(file_bytes).hexdigest()
                    print(f"[MEDIA] Intercepted APK file. Calculated SHA-256: {file_hash}")
                    try:
                        if record_id:
                            update_incident_record(record_id, apk_analysis={"apk_hash": file_hash})
                            creds = generate_and_assign_honeytokens(record_id)
                            print(f"[MEDIA] Auto-generated threat credentials for APK: {creds}")
                        else:
                            print(f"[MEDIA] Cannot assign credentials, no record_id available.")
                    except Exception as e:
                        print(f"[MEDIA] [!] Failed to auto-generate threat credentials: {e}")
                else:
                    filename = f"{base_name}.bin"
                
                print(f"[MEDIA] Downloaded successfully. Name={filename}, size={len(file_bytes)} bytes")
                print(f"[MEDIA] Layer 1 staging complete for ({filename}, {media_type}).")

                extracted_urls = []
                suspicious_indicators = []
                if "pdf" in media_type or filename.endswith('.pdf'):
                    extracted_urls, suspicious_indicators = extract_payload_from_pdf(file_bytes, filename)
                else:
                    extracted_urls, suspicious_indicators = extract_payload_from_generic_media(file_bytes, filename)

                if extracted_urls:
                    print(f"[ALERT] Extracted {len(extracted_urls)} URL(s) from media payload.")
                    for url in extracted_urls:
                        print(f"[ALERT] Embedded URL: {url}")
                        threading.Thread(target=analyze_url, args=(url, record_id)).start()
                else:
                    print("[MEDIA] No embedded URLs extracted from media payload.")

                if suspicious_indicators:
                    print(f"[ALERT] Suspicious media indicators: {', '.join(suspicious_indicators)}")
                else:
                    print("[MEDIA] No suspicious script/action indicators detected.")

            elif download_response.status_code == 401:
                print("[!] Twilio media download failed: HTTP 401 (check Account SID and Auth Token in .env)")
            else:
                print(f"[!] Twilio media download failed: HTTP {download_response.status_code}")

        except Exception as e:
            print(f"[!] Media processing failed: {e}")

        return twiml_reply(
            get_lure_reply(
                incoming_msg,
                branch=media_reply_branch,
                sender_id=sender_number,
            )
        )

    # ==========================================
    # BRANCH 2: DIRECT URL EXTRACTION FROM TEXT
    # ==========================================
    if urls:
        extracted_url = urls[0]
        print(f"[ALERT] URL/APK extracted from message body: {extracted_url}")
        threading.Thread(target=analyze_url, args=(extracted_url, record_id)).start()
        
        return twiml_reply(
            get_lure_reply(
                incoming_msg,
                branch="url",
                sender_id=sender_number,
            )
        )

    # ==========================================
    # BRANCH 3: LLM CONVERSATION
    # ==========================================
    branch = classify_branch(incoming_msg)
    print(f"[ENGAGE] Conversation branch={branch}")
    reply_text = get_lure_reply(incoming_msg, branch=branch, sender_id=sender_number)
    return twiml_reply(reply_text)


def start_flask_app():
    print("HoneyShield extraction server is active on port 5000.")
    print(f"[REPLY] {engine_status()}")
    if not TWILIO_ACCOUNT_SID or not TWILIO_AUTH_TOKEN:
        print("[WARN] TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN not set. Media downloads will fail with HTTP 401.")
    app.run(host="0.0.0.0", port=5000, use_reloader=False)

if __name__ == '__main__':
    start_flask_app()