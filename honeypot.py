from flask import Flask, request
import requests
import base64
import re
import os
import io
from pypdf import PdfReader
from dotenv import load_dotenv

from reply_engine import classify_branch, engine_status, get_lure_reply

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)
VT_API_KEY = os.getenv("VT_API_KEY")
TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN")
SUSPICIOUS_PDF_MARKERS = [
    "/javascript",
    "/js",
    "/openaction",
    "/launch",
    "/uri",
    "/submitform",
    "/richmedia",
]
SCRIPT_MARKERS = [
    "<script",
    "javascript:",
    "window.location",
    "document.location",
    "eval(",
    "powershell",
    "cmd.exe",
]
APK_HINTS = [".apk", "application/vnd.android.package-archive"]


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


def scan_url_with_virustotal(url_to_scan):
    """Encodes and checks a text URL via the VirusTotal API."""
    if not VT_API_KEY:
        print("[!] VirusTotal API key missing from configuration.")
        return

    url_id = base64.urlsafe_b64encode(url_to_scan.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }
    
    try:
        response = requests.get(api_url, headers=headers)
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            malicious_votes = stats['malicious']
            print(f"[VT] URL detections: {malicious_votes} malicious engines")
        else:
            print("[INFO] URL not yet indexed in VirusTotal database.")
            
    except Exception as e:
        print(f"[!] Error connecting to VirusTotal: {e}")


def extract_urls(text):
    return re.findall(r'(https?://[^\s<>"\'\]]+)', text or "", flags=re.IGNORECASE)


def inspect_pdf_content(file_bytes):
    """
    Inspect PDF body for links and suspicious auto-action/script markers.
    Returns tuple: (urls, suspicious_indicators).
    """
    print("[MEDIA] PDF inspection: scanning for links and script/action markers.")
    extracted_urls = []
    suspicious = set()
    try:
        pdf_file = io.BytesIO(file_bytes)
        reader = PdfReader(pdf_file)

        # Extract URL-like strings from rendered text layer.
        for page_num, page in enumerate(reader.pages):
            text = page.extract_text()
            if text:
                found_links = extract_urls(text)
                if found_links:
                    print(f"[MEDIA] Found {len(found_links)} URL(s) on PDF page {page_num + 1}.")
                    extracted_urls.extend(found_links)

        # Scan raw bytes for links hidden from text extraction.
        raw_text = file_bytes.decode("latin1", errors="ignore")
        extracted_urls.extend(extract_urls(raw_text))

        lowered = raw_text.lower()
        for marker in SUSPICIOUS_PDF_MARKERS:
            if marker in lowered:
                suspicious.add(f"pdf_marker:{marker}")

        for marker in SCRIPT_MARKERS:
            if marker in lowered:
                suspicious.add(f"script_marker:{marker}")

        for hint in APK_HINTS:
            if hint in lowered:
                suspicious.add(f"apk_hint:{hint}")

    except Exception as e:
        print(f"[!] PDF parsing failed: {e}")
    
    return sorted(set(extracted_urls)), sorted(suspicious)


def inspect_generic_media_content(file_bytes):
    """
    Inspect non-PDF media bytes for URL/script/APK indicators.
    Returns tuple: (urls, suspicious_indicators).
    """
    print("[MEDIA] Generic media inspection: scanning bytes for links and script hints.")
    decoded = file_bytes.decode("latin1", errors="ignore")
    urls = sorted(set(extract_urls(decoded)))
    lowered = decoded.lower()
    suspicious = set()

    for marker in SCRIPT_MARKERS:
        if marker in lowered:
            suspicious.add(f"script_marker:{marker}")

    for hint in APK_HINTS:
        if hint in lowered:
            suspicious.add(f"apk_hint:{hint}")

    return urls, sorted(suspicious)


@app.route('/webhook', methods=['POST'])
def incoming_message():
    incoming_msg = request.form.get('Body', '').lower()
    sender_number = request.form.get('From', '')
    num_media = int(request.form.get('NumMedia', 0))
    
    print(f"\n[WEBHOOK] New message from {sender_number}: {incoming_msg}")
    
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
                else:
                    filename = f"{base_name}.bin"
                
                print(f"[MEDIA] Downloaded successfully. Name={filename}, size={len(file_bytes)} bytes")
                print(f"[MEDIA] Layer 1 staging complete for ({filename}, {media_type}).")

                extracted_urls = []
                suspicious_indicators = []
                if "pdf" in media_type or filename.endswith('.pdf'):
                    extracted_urls, suspicious_indicators = inspect_pdf_content(file_bytes)
                else:
                    extracted_urls, suspicious_indicators = inspect_generic_media_content(file_bytes)

                if extracted_urls:
                    print(f"[ALERT] Extracted {len(extracted_urls)} URL(s) from media payload.")
                    for url in extracted_urls:
                        print(f"[ALERT] Embedded URL: {url}")
                        scan_url_with_virustotal(url)
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
    urls = re.findall(r'(https?://[^\s]+)', incoming_msg)
    if urls:
        extracted_url = urls[0]
        print(f"[ALERT] URL/APK extracted from message body: {extracted_url}")
        scan_url_with_virustotal(extracted_url)
        
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


if __name__ == '__main__':
    print("HoneyShield extraction server is active on port 5000.")
    print(f"[REPLY] {engine_status()}")
    if not TWILIO_ACCOUNT_SID or not TWILIO_AUTH_TOKEN:
        print("[WARN] TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN not set. Media downloads will fail with HTTP 401.")
    app.run(host="0.0.0.0", port=5000)