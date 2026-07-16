import imaplib
import email
import re
import time
import requests
import base64
import os
from dotenv import load_dotenv


from src.Database_manager.db_manager import create_incident_record
from src.analysis.sandbox import analyze_url
# Payload parsers — now live in the lures layer
from src.lures.pdfparser import extract_payload_from_pdf
from src.lures.zipparser import extract_payload_from_zip

# Load environment variables from .env file
load_dotenv()

# --- GMAIL CONFIGURATION ---
IMAP_SERVER = "imap.gmail.com"
EMAIL_ACCOUNT = os.getenv("EMAIL_ACCOUNT")
APP_PASSWORD = os.getenv("APP_PASSWORD")
# Folders to monitor for incoming threats
TARGET_FOLDERS = ["INBOX", '"[Gmail]/Spam"']
# ---------------------------

# URL and APK pattern for pre-screening emails before creating any incident
URL_PATTERN = re.compile(r'https?://[^\s]+', re.IGNORECASE)
APK_PATTERN = re.compile(r'https?://[^\s]+\.apk', re.IGNORECASE)


def _extract_body_and_attachments(msg):
    """
    Extracts the plain-text body and returns a list of attachment descriptors
    from a parsed email message. Does NOT create incidents — purely extracts data.

    Returns:
        body (str): The plain-text body of the email.
        attachments (list): List of dicts with keys: type, file_bytes, filename.
    """
    body = ""
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            if content_type == "text/plain":
                try:
                    body = part.get_payload(decode=True).decode(errors="replace")
                except Exception:
                    pass
            elif "pdf" in content_type:
                file_bytes = part.get_payload(decode=True)
                filename = part.get_filename() or "attachment.pdf"
                attachments.append({"type": "pdf", "file_bytes": file_bytes, "filename": filename})
            elif "zip" in content_type or (part.get_filename() or "").endswith(".zip"):
                file_bytes = part.get_payload(decode=True)
                filename = part.get_filename() or "attachment.zip"
                attachments.append({"type": "zip", "file_bytes": file_bytes, "filename": filename})
    else:
        try:
            body = msg.get_payload(decode=True).decode(errors="replace")
        except Exception:
            pass

    return body, attachments


def _email_has_actionable_payload(body, attachments):
    """
    Pre-screens an email BEFORE creating any incident record.
    Returns True only if the email contains a URL, an APK link, or a PDF/ZIP attachment.
    Noise emails (no URLs, no attachments) are rejected here.
    """
    # Check for HTTP/HTTPS URLs in body
    if URL_PATTERN.search(body):
        return True
    # Check for PDF or ZIP attachments (could contain embedded URLs)
    if any(a["type"] in ["pdf", "zip"] for a in attachments):
        return True
    return False


def check_inbox():
    if not EMAIL_ACCOUNT or not APP_PASSWORD:
        print("[!] Missing EMAIL_ACCOUNT or APP_PASSWORD. Please check your .env file.")
        time.sleep(60)
        return

    mail = None
    try:
        # Connect to the Gmail Server securely
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(EMAIL_ACCOUNT, APP_PASSWORD)

        # ── Iterate over both INBOX and Spam ─────────────────────────────────
        for folder in TARGET_FOLDERS:
            status, data = mail.select(folder)
            if status != "OK":
                print(f"[EMAIL] Could not select folder '{folder}': {data}")
                continue

            # Search for UNREAD emails in this folder
            status, messages = mail.search(None, "UNSEEN")
            email_ids = messages[0].split()

            if not email_ids:
                continue

            print(f"[EMAIL] Found {len(email_ids)} unread email(s) in {folder}.")

            for e_id in email_ids:
                status, msg_data = mail.fetch(e_id, "(RFC822)")
                for response_part in msg_data:
                    if not isinstance(response_part, tuple):
                        continue

                    msg = email.message_from_bytes(response_part[1])
                    sender = msg.get("From")
                    subject = msg.get("Subject")

                    # ── Step 1: Extract body/attachments WITHOUT creating incident ──
                    body, attachments = _extract_body_and_attachments(msg)

                    # ── Step 2: Pre-screen — skip noise emails with no payload ──────
                    if not _email_has_actionable_payload(body, attachments):
                        print(f"[EMAIL] Skipping noise email from {sender} | Subject: {subject} (no URLs/APKs/attachments found)")
                        continue

                    # ── Step 3: Payload confirmed — now create the incident record ──
                    print(f"NEW SCAM EMAIL CAPTURED!")
                    print(f"Attacker: {sender}")
                    print(f"Subject: {subject}")

                    record_id = create_incident_record(
                        incident_status="LURE_CAPTURED",
                        attacker_contact=sender,
                        channel="Email"
                    )
                    if record_id:
                        record_id = str(record_id)
                        print(f"[+] Incident recorded. Tracking ID: {record_id}")
                    else:
                        print("[-] Failed to initialize incident record.")

                    # ── Step 4: Process PDF/ZIP attachments ───────────────────────
                    for att in attachments:
                        if att["type"] == "pdf":
                            print(f" [EMAIL] Found PDF attachment: {att['filename']}")
                            extract_payload_from_pdf(att["file_bytes"], att["filename"], record_id)
                        elif att["type"] == "zip":
                            print(f" [EMAIL] Found ZIP attachment: {att['filename']}")
                            extract_payload_from_zip(att["file_bytes"], att["filename"], record_id)

                    # ── Step 5: Process URL from email body ───────────────────────
                    process_email_content(body, record_id)

    except Exception as e:
        print(f"Error connecting to Gmail: {e}")
    finally:
        if mail:
            try:
                mail.logout()
            except Exception:
                pass


def process_email_content(body, record_id=None):
    print(" Scanning email body for malicious payloads...")

    urls = URL_PATTERN.findall(body)

    if urls:
        extracted_url = urls[0]
        print(f" THREAT DETECTED! Extracted URL: {extracted_url}")
        print("Ready to forward to Threat Analysis..")
        analyze_url(extracted_url, record_id)
    else:
        print(" No URLs found in this email.")

def start_email_monitor():
    print(" HoneyShield Email Lure is active.")
    print(" Monitoring inbox for incoming threats...")

    while True:
        check_inbox()
        time.sleep(10)

if __name__ == "__main__":
    start_email_monitor()