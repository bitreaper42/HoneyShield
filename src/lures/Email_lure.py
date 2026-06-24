import imaplib
import email
import re
import time
import requests
import base64
import os
from dotenv import load_dotenv


from Database_manager.db_manager import create_incident_record
from src.analysis.sandbox import analyze_url
from src.analysis.pdfparser import extract_payload_from_pdf

# Load environment variables from .env file
load_dotenv()

# --- GMAIL CONFIGURATION ---
IMAP_SERVER = "imap.gmail.com"
EMAIL_ACCOUNT = os.getenv("EMAIL_ACCOUNT")
APP_PASSWORD = os.getenv("APP_PASSWORD")
# ---------------------------


def check_inbox():
    if not EMAIL_ACCOUNT or not APP_PASSWORD:
        print("[!] Missing EMAIL_ACCOUNT or APP_PASSWORD. Please check your .env file.")
        time.sleep(60) # Wait longer so we don't spam the console
        return

    try:
        #Connects to the Gmail Server securely
        mail = imaplib.IMAP4_SSL(IMAP_SERVER)
        mail.login(EMAIL_ACCOUNT, APP_PASSWORD)
        mail.select('inbox')

        # Search for UNREAD emails
        status, messages = mail.search(None, 'UNSEEN')
        email_ids = messages[0].split()

        if not email_ids:
            return 

        for e_id in email_ids:
            status, msg_data = mail.fetch(e_id, '(RFC822)')
            for response_part in msg_data:
                if isinstance(response_part, tuple):
                    msg = email.message_from_bytes(response_part[1])
                    sender = msg.get("From")
                    subject = msg.get("Subject")
                    
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
                    body = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            content_type = part.get_content_type()
                            if content_type == "text/plain":
                                body = part.get_payload(decode=True).decode()
                            elif "pdf" in content_type:
                                file_bytes = part.get_payload(decode=True)
                                filename = part.get_filename() or "attachment.pdf"
                                print(f" [EMAIL] Found PDF attachment: {filename}")
                                extract_payload_from_pdf(file_bytes, filename)
                    else:
                        body = msg.get_payload(decode=True).decode()
                    process_email_content(body, record_id)

    except Exception as e:
        print(f"Error connecting to Gmail: {e}")
    finally:
        mail.logout()

def process_email_content(body, record_id=None):
    print(" Scanning email body for malicious payloads...")
    
    # Use Regex to find URLs
    urls = re.findall(r'(https?://[^\s]+)', body)
    
    if urls:
        extracted_url = urls[0]
        print(f" THREAT DETECTED! Extracted URL: {extracted_url}")
        print("Ready to forward to Threat Analysis..")
        analyze_url(extracted_url, record_id)
        # NOTE: You can easily paste your VirusTotal function from the other script right here!
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