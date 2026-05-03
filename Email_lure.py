import imaplib
import email
import re
import time
import requests
import base64
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# --- GMAIL CONFIGURATION ---
IMAP_SERVER = "imap.gmail.com"
EMAIL_ACCOUNT = os.getenv("EMAIL_ACCOUNT")
APP_PASSWORD = os.getenv("APP_PASSWORD")
VT_API_KEY = os.getenv("VT_API_KEY")
# ---------------------------
def scan_url_with_virustotal(url_to_scan):

    
    # VirusTotal requires the URL to be converted to base64 format for the API
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
            harmless_votes = stats['harmless']
            
            print(f" VIRUSTOTAL RESULTS: {malicious_votes} ")
            
            if malicious_votes > 0:
                print(" ACTION: High Threat Detected! Preparing payload for isolated MobSF Sandbox detonation.")
            else:
                print(" ACTION: Unknown/New Threat. Pushing to MobSF Sandbox for Deep Dive Analysis.")
        else:
            print(" URL not yet in VirusTotal database. Pushing to Sandbox...")
            
    except Exception as e:
        print(f"Error connecting to VirusTotal: {e}")


def check_inbox():
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
                    body = ""
                    if msg.is_multipart():
                        for part in msg.walk():
                            if part.get_content_type() == "text/plain":
                                body = part.get_payload(decode=True).decode()
                    else:
                        body = msg.get_payload(decode=True).decode()
                    process_email_content(body)

    except Exception as e:
        print(f"Error connecting to Gmail: {e}")
    finally:
        mail.logout()

def process_email_content(body):
    print(" Scanning email body for malicious payloads...")
    
    # Use Regex to find URLs
    urls = re.findall(r'(https?://[^\s]+)', body)
    
    if urls:
        extracted_url = urls[0]
        print(f" THREAT DETECTED! Extracted URL: {extracted_url}")
        print("Ready to forward to VirusTotal..")
        scan_url_with_virustotal(extracted_url)
        # NOTE: You can easily paste your VirusTotal function from the other script right here!
    else:
        print(" No URLs found in this email.")

if __name__ == "__main__":
    print(" HoneyShield Email Lure is active.")
    print(" Monitoring inbox for incoming threats...")
    
    
    while True:
        check_inbox()
        time.sleep(10)