#Extraction Engine
from flask import Flask , request
import requests
import base64
import re
import os
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app=Flask(__name__)
VT_API_KEY = os.getenv("VT_API_KEY")
#virsu total API key

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

@app.route('/webhook',methods=['POST'])
def incoming_message():
    # Capture the incoming text and the attacker's phone number
    incoming_msg = request.form.get('Body', '').lower()
    sender_number = request.form.get('From', '')
    
    print(f"\n NEW MESSAGE RECEIVED from {sender_number}: {incoming_msg}")

    # Extracting malicious URLs or APK links using Regex
    urls = re.findall(r'(https?://[^\s]+)', incoming_msg)
    
    if urls:
        extracted_url = urls[0]
        print(f"THREAT DETECTED! Extracted URL/APK: {urls[0]}")
        print(" Forwarding payload to Sandbox Analysis Server...")
        scan_url_with_virustotal(extracted_url)
        
        return '''
        <Response>
            <Message>I clicked the link, what do I do next?</Message>
        </Response>'''
        

    # Step 2: Auto-responder to engage the scammer if they say "KYC" or "blocked"
    if "kyc" in incoming_msg or "blocked" in incoming_msg:
        print(" ENGAGING SCAMMER: Asking for instructions...")
        return '''
        <Response>
            <Message>Oh no! My YONO app is not working. How do I update my KYC?</Message>
        </Response>'''
    return '<Response></Response>'

if __name__ == '__main__':
    print(" HoneyShield Lure Server is running...")
    app.run(port=5000)
