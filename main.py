import threading
import time

# Import the main functions from the modules
from src.lures.reply_engine import init_engine
from src.lures.Email_lure import start_email_monitor
from src.lures.honeypot import start_flask_app
from src.SBIportal_simulation.bank_portal_api import start_bank_portal

def main():
    # 1. Initialize Reply Engine
    init_engine()
    
    # 2. Start Email Lure Monitor in a background thread
    print("\n[*] Starting Email Monitor Thread...")
    email_thread = threading.Thread(target=start_email_monitor, daemon=True)
    email_thread.start()
    
    # Give the thread a second to initialize and print its start messages
    time.sleep(1)

    # 3. Start Bank Portal API (SBI simulation) in a background thread on port 8080
    print("\n[*] Starting Bank Portal Trap API (port 8080)...")
    portal_thread = threading.Thread(target=start_bank_portal, daemon=True)
    portal_thread.start()
    
    time.sleep(1)

    # 4. Start Flask App for Honeypot Webhook on the main thread (port 5000)
    print("\n[*] Starting Honeypot Extraction Server (Flask)...")
    start_flask_app()

if __name__ == "__main__":
    main()

