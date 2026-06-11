import subprocess

def run_sandbox(apk_url):
    # Perform URL sanity check and parameter analysis first
    subprocess.run(
        ["bash", "url_sanity_check.sh", apk_url],
        check=True
    )
    
    # Safely download the APK and calculate its SHA-256 hash
    subprocess.run(
        ["python3", "apk_analyzer.py", apk_url],
        check=True
    )
    
    # Perform the interactive network sandbox analysis
    subprocess.run(
        ["bash", "interactive_analysis.sh", apk_url],
        check=True
    )