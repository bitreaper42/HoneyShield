import subprocess

def run_sandbox(apk_url):
    subprocess.run(
        ["bash", "interactive_analysis.sh", apk_url],
        check=True
    )