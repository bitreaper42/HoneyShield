import io
import re
from pypdf import PdfReader

# We will import analyze_url locally inside functions to avoid circular dependencies if any arise later

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


def extract_urls(text):
    return re.findall(r'(https?://[^\s<>"\'\]]+)', text or "", flags=re.IGNORECASE)


def extract_payload_from_pdf(file_bytes, filename=""):
    """
    Inspect PDF body for links and suspicious auto-action/script markers.
    Forwards extracted URLs to threat analysis.
    Returns tuple: (urls, suspicious_indicators).
    """
    print(f"\n[PDF_PARSER] Inspecting PDF: {filename}")
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
                    print(f"[PDF_PARSER] Found {len(found_links)} URL(s) on PDF page {page_num + 1}.")
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
        print(f"[PDF_PARSER] [!] PDF parsing failed: {e}")
    
    unique_urls = sorted(set(extracted_urls))
    unique_suspicious = sorted(suspicious)
    
    from sandbox import analyze_url
    for url in unique_urls:
        print(f"[PDF_PARSER] Forwarding extracted URL to Threat Analysis: {url}")
        analyze_url(url)
        
    return unique_urls, unique_suspicious


def extract_payload_from_generic_media(file_bytes, filename=""):
    """
    Inspect non-PDF media bytes for URL/script/APK indicators.
    Forwards extracted URLs to threat analysis.
    Returns tuple: (urls, suspicious_indicators).
    """
    print(f"\n[MEDIA_PARSER] Inspecting generic media: {filename}")
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

    from sandbox import analyze_url
    for url in urls:
        print(f"[MEDIA_PARSER] Forwarding extracted URL to Threat Analysis: {url}")
        analyze_url(url)

    return urls, sorted(suspicious)
