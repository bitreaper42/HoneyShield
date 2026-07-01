import io
import re
from pypdf import PdfReader

# Avoid circular imports — sandbox is imported locally inside functions.

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
    """Return all HTTP/HTTPS URLs found in *text*."""
    return re.findall(r'(https?://[^\s<>"\'\\]+)', text or "", flags=re.IGNORECASE)


def extract_payload_from_pdf(file_bytes, filename="", record_id=None):
    """
    Inspect a PDF's text layer and raw bytes for embedded links and
    suspicious auto-action / script markers.

    Args:
        file_bytes (bytes): Raw PDF content.
        filename   (str):   Display name used in log messages.
        record_id  (str|None): Incident tracking ID forwarded to analyze_url.

    Returns:
        tuple[list[str], list[str]]: (unique_urls, suspicious_indicators)
    """
    print(f"\n[PDF_PARSER] Inspecting PDF: {filename}")
    extracted_urls = []
    suspicious: set[str] = set()

    try:
        reader = PdfReader(io.BytesIO(file_bytes))

        # ── Text-layer URL extraction ─────────────────────────────────────
        for page_num, page in enumerate(reader.pages):
            text = page.extract_text()
            if text:
                found = extract_urls(text)
                if found:
                    print(f"[PDF_PARSER] Found {len(found)} URL(s) on PDF page {page_num + 1}.")
                    extracted_urls.extend(found)

        # ── Raw-byte scan (catches links hidden from text extraction) ─────
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

    except Exception as exc:
        print(f"[PDF_PARSER] [!] PDF parsing failed: {exc}")

    unique_urls = sorted(set(extracted_urls))
    unique_suspicious = sorted(suspicious)

    # Forward each URL to the threat-analysis pipeline
    from src.analysis.sandbox import analyze_url
    for url in unique_urls:
        print(f"[PDF_PARSER] Forwarding extracted URL to Threat Analysis: {url}")
        analyze_url(url, record_id)

    return unique_urls, unique_suspicious


def extract_payload_from_generic_media(file_bytes, filename="", record_id=None):
    """
    Inspect non-PDF media bytes for URL / script / APK indicators.

    Args:
        file_bytes (bytes): Raw media content.
        filename   (str):   Display name used in log messages.
        record_id  (str|None): Incident tracking ID forwarded to analyze_url.

    Returns:
        tuple[list[str], list[str]]: (unique_urls, suspicious_indicators)
    """
    print(f"\n[MEDIA_PARSER] Inspecting generic media: {filename}")
    decoded = file_bytes.decode("latin1", errors="ignore")
    urls = sorted(set(extract_urls(decoded)))
    lowered = decoded.lower()
    suspicious: set[str] = set()

    for marker in SCRIPT_MARKERS:
        if marker in lowered:
            suspicious.add(f"script_marker:{marker}")
    for hint in APK_HINTS:
        if hint in lowered:
            suspicious.add(f"apk_hint:{hint}")

    from src.analysis.sandbox import analyze_url
    for url in urls:
        print(f"[MEDIA_PARSER] Forwarding extracted URL to Threat Analysis: {url}")
        analyze_url(url, record_id)

    return urls, sorted(suspicious)
