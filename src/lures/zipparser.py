import io
import zipfile

from src.lures.pdfparser import extract_urls, SCRIPT_MARKERS, APK_HINTS

DANGEROUS_ZIP_EXTENSIONS = {
    ".apk", ".exe", ".bat", ".cmd", ".ps1", ".vbs", ".js", 
    ".wsf", ".scr", ".jar", ".dll", ".hta", ".cpl", ".pif"
}

def extract_payload_from_zip(file_bytes, filename="", record_id=None):
    """
    Safely inspect a ZIP archive in memory for embedded URLs, Drive links,
    and dangerous files.

    Args:
        file_bytes (bytes): Raw ZIP content.
        filename   (str):   Display name used in log messages.
        record_id  (str|None): Incident tracking ID forwarded to analyze_url.

    Returns:
        tuple[list[str], list[str]]: (unique_urls, suspicious_indicators)
    """
    print(f"\n[ZIP_PARSER] Inspecting ZIP Archive: {filename}")
    extracted_urls = []
    suspicious = set()

    try:
        with zipfile.ZipFile(io.BytesIO(file_bytes)) as zf:
            file_list = zf.namelist()
            print(f"[ZIP_PARSER] Found {len(file_list)} file(s) inside archive.")
            
            for inner_filename in file_list:
                # 1. Check for dangerous extensions inside the ZIP
                lower_name = inner_filename.lower()
                if any(lower_name.endswith(ext) for ext in DANGEROUS_ZIP_EXTENSIONS):
                    msg = f"dangerous_file_inside_zip:{inner_filename}"
                    suspicious.add(msg)
                    print(f"[ZIP_PARSER] [!] Suspicious file detected: {inner_filename}")

                # 2. Extract contents and look for URLs/Scripts
                try:
                    with zf.open(inner_filename) as f:
                        content_bytes = f.read()
                        
                    # Decode to text (ignoring binary garbage)
                    content_text = content_bytes.decode("latin1", errors="ignore")
                    
                    # Look for URLs
                    found_urls = extract_urls(content_text)
                    if found_urls:
                        print(f"[ZIP_PARSER] Found {len(found_urls)} URL(s) inside '{inner_filename}'")
                        extracted_urls.extend(found_urls)
                        
                    # Look for script/APK hints in the text
                    lower_text = content_text.lower()
                    for marker in SCRIPT_MARKERS:
                        if marker in lower_text:
                            suspicious.add(f"script_marker_in_zip:{marker}")
                    for hint in APK_HINTS:
                        if hint in lower_text:
                            suspicious.add(f"apk_hint_in_zip:{hint}")

                except Exception as e:
                    print(f"[ZIP_PARSER] Warning: Could not read '{inner_filename}': {e}")

    except zipfile.BadZipFile:
        print(f"[ZIP_PARSER] [!] Failed to parse. File is not a valid ZIP archive.")
    except Exception as exc:
        print(f"[ZIP_PARSER] [!] Unexpected error parsing ZIP: {exc}")

    unique_urls = sorted(set(extracted_urls))
    unique_suspicious = sorted(suspicious)

    # Route URLs: Generic VT/sandbox
    from src.analysis.sandbox import analyze_url
    for url in unique_urls:
        print(f"[ZIP_PARSER] Forwarding extracted URL to Threat Analysis: {url}")
        analyze_url(url, record_id)

    return unique_urls, unique_suspicious
