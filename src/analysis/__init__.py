# src/analysis/__init__.py
# Shared utilities for the HoneyShield analysis pipeline.
# All pipeline scripts import colours and the string extractor from here
# to eliminate copy-paste duplication across the package.

import os
import sys
import re

# ── Package-level path bootstrap ────────────────────────────────────────────
# Ensures the project root is on sys.path so that `src.*` imports resolve
# correctly regardless of which directory the script is invoked from.
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

# ── ANSI Colour Constants ────────────────────────────────────────────────────
RED    = '\033[0;31m'
GREEN  = '\033[0;32m'
YELLOW = '\033[1;33m'
BLUE   = '\033[0;34m'
PURPLE = '\033[0;35m'
CYAN   = '\033[0;36m'
NC     = '\033[0m'   # No Colour / Reset
BOLD   = '\033[1m'


# ── Shared String Extractor ──────────────────────────────────────────────────
def extract_strings_from_bytes(data, min_len=4):
    """
    Extract readable strings from raw binary data.

    Supports both UTF-8/ASCII and UTF-16LE encodings, which covers compiled
    Android DEX files, binary AndroidManifest.xml, and resources.arsc.

    Args:
        data (bytes): Raw bytes to scan.
        min_len (int): Minimum printable character run length to keep (default 4).

    Returns:
        list[str]: Deduplicated list of extracted printable strings.
    """
    pattern = r'[\x20-\x7E]{' + str(min_len) + r',}'
    strings = []

    # UTF-8 / ASCII pass
    try:
        strings.extend(re.findall(pattern, data.decode('utf-8', errors='ignore')))
    except Exception:
        pass

    # UTF-16LE pass (common in compiled Android XML / resource binaries)
    try:
        strings.extend(re.findall(pattern, data.decode('utf-16le', errors='ignore')))
    except Exception:
        pass

    return list(set(s.strip() for s in strings))
