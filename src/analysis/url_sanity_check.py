#!/usr/bin/env python3
# url_sanity_check.py
# Native Python equivalent of scripts/url_sanity_check.sh.
# Performs security and sanity analysis on a suspicious URL before downloading/analyzing an APK.
#
# Required packages (already added to requirements.txt):
#   pip install requests python-whois dnspython
#
# Standard library used for TLS/SSL:
#   ssl, socket (no extra install needed)

import ssl
import math
import socket
import hashlib
import base64
import datetime
import re
import urllib.parse
import urllib.request

import requests

# ── Shared ANSI colour constants from the package ───────────────────────────
from src.analysis import RED, GREEN, YELLOW, BLUE, PURPLE, CYAN, NC, BOLD

# ── Optional heavy imports (graceful degradation if missing) ─────────────────
try:
    import whois as python_whois          # pip install python-whois
    _WHOIS_AVAILABLE = True
except ImportError:
    _WHOIS_AVAILABLE = False

try:
    import dns.resolver                   # pip install dnspython
    _DNS_AVAILABLE = True
except ImportError:
    _DNS_AVAILABLE = False


# ────────────────────────────────────────────────────────────────────────────
# Constants
# ────────────────────────────────────────────────────────────────────────────

_USER_AGENT = "Mozilla/5.0 HoneyShield Analysis"

_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "rebrand.ly", "is.gd",
    "buff.ly", "adf.ly", "ow.ly", "shorturl.at", "bl.ink", "mcaf.ee",
    "su.pr", "tiny.cc", "lnk.to", "cutt.ly", "bit.do", "qr.ae",
    "rb.gy", "t2m.io", "tiny.one",
}

_SUSPICIOUS_PATH_KEYWORDS = [
    "login", "signin", "secure", "update", "banking", "verification",
    "verify", "account", "free", "gift", "support", "billing", "admin",
]

_SUSPICIOUS_EXTENSIONS = [".apk", ".exe", ".bin", ".scr", ".jar", ".zip", ".dex", ".rar"]

# Cyrillic / Greek homoglyph → Latin lookalike map (mirrors the bash script)
_HOMOGLYPH_MAP = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y",
    "х": "x", "і": "i", "ѕ": "s", "ԁ": "d", "һ": "h", "ј": "j",
    "ⅼ": "l", "ո": "n", "ԛ": "q", "ԝ": "w",
    "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "І": "I",
    "Ј": "J", "К": "K", "М": "M", "О": "O", "Р": "P", "Т": "T",
    "Х": "X", "Ү": "Y",
}

_CDN_PROVIDERS = {
    "cloudflare": "Cloudflare", "akamai": "Akamai", "fastly": "Fastly",
    "sucuri": "Sucuri", "imperva": "Imperva", "incapsula": "Incapsula / Imperva",
    "keycdn": "KeyCDN", "bunny": "Bunny CDN", "gcore": "Gcore",
    "limelight": "Limelight Networks", "edgecast": "Edgecast",
    "stackpath": "Stackpath",
}

_CLOUD_VPS = {
    "amazon": "Amazon Web Services (AWS)", "aws": "Amazon Web Services (AWS)",
    "cloudfront": "Amazon Web Services (AWS)", "azure": "Microsoft Azure",
    "microsoft": "Microsoft Azure", "google": "Google Cloud Platform (GCP)",
    "digitalocean": "DigitalOcean", "linode": "Linode / Akamai",
    "hetzner": "Hetzner", "ovh": "OVHcloud", "vultr": "Vultr",
    "heroku": "Heroku", "oracle": "Oracle Cloud", "hostinger": "Hostinger",
    "alibaba": "Alibaba Cloud", "leaseweb": "Leaseweb",
    "m247": "M247 VPS", "choopa": "Choopa",
}


# ────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ────────────────────────────────────────────────────────────────────────────

def _normalise_url(url: str) -> tuple[str, str]:
    """Return (scheme, url_with_scheme) for a raw URL string."""
    if "://" not in url:
        return "http", f"http://{url}"
    scheme = url.split("://")[0].lower()
    return scheme, url


def _extract_domain(url_with_scheme: str) -> str:
    """Return the bare hostname (no port) from a full URL."""
    parsed = urllib.parse.urlparse(url_with_scheme)
    return parsed.hostname or ""


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    probs = [s.count(c) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in probs)


def _murmur3_32(data: bytes, seed: int = 0) -> int:
    """Pure-Python MurmurHash3 32-bit — used for Shodan favicon fingerprinting."""
    data = bytearray(data)
    length = len(data)
    nblocks = length // 4
    h1 = seed
    c1, c2 = 0xCC9E2D51, 0x1B873593

    for i in range(nblocks):
        k1 = (data[i * 4]
              | (data[i * 4 + 1] << 8)
              | (data[i * 4 + 2] << 16)
              | (data[i * 4 + 3] << 24))
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    tail = data[nblocks * 4:]
    k1 = 0
    if len(tail) >= 3:
        k1 ^= tail[2] << 16
    if len(tail) >= 2:
        k1 ^= tail[1] << 8
    if len(tail) >= 1:
        k1 ^= tail[0]
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16

    # Return signed 32-bit integer (matches Shodan convention)
    return h1 if h1 < 0x80000000 else h1 - 0x100000000


# ────────────────────────────────────────────────────────────────────────────
# Section 1 — HTTP Redirect Tracing & URL Shortener Detection
# ────────────────────────────────────────────────────────────────────────────

def _check_redirects(url_with_scheme: str, domain: str) -> dict:
    """
    Follows the redirect chain and records each hop.
    Returns a dict with keys: is_shortener, hops, final_url, final_domain,
    final_scheme, response_headers.
    """
    result = {
        "is_shortener": domain in _SHORTENERS,
        "hops": [],
        "final_url": url_with_scheme,
        "final_domain": domain,
        "final_scheme": url_with_scheme.split("://")[0].lower(),
        "response_headers": {},
        "error": None,
    }

    print(f"\n{BLUE}{BOLD}--- 1. HTTP Redirect Tracing & URL Shorteners ---{NC}")

    if result["is_shortener"]:
        print(f"  {RED}{BOLD}[!] ALERT: URL Shortener Detected ({domain})!{NC}")
    else:
        print(f"  {GREEN}[+] URL is not using a known shortener service.{NC}")

    print(f"  {CYAN}[*] Hops trace:{NC}")
    try:
        session = requests.Session()
        # Manually follow redirects to capture each hop
        resp = session.get(
            url_with_scheme,
            allow_redirects=True,
            timeout=10,
            headers={"User-Agent": _USER_AGENT},
            stream=True,
        )
        resp.close()

        for r in resp.history:
            print(f"      [HTTP {r.status_code}] -> {r.headers.get('Location', '?')}")
            result["hops"].append({
                "status": r.status_code,
                "location": r.headers.get("Location", ""),
            })

        final_url = resp.url
        result["final_url"] = final_url
        result["final_domain"] = _extract_domain(final_url)
        result["final_scheme"] = final_url.split("://")[0].lower()
        result["response_headers"] = dict(resp.headers)
        print(f"      {GREEN}{BOLD}[Final Landing URL]{NC} {final_url}")

        if result["final_domain"] != domain:
            print(f"\n  {YELLOW}[i] Target redirected to a new domain.{NC}")
            print(f"      From: {RED}{domain}{NC}")
            print(f"      To:   {GREEN}{result['final_domain']}{NC}")

    except Exception as exc:
        result["error"] = str(exc)
        print(f"  {RED}[!] Could not connect for redirect tracing: {exc}{NC}")

    return result


# ────────────────────────────────────────────────────────────────────────────
# Section 2 — WHOIS / Domain Age
# ────────────────────────────────────────────────────────────────────────────

def _check_whois(domain: str) -> dict:
    """
    Queries WHOIS for the apex domain.  Uses python-whois when available.
    Returns a dict with keys: registrar, creation_date, age_days, raw.
    """
    result = {
        "registrar": None,
        "creation_date": None,
        "age_days": None,
        "raw": "",
        "error": None,
    }

    print(f"\n{BLUE}{BOLD}--- 2. Domain Registration & WHOIS Details ---{NC}")

    # ── Resolve apex domain (strip sub-domains) ───────────────────────────
    parts = domain.split(".")
    cc_slds = {"co", "com", "org", "net", "gov", "edu", "ac", "mil",
               "nom", "ind", "ltd", "plc", "me"}
    if len(parts) <= 2:
        apex = domain
    elif parts[-2].lower() in cc_slds and len(parts[-1]) == 2:
        apex = ".".join(parts[-3:])
    else:
        apex = ".".join(parts[-2:])

    print(f"  {CYAN}[*] Querying WHOIS for apex domain: {apex}...{NC}")

    if not _WHOIS_AVAILABLE:
        result["error"] = "python-whois not installed"
        print(f"  {YELLOW}[!] python-whois not available. Skipping WHOIS lookup.{NC}")
        return result

    try:
        w = python_whois.whois(apex)
        result["raw"] = str(w)
        result["registrar"] = w.registrar
        print(f"  {GREEN}[+]{NC} Registrar: {w.registrar or 'N/A'}")

        # creation_date can be a list or a single datetime
        cd = w.creation_date
        if isinstance(cd, list):
            cd = cd[0]
        if isinstance(cd, datetime.datetime):
            result["creation_date"] = cd.strftime("%Y-%m-%d")
            age_days = (datetime.datetime.utcnow() - cd).days
            result["age_days"] = age_days
            print(f"  {GREEN}[+]{NC} Registration Date: {result['creation_date']}")
            if age_days < 30:
                print(f"  {RED}{BOLD}[!] CRITICAL: Domain is very young! Age: {age_days} days{NC}")
            elif age_days < 180:
                print(f"  {YELLOW}[!] WARNING: Domain is relatively new. Age: {age_days} days{NC}")
            else:
                print(f"  {GREEN}[✔]{NC} Domain Age: {age_days} days (~{age_days // 365} years old)")
        else:
            print(f"  {YELLOW}[!] Warning: Could not parse domain creation date.{NC}")

    except Exception as exc:
        result["error"] = str(exc)
        print(f"  {RED}[!] WHOIS lookup failed: {exc}{NC}")

    return result


# ────────────────────────────────────────────────────────────────────────────
# Section 3 — IP Resolution, ASN & Hosting Provider
# ────────────────────────────────────────────────────────────────────────────

def _check_ip_and_asn(domain: str) -> dict:
    """
    Resolves the domain to an IP and queries ip-api.com for ASN/ISP/org data.
    Falls back to a raw socket lookup if dnspython is unavailable.
    Returns a dict with keys: ip, isp, org, asn, country, cdn_detected,
    cloud_detected, infrastructure_notes.
    """
    result = {
        "ip": None,
        "isp": "",
        "org": "",
        "asn": "",
        "country": "",
        "cdn_detected": [],
        "cloud_detected": [],
        "infrastructure_notes": [],
        "error": None,
    }

    print(f"\n{BLUE}{BOLD}--- 3. IP Resolution, ASN & Hosting Provider ---{NC}")

    # ── DNS A-record lookup ───────────────────────────────────────────────
    ip = None
    if _DNS_AVAILABLE:
        try:
            answers = dns.resolver.resolve(domain, "A")
            ip = str(answers[0])
        except Exception:
            pass

    if not ip:
        try:
            ip = socket.gethostbyname(domain)
        except Exception:
            pass

    if not ip:
        result["error"] = "DNS resolution failed"
        print(f"  {RED}[!] DNS Resolution failed. Domain could be offline or malicious DGA.{NC}")
        return result

    result["ip"] = ip
    print(f"  {GREEN}[+]{NC} Resolved IP Address: {BOLD}{ip}{NC}")

    # ── ip-api.com geo/ASN lookup ─────────────────────────────────────────
    try:
        resp = requests.get(
            f"http://ip-api.com/json/{ip}",
            timeout=5,
            headers={"User-Agent": _USER_AGENT},
        )
        if resp.ok:
            data = resp.json()
            if data.get("status") == "success":
                result["isp"] = data.get("isp", "")
                result["org"] = data.get("org", "")
                result["asn"] = data.get("as", "")
                result["country"] = f"{data.get('country', 'N/A')} ({data.get('countryCode', 'N/A')})"
                print(f"  {GREEN}[+]{NC} ASN: {result['asn']}")
                print(f"  {GREEN}[+]{NC} ISP / Host: {result['isp']}")
                print(f"  {GREEN}[+]{NC} Org Name: {result['org']}")
                print(f"  {GREEN}[+]{NC} Country: {result['country']}")
    except Exception as exc:
        result["error"] = str(exc)
        print(f"  {YELLOW}[!] Geo-IP lookup failed: {exc}{NC}")

    # ── Infrastructure audit (CDN / Cloud / Proxy) ────────────────────────
    combined = (result["isp"] + result["org"] + result["asn"]).lower()
    detected_cdns = [v for k, v in _CDN_PROVIDERS.items() if k in combined]
    detected_cloud = [v for k, v in _CLOUD_VPS.items() if k in combined]

    result["cdn_detected"] = list(set(detected_cdns))
    result["cloud_detected"] = list(set(detected_cloud))

    print(f"\n  {CYAN}[*] Infrastructure Audit:{NC}")
    if result["cdn_detected"]:
        print(f"      - {GREEN}[CDN Detected]{NC} {', '.join(result['cdn_detected'])}")
    if result["cloud_detected"]:
        if result["cdn_detected"]:
            note = (f"Cloud infrastructure ({', '.join(result['cloud_detected'])}) is "
                    f"protected behind a CDN ({', '.join(result['cdn_detected'])}).")
            print(f"      {GREEN}[+] {note}{NC}")
        else:
            note = (f"Exposed Cloud/VPS Host detected ({', '.join(result['cloud_detected'])}) "
                    f"without CDN proxy — common for ad-hoc malware C2s and phishing hosts.")
            print(f"      {YELLOW}[!] WARNING: {note}{NC}")
        result["infrastructure_notes"].append(note)
    elif not result["cdn_detected"]:
        print(f"      {GREEN}[+] No direct raw cloud hosting detected (Standard Hosting).{NC}")

    return result


# ────────────────────────────────────────────────────────────────────────────
# Section 4 — TLS / SSL Certificate
# ────────────────────────────────────────────────────────────────────────────

def _check_tls(domain: str, scheme: str) -> dict:
    """
    Connects on port 443 via ssl.SSLContext and extracts issuer, subject,
    validity dates, and SANs from the DER-encoded peer certificate.
    Returns a dict with keys: issuer, subject, not_before, not_after,
    days_remaining, sans, is_expired.
    """
    result = {
        "issuer": None,
        "subject": None,
        "not_before": None,
        "not_after": None,
        "days_remaining": None,
        "sans": [],
        "is_expired": None,
        "error": None,
    }

    if scheme != "https":
        return result

    print(f"\n{BLUE}{BOLD}--- 4. TLS/SSL Certificate Details ---{NC}")

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=10) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()  # parsed dict

        def _rdn(rdn_seq) -> str:
            return ", ".join(f"{k}={v}" for rdn in rdn_seq for k, v in rdn)

        result["issuer"] = _rdn(cert.get("issuer", ()))
        result["subject"] = _rdn(cert.get("subject", ()))

        # Validity dates are strings like "Jun 10 00:00:00 2025 GMT"
        not_before_str = cert.get("notBefore", "")
        not_after_str = cert.get("notAfter", "")
        result["not_before"] = not_before_str
        result["not_after"] = not_after_str

        fmt = "%b %d %H:%M:%S %Y %Z"
        try:
            expiry_dt = datetime.datetime.strptime(not_after_str, fmt)
            now_dt = datetime.datetime.utcnow()
            days_left = (expiry_dt - now_dt).days
            result["days_remaining"] = days_left
            result["is_expired"] = days_left < 0
        except Exception:
            pass

        # SANs (Subject Alternative Names)
        sans = [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"]
        result["sans"] = sans

        print(f"  {GREEN}[+]{NC} Issuer:  {result['issuer']}")
        print(f"  {GREEN}[+]{NC} Subject: {result['subject']}")
        print(f"  {GREEN}[+]{NC} Valid From:  {not_before_str}")
        print(f"  {GREEN}[+]{NC} Valid Until: {not_after_str}")

        if result["is_expired"] is True:
            print(f"  {RED}{BOLD}[!] CRITICAL: TLS Certificate is EXPIRED!{NC}")
        elif result["days_remaining"] is not None and result["days_remaining"] < 7:
            print(f"  {YELLOW}[!] WARNING: Certificate expires in {result['days_remaining']} days!{NC}")
        elif result["days_remaining"] is not None:
            print(f"  {GREEN}[+] Certificate is valid for another {result['days_remaining']} days.")

        if sans:
            print(f"  {GREEN}[+]{NC} SANs: {', '.join(sans[:5])}{'...' if len(sans) > 5 else ''}")

    except ssl.SSLCertVerificationError as exc:
        result["error"] = f"SSL verification error: {exc}"
        print(f"  {RED}[!] SSL Certificate verification failed: {exc}{NC}")
    except Exception as exc:
        result["error"] = str(exc)
        print(f"  {RED}[!] Failed to fetch TLS Certificate: {exc}{NC}")

    return result


# ────────────────────────────────────────────────────────────────────────────
# Section 5 — Favicon Hash Analysis
# ────────────────────────────────────────────────────────────────────────────

def _check_favicon(url_with_scheme: str) -> dict:
    """
    Fetches the favicon (via HTML link tag discovery or /favicon.ico fallback)
    and computes MD5, SHA-256, and Shodan MurmurHash3.
    Returns a dict with keys: favicon_url, md5, sha256, shodan_hash.
    """
    result = {
        "favicon_url": None,
        "md5": None,
        "sha256": None,
        "shodan_hash": None,
        "error": None,
    }

    print(f"\n{BLUE}{BOLD}--- 5. Favicon Analysis & Hashing (MD5, SHA-256, Shodan MurmurHash) ---{NC}")

    favicon_url = urllib.parse.urljoin(url_with_scheme, "/favicon.ico")

    # Try to discover the favicon URL from HTML <link> tags first
    try:
        resp = requests.get(
            url_with_scheme,
            timeout=5,
            headers={"User-Agent": _USER_AGENT},
        )
        if "html" in resp.headers.get("Content-Type", ""):
            html = resp.text
            match = re.search(
                r'<link[^>]*rel=["\'](?:shortcut )?icon["\'][^>]*href=["\']([^"\']+)["\']',
                html, re.IGNORECASE,
            )
            if not match:
                match = re.search(
                    r'<link[^>]*href=["\']([^"\']+)["\'][^>]*rel=["\'](?:shortcut )?icon["\']',
                    html, re.IGNORECASE,
                )
            if match:
                favicon_url = urllib.parse.urljoin(url_with_scheme, match.group(1))
    except Exception:
        pass

    result["favicon_url"] = favicon_url
    print(f"  [*] Favicon URL: {favicon_url}")

    try:
        fav_resp = requests.get(
            favicon_url, timeout=5, headers={"User-Agent": _USER_AGENT}
        )
        fav_data = fav_resp.content
        if fav_data:
            result["md5"] = hashlib.md5(fav_data).hexdigest()
            result["sha256"] = hashlib.sha256(fav_data).hexdigest()
            b64_data = base64.encodebytes(fav_data)
            result["shodan_hash"] = _murmur3_32(b64_data)
            print(f"  {GREEN}[+]{NC} Favicon MD5:         {result['md5']}")
            print(f"  {GREEN}[+]{NC} Favicon SHA-256:     {result['sha256']}")
            print(f"  {GREEN}[+]{NC} Shodan MurmurHash:   {result['shodan_hash']}")
        else:
            print(f"  {YELLOW}[!] Warning: Favicon file is empty.{NC}")
    except Exception as exc:
        result["error"] = str(exc)
        print(f"  {YELLOW}[!] Warning: Could not retrieve favicon ({exc}).{NC}")

    return result


# ────────────────────────────────────────────────────────────────────────────
# Section 6 — URL Path Patterns & Query Parameters
# ────────────────────────────────────────────────────────────────────────────

def _check_url_structure(url: str) -> dict:
    """
    Inspects the URL path for suspicious keywords/extensions, directory depth,
    and query parameters (including nested URLs and Base64-encoded values).
    Returns a dict with keys: path, depth, suspicious_keywords,
    suspicious_extensions, query_params, warnings.
    """
    result = {
        "path": "/",
        "depth": 0,
        "suspicious_keywords": [],
        "suspicious_extensions": [],
        "query_params": {},
        "warnings": [],
    }

    print(f"\n{BLUE}{BOLD}--- 6. Path Patterns & Query Parameters ---{NC}")

    parsed = urllib.parse.urlparse(url)
    path = parsed.path or "/"
    result["path"] = path
    print(f"  {GREEN}[+]{NC} Path: {path}")

    # Keyword & extension checks
    kw_hits = [w for w in _SUSPICIOUS_PATH_KEYWORDS
               if w in path.lower() or w in (parsed.netloc or "").lower()]
    ext_hits = [e for e in _SUSPICIOUS_EXTENSIONS if path.lower().endswith(e)]

    result["suspicious_keywords"] = kw_hits
    result["suspicious_extensions"] = ext_hits

    if ext_hits:
        msg = f"Executable extension in path: {ext_hits}"
        print(f"  {YELLOW}[!] WARNING: {msg}{NC}")
        result["warnings"].append(msg)
    if kw_hits:
        msg = f"Suspicious phishing keywords detected: {kw_hits}"
        print(f"  {YELLOW}[!] WARNING: {msg}{NC}")
        result["warnings"].append(msg)

    # Directory depth
    depth = len([p for p in path.split("/") if p])
    result["depth"] = depth
    print(f"  {GREEN}[+]{NC} Directory Depth: {depth}")
    if depth > 4:
        msg = "Unusually deep path directories (potential directory obfuscation)."
        print(f"  {YELLOW}[!] WARNING: {msg}{NC}")
        result["warnings"].append(msg)

    # Query params
    if parsed.query:
        params = urllib.parse.parse_qs(parsed.query)
        result["query_params"] = {k: v[0] for k, v in params.items()}
        print(f"  {GREEN}[+]{NC} Query Parameters found: {len(params)}")
        for key, vals in params.items():
            for val in vals:
                print(f"      - {key} = {val}")
                if val.startswith("http://") or val.startswith("https://"):
                    msg = f"Nested URL in parameter '{key}'."
                    print(f"        {YELLOW}[!] WARNING: {msg}{NC}")
                    result["warnings"].append(msg)
                # Base64 decode attempt
                b64_pattern = re.compile(
                    r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'
                )
                if b64_pattern.match(val) and len(val) > 8:
                    try:
                        decoded = base64.b64decode(val).decode("utf-8", errors="ignore")
                        if any(c.isalnum() for c in decoded):
                            print(f"        {GREEN}[i]{NC} Decoded Base64: {decoded}")
                    except Exception:
                        pass
    else:
        print(f"  {GREEN}[+]{NC} No Query Parameters detected.")

    return result


# ────────────────────────────────────────────────────────────────────────────
# Section 7 — Shannon Entropy & Homoglyph / IDN Audit
# ────────────────────────────────────────────────────────────────────────────

def _check_entropy_and_homoglyphs(domain: str, url: str) -> dict:
    """
    Calculates Shannon entropy of the domain and full URL, then checks for
    Punycode (IDN) encoding and Cyrillic/Greek homoglyph characters.
    Returns a dict with keys: domain_entropy, url_entropy, is_punycode,
    homoglyphs_found, mixed_scripts, warnings.
    """
    result = {
        "domain_entropy": 0.0,
        "url_entropy": 0.0,
        "is_punycode": False,
        "homoglyphs_found": [],
        "mixed_scripts": False,
        "warnings": [],
    }

    print(f"\n{BLUE}{BOLD}--- 7. Shannon Entropy & Homoglyph Audit ---{NC}")

    dom_ent = _shannon_entropy(domain)
    url_ent = _shannon_entropy(url)
    result["domain_entropy"] = round(dom_ent, 4)
    result["url_entropy"] = round(url_ent, 4)

    print(f"  {GREEN}[+]{NC} Domain Shannon Entropy: {dom_ent:.4f}")
    print(f"  {GREEN}[+]{NC} Total URL Shannon Entropy: {url_ent:.4f}")

    if dom_ent > 4.2:
        msg = "High Domain Entropy — potential DGA (Domain Generation Algorithm)."
        print(f"  {YELLOW}[!] WARNING: {msg}{NC}")
        result["warnings"].append(msg)
    if url_ent > 5.0:
        msg = "High URL Entropy — potential encoded payload or path obfuscation."
        print(f"  {YELLOW}[!] WARNING: {msg}{NC}")
        result["warnings"].append(msg)

    # Punycode / IDN check
    is_punycode = domain.lower().startswith("xn--")
    result["is_punycode"] = is_punycode
    decoded_domain = domain

    if is_punycode:
        print(f"  {RED}{BOLD}[!] ALERT: Internationalized Domain Name (Punycode / IDN) detected!{NC}")
        try:
            decoded_domain = domain.encode("ascii").decode("idna")
            print(f"      Decoded UTF-8 domain: {decoded_domain}")
        except Exception as exc:
            print(f"      Failed to decode Punycode: {exc}")

    # Homoglyph scan
    found_homoglyphs = [
        (char, _HOMOGLYPH_MAP[char])
        for char in decoded_domain
        if char in _HOMOGLYPH_MAP
    ]
    result["homoglyphs_found"] = [
        {"char": c, "lookalike": l, "codepoint": f"U+{ord(c):04X}"}
        for c, l in found_homoglyphs
    ]

    if found_homoglyphs:
        print(f"  {RED}{BOLD}[!] ALERT: Homoglyph characters detected! Potential visual impersonation.{NC}")
        for char, target in found_homoglyphs:
            print(f'      - Character: "{char}" (U+{ord(char):04X}) looks like Latin "{target}"')
        result["warnings"].append("Homoglyph characters detected in domain.")

    # Mixed-script check (Latin + Cyrillic + Greek)
    has_latin = any(65 <= ord(c) <= 90 or 97 <= ord(c) <= 122 for c in decoded_domain)
    has_cyrillic = any(0x0400 <= ord(c) <= 0x04FF for c in decoded_domain)
    has_greek = any(0x0370 <= ord(c) <= 0x03FF for c in decoded_domain)

    if sum([has_latin, has_cyrillic, has_greek]) >= 2:
        msg = "Mixed Scripts in domain — potential IDN Homograph Phishing."
        print(f"  {RED}{BOLD}[!] ALERT: {msg}{NC}")
        result["mixed_scripts"] = True
        result["warnings"].append(msg)
    elif not is_punycode and not found_homoglyphs:
        print(f"  {GREEN}[+]{NC} Domain uses standard scripts. No homoglyphs detected.")

    return result


# ────────────────────────────────────────────────────────────────────────────
# Public API
# ────────────────────────────────────────────────────────────────────────────

def perform_url_sanity_check(url: str) -> dict:
    """
    Run all seven security/sanity checks on *url* and return a consolidated
    results dictionary.  Each section is independently wrapped in a try/except
    so a failure in one check (e.g. WHOIS timeout) never stops the others.

    Args:
        url (str): The raw URL to analyse (with or without scheme).

    Returns:
        dict: Keys — redirects, whois, ip_asn, tls, favicon, url_structure,
              entropy_homoglyphs — each containing the output of the
              corresponding check section, plus a top-level 'target' dict
              holding the resolved domain and final URL after redirect tracing.
    """
    scheme, url_with_scheme = _normalise_url(url)
    domain = _extract_domain(url_with_scheme)

    print(f"\n{CYAN}{BOLD}{'=' * 70}{NC}")
    print(f"{CYAN}{BOLD}{'HoneyShield Suspicious URL Analysis':^70}{NC}")
    print(f"{CYAN}{BOLD}{'=' * 70}{NC}")
    print(f"{BLUE}[*] Target URL:{NC} {BOLD}{url}{NC}")
    print(f"{GREEN}[+] Target Domain:{NC} {BOLD}{domain}{NC}")

    results: dict = {
        "target": {
            "original_url": url,
            "url_with_scheme": url_with_scheme,
            "domain": domain,
            "scheme": scheme,
        },
        "redirects": {},
        "whois": {},
        "ip_asn": {},
        "tls": {},
        "favicon": {},
        "url_structure": {},
        "entropy_homoglyphs": {},
    }

    # ── Section 1: Redirect Tracing ──────────────────────────────────────
    try:
        results["redirects"] = _check_redirects(url_with_scheme, domain)
        # Update working domain/scheme/url after redirect resolution
        final_domain = results["redirects"].get("final_domain") or domain
        final_scheme = results["redirects"].get("final_scheme") or scheme
        final_url    = results["redirects"].get("final_url")    or url_with_scheme
        results["target"]["final_domain"] = final_domain
        results["target"]["final_scheme"] = final_scheme
        results["target"]["final_url"]    = final_url
    except Exception as exc:
        results["redirects"] = {"error": str(exc)}
        final_domain, final_scheme, final_url = domain, scheme, url_with_scheme

    # ── Section 2: WHOIS ──────────────────────────────────────────────────
    try:
        results["whois"] = _check_whois(final_domain)
    except Exception as exc:
        results["whois"] = {"error": str(exc)}

    # ── Section 3: IP / ASN ───────────────────────────────────────────────
    try:
        results["ip_asn"] = _check_ip_and_asn(final_domain)
    except Exception as exc:
        results["ip_asn"] = {"error": str(exc)}

    # ── Section 4: TLS / SSL ──────────────────────────────────────────────
    try:
        results["tls"] = _check_tls(final_domain, final_scheme)
    except Exception as exc:
        results["tls"] = {"error": str(exc)}

    # ── Section 5: Favicon ────────────────────────────────────────────────
    try:
        results["favicon"] = _check_favicon(final_url)
    except Exception as exc:
        results["favicon"] = {"error": str(exc)}

    # ── Section 6: URL Structure ──────────────────────────────────────────
    try:
        results["url_structure"] = _check_url_structure(final_url)
    except Exception as exc:
        results["url_structure"] = {"error": str(exc)}

    # ── Section 7: Entropy & Homoglyphs ──────────────────────────────────
    try:
        results["entropy_homoglyphs"] = _check_entropy_and_homoglyphs(final_domain, final_url)
    except Exception as exc:
        results["entropy_homoglyphs"] = {"error": str(exc)}

    print(f"\n{CYAN}{BOLD}{'=' * 70}{NC}")
    print(f"{GREEN}{BOLD}[+] Sanity Check & URL Parameter Analysis Complete.{NC}")
    print(f"{CYAN}{BOLD}{'=' * 70}{NC}\n")

    return results


# ────────────────────────────────────────────────────────────────────────────
# CLI entry-point (mirrors bash script usage: python url_sanity_check.py <URL>)
# ────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import argparse, json, sys

    parser = argparse.ArgumentParser(
        description="HoneyShield URL Sanity Check (cross-platform Python equivalent of url_sanity_check.sh)"
    )
    parser.add_argument("url", help="Suspicious URL to analyse")
    parser.add_argument(
        "--json", dest="output_json", action="store_true",
        help="Dump the full results dict as JSON after analysis"
    )
    args = parser.parse_args()

    report = perform_url_sanity_check(args.url)

    if args.output_json:
        print(json.dumps(report, indent=2, default=str))
