#!/usr/bin/env bash
# url_sanity_check.sh
# Performs sanity check and security analysis on a suspicious URL before downloading/analyzing an APK.

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'
UNDERLINE='\033[4m'

# Check arguments
if [ -z "$1" ]; then
    echo -e "${RED}${BOLD}Usage:${NC} $0 <URL>"
    exit 1
fi

URL="$1"

echo -e "${CYAN}${BOLD}======================================================================${NC}"
echo -e "${CYAN}${BOLD}                 HoneyShield suspicious URL Analysis                  ${NC}"
echo -e "${CYAN}${BOLD}======================================================================${NC}"
echo -e "${BLUE}[*] Target URL:${NC} ${BOLD}$URL${NC}"

# Check required binaries
MISSING_TOOLS=()
for tool in curl python3 whois openssl; do
    if ! command -v "$tool" &>/dev/null; then
        MISSING_TOOLS+=("$tool")
    fi
done

if [ ${#MISSING_TOOLS[@]} -ne 0 ]; then
    echo -e "${YELLOW}[!] Warning: Missing recommended tool(s): ${MISSING_TOOLS[*]}.${NC}"
    echo -e "${YELLOW}    Some analysis features might be degraded or skipped.${NC}\n"
fi

# Extract Domain and Scheme
SCHEME=$(echo "$URL" | grep :// | sed -e 's/^\([^:]*\).*/\1/')
if [ -z "$SCHEME" ]; then
    # Default to http if no scheme
    SCHEME="http"
    URL_WITH_SCHEME="http://$URL"
else
    URL_WITH_SCHEME="$URL"
fi

DOMAIN=$(echo "$URL_WITH_SCHEME" | awk -F/ '{print $3}' | cut -d: -f1)

if [ -z "$DOMAIN" ]; then
    echo -e "${RED}[!] Error: Could not extract domain from URL.${NC}"
    exit 1
fi

echo -e "${GREEN}[+] Target Domain:${NC} ${BOLD}$DOMAIN${NC}"

# --- SECTION 1: REDIRECT TRACING & URL SHORTENERS ---
echo -e "\n${BLUE}${BOLD}--- 1. HTTP Redirect Tracing & URL Shorteners ---${NC}"

# Define common URL shorteners
SHORTENERS=(
    "bit.ly" "tinyurl.com" "t.co" "goo.gl" "rebrand.ly" "is.gd" "buff.ly"
    "adf.ly" "ow.ly" "shorturl.at" "bl.ink" "mcaf.ee" "su.pr" "tiny.cc"
    "lnk.to" "cutt.ly" "bit.do" "qr.ae" "rb.gy" "t2m.io" "tiny.one"
)

IS_SHORTENER=false
for shortener in "${SHORTENERS[@]}"; do
    if [ "$DOMAIN" = "$shortener" ]; then
        IS_SHORTENER=true
        break
    fi
done

if [ "$IS_SHORTENER" = true ]; then
    echo -e "  ${RED}${BOLD}[!] ALERT: URL Shortener Detected (${DOMAIN})!${NC}"
else
    echo -e "  ${GREEN}[✔] URL is not using a known shortener service.${NC}"
fi

echo -e "  ${CYAN}[*] Hops trace:${NC}"
# Use curl to trace redirects and extract status codes + landing locations
REDIRECT_TRACE=$(curl -s -L -D - -o /dev/null "$URL_WITH_SCHEME" -m 10 2>/dev/null)
if [ -z "$REDIRECT_TRACE" ]; then
    echo -e "  ${RED}    [!] Could not connect to target URL for redirect tracing.${NC}"
    FINAL_URL="$URL_WITH_SCHEME"
else
    # Parse headers for redirects
    echo "$REDIRECT_TRACE" | grep -Ei "^(HTTP/|Location:)" | while read -r line; do
        if [[ "$line" =~ ^HTTP ]]; then
            STATUS=$(echo "$line" | awk '{print $2}')
            echo -n -e "      [HTTP $STATUS] -> "
        elif [[ "$line" =~ ^[Ll]ocation: ]]; then
            LOC=$(echo "$line" | cut -d' ' -f2- | tr -d '\r')
            echo -e "${YELLOW}$LOC${NC}"
        fi
    done
    FINAL_URL=$(curl -Ls -o /dev/null -w "%{url_effective}" "$URL_WITH_SCHEME" -m 10 2>/dev/null)
    echo -e "      ${GREEN}${BOLD}[Final Landing URL]${NC} $FINAL_URL"
fi


# --- SECTION 2: WHOIS, REGISTRAR, AND DOMAIN AGE ---
echo -e "\n${BLUE}${BOLD}--- 2. Domain Registration & WHOIS Details ---${NC}"

# Extract Apex Domain for WHOIS lookup (whois on subdomains like www.google.com often fails)
APEX_DOMAIN=$(python3 -c "
domain = '$DOMAIN'
parts = domain.split('.')
if len(parts) <= 2:
    print(domain)
else:
    cc_slds = {'co', 'com', 'org', 'net', 'gov', 'edu', 'ac', 'mil', 'nom', 'ind', 'ltd', 'plc', 'me'}
    if parts[-2].lower() in cc_slds and len(parts[-1]) == 2:
        print('.'.join(parts[-3:]))
    else:
        print('.'.join(parts[-2:]))
")

echo -e "  ${CYAN}[*] Querying WHOIS for apex domain: ${APEX_DOMAIN}...${NC}"
WHOIS_OUT=$(whois "$APEX_DOMAIN" 2>/dev/null)

if [ -z "$WHOIS_OUT" ] || echo "$WHOIS_OUT" | grep -qE "(No match|NOT FOUND|No detail|No entries|not registered)"; then
    echo -e "  ${RED}[!] WHOIS Lookup failed or domain is not registered.${NC}"
    WHOIS_OUT=""
else
    # Use python inline to parse registrar and age from the whois output
    python3 -c "
import sys, re, datetime

whois_text = \"\"\"$WHOIS_OUT\"\"\"

# Extract registrar
registrar = None
for line in whois_text.splitlines():
    line_lower = line.lower().strip()
    if line_lower.startswith('registrar:') or line_lower.startswith('sponsoring registrar:'):
        parts = line.split(':', 1)
        if len(parts) > 1:
            registrar = parts[1].strip()
            break

# Date patterns
date_patterns = [
    r'(?:creation date|created on|registration time|registered|creation-date|created|registered-on|domain name commencement date)\s*:\s*([^\r\n]+)',
    r'(?:record created on)\s*([^\r\n]+)',
    r'(?:created)\s*\.+\s*:\s*([^\r\n]+)',
    r'(?:changed|updated|last-update)\s*:\s*([^\r\n]+)'
]

creation_date = None
for pattern in date_patterns:
    match = re.search(pattern, whois_text, re.IGNORECASE)
    if match:
        date_str = match.group(1).strip()
        # strip zone/tz details
        date_str_clean = re.sub(r'\s*(?:UTC|GMT|Z|[+-]\d{2}:?\d{2})', '', date_str)
        formats = [
            '%Y-%m-%dT%H:%M:%S',
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%d',
            '%d-%m-%Y',
            '%d/%m/%Y',
            '%Y.%m.%d',
            '%d-%b-%Y',
            '%d %b %Y'
        ]
        for fmt in formats:
            try:
                creation_date = datetime.datetime.strptime(date_str_clean.split('.')[0].strip(), fmt)
                break
            except Exception:
                continue
        if creation_date:
            break

print(f'  \033[32m[+]\033[0m Registrar: {registrar if registrar else \"N/A\"}')
if creation_date:
    now_dt = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    age_days = (now_dt - creation_date).days
    print(f'  \033[32m[+]\033[0m Registration Date: {creation_date.strftime(\"%Y-%m-%d\")}')
    if age_days < 30:
        print(f'  \033[1;31m[!] CRITICAL: Domain is very young! Age: {age_days} days (Created < 1 month ago)\033[0m')
    elif age_days < 180:
        print(f'  \033[1;33m[!] WARNING: Domain is relatively new. Age: {age_days} days (< 6 months)\033[0m')
    else:
        print(f'  \033[32m[✔]\033[0m Domain Age: {age_days} days (~{age_days//365} years old)')
else:
    print('  \033[1;33m[!] Warning: Could not calculate domain age from WHOIS dates.\033[0m')
"
fi


# --- SECTION 3: IP RESOLUTION, ASN, AND HOSTING PROVIDER ---
echo -e "\n${BLUE}${BOLD}--- 3. IP Resolution, ASN & Hosting Provider ---${NC}"
IP=""
# Try resolving using python or dig/host
IP=$(python3 -c "
import socket, sys
try:
    print(socket.gethostbyname('$DOMAIN'))
except Exception:
    pass
")

if [ -z "$IP" ]; then
    # Fallback to dig
    IP=$(dig +short "$DOMAIN" | tail -n1)
fi

if [ -n "$IP" ]; then
    echo -e "  ${GREEN}[+]$NC Resolved IP Address: ${BOLD}$IP${NC}"
    
    # Query ip-api.com for hosting/geo metadata
    IP_INFO=$(curl -s --max-time 5 "http://ip-api.com/json/$IP" 2>/dev/null)
    if [ -n "$IP_INFO" ] && echo "$IP_INFO" | grep -q '"status":"success"'; then
        python3 -c "
import sys, json
info = json.loads('''$IP_INFO''')
print(f'  \033[32m[+]\033[0m ASN: {info.get(\"as\", \"N/A\")}')
print(f'  \033[32m[+]\033[0m ISP / Host: {info.get(\"isp\", \"N/A\")}')
print(f'  \033[32m[+]\033[0m Org Name: {info.get(\"org\", \"N/A\")}')
print(f'  \033[32m[+]\033[0m Country: {info.get(\"country\", \"N/A\")} ({info.get(\"countryCode\", \"N/A\")})')
"
    else
        # Local WHOIS lookup fallback on IP
        echo -e "  ${YELLOW}[!] Online geo-IP lookup failed. Parsing WHOIS on IP...${NC}"
        IP_WHOIS=$(whois "$IP" 2>/dev/null)
        if [ -n "$IP_WHOIS" ]; then
            python3 -c "
import sys, re
whois_ip = \"\"\"$IP_WHOIS\"\"\"
asn = re.search(r'(?:origin|originas|asn|origin-as)\s*:\s*(AS\d+)', whois_ip, re.IGNORECASE)
org = re.search(r'(?:orgname|descr|owner|organization|org-name)\s*:\s*([^\r\n]+)', whois_ip, re.IGNORECASE)
print(f'  \033[32m[+]\033[0m ASN (WHOIS): {asn.group(1).strip() if asn else \"N/A\"}')
print(f'  \033[32m[+]\033[0m Org (WHOIS): {org.group(1).strip() if org else \"N/A\"}')
"
        else
            echo -e "  ${RED}[!] IP WHOIS lookup failed.${NC}"
        fi
    fi
else
    echo -e "  ${RED}[!] DNS Resolution failed. Domain could be offline or malicious DGA.${NC}"
fi


# --- SECTION 4: TLS CERTIFICATE DETAILS ---
if [[ "$SCHEME" = "https" ]]; then
    echo -e "\n${BLUE}${BOLD}--- 4. TLS/SSL Certificate Details ---${NC}"
    TLS_OUT=$(echo | openssl s_client -connect "$DOMAIN":443 -servername "$DOMAIN" 2>/dev/null | openssl x509 -noout -text 2>/dev/null)
    
    if [ -z "$TLS_OUT" ]; then
        echo -e "  ${RED}[!] Failed to fetch TLS Certificate. HTTPS might be misconfigured.${NC}"
    else
        python3 -c "
import sys, re, datetime
tls_text = \"\"\"$TLS_OUT\"\"\"

issuer = re.search(r'Issuer:\s*([^\r\n]+)', tls_text)
subject = re.search(r'Subject:\s*([^\r\n]+)', tls_text)
not_before = re.search(r'Not Before\s*:\s*([^\r\n]+)', tls_text)
not_after = re.search(r'Not After\s*:\s*([^\r\n]+)', tls_text)
sans_match = re.search(r'Subject Alternative Name:\s*\n\s*([^\r\n]+)', tls_text, re.IGNORECASE)

print(f'  \033[32m[+]\033[0m Issuer: {issuer.group(1).strip() if issuer else \"N/A\"}')
print(f'  \033[32m[+]\033[0m Subject: {subject.group(1).strip() if subject else \"N/A\"}')

if not_before and not_after:
    nb_str = not_before.group(1).strip().replace('GMT', '').strip()
    na_str = not_after.group(1).strip().replace('GMT', '').strip()
    print(f'  \033[32m[+]\033[0m Valid From: {nb_str}')
    print(f'  \033[32m[+]\033[0m Valid Until: {na_str}')
    
    # Expiry Check
    try:
        na_dt = datetime.datetime.strptime(na_str, '%b %d %H:%M:%S %Y')
        now_dt = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
        if na_dt < now_dt:
            print('  \033[1;31m[!] CRITICAL: TLS Certificate is EXPIRED!\033[0m')
        else:
            days_left = (na_dt - now_dt).days
            if days_left < 7:
                print(f'  \033[1;33m[!] WARNING: TLS Certificate expires in {days_left} days!\033[0m')
            else:
                print(f'  \033[32m[✔]\033[0m Certificate is valid for another {days_left} days.')
    except Exception as e:
        pass

if sans_match:
    print(f'  \033[32m[+]\033[0m Subject Alternative Names (SANs):')
    print(f'      {sans_match.group(1).strip()}')
"
    fi
fi


# --- SECTION 5: FAVICON HASH ANALYSIS ---
echo -e "\n${BLUE}${BOLD}--- 5. Favicon Analysis & Hashing (MD5, SHA-256, Shodan MurmurHash) ---${NC}"
python3 -c "
import sys, re, urllib.request, urllib.parse, hashlib, base64

url = '$URL_WITH_SCHEME'
domain = '$DOMAIN'

def murmur3_32(data, seed=0):
    data = bytearray(data)
    length = len(data)
    nblocks = length // 4
    h1 = seed
    c1 = 0xcc9e2d51
    c2 = 0x1b873593

    for i in range(nblocks):
        k1 = data[i*4] | (data[i*4+1] << 8) | (data[i*4+2] << 16) | (data[i*4+3] << 24)
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xe6546b64) & 0xFFFFFFFF

    tail = data[nblocks*4:]
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
    h1 ^= (h1 >> 16)
    h1 = (h1 * 0x85ebca6b) & 0xFFFFFFFF
    h1 ^= (h1 >> 13)
    h1 = (h1 * 0xc2b2ae35) & 0xFFFFFFFF
    h1 ^= (h1 >> 16)

    if h1 & 0x80000000:
        return -((~h1 + 1) & 0xFFFFFFFF)
    return h1

# Try to find favicon URL in HTML
favicon_url = urllib.parse.urljoin(url, '/favicon.ico')
html_content = ''
req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0 HoneyShield Analysis'})

try:
    with urllib.request.urlopen(req, timeout=5) as resp:
        # Check if text/html
        content_type = resp.headers.get('Content-Type', '')
        if 'html' in content_type:
            html_content = resp.read().decode('utf-8', errors='ignore')
            # Look for link containing shortcut icon or icon
            match = re.search(r'<link[^>]*rel=[\"\'](?:shortcut )?icon[\"\'][^>]*href=[\"\']([^\"\']+)[\"\']', html_content, re.IGNORECASE)
            if not match:
                match = re.search(r'<link[^>]*href=[\"\']([^\"\']+)[\"\'][^>]*rel=[\"\'](?:shortcut )?icon[\"\']', html_content, re.IGNORECASE)
            if match:
                favicon_url = urllib.parse.urljoin(url, match.group(1))
except Exception:
    pass

print(f'  [*] Favicon URL location: {favicon_url}')

# Fetch favicon
try:
    fav_req = urllib.request.Request(favicon_url, headers={'User-Agent': 'Mozilla/5.0 HoneyShield Analysis'})
    with urllib.request.urlopen(fav_req, timeout=5) as resp:
        favicon_data = resp.read()
        if favicon_data:
            md5_val = hashlib.md5(favicon_data).hexdigest()
            sha_val = hashlib.sha256(favicon_data).hexdigest()
            
            # Shodan hash: Murmur3(base64(favicon_data)) with newlines every 76 characters and a trailing newline
            b64_data = base64.encodebytes(favicon_data)
            shodan_val = murmur3_32(b64_data)
            
            print(f'  \033[32m[+]\033[0m Favicon MD5: {md5_val}')
            print(f'  \033[32m[+]\033[0m Favicon SHA-256: {sha_val}')
            print(f'  \033[32m[+]\033[0m Shodan MurmurHash: {shodan_val}')
        else:
            print('  \033[1;33m[!] Warning: Favicon file is empty.\033[0m')
except Exception as e:
    print(f'  \033[1;33m[!] Warning: Could not retrieve favicon ({str(e)}).\033[0m')
"


# --- SECTION 6: URL PATH PATTERNS & QUERY PARAMS ---
echo -e "\n${BLUE}${BOLD}--- 6. Path Patterns & Query Parameters ---${NC}"
python3 -c "
import sys, urllib.parse, re

url = '$URL'
parsed = urllib.parse.urlparse(url)
path = parsed.path
query = parsed.query

print(f'  \033[32m[+]\033[0m Path: {path if path else \"/\"}')

# Path Pattern Checks
suspicious_keywords = ['login', 'signin', 'secure', 'update', 'banking', 'verification', 'verify', 'account', 'free', 'gift', 'support', 'billing', 'admin']
suspicious_exts = ['.apk', '.exe', '.bin', '.scr', '.jar', '.zip', '.dex', '.rar']

matches_keywords = [w for w in suspicious_keywords if w in path.lower() or w in parsed.netloc.lower()]
matches_exts = [e for e in suspicious_exts if path.lower().endswith(e)]

if matches_exts:
    print(f'  \033[1;33m[!] WARNING: Executable extension in path: {matches_exts}\033[0m')
if matches_keywords:
    print(f'  \033[1;33m[!] WARNING: Suspicious phishing keywords detected: {matches_keywords}\033[0m')

depth = len([p for p in path.split('/') if p])
print(f'  \033[32m[+]\033[0m Directory Depth: {depth}')
if depth > 4:
    print('  \033[1;33m[!] WARNING: Unusually deep path directories (potential directory obfuscation).\033[0m')

# Query Params
if query:
    params = urllib.parse.parse_qs(query)
    print(f'  \033[32m[+]\033[0m Query Parameters found: {len(params)}')
    for key, vals in params.items():
        for val in vals:
            print(f'      - {key} = {val}')
            # Check for base64 or nested URLs
            if val.startswith('http://') or val.startswith('https://'):
                print('        \033[1;33m[!] WARNING: Nested URL found in parameter value.\033[0m')
            if re.match(r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$', val) and len(val) > 8:
                try:
                    import base64
                    decoded = base64.b64decode(val).decode('utf-8', errors='ignore')
                    # check if readable ASCII or looks like another URL
                    if any(c.isalnum() for c in decoded):
                        print(f'        \033[32m[i]\033[0m Decoded Base64 Parameter value: {decoded}')
                except Exception:
                    pass
else:
    print('  \033[32m[✔]\033[0m No Query Parameters detected.')
"


# --- SECTION 7: ENTROPY & HOMOGLYPH DETECTION ---
echo -e "\n${BLUE}${BOLD}--- 7. Shannon Entropy & Homoglyph Audit ---${NC}"
python3 -c "
import sys, math, urllib.parse

domain = '$DOMAIN'
url = '$URL'

def shannon_entropy(s):
    if not s: return 0.0
    probs = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log(p, 2) for p in probs)

# Calculate Entropy
dom_ent = shannon_entropy(domain)
url_ent = shannon_entropy(url)

print(f'  \033[32m[+]\033[0m Domain Shannon Entropy: {dom_ent:.4f}')
print(f'  \033[32m[+]\033[0m Total URL Shannon Entropy: {url_ent:.4f}')

if dom_ent > 4.2:
    print('  \033[1;33m[!] WARNING: High Domain Entropy. Potential DGA (Domain Generation Algorithm).\033[0m')
if url_ent > 5.0:
    print('  \033[1;33m[!] WARNING: High URL Entropy. Potential encoded payload or random path obfuscation.\033[0m')

# Homoglyph Check
is_punycode = domain.lower().startswith('xn--')
decoded = domain

if is_punycode:
    print('  \033[1;31m[!] ALERT: Internationalized Domain Name (Punycode / IDN) detected!\033[0m')
    try:
        decoded = domain.encode('ascii').decode('idna')
        print(f'      Decoded UTF-8 domain: {decoded}')
    except Exception as e:
        print(f'      Failed to decode Punycode: {str(e)}')

# Check lookalikes
lookalikes = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ѕ': 's',
    'ԁ': 'd', 'һ': 'h', 'ј': 'j', 'ⅼ': 'l', 'ո': 'n', 'ԛ': 'q', 'ԝ': 'w',
    'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'І': 'I', 'Ј': 'J',
    'К': 'K', 'М': 'M', 'О': 'O', 'Р': 'P', 'Т': 'T', 'Х': 'X', 'Ү': 'Y'
}

found_homoglyphs = []
for char in decoded:
    if char in lookalikes:
        found_homoglyphs.append((char, lookalikes[char]))

if found_homoglyphs:
    print('  \033[1;31m[!] ALERT: Homoglyph characters detected! Potential visual impersonation.\033[0m')
    for char, target in found_homoglyphs:
        print(f'      - Character: \"{char}\" (U+{ord(char):04X}) looks like Latin \"{target}\"')

# Mixed scripts check
has_latin = False
has_cyrillic = False
has_greek = False
for char in decoded:
    val = ord(char)
    if 65 <= val <= 90 or 97 <= val <= 122:
        has_latin = True
    elif 0x0400 <= val <= 0x04FF:
        has_cyrillic = True
    elif 0x0370 <= val <= 0x03FF:
        has_greek = True

if sum([has_latin, has_cyrillic, has_greek]) >= 2:
    print('  \033[1;31m[!] ALERT: Mixed Scripts detected in Domain labels! Potential IDN Homograph Phishing.\033[0m')
elif not is_punycode and not found_homoglyphs:
    print('  \033[32m[✔]\033[0m Domain uses standard scripts. No homoglyphs detected.')
"

echo -e "\n${CYAN}${BOLD}======================================================================${NC}"
echo -e "${GREEN}${BOLD}[✔] Sanity Check & URL Parameter Analysis Complete.${NC}"
echo -e "${CYAN}${BOLD}======================================================================${NC}\n"
