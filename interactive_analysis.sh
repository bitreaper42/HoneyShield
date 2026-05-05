#!/bin/zsh

PORT=1234
OUT="capture.pcap"
TIMEOUT=10

echo "======================================="
echo "   APK Network Analysis Workflow"
echo "======================================="
sleep 3

APK_URL="$1"

echo "[*] Downloading APK..."
sleep 3
wget -q -O sample.apk "$APK_URL" || { echo "[!] Download failed"; exit 1; }

echo ""
echo "[*] APK saved as sample.apk"
sleep 3

echo ""
echo "===== MANUAL STEPS (DO THIS ON PHONE) ====="
echo "1. Transfer 'sample.apk' to your Android device"
echo "2. Install the APK (enable unknown sources if needed)"
echo "3. Open PCAPdroid"
echo "4. Enable:"
echo "   - Capture traffic"
echo "   - TCP export → set IP = YOUR LAPTOP IP"
echo "   - Port = $PORT"
echo "5. Start capture in PCAPdroid"
echo "6. Launch the app and perform the action (login, etc.)"
echo "==========================================="
read -p "[+] Press ENTER when ready to start capture..."

echo "[*] Listening on TCP port $PORT (timeout: ${TIMEOUT}s)..."

# capture with inactivity timeout
nc -l -v -p $PORT -w $TIMEOUT > "$OUT"

echo "[*] Capture stopped. Processing..."

echo "=== DNS ==="
tshark -r "$OUT" -Y "dns.a && dns.flags.response == 1" \
  -T fields -e dns.qry.name -e dns.a

echo -e "\n=== TLS SNI ==="
tshark -r "$OUT" -Y "tls.handshake.type == 1" \
  -T fields -e ip.dst -e tls.handshake.extensions_server_name

echo -e "\n=== TCP Connections ==="
tshark -r "$OUT" -Y "tcp.flags.syn == 1 && tcp.flags.ack == 0" \
  -T fields -e ip.dst -e tcp.dstport

echo ""
echo "[✔] Analysis complete."