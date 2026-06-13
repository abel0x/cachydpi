#!/bin/bash
# CachyDPI v1.0.0 Deploy Script
# Quick deploy and verify for development/testing
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== CachyDPI Deploy ==="
echo "Deploying binary..."
cp "$SCRIPT_DIR/target/release/cachydpi" /usr/bin/cachydpi

echo "Deploying config..."
cp "$SCRIPT_DIR/config/config.toml" /etc/cachydpi/config.toml

echo "Restarting service..."
systemctl daemon-reload
systemctl restart cachydpi
sleep 2

STATUS=$(systemctl is-active cachydpi)
echo "Service: $STATUS"

if [ "$STATUS" != "active" ]; then
    echo "ERROR: Service failed to start!"
    journalctl -u cachydpi --no-pager -n 20
    exit 1
fi

echo ""
echo "=== Testing Sites ==="
for site in github.com www.google.com twitter.com reddit.com youtube.com; do
    CODE=$(timeout 8 curl -sI --max-time 5 "https://$site" -o /dev/null -w "%{http_code}" 2>/dev/null || echo "000")
    echo "$site = $CODE"
done

echo ""
echo "=== Packet Verification ==="
# Quick tcpdump to verify NO fake RST packets are sent
INTERFACE=$(ip route show default | awk '{print $5; exit}')
if [ -z "$INTERFACE" ]; then
    echo "WARNING: Could not detect default network interface, skipping packet verification"
    echo "=== DONE ==="
    exit 0
fi
rm -f /tmp/verify.pcap
timeout 8 tcpdump -nn -v -i "$INTERFACE" "host 140.82.121.3 and port 443" -c 15 -w /tmp/verify.pcap &
TCPPID=$!
sleep 1
curl -4 -sI --max-time 5 https://github.com --resolve "github.com:443:140.82.121.3" -o /dev/null -w "verify_code=%{http_code}\n" 2>/dev/null || true
sleep 2
kill $TCPPID 2>/dev/null || true
wait $TCPPID 2>/dev/null || true
echo "Packets (should show NO ttl 8 / RST packets):"
tcpdump -nn -v -r /tmp/verify.pcap 2>/dev/null | grep -E "ttl|Flags" | head -15
echo ""
echo "=== DONE ==="
