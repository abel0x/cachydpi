#!/bin/bash
# CachyDPI v1.0.0 Deploy Script
# Quick deploy and verify for development/testing
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Destinations are overridable so the script can be exercised against a
# sandbox instead of the live system.
BIN_DEST="${CACHYDPI_BIN_DEST:-/usr/bin/cachydpi}"
CONFIG_DEST="${CACHYDPI_CONFIG_DEST:-/etc/cachydpi/config.toml}"

echo "=== CachyDPI Deploy ==="
echo "Deploying binary..."
install -Dm755 "$SCRIPT_DIR/target/release/cachydpi" "$BIN_DEST"

# Never overwrite a config that is already in place. It holds operator
# choices — the domain filter mode above all — and replacing it does not
# fail loudly the way a corrupt config does: the daemon starts happily with
# settings nobody asked for. This mirrors what install.sh does and what
# pacman does for the backup= entries in PKGBUILD.
echo "Deploying config..."
if [[ -e "$CONFIG_DEST" ]]; then
    install -Dm644 "$SCRIPT_DIR/config/config.toml" "$CONFIG_DEST.new"
    echo "  existing config left untouched; shipped version written to $CONFIG_DEST.new"
else
    install -Dm644 "$SCRIPT_DIR/config/config.toml" "$CONFIG_DEST"
    echo "  installed $CONFIG_DEST"
fi

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
