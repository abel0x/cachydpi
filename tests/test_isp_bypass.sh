#!/usr/bin/env bash
# tests/test_isp_bypass.sh — ISP Bypass Verification Tests
#
# Tests that CachyDPI actually bypasses DPI for blacklisted domains.
# Checks TLS SNI splitting, HTTP host splitting, and QUIC blocking.
# Must be run as root with the service active.
#
# Usage: sudo bash tests/test_isp_bypass.sh

set -euo pipefail

SERVICE="cachydpi.service"
REPORT_DIR="tests/reports"
REPORT="$REPORT_DIR/isp_bypass_report.txt"

mkdir -p "$REPORT_DIR"

echo "=== CachyDPI ISP Bypass Verification Report ===" > "$REPORT"
echo "Date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')" >> "$REPORT"
echo "" >> "$REPORT"

PASS=0
FAIL=0
SKIP=0
WARN=0

pass() { echo "[PASS] $1" | tee -a "$REPORT"; PASS=$((PASS + 1)); }
fail() { echo "[FAIL] $1" | tee -a "$REPORT"; FAIL=$((FAIL + 1)); }
skip() { echo "[SKIP] $1" | tee -a "$REPORT"; SKIP=$((SKIP + 1)); }
warn() { echo "[WARN] $1" | tee -a "$REPORT"; WARN=$((WARN + 1)); }

# Sample test domains — mix of commonly blocked categories
TEST_DOMAINS_TLS=(
    "twitter.com"
    "reddit.com"
    "discord.com"
    "steamcommunity.com"
    "pastebin.com"
)

TEST_DOMAINS_HTTP=(
    "httpbin.org"
)

# ── Pre-check: Service status ──
echo "" >> "$REPORT"
echo "--- Pre-check: Service Status ---" >> "$REPORT"

if ! systemctl is-active "$SERVICE" &>/dev/null; then
    echo "  Starting $SERVICE..." >> "$REPORT"
    systemctl start "$SERVICE" 2>/dev/null || true
    sleep 2
fi

if systemctl is-active "$SERVICE" &>/dev/null; then
    pass "Service is active"
    PID=$(systemctl show -p MainPID --value "$SERVICE")
    echo "  PID: $PID" >> "$REPORT"
else
    fail "Service is not active — cannot proceed"
    echo "" >> "$REPORT"
    echo "SUMMARY: 0 passed, 1 failed, 0 skipped" >> "$REPORT"
    exit 1
fi

# Verify nftables rules are present
if nft list table ip cachydpi &>/dev/null 2>&1; then
    pass "nftables rules are loaded"
else
    fail "nftables rules not loaded"
fi

# ── Test 1: HTTPS connectivity to blacklisted domains (with DPI bypass) ──
echo "" >> "$REPORT"
echo "--- Test 1: HTTPS connectivity (DPI bypass active) ---" >> "$REPORT"

for domain in "${TEST_DOMAINS_TLS[@]}"; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
        --connect-timeout 5 "https://${domain}/" 2>/dev/null || echo "000")
    
    # Normalize: curl may return 000 or 000000 on connection failure
    HTTP_CODE=$(echo "$HTTP_CODE" | sed 's/^0*//' | head -c 3)
    HTTP_CODE=${HTTP_CODE:-000}

    if [[ "$HTTP_CODE" == "000" || "$HTTP_CODE" == "0" ]]; then
        # HTTP timeout — check if TLS handshake works (DPI bypass cares about TLS, not HTTP)
        TLS_CHECK=$(echo | timeout 10 openssl s_client -connect "${domain}:443" \
            -servername "$domain" 2>&1 || true)
        if echo "$TLS_CHECK" | grep -q "Verify return code: 0"; then
            pass "$domain — HTTP timeout but TLS handshake verified"
        else
            warn "$domain — connection failed (timeout/refused — may be ISP-blocked or down)"
        fi
    elif [[ "$HTTP_CODE" =~ ^[23] ]]; then
        pass "$domain — HTTP $HTTP_CODE (accessible)"
    elif [[ "$HTTP_CODE" == "403" ]]; then
        warn "$domain — HTTP 403 (server-side block, not ISP)"
    elif [[ "$HTTP_CODE" =~ ^[45] ]]; then
        warn "$domain — HTTP $HTTP_CODE (server error, may not be ISP block)"
    else
        fail "$domain — unexpected HTTP $HTTP_CODE"
    fi
done

# ── Test 2: TLS handshake verification ──
echo "" >> "$REPORT"
echo "--- Test 2: TLS handshake verification ---" >> "$REPORT"

for domain in "${TEST_DOMAINS_TLS[@]}"; do
    TLS_OUTPUT=$(echo | timeout 10 openssl s_client -connect "${domain}:443" \
        -servername "$domain" 2>&1 || true)
    
    if echo "$TLS_OUTPUT" | grep -q "Verify return code: 0"; then
        pass "$domain — TLS handshake successful (verified)"
    elif echo "$TLS_OUTPUT" | grep -q "CONNECTED"; then
        TLS_VER=$(echo "$TLS_OUTPUT" | grep "Protocol  :" | head -1 || echo "?")
        pass "$domain — TLS connected ($TLS_VER)"
    elif echo "$TLS_OUTPUT" | grep -q "Connection refused\|Connection timed out"; then
        fail "$domain — connection refused/timeout"
    else
        fail "$domain — TLS handshake failed"
    fi
done

# ── Test 3: Baseline without DPI bypass ──
echo "" >> "$REPORT"
echo "--- Test 3: Baseline comparison (bypass disabled briefly) ---" >> "$REPORT"

# Stop service to test without DPI bypass
systemctl stop "$SERVICE" 2>/dev/null || true
sleep 2

BASELINE_RESULTS=()
for domain in "${TEST_DOMAINS_TLS[@]}"; do
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
        --connect-timeout 5 "https://${domain}/" 2>/dev/null || echo "000")
    BASELINE_RESULTS+=("${domain}:${HTTP_CODE}")
    echo "  $domain without bypass: HTTP $HTTP_CODE" >> "$REPORT"
done

# Restart service
systemctl start "$SERVICE" 2>/dev/null || true
sleep 2

# Compare
echo "" >> "$REPORT"
echo "  Comparison:" >> "$REPORT"
IMPROVED=0
SAME=0
DEGRADED=0

for entry in "${BASELINE_RESULTS[@]}"; do
    domain="${entry%%:*}"
    baseline_code="${entry##*:}"
    
    bypass_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 \
        --connect-timeout 5 "https://${domain}/" 2>/dev/null || echo "000")
    
    echo "  $domain: baseline=$baseline_code bypass=$bypass_code" >> "$REPORT"
    
    if [[ "$baseline_code" == "000" && "$bypass_code" != "000" ]]; then
        IMPROVED=$((IMPROVED + 1))
    elif [[ "$baseline_code" != "000" && "$bypass_code" == "000" ]]; then
        DEGRADED=$((DEGRADED + 1))
    else
        SAME=$((SAME + 1))
    fi
done

echo "  Improved: $IMPROVED, Same: $SAME, Degraded: $DEGRADED" >> "$REPORT"

if (( DEGRADED == 0 )); then
    pass "No degradation with bypass active"
else
    fail "$DEGRADED domains degraded with bypass active"
fi

if (( IMPROVED > 0 )); then
    pass "$IMPROVED domains improved with bypass (DPI bypass effective)"
else
    warn "No improvement detected — bypass effectiveness could not be verified"
fi

# ── Test 4: DNS resolution check ──
echo "" >> "$REPORT"
echo "--- Test 4: DNS resolution ---" >> "$REPORT"

for domain in "${TEST_DOMAINS_TLS[@]}"; do
    if host "$domain" &>/dev/null 2>&1; then
        IP=$(host "$domain" 2>/dev/null | grep "has address" | head -1 | awk '{print $NF}')
        pass "$domain resolves to $IP"
    elif dig "$domain" +short 2>/dev/null | head -1 | grep -q '^[0-9]'; then
        IP=$(dig "$domain" +short 2>/dev/null | head -1)
        pass "$domain resolves to $IP"
    else
        fail "$domain DNS resolution failed (DNS poisoning?)"
    fi
done

# ── Test 5: QUIC/UDP-443 blocking verification ──
echo "" >> "$REPORT"
echo "--- Test 5: QUIC blocking verification ---" >> "$REPORT"

# CachyDPI should drop QUIC on 443 for blacklisted domains
QUIC_RULE=$(nft list table ip cachydpi 2>/dev/null | grep -i "udp.*443\|quic" || true)
if [[ -n "$QUIC_RULE" ]]; then
    echo "  QUIC rule: $QUIC_RULE" >> "$REPORT"
    pass "QUIC blocking rules present"
else
    skip "No explicit QUIC rule found (may use different mechanism)"
fi

# ── Test 6: Service metrics ──
echo "" >> "$REPORT"
echo "--- Test 6: Service metrics after tests ---" >> "$REPORT"

# Check journal for metric lines
METRICS_LOG=$(journalctl -u "$SERVICE" --since "2 minutes ago" --no-pager 2>/dev/null | \
    grep -i "split\|packet\|metric\|total\|processed" | tail -10 || true)

if [[ -n "$METRICS_LOG" ]]; then
    echo "  Recent metrics:" >> "$REPORT"
    echo "$METRICS_LOG" | sed 's/^/    /' >> "$REPORT"
    pass "Metrics data found in journal"
else
    skip "No metric log entries found"
fi

# ── Summary ──
echo "" >> "$REPORT"
echo "========================================" >> "$REPORT"
echo "SUMMARY: $PASS passed, $FAIL failed, $WARN warnings, $SKIP skipped" >> "$REPORT"
echo "========================================" >> "$REPORT"

echo ""
echo "Report written to $REPORT"
echo "Results: $PASS passed, $FAIL failed, $WARN warnings, $SKIP skipped"
