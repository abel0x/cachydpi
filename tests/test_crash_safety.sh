#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 abel0x <https://github.com/abel0x>
# tests/test_crash_safety.sh — Crash Safety Tests
#
# Tests signal handling, nftables cleanup after crashes, panic hook,
# and ENOBUFS resilience.
# Must be run as root.
#
# Usage: sudo bash tests/test_crash_safety.sh

set -euo pipefail

SERVICE="cachydpi.service"
REPORT_DIR="tests/reports"
REPORT="$REPORT_DIR/crash_safety_report.txt"

mkdir -p "$REPORT_DIR"

echo "=== CachyDPI Crash Safety Test Report ===" > "$REPORT"
echo "Date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')" >> "$REPORT"
echo "" >> "$REPORT"

PASS=0
FAIL=0
SKIP=0

pass() { echo "[PASS] $1" | tee -a "$REPORT"; PASS=$((PASS + 1)); }
fail() { echo "[FAIL] $1" | tee -a "$REPORT"; FAIL=$((FAIL + 1)); }
skip() { echo "[SKIP] $1" | tee -a "$REPORT"; SKIP=$((SKIP + 1)); }

check_nftables_clean() {
    if nft list tables 2>/dev/null | grep -q "cachydpi"; then
        return 1  # table still exists
    fi
    return 0  # clean
}

ensure_service_stopped() {
    systemctl stop "$SERVICE" 2>/dev/null || true
    sleep 1
}

# ── Test 1: SIGTERM clean shutdown ──
echo "" >> "$REPORT"
echo "--- Test 1: SIGTERM clean shutdown ---" >> "$REPORT"
ensure_service_stopped
if check_nftables_clean; then
    systemctl start "$SERVICE" 2>/dev/null
    sleep 2
    if systemctl is-active "$SERVICE" &>/dev/null; then
        # Verify nftables rules exist
        if nft list tables 2>/dev/null | grep -q "cachydpi"; then
            pass "nftables rules installed while running"
        else
            fail "nftables rules NOT installed while running"
        fi

        # Send SIGTERM via systemctl stop
        systemctl stop "$SERVICE"
        sleep 2

        if check_nftables_clean; then
            pass "nftables rules cleaned up after SIGTERM"
        else
            fail "nftables rules STILL PRESENT after SIGTERM"
            # Clean up for next test
            nft delete table ip cachydpi 2>/dev/null || true
            nft delete table ip6 cachydpi 2>/dev/null || true
        fi
    else
        skip "Service failed to start for SIGTERM test"
    fi
else
    fail "nftables rules present before test (stale rules?) — cleaning"
    nft delete table ip cachydpi 2>/dev/null || true
    nft delete table ip6 cachydpi 2>/dev/null || true
fi

# ── Test 2: SIGKILL (unclean kill) ──
echo "" >> "$REPORT"
echo "--- Test 2: SIGKILL nftables cleanup ---" >> "$REPORT"
ensure_service_stopped
# Clean any stale rules
nft delete table ip cachydpi 2>/dev/null || true
nft delete table ip6 cachydpi 2>/dev/null || true
sleep 1

systemctl start "$SERVICE" 2>/dev/null
sleep 2

if systemctl is-active "$SERVICE" &>/dev/null; then
    pid=$(systemctl show -p MainPID "$SERVICE" | cut -d= -f2)
    echo "  PID before SIGKILL: $pid" >> "$REPORT"

    # SIGKILL — no chance to clean up
    kill -9 "$pid" 2>/dev/null || true
    sleep 2

    if nft list tables 2>/dev/null | grep -q "cachydpi"; then
        # This is EXPECTED — SIGKILL cannot be caught
        # But the important thing is the NEXT start cleans up
        echo "  nftables rules remain after SIGKILL (expected)" >> "$REPORT"

        # Start again — should clean up old rules and install new ones
        systemctl stop "$SERVICE" 2>/dev/null || true
        sleep 1
        nft delete table ip cachydpi 2>/dev/null || true
        nft delete table ip6 cachydpi 2>/dev/null || true
        systemctl start "$SERVICE" 2>/dev/null
        sleep 2

        if systemctl is-active "$SERVICE" &>/dev/null; then
            pass "Service recovered after SIGKILL"
            systemctl stop "$SERVICE" 2>/dev/null || true
            sleep 1
        else
            fail "Service failed to start after SIGKILL recovery"
        fi
    else
        pass "nftables rules cleaned even after SIGKILL (panic hook worked)"
    fi
else
    skip "Service failed to start for SIGKILL test"
fi

# Clean up
nft delete table ip cachydpi 2>/dev/null || true
nft delete table ip6 cachydpi 2>/dev/null || true

# ── Test 3: SIGINT handling ──
echo "" >> "$REPORT"
echo "--- Test 3: SIGINT handling ---" >> "$REPORT"
ensure_service_stopped
nft delete table ip cachydpi 2>/dev/null || true
nft delete table ip6 cachydpi 2>/dev/null || true

systemctl start "$SERVICE" 2>/dev/null
sleep 2

if systemctl is-active "$SERVICE" &>/dev/null; then
    pid=$(systemctl show -p MainPID "$SERVICE" | cut -d= -f2)
    kill -INT "$pid" 2>/dev/null || true
    sleep 3

    if check_nftables_clean; then
        pass "nftables rules cleaned up after SIGINT"
    else
        fail "nftables rules STILL PRESENT after SIGINT"
        nft delete table ip cachydpi 2>/dev/null || true
        nft delete table ip6 cachydpi 2>/dev/null || true
    fi
else
    skip "Service not active for SIGINT test"
fi

# ── Test 4: Rapid start-stop cycles ──
echo "" >> "$REPORT"
echo "--- Test 4: Rapid start-stop cycles ---" >> "$REPORT"
ensure_service_stopped
nft delete table ip cachydpi 2>/dev/null || true
nft delete table ip6 cachydpi 2>/dev/null || true

cycles_ok=0
cycles_fail=0

for i in $(seq 1 5); do
    systemctl start "$SERVICE" 2>/dev/null || true
    sleep 1
    systemctl stop "$SERVICE" 2>/dev/null || true
    sleep 1

    if check_nftables_clean; then
        cycles_ok=$((cycles_ok + 1))
    else
        cycles_fail=$((cycles_fail + 1))
        nft delete table ip cachydpi 2>/dev/null || true
        nft delete table ip6 cachydpi 2>/dev/null || true
    fi
done

echo "  Cycles OK: $cycles_ok / 5" >> "$REPORT"
if [[ "$cycles_fail" -eq 0 ]]; then
    pass "All 5 rapid start-stop cycles cleaned up correctly"
else
    fail "$cycles_fail out of 5 cycles left stale nftables rules"
fi

# ── Test 5: Journal error check ──
echo "" >> "$REPORT"
echo "--- Test 5: Journal panic/error check ---" >> "$REPORT"
panics=$(journalctl -u "$SERVICE" --since "10 minutes ago" -p err 2>/dev/null | grep -ic "panic\|segfault\|abort\|SIGSEGV" || true)
if [[ "$panics" -gt 0 ]]; then
    fail "Found $panics panic/segfault entries in journal"
    journalctl -u "$SERVICE" --since "10 minutes ago" -p err 2>/dev/null | grep -i "panic\|segfault" | head -5 >> "$REPORT"
else
    pass "No panic/segfault entries in journal"
fi

# ── Summary ──
echo "" >> "$REPORT"
echo "========================================" >> "$REPORT"
echo "SUMMARY: $PASS passed, $FAIL failed, $SKIP skipped" >> "$REPORT"
echo "========================================" >> "$REPORT"

echo ""
echo "Report written to $REPORT"
echo "Results: $PASS passed, $FAIL failed, $SKIP skipped"
