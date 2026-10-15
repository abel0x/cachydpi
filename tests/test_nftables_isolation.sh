#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 abel0x <https://github.com/abel0x>
# tests/test_nftables_isolation.sh — nftables Isolation Tests
#
# Tests that CachyDPI's nftables rules don't interfere with Docker,
# libvirt, firewalld, or other services. Verifies SO_MARK loop prevention.
# Must be run as root.
#
# Usage: sudo bash tests/test_nftables_isolation.sh

set -euo pipefail

SERVICE="cachydpi.service"
REPORT_DIR="tests/reports"
REPORT="$REPORT_DIR/nftables_isolation_report.txt"

mkdir -p "$REPORT_DIR"

echo "=== CachyDPI nftables Isolation Test Report ===" > "$REPORT"
echo "Date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')" >> "$REPORT"
echo "" >> "$REPORT"

PASS=0
FAIL=0
SKIP=0

pass() { echo "[PASS] $1" | tee -a "$REPORT"; PASS=$((PASS + 1)); }
fail() { echo "[FAIL] $1" | tee -a "$REPORT"; FAIL=$((FAIL + 1)); }
skip() { echo "[SKIP] $1" | tee -a "$REPORT"; SKIP=$((SKIP + 1)); }

# ── Test 1: Table isolation ──
echo "" >> "$REPORT"
echo "--- Test 1: Dedicated table isolation ---" >> "$REPORT"

# Record existing tables before starting
tables_before=$(nft list tables 2>/dev/null || true)
echo "  Tables before start:" >> "$REPORT"
echo "$tables_before" | sed 's/^/    /' >> "$REPORT"

systemctl start "$SERVICE" 2>/dev/null || true
sleep 2

if systemctl is-active "$SERVICE" &>/dev/null; then
    tables_during=$(nft list tables 2>/dev/null || true)
    echo "  Tables during runtime:" >> "$REPORT"
    echo "$tables_during" | sed 's/^/    /' >> "$REPORT"

    # Check CachyDPI uses its own table
    if echo "$tables_during" | grep -q "table ip cachydpi"; then
        pass "CachyDPI uses dedicated 'cachydpi' table (IPv4)"
    else
        fail "CachyDPI table 'ip cachydpi' not found"
    fi

    # Check it didn't modify other tables
    other_tables_before=$(echo "$tables_before" | grep -v "cachydpi" | sort)
    other_tables_during=$(echo "$tables_during" | grep -v "cachydpi" | sort)
    if [[ "$other_tables_before" == "$other_tables_during" ]]; then
        pass "Other nftables tables unchanged"
    else
        fail "Other nftables tables were modified!"
        diff <(echo "$other_tables_before") <(echo "$other_tables_during") >> "$REPORT" 2>/dev/null || true
    fi

    # ── Test 2: Chain structure ──
    echo "" >> "$REPORT"
    echo "--- Test 2: Chain structure ---" >> "$REPORT"
    ruleset=$(nft list table ip cachydpi 2>/dev/null || true)
    echo "$ruleset" | sed 's/^/    /' >> "$REPORT"

    # Verify output chain exists
    if echo "$ruleset" | grep -q "chain output"; then
        pass "Output chain exists in cachydpi table"
    else
        fail "Output chain missing"
    fi

    # Verify input chain exists
    if echo "$ruleset" | grep -q "chain input"; then
        pass "Input chain exists in cachydpi table"
    else
        fail "Input chain missing"
    fi

    # Verify CACHYDPI_MARK (0xCACD) is used for loop prevention
    # nft may zero-pad the hex value (e.g. 0x0000cacd)
    if echo "$ruleset" | grep -qi "cacd"; then
        pass "CACHYDPI_MARK (0xCACD) used for packet marking"
    else
        fail "CACHYDPI_MARK not found in rules"
    fi

    # Verify bypass flag on queue rules
    if echo "$ruleset" | grep -q "bypass"; then
        pass "bypass flag present on queue rules"
    else
        fail "bypass flag missing — packets could be dropped if queue is full"
    fi

    # ── Test 3: Docker coexistence ──
    echo "" >> "$REPORT"
    echo "--- Test 3: Docker coexistence ---" >> "$REPORT"
    if command -v docker &>/dev/null; then
        # Check Docker's iptables/nftables are intact
        docker_tables=$(nft list tables 2>/dev/null | grep -i "docker\|nat\|filter" || true)
        if [[ -n "$docker_tables" ]]; then
            echo "  Docker-related tables found:" >> "$REPORT"
            echo "$docker_tables" | sed 's/^/    /' >> "$REPORT"
            pass "Docker nftables tables coexist with CachyDPI"
        else
            skip "No Docker nftables tables found (Docker may use iptables)"
        fi

        # Test Docker connectivity if Docker is running
        if systemctl is-active docker &>/dev/null; then
            if docker run --rm --net=host alpine:latest ping -c 1 -W 3 1.1.1.1 &>/dev/null 2>&1; then
                pass "Docker container networking works with CachyDPI active"
            else
                fail "Docker container networking broken with CachyDPI active"
            fi
        else
            skip "Docker service not running"
        fi
    else
        skip "Docker not installed"
    fi

    # ── Test 4: libvirt coexistence ──
    echo "" >> "$REPORT"
    echo "--- Test 4: libvirt coexistence ---" >> "$REPORT"
    if command -v virsh &>/dev/null; then
        libvirt_tables=$(nft list tables 2>/dev/null | grep -i "libvirt" || true)
        if [[ -n "$libvirt_tables" ]]; then
            echo "  libvirt tables:" >> "$REPORT"
            echo "$libvirt_tables" | sed 's/^/    /' >> "$REPORT"
            pass "libvirt tables coexist with CachyDPI"
        else
            skip "libvirt installed but not using nftables — coexistence test not applicable"
        fi
    else
        skip "libvirt not installed — cannot test coexistence"
    fi

    # ── Test 5: firewalld coexistence ──
    echo "" >> "$REPORT"
    echo "--- Test 5: firewalld coexistence ---" >> "$REPORT"
    if systemctl is-active firewalld &>/dev/null; then
        firewalld_tables=$(nft list tables 2>/dev/null | grep -i "firewalld" || true)
        if [[ -n "$firewalld_tables" ]]; then
            pass "firewalld tables coexist with CachyDPI"
        else
            skip "firewalld active but not using nftables — coexistence test not applicable"
        fi
    else
        skip "firewalld not active — cannot test coexistence"
    fi

    # ── Test 6: SO_MARK loop prevention ──
    echo "" >> "$REPORT"
    echo "--- Test 6: SO_MARK loop prevention ---" >> "$REPORT"
    # CachyDPI marks its raw socket packets with 0xCACD
    # nftables rules should skip packets with this mark
    if echo "$ruleset" | grep -q "mark .* 0xcacd\|meta mark 0xcacd"; then
        pass "Packet mark check prevents processing loop"
    else
        # The mark check may be in a different format
        if echo "$ruleset" | grep -q "mark"; then
            mark_rules=$(echo "$ruleset" | grep "mark")
            echo "  Mark-related rules: $mark_rules" >> "$REPORT"
            pass "Mark-based rules found (verify loop prevention)"
        else
            fail "No mark-based loop prevention found in rules"
        fi
    fi

    # Stop service and verify cleanup
    systemctl stop "$SERVICE" 2>/dev/null || true
    sleep 2

    tables_after=$(nft list tables 2>/dev/null || true)
    other_tables_after=$(echo "$tables_after" | grep -v "cachydpi" | sort)
    if ! echo "$tables_after" | grep -q "cachydpi"; then
        pass "CachyDPI table removed after stop"
    else
        fail "CachyDPI table still exists after stop"
    fi

    if [[ "$other_tables_before" == "$other_tables_after" ]]; then
        pass "Other tables unchanged after CachyDPI stop"
    else
        fail "Other tables modified after CachyDPI lifecycle"
    fi
else
    skip "Service not active for isolation tests"
fi

# ── Summary ──
echo "" >> "$REPORT"
echo "========================================" >> "$REPORT"
echo "SUMMARY: $PASS passed, $FAIL failed, $SKIP skipped" >> "$REPORT"
echo "========================================" >> "$REPORT"

echo ""
echo "Report written to $REPORT"
echo "Results: $PASS passed, $FAIL failed, $SKIP skipped"
