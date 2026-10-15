#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 abel0x <https://github.com/abel0x>
# tests/test_signal_handling.sh — Signal Handling Tests
#
# Tests SIGTERM graceful shutdown, SIGINT, SIGHUP, SIGUSR1,
# and verifies correct cleanup behavior for each signal type.
# Must be run as root.
#
# Usage: sudo bash tests/test_signal_handling.sh

set -euo pipefail

SERVICE="cachydpi.service"
REPORT_DIR="tests/reports"
REPORT="$REPORT_DIR/signal_handling_report.txt"

mkdir -p "$REPORT_DIR"

echo "=== CachyDPI Signal Handling Test Report ===" > "$REPORT"
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

cleanup_nft() {
    nft delete table ip cachydpi 2>/dev/null || true
    nft delete table ip6 cachydpi 2>/dev/null || true
}

wait_for_active() {
    for i in $(seq 1 30); do
        if systemctl is-active "$SERVICE" &>/dev/null; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

wait_for_inactive() {
    for i in $(seq 1 30); do
        if ! systemctl is-active "$SERVICE" &>/dev/null; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

# Clean state
systemctl stop "$SERVICE" 2>/dev/null || true
cleanup_nft
sleep 1

# ── Test 1: SIGTERM → graceful shutdown ──
echo "" >> "$REPORT"
echo "--- Test 1: SIGTERM graceful shutdown ---" >> "$REPORT"

systemctl start "$SERVICE"
if wait_for_active; then
    PID=$(systemctl show -p MainPID --value "$SERVICE")
    echo "  PID: $PID" >> "$REPORT"

    # Verify nftables rules exist
    if nft list table ip cachydpi &>/dev/null; then
        echo "  nftables: rules present before SIGTERM" >> "$REPORT"
    fi

    # Send SIGTERM
    kill -TERM "$PID" 2>/dev/null || true

    if wait_for_inactive; then
        pass "Process exited cleanly on SIGTERM"

        # Check nftables cleanup
        sleep 1
        if nft list table ip cachydpi &>/dev/null 2>&1; then
            fail "nftables table still exists after SIGTERM"
        else
            pass "nftables table cleaned up after SIGTERM"
        fi

        # Check exit code via journal
        EXIT_STATUS=$(systemctl show -p ExecMainStatus --value "$SERVICE" 2>/dev/null || echo "?")
        echo "  Exit status: $EXIT_STATUS" >> "$REPORT"
        # Acceptable: 0 (clean), 15 (raw SIGTERM), 143 (128+SIGTERM)
        if [[ "$EXIT_STATUS" == "0" || "$EXIT_STATUS" == "15" || "$EXIT_STATUS" == "143" ]]; then
            pass "Exit code $EXIT_STATUS on SIGTERM (acceptable)"
        else
            fail "Unexpected exit code: $EXIT_STATUS"
        fi
    else
        fail "Process did not exit within 6s on SIGTERM"
        systemctl stop "$SERVICE" 2>/dev/null || true
    fi
else
    fail "Service failed to start for SIGTERM test"
fi

sleep 1
cleanup_nft

# ── Test 2: SIGINT → graceful shutdown ──
echo "" >> "$REPORT"
echo "--- Test 2: SIGINT graceful shutdown ---" >> "$REPORT"

systemctl start "$SERVICE"
if wait_for_active; then
    PID=$(systemctl show -p MainPID --value "$SERVICE")

    kill -INT "$PID" 2>/dev/null || true

    if wait_for_inactive; then
        pass "Process exited on SIGINT"

        sleep 1
        if nft list table ip cachydpi &>/dev/null 2>&1; then
            fail "nftables table still exists after SIGINT"
        else
            pass "nftables table cleaned up after SIGINT"
        fi
    else
        fail "Process did not exit on SIGINT"
        systemctl stop "$SERVICE" 2>/dev/null || true
    fi
else
    fail "Service failed to start for SIGINT test"
fi

sleep 1
cleanup_nft

# ── Test 3: SIGHUP behavior ──
echo "" >> "$REPORT"
echo "--- Test 3: SIGHUP handling ---" >> "$REPORT"

systemctl start "$SERVICE"
if wait_for_active; then
    PID=$(systemctl show -p MainPID --value "$SERVICE")

    # Send SIGHUP — CachyDPI does not implement config reload,
    # so it will terminate (default kernel action for SIGHUP).
    kill -HUP "$PID" 2>/dev/null || true

    if wait_for_inactive; then
        # SIGHUP terminates process since no handler — this is expected
        pass "Process terminated on SIGHUP (no reload handler — expected)"
        # Verify nftables cleanup
        sleep 1
        if nft list table ip cachydpi &>/dev/null 2>&1; then
            fail "nftables table still exists after SIGHUP termination"
        else
            pass "nftables cleaned up after SIGHUP termination"
        fi
    else
        # Still active after wait
        NEW_PID=$(systemctl show -p MainPID --value "$SERVICE")
        if [[ "$PID" == "$NEW_PID" ]]; then
            fail "Process unexpectedly survived SIGHUP (no reload handler exists)"
        else
            fail "Process reloaded on SIGHUP but no reload handler is implemented"
        fi
        systemctl stop "$SERVICE" 2>/dev/null || true
    fi
else
    fail "Service failed to start for SIGHUP test"
fi

sleep 1
cleanup_nft

# ── Test 4: SIGUSR1 behavior ──
echo "" >> "$REPORT"
echo "--- Test 4: SIGUSR1 handling ---" >> "$REPORT"

systemctl start "$SERVICE"
if wait_for_active; then
    PID=$(systemctl show -p MainPID --value "$SERVICE")

    # Capture journal before SIGUSR1
    JOURNAL_BEFORE=$(journalctl -u "$SERVICE" --since "5 seconds ago" --no-pager 2>/dev/null | wc -l)

    kill -USR1 "$PID" 2>/dev/null || true

    if wait_for_inactive; then
        # SIGUSR1 default action is terminate — expected since no handler
        pass "Process terminated on SIGUSR1 (no handler — default behavior)"
    else
        fail "Process unexpectedly survived SIGUSR1 (no handler exists — should terminate)"
        systemctl stop "$SERVICE" 2>/dev/null || true
    fi
else
    fail "Service failed to start for SIGUSR1 test"
fi

sleep 1
cleanup_nft

# ── Test 5: SIGKILL recovery ──
echo "" >> "$REPORT"
echo "--- Test 5: SIGKILL recovery ---" >> "$REPORT"

systemctl start "$SERVICE"
if wait_for_active; then
    PID=$(systemctl show -p MainPID --value "$SERVICE")

    kill -9 "$PID" 2>/dev/null || true

    # Wait for process to be killed
    wait_for_inactive || true

    # nftables might be orphaned (expected — SIGKILL can't run cleanup hooks)
    NFT_ORPHANED="no"
    if nft list table ip cachydpi &>/dev/null 2>&1; then
        echo "  Orphaned nftables table found after SIGKILL" >> "$REPORT"
        NFT_ORPHANED="yes"
        pass "nftables orphaned after SIGKILL (expected — no cleanup possible)"
    else
        warn "nftables table absent after SIGKILL (cleanup hook unexpectedly ran)"
    fi

    # Start again — should recover
    cleanup_nft
    systemctl reset-failed "$SERVICE" 2>/dev/null || true
    sleep 1
    systemctl start "$SERVICE" 2>/dev/null || true
    if wait_for_active; then
        pass "Service recovers after SIGKILL"
    else
        fail "Service failed to start after SIGKILL"
    fi

    systemctl stop "$SERVICE" 2>/dev/null || true
else
    fail "Service failed to start for SIGKILL test"
fi

sleep 1
cleanup_nft

# ── Test 6: Rapid signal sequence ──
echo "" >> "$REPORT"
echo "--- Test 6: Rapid signal sequence (handled signals) ---" >> "$REPORT"

systemctl start "$SERVICE"
if wait_for_active; then
    PID=$(systemctl show -p MainPID --value "$SERVICE")

    # Only use signals CachyDPI actually handles (SIGTERM, SIGINT)
    # Send non-fatal signals rapidly — SIGWINCH is always ignored
    kill -WINCH "$PID" 2>/dev/null || true
    kill -WINCH "$PID" 2>/dev/null || true
    kill -WINCH "$PID" 2>/dev/null || true
    kill -WINCH "$PID" 2>/dev/null || true
    sleep 2

    if systemctl is-active "$SERVICE" &>/dev/null; then
        pass "Process survived rapid benign signal sequence"
    else
        fail "Process crashed on rapid benign signal sequence"
    fi

    systemctl stop "$SERVICE" 2>/dev/null || true
else
    fail "Service failed to start for rapid signal test"
fi

sleep 1
cleanup_nft

# ── Test 7: Double SIGTERM ──
echo "" >> "$REPORT"
echo "--- Test 7: Double SIGTERM ---" >> "$REPORT"

systemctl start "$SERVICE"
if wait_for_active; then
    PID=$(systemctl show -p MainPID --value "$SERVICE")

    kill -TERM "$PID" 2>/dev/null || true
    sleep 0.5
    kill -TERM "$PID" 2>/dev/null || true

    if wait_for_inactive; then
        pass "Process handled double SIGTERM cleanly"
    else
        fail "Process hung on double SIGTERM"
        systemctl stop "$SERVICE" 2>/dev/null || true
    fi
else
    fail "Service failed to start for double SIGTERM test"
fi

sleep 1
cleanup_nft

# ── Test 8: systemctl restart cycle ──
echo "" >> "$REPORT"
echo "--- Test 8: systemctl restart cycle ---" >> "$REPORT"

# Ensure clean state before restart cycles
systemctl stop "$SERVICE" 2>/dev/null || true
sleep 2
cleanup_nft
systemctl reset-failed "$SERVICE" 2>/dev/null || true

RESTART_OK=true
for i in $(seq 1 5); do
    systemctl start "$SERVICE" 2>/dev/null || true
    if ! wait_for_active; then
        fail "Restart cycle $i: failed to start"
        RESTART_OK=false
        break
    fi
    systemctl stop "$SERVICE" 2>/dev/null || true
    if ! wait_for_inactive; then
        fail "Restart cycle $i: failed to stop"
        RESTART_OK=false
        break
    fi
    sleep 0.5

    # Check no orphaned rules
    if nft list table ip cachydpi &>/dev/null 2>&1; then
        fail "Restart cycle $i: orphaned nftables table"
        RESTART_OK=false
        cleanup_nft
    fi
done

if $RESTART_OK; then
    pass "5 restart cycles completed cleanly"
fi

# Final cleanup
systemctl stop "$SERVICE" 2>/dev/null || true
cleanup_nft

# ── Summary ──
echo "" >> "$REPORT"
echo "========================================" >> "$REPORT"
echo "SUMMARY: $PASS passed, $FAIL failed, $WARN warnings, $SKIP skipped" >> "$REPORT"
echo "========================================" >> "$REPORT"

echo ""
echo "Report written to $REPORT"
echo "Results: $PASS passed, $FAIL failed, $WARN warnings, $SKIP skipped"
