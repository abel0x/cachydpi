#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 abel0x <https://github.com/abel0x>
# tests/test_performance.sh — Performance & Resource Limit Tests
#
# Tests CachyDPI's compliance with systemd resource limits and
# measures idle/active resource consumption.
# Must be run as root.
#
# Usage: sudo bash tests/test_performance.sh

set -euo pipefail

SERVICE="cachydpi.service"
REPORT_DIR="tests/reports"
REPORT="$REPORT_DIR/performance_report.txt"
CACHYDPI_BIN="/usr/bin/cachydpi"

mkdir -p "$REPORT_DIR"

echo "=== CachyDPI Performance & Resource Limit Test Report ===" > "$REPORT"
echo "Date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')" >> "$REPORT"
echo "Kernel: $(uname -r)" >> "$REPORT"
echo "CPU: $(grep 'model name' /proc/cpuinfo | head -1 | cut -d: -f2 | xargs)" >> "$REPORT"
echo "RAM: $(free -h | awk '/^Mem:/ {print $2}')" >> "$REPORT"
echo "" >> "$REPORT"

PASS=0
FAIL=0
SKIP=0

pass() { echo "[PASS] $1" | tee -a "$REPORT"; PASS=$((PASS + 1)); }
fail() { echo "[FAIL] $1" | tee -a "$REPORT"; FAIL=$((FAIL + 1)); }
skip() { echo "[SKIP] $1" | tee -a "$REPORT"; SKIP=$((SKIP + 1)); }

# Ensure clean state
systemctl stop "$SERVICE" 2>/dev/null || true
systemctl reset-failed "$SERVICE" 2>/dev/null || true
sleep 1

# ── Test 1: Idle resource consumption ──
echo "" >> "$REPORT"
echo "--- Test 1: Idle resource consumption ---" >> "$REPORT"

systemctl start "$SERVICE" 2>/dev/null || true
sleep 3

if systemctl is-active "$SERVICE" &>/dev/null; then
    PID=$(systemctl show -p MainPID --value "$SERVICE" 2>/dev/null)
    if [[ -n "$PID" && "$PID" != "0" ]]; then
        # RSS memory in KB
        RSS_KB=$(ps -o rss= -p "$PID" 2>/dev/null | xargs)
        RSS_MB=$((RSS_KB / 1024))
        echo "  Idle RSS: ${RSS_MB}MB (${RSS_KB}KB)" >> "$REPORT"

        if [[ "$RSS_KB" =~ ^[0-9]+$ ]] && (( RSS_KB < 10240 )); then
            pass "Idle RSS < 10MB (actual: ${RSS_MB}MB)"
        elif [[ "$RSS_KB" =~ ^[0-9]+$ ]] && (( RSS_KB < 20480 )); then
            pass "Idle RSS < 20MB (actual: ${RSS_MB}MB) — acceptable"
        else
            fail "Idle RSS too high: ${RSS_MB}MB"
        fi

        # CPU usage over 3 seconds
        CPU_USAGE=$(ps -o %cpu= -p "$PID" 2>/dev/null | xargs)
        echo "  Idle CPU: ${CPU_USAGE}%" >> "$REPORT"

        CPU_INT=$(echo "$CPU_USAGE" | cut -d. -f1)
        if [[ "$CPU_INT" =~ ^[0-9]*$ ]] && (( ${CPU_INT:-0} < 2 )); then
            pass "Idle CPU < 2% (actual: ${CPU_USAGE}%)"
        else
            fail "Idle CPU too high: ${CPU_USAGE}%"
        fi

        # Thread count
        THREADS=$(ls /proc/"$PID"/task 2>/dev/null | wc -l)
        echo "  Thread count: $THREADS" >> "$REPORT"

        if (( THREADS <= 8 )); then
            pass "Thread count reasonable: $THREADS"
        else
            fail "Too many threads: $THREADS"
        fi

        # File descriptor count
        FD_COUNT=$(ls /proc/"$PID"/fd 2>/dev/null | wc -l)
        echo "  Open FDs: $FD_COUNT" >> "$REPORT"

        if (( FD_COUNT < 64 )); then
            pass "Open FDs < 64 (actual: $FD_COUNT)"
        else
            fail "Too many open FDs: $FD_COUNT"
        fi
    else
        skip "Could not get PID for idle test"
    fi
else
    skip "Service not running for idle test"
fi

# ── Test 2: MemoryMax enforcement ──
echo "" >> "$REPORT"
echo "--- Test 2: MemoryMax enforcement ---" >> "$REPORT"

MEMORY_MAX=$(systemctl show -p MemoryMax --value "$SERVICE" 2>/dev/null || echo "")
echo "  MemoryMax setting: $MEMORY_MAX" >> "$REPORT"

if [[ -n "$MEMORY_MAX" && "$MEMORY_MAX" != "infinity" ]]; then
    # Convert to MB for display
    if [[ "$MEMORY_MAX" =~ ^[0-9]+$ ]]; then
        LIMIT_MB=$((MEMORY_MAX / 1024 / 1024))
        echo "  MemoryMax: ${LIMIT_MB}MB" >> "$REPORT"
        pass "MemoryMax is set to ${LIMIT_MB}MB"
    else
        echo "  MemoryMax raw: $MEMORY_MAX" >> "$REPORT"
        pass "MemoryMax is configured: $MEMORY_MAX"
    fi

    # Verify the cgroup memory limit is enforced
    CGROUP=$(systemctl show -p ControlGroup --value "$SERVICE" 2>/dev/null || echo "")
    if [[ -n "$CGROUP" ]]; then
        MEM_LIMIT_FILE="/sys/fs/cgroup${CGROUP}/memory.max"
        if [[ -f "$MEM_LIMIT_FILE" ]]; then
            CGROUP_LIMIT=$(cat "$MEM_LIMIT_FILE")
            echo "  cgroup memory.max: $CGROUP_LIMIT" >> "$REPORT"
            if [[ "$CGROUP_LIMIT" != "max" ]]; then
                pass "cgroup memory limit enforced: $CGROUP_LIMIT bytes"
            else
                fail "cgroup memory limit is 'max' (unlimited)"
            fi
        else
            skip "cgroup memory.max file not found"
        fi
    fi
else
    fail "MemoryMax not set or unlimited"
fi

# ── Test 3: CPUQuota enforcement ──
echo "" >> "$REPORT"
echo "--- Test 3: CPUQuota enforcement ---" >> "$REPORT"

CPU_QUOTA=$(systemctl show -p CPUQuotaPerSecUSec --value "$SERVICE" 2>/dev/null || echo "")
echo "  CPUQuota setting: $CPU_QUOTA" >> "$REPORT"

if [[ -n "$CPU_QUOTA" && "$CPU_QUOTA" != "infinity" ]]; then
    pass "CPUQuota is configured: $CPU_QUOTA"
else
    fail "CPUQuota not set"
fi

# ── Test 4: FD leak detection over time ──
echo "" >> "$REPORT"
echo "--- Test 4: FD leak detection ---" >> "$REPORT"

PID=$(systemctl show -p MainPID --value "$SERVICE" 2>/dev/null)
if [[ -n "$PID" && "$PID" != "0" ]]; then
    FD_BEFORE=$(ls /proc/"$PID"/fd 2>/dev/null | wc -l)
    echo "  FDs before: $FD_BEFORE" >> "$REPORT"

    # Generate some traffic to exercise the service
    for i in $(seq 1 20); do
        curl -s -o /dev/null --max-time 2 "https://www.google.com/" 2>/dev/null &
    done
    wait 2>/dev/null || true
    sleep 3

    FD_AFTER=$(ls /proc/"$PID"/fd 2>/dev/null | wc -l)
    echo "  FDs after traffic: $FD_AFTER" >> "$REPORT"

    FD_DIFF=$((FD_AFTER - FD_BEFORE))
    echo "  FD change: $FD_DIFF" >> "$REPORT"

    if (( FD_DIFF < 5 )); then
        pass "No significant FD leak: delta=$FD_DIFF"
    elif (( FD_DIFF < 10 )); then
        pass "Minor FD increase: delta=$FD_DIFF (acceptable)"
    else
        fail "Possible FD leak: delta=$FD_DIFF"
    fi
else
    skip "Could not get PID for FD leak test"
fi

# ── Test 5: Memory stability under load ──
echo "" >> "$REPORT"
echo "--- Test 5: Memory stability under load ---" >> "$REPORT"

PID=$(systemctl show -p MainPID --value "$SERVICE" 2>/dev/null)
if [[ -n "$PID" && "$PID" != "0" ]]; then
    RSS_BEFORE=$(ps -o rss= -p "$PID" 2>/dev/null | xargs)

    # Generate sustained traffic
    for round in $(seq 1 3); do
        for i in $(seq 1 10); do
            curl -s -o /dev/null --max-time 3 "https://www.google.com/" 2>/dev/null &
            curl -s -o /dev/null --max-time 3 "https://www.youtube.com/" 2>/dev/null &
        done
        wait 2>/dev/null || true
        sleep 1
    done

    RSS_AFTER=$(ps -o rss= -p "$PID" 2>/dev/null | xargs)
    RSS_BEFORE_MB=$((RSS_BEFORE / 1024))
    RSS_AFTER_MB=$((RSS_AFTER / 1024))
    echo "  RSS before load: ${RSS_BEFORE_MB}MB" >> "$REPORT"
    echo "  RSS after load: ${RSS_AFTER_MB}MB" >> "$REPORT"

    if [[ "$RSS_BEFORE" =~ ^[0-9]+$ && "$RSS_AFTER" =~ ^[0-9]+$ ]]; then
        RSS_GROWTH=$((RSS_AFTER - RSS_BEFORE))
        RSS_GROWTH_MB=$((RSS_GROWTH / 1024))
        echo "  RSS growth: ${RSS_GROWTH_MB}MB" >> "$REPORT"

        if (( RSS_AFTER < 30720 )); then
            pass "Memory under load < 30MB: ${RSS_AFTER_MB}MB"
        elif (( RSS_AFTER < 65536 )); then
            pass "Memory under load < 64MB: ${RSS_AFTER_MB}MB"
        else
            fail "Memory under load exceeds 64MB: ${RSS_AFTER_MB}MB"
        fi
    fi
else
    skip "Could not get PID for memory stability test"
fi

# ── Test 6: Binary size ──
echo "" >> "$REPORT"
echo "--- Test 6: Binary size ---" >> "$REPORT"

if [[ -f "$CACHYDPI_BIN" ]]; then
    BIN_SIZE=$(stat -c %s "$CACHYDPI_BIN" 2>/dev/null)
    BIN_SIZE_MB=$((BIN_SIZE / 1024 / 1024))
    BIN_SIZE_KB=$((BIN_SIZE / 1024))
    echo "  Binary size: ${BIN_SIZE_MB}MB (${BIN_SIZE_KB}KB)" >> "$REPORT"

    if (( BIN_SIZE < 10485760 )); then
        pass "Binary size < 10MB: ${BIN_SIZE_MB}MB"
    else
        fail "Binary too large: ${BIN_SIZE_MB}MB"
    fi
else
    skip "Binary not found at $CACHYDPI_BIN"
fi

# ── Test 7: Startup time ──
echo "" >> "$REPORT"
echo "--- Test 7: Startup time ---" >> "$REPORT"

systemctl stop "$SERVICE" 2>/dev/null || true
sleep 1

START_TIME=$(date +%s%N)
systemctl start "$SERVICE" 2>/dev/null || true

# Wait until active
for i in $(seq 1 30); do
    if systemctl is-active "$SERVICE" &>/dev/null; then
        break
    fi
    sleep 0.1
done
END_TIME=$(date +%s%N)

ELAPSED_MS=$(( (END_TIME - START_TIME) / 1000000 ))
echo "  Startup time: ${ELAPSED_MS}ms" >> "$REPORT"

if (( ELAPSED_MS < 2000 )); then
    pass "Startup time < 2s: ${ELAPSED_MS}ms"
elif (( ELAPSED_MS < 5000 )); then
    pass "Startup time < 5s: ${ELAPSED_MS}ms"
else
    fail "Startup time too slow: ${ELAPSED_MS}ms"
fi

# Cleanup
systemctl stop "$SERVICE" 2>/dev/null || true

# ── Summary ──
echo "" >> "$REPORT"
echo "========================================" >> "$REPORT"
echo "SUMMARY: $PASS passed, $FAIL failed, $SKIP skipped" >> "$REPORT"
echo "========================================" >> "$REPORT"

echo ""
echo "Report written to $REPORT"
echo "Results: $PASS passed, $FAIL failed, $SKIP skipped"
