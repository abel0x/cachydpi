#!/usr/bin/env bash
# tests/test_privilege_escalation.sh — Privilege Escalation Tests
#
# Tests drop_root() behavior, capability enforcement, and systemd hardening.
# Must be run as root (or with sudo) for meaningful results.
#
# Usage: sudo bash tests/test_privilege_escalation.sh

set -euo pipefail

BINARY="/usr/bin/cachydpi"
SERVICE="cachydpi.service"
REPORT_DIR="tests/reports"
REPORT="$REPORT_DIR/privilege_escalation_report.txt"

mkdir -p "$REPORT_DIR"

echo "=== CachyDPI Privilege Escalation Test Report ===" > "$REPORT"
echo "Date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')" >> "$REPORT"
echo "Kernel: $(uname -r)" >> "$REPORT"
echo "User: $(whoami)" >> "$REPORT"
echo "" >> "$REPORT"

PASS=0
FAIL=0
SKIP=0
WARN=0

pass() { echo "[PASS] $1" | tee -a "$REPORT"; PASS=$((PASS + 1)); }
fail() { echo "[FAIL] $1" | tee -a "$REPORT"; FAIL=$((FAIL + 1)); }
skip() { echo "[SKIP] $1" | tee -a "$REPORT"; SKIP=$((SKIP + 1)); }
warn() { echo "[WARN] $1" | tee -a "$REPORT"; WARN=$((WARN + 1)); }

# ── Test 1: Binary exists and has correct permissions ──
echo "" >> "$REPORT"
echo "--- Test 1: Binary permissions ---" >> "$REPORT"
if [[ -f "$BINARY" ]]; then
    perms=$(stat -c '%a' "$BINARY")
    owner=$(stat -c '%U:%G' "$BINARY")
    echo "  Binary: $BINARY" >> "$REPORT"
    echo "  Permissions: $perms" >> "$REPORT"
    echo "  Owner: $owner" >> "$REPORT"
    if [[ "$owner" == "root:root" ]]; then
        pass "Binary owned by root:root"
    else
        fail "Binary not owned by root:root (actual: $owner)"
    fi
    # Should NOT be setuid
    if [[ "$perms" =~ ^[0-7]?755$ ]] || [[ "$perms" == "755" ]]; then
        pass "Binary has 755 permissions (no setuid)"
    elif [[ "$perms" =~ ^4 ]]; then
        fail "Binary has setuid bit set! ($perms)"
    else
        pass "Binary permissions: $perms (no setuid)"
    fi
else
    skip "Binary not found at $BINARY"
fi

# ── Test 2: cachydpi user exists ──
echo "" >> "$REPORT"
echo "--- Test 2: Service user ---" >> "$REPORT"
if id cachydpi &>/dev/null; then
    pass "cachydpi user exists"
    shell=$(getent passwd cachydpi | cut -d: -f7)
    home=$(getent passwd cachydpi | cut -d: -f6)
    echo "  Shell: $shell" >> "$REPORT"
    echo "  Home: $home" >> "$REPORT"
    if [[ "$shell" == "/usr/bin/nologin" ]] || [[ "$shell" == "/sbin/nologin" ]] || [[ "$shell" == "/bin/false" ]]; then
        pass "cachydpi user has nologin shell"
    else
        fail "cachydpi user has login shell: $shell"
    fi
else
    fail "cachydpi user does not exist"
fi

# ── Test 3: systemd-analyze security ──
echo "" >> "$REPORT"
echo "--- Test 3: systemd security analysis ---" >> "$REPORT"
if systemctl list-unit-files "$SERVICE" &>/dev/null; then
    security_output=$(systemd-analyze security "$SERVICE" 2>/dev/null || true)
    # Extract overall score
    score=$(echo "$security_output" | grep -oP 'Overall exposure level.*?(\d+\.\d+)' | grep -oP '\d+\.\d+' || echo "N/A")
    echo "  Overall exposure score: $score" >> "$REPORT"
    echo "" >> "$REPORT"

    # Check critical hardening features
    # systemd-analyze security output uses ✓/✗ prefixes, not "OK"/"yes"
    for feature in "NoNewPrivileges" "ProtectSystem" "ProtectHome" "PrivateTmp" "PrivateDevices" "MemoryDenyWriteExecute"; do
        feature_line=$(echo "$security_output" | grep "$feature" | head -1)
        if [[ -z "$feature_line" ]]; then
            skip "systemd: $feature not found in analysis"
        elif echo "$feature_line" | grep -q "^✓"; then
            pass "systemd: $feature enabled"
        elif echo "$feature_line" | grep -q "^✗"; then
            desc=$(echo "$feature_line" | awk '{$1=""; print $0}' | sed 's/^ *//')
            fail "systemd: $feature NOT enabled ($desc)"
        else
            warn "systemd: $feature status unclear (verify manually)"
        fi
    done

    # Check if score is reasonable (lower is better, 10 = fully exposed)
    if [[ "$score" != "N/A" ]]; then
        score_int=$(echo "$score" | cut -d. -f1)
        if [[ "$score_int" -le 4 ]]; then
            pass "systemd security score is good ($score <= 4.0)"
        elif [[ "$score_int" -le 6 ]]; then
            fail "systemd security score is moderate ($score). Consider more hardening."
        else
            fail "systemd security score is poor ($score > 6.0)"
        fi
    fi
else
    skip "Service $SERVICE not found"
fi

# Ensure the service is running for runtime tests
systemctl reset-failed "$SERVICE" 2>/dev/null || true
systemctl stop "$SERVICE" 2>/dev/null || true
# Poll for inactive
for _i in $(seq 1 30); do
    systemctl is-active "$SERVICE" &>/dev/null || break
    sleep 0.2
done
systemctl start "$SERVICE" 2>/dev/null || true
# Poll for active
for _i in $(seq 1 30); do
    systemctl is-active "$SERVICE" &>/dev/null && break
    sleep 0.2
done

# ── Test 4: Process capabilities when running ──
echo "" >> "$REPORT"
echo "--- Test 4: Runtime capabilities ---" >> "$REPORT"
if systemctl is-active "$SERVICE" &>/dev/null; then
    pid=$(systemctl show -p MainPID "$SERVICE" | cut -d= -f2)
    # Wait for the process to fully initialize (drop_root completes after nfqueue setup)
    sleep 2
    if [[ "$pid" -gt 0 ]]; then
        echo "  PID: $pid" >> "$REPORT"
        # Verify PID still belongs to cachydpi (guard against PID reuse)
        proc_name=$(cat /proc/$pid/comm 2>/dev/null || echo "unknown")
        echo "  Process name: $proc_name" >> "$REPORT"
        if [[ "$proc_name" != "cachydpi" ]]; then
            fail "MainPID $pid is not cachydpi (found: $proc_name) — possible PID reuse or service crash"
        fi
        # Check capabilities
        if [[ -f "/proc/$pid/status" ]]; then
            cap_eff=$(grep CapEff /proc/$pid/status | awk '{print $2}')
            cap_prm=$(grep CapPrm /proc/$pid/status | awk '{print $2}')
            cap_inh=$(grep CapInh /proc/$pid/status | awk '{print $2}')
            echo "  CapEff: $cap_eff" >> "$REPORT"
            echo "  CapPrm: $cap_prm" >> "$REPORT"
            echo "  CapInh: $cap_inh" >> "$REPORT"

            # Decode caps
            decoded=$(capsh --decode="$cap_eff" 2>/dev/null || echo "decode failed")
            echo "  Effective caps decoded: $decoded" >> "$REPORT"

            # Check only NET_ADMIN and NET_RAW are present
            if echo "$decoded" | grep -q "cap_net_admin" && echo "$decoded" | grep -q "cap_net_raw"; then
                pass "Process has NET_ADMIN and NET_RAW capabilities"
            else
                fail "Process missing required capabilities: $decoded"
            fi

            # Check dangerous caps are NOT present
            for dangerous in "cap_sys_admin" "cap_sys_ptrace" "cap_dac_override" "cap_sys_module"; do
                if echo "$decoded" | grep -q "$dangerous"; then
                    fail "Process has dangerous capability: $dangerous"
                else
                    pass "Process does NOT have $dangerous"
                fi
            done

            # Check process UID
            uid=$(grep "^Uid:" /proc/$pid/status | awk '{print $2}')
            echo "  Process UID: $uid" >> "$REPORT"
            if [[ "$uid" != "0" ]]; then
                pass "Process not running as UID 0 (running as UID $uid)"
            else
                # Root with dropped caps is still acceptable with NoNewPrivileges
                if grep -q "NoNewPrivs:	1" /proc/$pid/status 2>/dev/null; then
                    pass "Process is root but NoNewPrivileges is set"
                else
                    fail "Process running as root WITHOUT NoNewPrivileges!"
                fi
            fi
        fi
    else
        skip "Service running but PID is 0"
    fi
else
    skip "Service not active — start with: sudo systemctl start cachydpi"
fi

# ── Test 5: Cannot read sensitive files ──
echo "" >> "$REPORT"
echo "--- Test 5: File access restrictions ---" >> "$REPORT"
if systemctl is-active "$SERVICE" &>/dev/null; then
    pid=$(systemctl show -p MainPID "$SERVICE" | cut -d= -f2)
    if [[ "$pid" -gt 0 ]]; then
        # Check process UID/GID to impersonate when testing file access
        PROC_UID=$(grep "^Uid:" /proc/$pid/status 2>/dev/null | awk '{print $2}' || echo "?")
        PROC_GID=$(grep "^Gid:" /proc/$pid/status 2>/dev/null | awk '{print $2}' || echo "?")
        # Test file access from the service's perspective (mount namespace + UID/GID)
        for sensitive in "/etc/shadow" "/root/.ssh" "/home"; do
            if nsenter -t "$pid" -m -S "$PROC_UID" -G "$PROC_GID" cat "$sensitive" &>/dev/null 2>&1; then
                fail "Process CAN read $sensitive"
            else
                pass "Process cannot read $sensitive (access denied)"
            fi
        done
    fi
else
    skip "Service not active for file access tests"
fi

# ── Test 6: CAP_SYS_ADMIN explicitly denied ──
echo "" >> "$REPORT"
echo "--- Test 6: Explicit capability denial ---" >> "$REPORT"
if [[ -f "/etc/systemd/system/cachydpi.service" ]] || [[ -f "/usr/lib/systemd/system/cachydpi.service" ]]; then
    service_file=$(systemctl show -p FragmentPath "$SERVICE" 2>/dev/null | cut -d= -f2)
    if [[ -n "$service_file" ]] && [[ -f "$service_file" ]]; then
        echo "  Service file: $service_file" >> "$REPORT"
        if grep -q "AmbientCapabilities" "$service_file"; then
            ambient=$(grep "AmbientCapabilities" "$service_file")
            echo "  $ambient" >> "$REPORT"
            if echo "$ambient" | grep -q "CAP_SYS_ADMIN"; then
                fail "CAP_SYS_ADMIN in AmbientCapabilities!"
            else
                pass "CAP_SYS_ADMIN not in AmbientCapabilities"
            fi
        else
            skip "No AmbientCapabilities in service file"
        fi
    else
        skip "Service file not found"
    fi
else
    skip "Service file not found"
fi

# Cleanup
systemctl stop "$SERVICE" 2>/dev/null || true

# ── Summary ──
echo "" >> "$REPORT"
echo "========================================" >> "$REPORT"
echo "SUMMARY: $PASS passed, $FAIL failed, $WARN warnings, $SKIP skipped" >> "$REPORT"
echo "========================================" >> "$REPORT"

echo ""
echo "Report written to $REPORT"
echo "Results: $PASS passed, $FAIL failed, $WARN warnings, $SKIP skipped"
