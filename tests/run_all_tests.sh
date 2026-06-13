#!/usr/bin/env bash
# tests/run_all_tests.sh — Master Test Runner for CachyDPI
#
# Runs all test categories in order and generates a combined report.
# Some tests require root (sudo). Run without sudo for non-root tests only.
#
# Usage:
#   sudo bash tests/run_all_tests.sh          # Full suite (recommended)
#   bash tests/run_all_tests.sh               # Non-root tests only
#   bash tests/run_all_tests.sh --skip-root   # Explicitly skip root tests

set -euo pipefail

# Resolve project root (script may be called from anywhere)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

REPORT_DIR="tests/reports"
COMBINED="$REPORT_DIR/combined_report.txt"
SKIP_ROOT=false

if [[ "${1:-}" == "--skip-root" ]] || [[ "$(id -u)" != "0" ]]; then
    SKIP_ROOT=true
fi

# When running under sudo, cargo/rustup may not be in root's PATH.
# Detect the real user and run cargo commands via their environment.
REAL_USER="${SUDO_USER:-$(whoami)}"
REAL_HOME=$(eval echo "~$REAL_USER")

run_as_user() {
    # Run a command as the real (non-root) user with their cargo/rustup env
    if [[ "$(id -u)" == "0" && -n "${SUDO_USER:-}" ]]; then
        sudo -u "$SUDO_USER" bash -c "source \"$REAL_HOME/.cargo/env\" 2>/dev/null; cd \"$PROJECT_DIR\"; $*"
    else
        bash -c "$*"
    fi
}

mkdir -p "$REPORT_DIR"

echo "============================================================" > "$COMBINED"
echo "  CachyDPI Comprehensive Test Suite — Combined Report" >> "$COMBINED"
echo "  Date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')" >> "$COMBINED"
echo "  Host: $(uname -n) ($(uname -r))" >> "$COMBINED"
echo "  Root: $(if $SKIP_ROOT; then echo 'No (skipping root tests)'; else echo 'Yes'; fi)" >> "$COMBINED"
echo "============================================================" >> "$COMBINED"
echo "" >> "$COMBINED"

TOTAL_PASS=0
TOTAL_FAIL=0
TOTAL_SKIP=0

run_section() {
    local name="$1"
    local script="$2"
    local needs_root="${3:-false}"

    echo ""
    echo "━━━ Running: $name ━━━"
    echo "" >> "$COMBINED"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$COMBINED"
    echo "  SECTION: $name" >> "$COMBINED"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$COMBINED"

    if $needs_root && $SKIP_ROOT; then
        echo "  [SKIPPED — requires root]" >> "$COMBINED"
        echo "  Skipped (requires root)"
        return
    fi

    if [[ -x "$script" ]]; then
        OUTPUT=$($script 2>&1 || true)
        echo "$OUTPUT" | tee -a "$COMBINED"

        # Extract pass/fail/skip counts from output (sum all matches)
        P=$(echo "$OUTPUT" | grep -oP '\d+ passed' | grep -oP '\d+' | awk '{s+=$1} END {print s+0}')
        F=$(echo "$OUTPUT" | grep -oP '\d+ failed' | grep -oP '\d+' | awk '{s+=$1} END {print s+0}')
        S=$(echo "$OUTPUT" | grep -oP '\d+ skipped' | grep -oP '\d+' | awk '{s+=$1} END {print s+0}')
        TOTAL_PASS=$((TOTAL_PASS + P))
        TOTAL_FAIL=$((TOTAL_FAIL + F))
        TOTAL_SKIP=$((TOTAL_SKIP + S))
    else
        echo "  [ERROR — script not found or not executable: $script]" >> "$COMBINED"
        echo "  Error: script not found"
    fi
}

# ═══ Phase 1: Rust tests (no sudo) ═══
echo ""
echo "━━━ Running: Cargo Tests (unit + comprehensive) ━━━"
echo "" >> "$COMBINED"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$COMBINED"
echo "  SECTION: Cargo Tests" >> "$COMBINED"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$COMBINED"

CARGO_OUTPUT=$(run_as_user "cargo test" 2>&1 || true)
echo "$CARGO_OUTPUT" | tail -30 | tee -a "$COMBINED"

# Count all lines like "test result: ok. N passed; M failed"
CARGO_PASS=$(echo "$CARGO_OUTPUT" | grep -oP '\d+ passed' | awk '{s+=$1} END {print s+0}')
CARGO_FAIL=$(echo "$CARGO_OUTPUT" | grep -oP '\d+ failed' | awk '{s+=$1} END {print s+0}')
TOTAL_PASS=$((TOTAL_PASS + CARGO_PASS))
TOTAL_FAIL=$((TOTAL_FAIL + CARGO_FAIL))

echo ""
echo "  Cargo tests: $CARGO_PASS passed, $CARGO_FAIL failed"

# ═══ Phase 2: Build quality (no sudo) ═══
# Build tests also need cargo — run as real user
echo ""
echo "━━━ Running: Build Reproducibility & Code Quality ━━━"
echo "" >> "$COMBINED"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$COMBINED"
echo "  SECTION: Build Reproducibility & Code Quality" >> "$COMBINED"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$COMBINED"
BUILD_OUTPUT=$(run_as_user "bash tests/test_build_reproducibility.sh" 2>&1 || true)
echo "$BUILD_OUTPUT" | tee -a "$COMBINED"
P=$(echo "$BUILD_OUTPUT" | grep -oP '\d+ passed' | grep -oP '\d+' | awk '{s+=$1} END {print s+0}')
F=$(echo "$BUILD_OUTPUT" | grep -oP '\d+ failed' | grep -oP '\d+' | awk '{s+=$1} END {print s+0}')
S=$(echo "$BUILD_OUTPUT" | grep -oP '\d+ skipped' | grep -oP '\d+' | awk '{s+=$1} END {print s+0}')
TOTAL_PASS=$((TOTAL_PASS + P))
TOTAL_FAIL=$((TOTAL_FAIL + F))
TOTAL_SKIP=$((TOTAL_SKIP + S))

# ═══ Phase 3: Root-required tests ═══
run_section "Privilege Escalation" "tests/test_privilege_escalation.sh" true
run_section "Crash Safety" "tests/test_crash_safety.sh" true
run_section "nftables Isolation" "tests/test_nftables_isolation.sh" true
run_section "Signal Handling" "tests/test_signal_handling.sh" true
run_section "Performance & Resources" "tests/test_performance.sh" true
run_section "ISP Bypass Verification" "tests/test_isp_bypass.sh" true

# ═══ Final Summary ═══
echo "" >> "$COMBINED"
echo "============================================================" >> "$COMBINED"
echo "  GRAND TOTAL: $TOTAL_PASS passed, $TOTAL_FAIL failed, $TOTAL_SKIP skipped" >> "$COMBINED"
echo "============================================================" >> "$COMBINED"

echo ""
echo "============================================================"
echo "  GRAND TOTAL: $TOTAL_PASS passed, $TOTAL_FAIL failed, $TOTAL_SKIP skipped"
echo "============================================================"
echo "  Combined report: $COMBINED"
echo "  Individual reports: $REPORT_DIR/"
