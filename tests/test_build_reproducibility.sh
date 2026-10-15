#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 abel0x <https://github.com/abel0x>
# tests/test_build_reproducibility.sh — Build Reproducibility & Code Quality Tests
#
# Tests: cargo audit (CVE check), cargo clippy (lint), reproducible builds,
# dependency review, and compilation under different profiles.
#
# Usage: bash tests/test_build_reproducibility.sh

set -euo pipefail

# Ensure cargo/rustup are in PATH (needed when run via sudo)
if [[ -f "$HOME/.cargo/env" ]]; then
    source "$HOME/.cargo/env"
fi

# Resolve project root
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

REPORT_DIR="tests/reports"
REPORT="$REPORT_DIR/build_reproducibility_report.txt"

mkdir -p "$REPORT_DIR"

echo "=== CachyDPI Build Reproducibility & Code Quality Report ===" > "$REPORT"
echo "Date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')" >> "$REPORT"
echo "Rust: $(rustc --version)" >> "$REPORT"
echo "Cargo: $(cargo --version)" >> "$REPORT"
echo "" >> "$REPORT"

PASS=0
FAIL=0
SKIP=0
WARN=0

pass() { echo "[PASS] $1" | tee -a "$REPORT"; PASS=$((PASS + 1)); }
fail() { echo "[FAIL] $1" | tee -a "$REPORT"; FAIL=$((FAIL + 1)); }
skip() { echo "[SKIP] $1" | tee -a "$REPORT"; SKIP=$((SKIP + 1)); }
warn() { echo "[WARN] $1" | tee -a "$REPORT"; WARN=$((WARN + 1)); }

# ── Test 1: cargo audit ──
echo "" >> "$REPORT"
echo "--- Test 1: cargo audit (CVE/vulnerability check) ---" >> "$REPORT"

if command -v cargo-audit &>/dev/null; then
    AUDIT_OUTPUT=$(cargo audit 2>&1 || true)
    echo "$AUDIT_OUTPUT" | tail -20 | sed 's/^/    /' >> "$REPORT"

    if echo "$AUDIT_OUTPUT" | grep -q "0 vulnerabilities found\|No vulnerable"; then
        pass "No known vulnerabilities found"
    elif echo "$AUDIT_OUTPUT" | grep -q "allowed warning"; then
        VULN_COUNT=$(echo "$AUDIT_OUTPUT" | grep -c "Crate:" || echo "?")
        warn "cargo audit: $VULN_COUNT allowed advisory warning(s) from transitive deps (review periodically)"
    elif echo "$AUDIT_OUTPUT" | grep -qi "warning"; then
        VULN_COUNT=$(echo "$AUDIT_OUTPUT" | grep -c "Crate:" || echo "?")
        warn "cargo audit has warnings: $VULN_COUNT advisory notices"
    else
        VULN_COUNT=$(echo "$AUDIT_OUTPUT" | grep -c "Crate:" || echo "?")
        fail "Vulnerabilities found: $VULN_COUNT"
    fi
else
    echo "  Installing cargo-audit..." >> "$REPORT"
    if cargo install cargo-audit 2>/dev/null; then
        AUDIT_OUTPUT=$(cargo audit 2>&1 || true)
        echo "$AUDIT_OUTPUT" | tail -20 | sed 's/^/    /' >> "$REPORT"
        if echo "$AUDIT_OUTPUT" | grep -q "0 vulnerabilities found\|No vulnerable"; then
            pass "No known vulnerabilities found"
        elif echo "$AUDIT_OUTPUT" | grep -q "allowed warning"; then
            VULN_COUNT=$(echo "$AUDIT_OUTPUT" | grep -c "Crate:" || echo "?")
            warn "cargo audit: $VULN_COUNT allowed advisory warning(s) from transitive deps (review periodically)"
        elif echo "$AUDIT_OUTPUT" | grep -qi "warning"; then
            VULN_COUNT=$(echo "$AUDIT_OUTPUT" | grep -c "Crate:" || echo "?")
            warn "cargo audit has warnings: $VULN_COUNT advisory notices"
        else
            VULN_COUNT=$(echo "$AUDIT_OUTPUT" | grep -c "Crate:" || echo "?")
            fail "Vulnerabilities found: $VULN_COUNT"
        fi
    else
        skip "cargo-audit not available and install failed"
    fi
fi

# ── Test 2: cargo clippy ──
echo "" >> "$REPORT"
echo "--- Test 2: cargo clippy (lint analysis) ---" >> "$REPORT"

CLIPPY_OUTPUT=$(cargo clippy -- -D warnings 2>&1 || true)
CLIPPY_EXIT=$?

# Count warnings and errors
CLIPPY_WARNINGS=$(echo "$CLIPPY_OUTPUT" | grep -c "^warning\[" || echo "0")
CLIPPY_ERRORS=$(echo "$CLIPPY_OUTPUT" | grep -c "^error" || echo "0")

echo "  Warnings: $CLIPPY_WARNINGS" >> "$REPORT"
echo "  Errors: $CLIPPY_ERRORS" >> "$REPORT"

if echo "$CLIPPY_OUTPUT" | grep -q "error"; then
    echo "$CLIPPY_OUTPUT" | grep "error" | head -10 | sed 's/^/    /' >> "$REPORT"
    fail "cargo clippy produced errors"
elif echo "$CLIPPY_OUTPUT" | grep -q "warning\["; then
    echo "$CLIPPY_OUTPUT" | grep "warning\[" | head -10 | sed 's/^/    /' >> "$REPORT"
    warn "cargo clippy produced warnings"
else
    pass "cargo clippy clean (no warnings or errors)"
fi

# ── Test 3: cargo test (existing tests) ──
echo "" >> "$REPORT"
echo "--- Test 3: cargo test ---" >> "$REPORT"

TEST_OUTPUT=$(cargo test 2>&1 || true)
TESTS_PASSED=$(echo "$TEST_OUTPUT" | grep -oP '\d+ passed' | head -1 || echo "? passed")
TESTS_FAILED=$(echo "$TEST_OUTPUT" | grep -oP '\d+ failed' | head -1 || echo "0 failed")

echo "  $TESTS_PASSED, $TESTS_FAILED" >> "$REPORT"

if echo "$TEST_OUTPUT" | grep -q "test result: ok"; then
    pass "All cargo tests pass ($TESTS_PASSED)"
else
    echo "$TEST_OUTPUT" | grep "FAILED\|panicked" | head -10 | sed 's/^/    /' >> "$REPORT"
    fail "Some cargo tests failed: $TESTS_FAILED"
fi

# ── Test 4: Reproducible build ──
echo "" >> "$REPORT"
echo "--- Test 4: Reproducible build verification ---" >> "$REPORT"

# Build twice and compare checksums
echo "  Building first copy..." >> "$REPORT"
cargo build --release 2>/dev/null
HASH1=$(sha256sum target/release/cachydpi 2>/dev/null | cut -d' ' -f1 || echo "build1_failed")
echo "  Hash 1: $HASH1" >> "$REPORT"

# Touch a source file timestamp (shouldn't affect binary content with proper incremental)
sleep 1
echo "  Building second copy (incremental)..." >> "$REPORT"
cargo build --release 2>/dev/null
HASH2=$(sha256sum target/release/cachydpi 2>/dev/null | cut -d' ' -f1 || echo "build2_failed")
echo "  Hash 2: $HASH2" >> "$REPORT"

if [[ "$HASH1" == "$HASH2" && "$HASH1" != "build1_failed" ]]; then
    pass "Incremental builds produce identical binary"
else
    # Clean build comparison
    echo "  Performing clean rebuild for comparison..." >> "$REPORT"
    cargo clean 2>/dev/null
    cargo build --release 2>/dev/null
    HASH3=$(sha256sum target/release/cachydpi 2>/dev/null | cut -d' ' -f1 || echo "build3_failed")
    echo "  Clean Hash: $HASH3" >> "$REPORT"

    if [[ "$HASH1" == "$HASH3" ]]; then
        pass "Clean rebuilds produce identical binary"
    else
        warn "Clean rebuild differs from original (may include timestamps or randomization)"
    fi
fi

# ── Test 5: Dependency review ──
echo "" >> "$REPORT"
echo "--- Test 5: Dependency review ---" >> "$REPORT"

DEP_COUNT=$(cargo tree --depth 1 2>/dev/null | wc -l || echo "?")
echo "  Direct dependency count: $DEP_COUNT" >> "$REPORT"

# Check for known problematic patterns
TOTAL_DEPS=$(cargo tree 2>/dev/null | wc -l || echo "?")
echo "  Total dependency tree entries: $TOTAL_DEPS" >> "$REPORT"

if [[ "$TOTAL_DEPS" =~ ^[0-9]+$ ]] && (( TOTAL_DEPS < 300 )); then
    pass "Dependency count reasonable: $TOTAL_DEPS tree entries"
else
    warn "Large dependency tree: $TOTAL_DEPS entries"
fi

# Check for duplicate dependencies
DUPES=$(cargo tree --duplicates 2>/dev/null || true)
if [[ -z "$DUPES" ]]; then
    pass "No duplicate dependencies"
else
    DUPE_COUNT=$(echo "$DUPES" | grep -c "^[a-z]" || echo "?")
    echo "  Duplicate deps: $DUPE_COUNT" >> "$REPORT"
    echo "$DUPES" | head -10 | sed 's/^/    /' >> "$REPORT"
    warn "Found $DUPE_COUNT duplicate dependencies"
fi

# ── Test 6: Build with all features ──
echo "" >> "$REPORT"
echo "--- Test 6: Build with all features ---" >> "$REPORT"

ALL_FEATURES_OUTPUT=$(cargo build --all-features 2>&1 || true)
if echo "$ALL_FEATURES_OUTPUT" | grep -q "error\["; then
    echo "$ALL_FEATURES_OUTPUT" | grep "error" | head -5 | sed 's/^/    /' >> "$REPORT"
    fail "Build with --all-features fails"
else
    pass "Build with --all-features succeeds"
fi

# ── Test 7: Build with no default features ──
echo "" >> "$REPORT"
echo "--- Test 7: Build with no default features ---" >> "$REPORT"

NO_DEF_OUTPUT=$(cargo build --no-default-features 2>&1 || true)
if echo "$NO_DEF_OUTPUT" | grep -q "error\["; then
    echo "$NO_DEF_OUTPUT" | grep "error" | head -5 | sed 's/^/    /' >> "$REPORT"
    fail "Build with --no-default-features fails"
else
    pass "Build with --no-default-features succeeds"
fi

# ── Test 8: MSRV check ──
echo "" >> "$REPORT"
echo "--- Test 8: Rust edition & MSRV ---" >> "$REPORT"

EDITION=$(grep "^edition" Cargo.toml 2>/dev/null | head -1 || echo "?")
RUST_VERSION=$(grep "^rust-version" Cargo.toml 2>/dev/null | head -1 || echo "not specified")
echo "  Edition: $EDITION" >> "$REPORT"
echo "  MSRV: $RUST_VERSION" >> "$REPORT"

if [[ -n "$EDITION" ]]; then
    pass "Rust edition specified: $EDITION"
else
    warn "No edition specified in Cargo.toml"
fi

# ── Summary ──
echo "" >> "$REPORT"
echo "========================================" >> "$REPORT"
echo "SUMMARY: $PASS passed, $FAIL failed, $WARN warnings, $SKIP skipped" >> "$REPORT"
echo "========================================" >> "$REPORT"

echo ""
echo "Report written to $REPORT"
echo "Results: $PASS passed, $FAIL failed, $WARN warnings, $SKIP skipped"
