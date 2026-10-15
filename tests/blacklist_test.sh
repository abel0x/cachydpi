#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 abel0x <https://github.com/abel0x>
# ═══════════════════════════════════════════════════════════════════
# CachyDPI Blacklist Test Suite
# Tests all domains in the blacklist and generates a Markdown report
# ═══════════════════════════════════════════════════════════════════
#
# Usage:
#   sudo ./tests/blacklist_test.sh                  # Test all domains
#   sudo ./tests/blacklist_test.sh --sample 100     # Test random 100 domains
#   sudo ./tests/blacklist_test.sh --category       # Test 1 per category
#   sudo ./tests/blacklist_test.sh --quick           # Top 50 important sites
#
# Output: tests/BLACKLIST_REPORT.md

set -uo pipefail

# ── Configuration ──
BLACKLIST="/etc/cachydpi/blacklist.txt"
REPORT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPORT="$REPORT_DIR/BLACKLIST_REPORT.md"
TIMEOUT=5          # curl timeout per site (seconds)
PARALLEL=60        # concurrent curl jobs
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

# ── Colors ──
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ── Parse arguments ──
MODE="all"
SAMPLE_SIZE=0

while [[ $# -gt 0 ]]; do
    case $1 in
        --sample)
            MODE="sample"
            SAMPLE_SIZE="${2:-100}"
            shift 2
            ;;
        --category)
            MODE="category"
            shift
            ;;
        --quick)
            MODE="quick"
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--sample N] [--category] [--quick]"
            echo "  --sample N    Test random N domains"
            echo "  --category    Test representative domains per category"
            echo "  --quick       Test top 50 important sites only"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# ── Quick mode: hand-picked important domains ──
QUICK_DOMAINS=(
    # Social Media
    twitter.com x.com facebook.com instagram.com reddit.com
    tiktok.com pinterest.com tumblr.com linkedin.com
    # Messaging
    discord.com telegram.org web.telegram.org signal.org
    # Video/Streaming
    youtube.com twitch.tv vimeo.com dailymotion.com
    # Search/Tech
    google.com bing.com duckduckgo.com
    github.com gitlab.com stackoverflow.com
    # News
    bbc.com nytimes.com reuters.com theguardian.com
    # Privacy/VPN
    protonvpn.com nordvpn.com expressvpn.com torproject.org
    protonmail.com
    # File Sharing
    archive.org mega.nz dropbox.com mediafire.com
    # Gaming
    store.steampowered.com epicgames.com
    # Adult (commonly blocked in TR)
    pornhub.com xvideos.com xhamster.com
    # Crypto
    binance.com coinbase.com
    # Other
    wikipedia.org pastebin.com imgur.com
    medium.com wordpress.com
)

# ── Extract categories from blacklist ──
extract_categories() {
    local current_cat=""
    local prev_line=""
    while IFS= read -r line; do
        if [[ "$line" =~ ^#\ ---\ (.+)\ ---$ ]]; then
            current_cat="${BASH_REMATCH[1]}"
        elif [[ -n "$current_cat" && ! "$line" =~ ^# && -n "$line" ]]; then
            echo "$current_cat|$line"
            current_cat=""
        fi
    done < "$BLACKLIST"
}

# ── Build domain list based on mode ──
echo -e "${CYAN}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║       CachyDPI Blacklist Test Suite           ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════╝${NC}"
echo ""

case "$MODE" in
    all)
        grep -v '^#' "$BLACKLIST" | grep -v '^$' | sort -u > "$TMPDIR/domains.txt"
        TOTAL=$(wc -l < "$TMPDIR/domains.txt")
        echo -e "Mode: ${YELLOW}ALL${NC} ($TOTAL domains)"
        echo -e "${RED}WARNING: This will take a LONG time (~$((TOTAL * TIMEOUT / PARALLEL / 60)) minutes)${NC}"
        echo ""
        ;;
    sample)
        grep -v '^#' "$BLACKLIST" | grep -v '^$' | sort -u | shuf -n "$SAMPLE_SIZE" > "$TMPDIR/domains.txt"
        TOTAL=$(wc -l < "$TMPDIR/domains.txt")
        echo -e "Mode: ${YELLOW}SAMPLE${NC} ($TOTAL random domains)"
        ;;
    category)
        extract_categories | sort -t'|' -k1,1 -u | cut -d'|' -f2 > "$TMPDIR/domains.txt"
        TOTAL=$(wc -l < "$TMPDIR/domains.txt")
        echo -e "Mode: ${YELLOW}CATEGORY${NC} ($TOTAL domains, 1 per category)"
        ;;
    quick)
        printf '%s\n' "${QUICK_DOMAINS[@]}" > "$TMPDIR/domains.txt"
        TOTAL=${#QUICK_DOMAINS[@]}
        echo -e "Mode: ${YELLOW}QUICK${NC} ($TOTAL important domains)"
        ;;
esac

echo -e "Timeout: ${TIMEOUT}s per site | Parallelism: ${PARALLEL}"
echo -e "Report: ${CYAN}$REPORT${NC}"
echo ""

# ── Check if CachyDPI is running ──
CACHYDPI_STATUS="unknown"
if systemctl is-active cachydpi &>/dev/null 2>&1; then
    CACHYDPI_STATUS="active"
    echo -e "CachyDPI: ${GREEN}● active${NC}"
elif pgrep -x cachydpi &>/dev/null; then
    CACHYDPI_STATUS="active (manual)"
    echo -e "CachyDPI: ${GREEN}● active (manual)${NC}"
else
    CACHYDPI_STATUS="inactive"
    echo -e "CachyDPI: ${RED}● inactive${NC}"
fi

# ── Test a single domain ──
test_domain() {
    local domain="$1"
    local idx="$2"
    local total="$3"
    local outfile="$TMPDIR/result_$(printf '%05d' "$idx").txt"

    # Try HTTPS first
    local start_ms=$(date +%s%3N)
    local http_code
    http_code=$(timeout "$TIMEOUT" curl -sI --max-time "$((TIMEOUT - 1))" \
        -o /dev/null -w "%{http_code}" \
        "https://$domain" 2>/dev/null) || http_code="000"
    local end_ms=$(date +%s%3N)
    local latency_ms=$((end_ms - start_ms))

    # Determine status
    local status="FAIL"
    local emoji="❌"
    if [[ "$http_code" =~ ^[23] ]]; then
        status="OK"
        emoji="✅"
    elif [[ "$http_code" == "403" ]]; then
        status="BLOCKED"
        emoji="🚫"
    elif [[ "$http_code" =~ ^[45] ]]; then
        status="ERROR"
        emoji="⚠️"
    elif [[ "$http_code" == "000" ]]; then
        status="TIMEOUT"
        emoji="⏱️"
    fi

    # Write result
    echo "$domain|$http_code|$status|$emoji|${latency_ms}ms" > "$outfile"

    # Console progress
    local color="$RED"
    [[ "$status" == "OK" ]] && color="$GREEN"
    [[ "$status" == "BLOCKED" ]] && color="$YELLOW"
    [[ "$status" == "ERROR" ]] && color="$YELLOW"

    printf "\r  [%d/%d] %-40s %s%-4s%s %s" \
        "$idx" "$total" "$domain" "$color" "$http_code" "$NC" "${latency_ms}ms"
}
export -f test_domain
export TIMEOUT TMPDIR

# ── Run tests ──
echo ""
echo -e "${CYAN}Starting tests...${NC}"
echo ""

STARTED_AT=$(date "+%Y-%m-%d %H:%M:%S")
START_EPOCH=$(date +%s)

# Run with GNU parallel or xargs fallback
IDX=0
TOTAL_DOMAINS=$(wc -l < "$TMPDIR/domains.txt")

if command -v parallel &>/dev/null; then
    cat "$TMPDIR/domains.txt" | parallel -j "$PARALLEL" --line-buffer \
        "test_domain {} {#} $TOTAL_DOMAINS"
else
    # xargs fallback with index tracking
    while IFS= read -r domain; do
        ((IDX++)) || true
        test_domain "$domain" "$IDX" "$TOTAL_DOMAINS" &

        # Limit parallelism
        if (( IDX % PARALLEL == 0 )); then
            wait
        fi
    done < "$TMPDIR/domains.txt"
    wait
fi

END_EPOCH=$(date +%s)
ELAPSED=$((END_EPOCH - START_EPOCH))
ENDED_AT=$(date "+%Y-%m-%d %H:%M:%S")

echo ""
echo ""

# ── Collect and analyze results ──
echo -e "${CYAN}Analyzing results...${NC}"

# Merge all results
cat "$TMPDIR"/result_*.txt 2>/dev/null | sort -t'|' -k1,1 > "$TMPDIR/all_results.txt"

TOTAL_TESTED=$(wc -l < "$TMPDIR/all_results.txt")
COUNT_OK=$(grep -c '|OK|' "$TMPDIR/all_results.txt" || true)
COUNT_TIMEOUT=$(grep -c '|TIMEOUT|' "$TMPDIR/all_results.txt" || true)
COUNT_BLOCKED=$(grep -c '|BLOCKED|' "$TMPDIR/all_results.txt" || true)
COUNT_ERROR=$(grep -c '|ERROR|' "$TMPDIR/all_results.txt" || true)
COUNT_FAIL=$((COUNT_TIMEOUT + COUNT_BLOCKED + COUNT_ERROR))

PCT_OK=0
[[ $TOTAL_TESTED -gt 0 ]] && PCT_OK=$((COUNT_OK * 100 / TOTAL_TESTED))

# ── Generate Markdown Report ──
echo -e "${CYAN}Generating report...${NC}"

cat > "$REPORT" << HEADER
# CachyDPI Blacklist Test Report

> **Generated:** $ENDED_AT
> **CachyDPI Status:** \`$CACHYDPI_STATUS\`
> **Test Mode:** \`$MODE\`
> **Duration:** ${ELAPSED}s

---

## Summary

| Metric | Value |
|--------|-------|
| **Total Domains Tested** | $TOTAL_TESTED |
| **✅ Accessible (2xx/3xx)** | $COUNT_OK ($PCT_OK%) |
| **⏱️ Timeout (000)** | $COUNT_TIMEOUT |
| **🚫 Blocked (403)** | $COUNT_BLOCKED |
| **⚠️ Server Error (4xx/5xx)** | $COUNT_ERROR |
| **Total Failed** | $COUNT_FAIL |
| **Success Rate** | **${PCT_OK}%** |

HEADER

# Progress bar
BAR_LEN=30
FILLED=$((PCT_OK * BAR_LEN / 100))
EMPTY=$((BAR_LEN - FILLED))
BAR=""
for ((i=0; i<FILLED; i++)); do BAR+="█"; done
for ((i=0; i<EMPTY; i++)); do BAR+="░"; done

cat >> "$REPORT" << PROGRESSBAR
\`\`\`
Success: [${BAR}] ${PCT_OK}%
\`\`\`

---

## ✅ Accessible Sites ($COUNT_OK)

| Domain | HTTP Code | Latency |
|--------|-----------|---------|
PROGRESSBAR

grep '|OK|' "$TMPDIR/all_results.txt" | while IFS='|' read -r domain code status emoji latency; do
    echo "| \`$domain\` | $code | $latency |"
done >> "$REPORT"

cat >> "$REPORT" << SECTION

---

## ⏱️ Timeout / Unreachable ($COUNT_TIMEOUT)

These sites did not respond within ${TIMEOUT}s. Could be:
- ISP DPI blocking (CachyDPI bypass not working)
- Site genuinely down
- DNS resolution failure
- Network routing issue

| Domain | HTTP Code | Latency |
|--------|-----------|---------|
SECTION

grep '|TIMEOUT|' "$TMPDIR/all_results.txt" | while IFS='|' read -r domain code status emoji latency; do
    echo "| \`$domain\` | $code | $latency |"
done >> "$REPORT"

cat >> "$REPORT" << SECTION

---

## 🚫 Blocked / Forbidden ($COUNT_BLOCKED)

These sites returned HTTP 403. The request reached the server but access was denied
(could be geo-blocking, server-side block, or DPI injection).

| Domain | HTTP Code | Latency |
|--------|-----------|---------|
SECTION

grep '|BLOCKED|' "$TMPDIR/all_results.txt" | while IFS='|' read -r domain code status emoji latency; do
    echo "| \`$domain\` | $code | $latency |"
done >> "$REPORT"

cat >> "$REPORT" << SECTION

---

## ⚠️ Server Errors ($COUNT_ERROR)

These sites returned 4xx/5xx errors. The connection was established but the server
returned an error (not necessarily a DPI issue).

| Domain | HTTP Code | Latency |
|--------|-----------|---------|
SECTION

grep '|ERROR|' "$TMPDIR/all_results.txt" | while IFS='|' read -r domain code status emoji latency; do
    echo "| \`$domain\` | $code | $latency |"
done >> "$REPORT"

# ── Detailed statistics ──
cat >> "$REPORT" << SECTION

---

## HTTP Code Distribution

| Code | Count | Meaning |
|------|-------|---------|
SECTION

# Count each HTTP code
cut -d'|' -f2 "$TMPDIR/all_results.txt" | sort | uniq -c | sort -rn | while read -r count code; do
    meaning=""
    case "$code" in
        000) meaning="Timeout / Connection Failed" ;;
        200) meaning="OK" ;;
        301) meaning="Moved Permanently (redirect)" ;;
        302) meaning="Found (redirect)" ;;
        303) meaning="See Other" ;;
        307) meaning="Temporary Redirect" ;;
        308) meaning="Permanent Redirect" ;;
        400) meaning="Bad Request" ;;
        403) meaning="Forbidden" ;;
        404) meaning="Not Found" ;;
        405) meaning="Method Not Allowed" ;;
        406) meaning="Not Acceptable" ;;
        409) meaning="Conflict" ;;
        410) meaning="Gone" ;;
        421) meaning="Misdirected Request" ;;
        429) meaning="Too Many Requests" ;;
        444) meaning="Connection Closed (nginx)" ;;
        451) meaning="Unavailable For Legal Reasons" ;;
        500) meaning="Internal Server Error" ;;
        502) meaning="Bad Gateway" ;;
        503) meaning="Service Unavailable" ;;
        504) meaning="Gateway Timeout" ;;
        530) meaning="Origin DNS Error (Cloudflare)" ;;
        *) meaning="Other" ;;
    esac
    echo "| \`$code\` | $count | $meaning |"
done >> "$REPORT"

cat >> "$REPORT" << FOOTER

---

## Test Configuration

| Parameter | Value |
|-----------|-------|
| Blacklist File | \`$BLACKLIST\` |
| Total Blacklist Entries | $(grep -vc '^#\|^$' "$BLACKLIST") |
| Unique Domains Tested | $TOTAL_TESTED |
| Test Mode | \`$MODE\` |
| Timeout Per Site | ${TIMEOUT}s |
| Parallel Connections | $PARALLEL |
| Started At | $STARTED_AT |
| Finished At | $ENDED_AT |
| Total Duration | ${ELAPSED}s |
| CachyDPI Service | \`$CACHYDPI_STATUS\` |

---

*Report generated by \`tests/blacklist_test.sh\`*
FOOTER

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════${NC}"
echo -e "  ${GREEN}Report saved to:${NC} $REPORT"
echo ""
echo -e "  ✅ Accessible:  ${GREEN}$COUNT_OK${NC}"
echo -e "  ⏱️  Timeout:     ${RED}$COUNT_TIMEOUT${NC}"
echo -e "  🚫 Blocked:     ${YELLOW}$COUNT_BLOCKED${NC}"
echo -e "  ⚠️  Error:       ${YELLOW}$COUNT_ERROR${NC}"
echo -e "  📊 Success:     ${GREEN}${PCT_OK}%${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════${NC}"
