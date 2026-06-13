#!/bin/bash
# ═══════════════════════════════════════════════════════════════════
# CachyDPI Dead Site Analyzer
# Classifies failed sites as: DNS_DEAD, SERVER_DEAD, ISP_BLOCKED, SERVER_BLOCKED
# ═══════════════════════════════════════════════════════════════════
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

FAILED_LIST="/tmp/all_failed.txt"
TIMEOUT_LIST="/tmp/timeout_sites.txt"
BLOCKED_LIST="/tmp/blocked_sites.txt"
ERROR_LIST="/tmp/error_sites.txt"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

PARALLEL=80
DNS_TIMEOUT=3
HTTP_TIMEOUT=4

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║     CachyDPI Dead Site Analyzer               ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════════╝${NC}"

TOTAL=$(wc -l < "$FAILED_LIST")
echo -e "Analyzing ${YELLOW}$TOTAL${NC} failed domains..."
echo ""

# ── Phase 1: DNS Resolution ──
echo -e "${CYAN}[Phase 1/3]${NC} DNS resolution check..."

dns_check() {
    local domain="$1"
    local idx="$2"
    local total="$3"
    local outfile="$TMPDIR/dns_$(echo "$domain" | md5sum | cut -c1-8).txt"
    
    # Try resolving with timeout
    local ip
    ip=$(timeout "$DNS_TIMEOUT" dig +short "$domain" A 2>/dev/null | grep -E '^[0-9]+\.' | head -1)
    
    if [[ -z "$ip" ]]; then
        # Try with getent as fallback
        ip=$(timeout "$DNS_TIMEOUT" getent ahosts "$domain" 2>/dev/null | grep -E '^[0-9]+\.' | head -1 | awk '{print $1}')
    fi
    
    if [[ -z "$ip" ]]; then
        echo "$domain|NO_DNS|" > "$outfile"
    else
        echo "$domain|HAS_DNS|$ip" > "$outfile"
    fi
    printf "\r  [%d/%d] %-40s" "$idx" "$total" "$domain" >&2
}
export -f dns_check
export TMPDIR DNS_TIMEOUT

IDX=0
while IFS= read -r domain; do
    ((IDX++)) || true
    dns_check "$domain" "$IDX" "$TOTAL" &
    if (( IDX % PARALLEL == 0 )); then
        wait
    fi
done < "$FAILED_LIST"
wait

echo ""

# Collect DNS results
cat "$TMPDIR"/dns_*.txt 2>/dev/null | sort > "$TMPDIR/dns_results.txt"
DNS_DEAD=$(grep '|NO_DNS|' "$TMPDIR/dns_results.txt" | wc -l)
DNS_OK=$(grep '|HAS_DNS|' "$TMPDIR/dns_results.txt" | wc -l)
echo -e "  DNS resolves: ${GREEN}$DNS_OK${NC}  |  No DNS: ${RED}$DNS_DEAD${NC}"

# Extract domains that DO resolve
grep '|HAS_DNS|' "$TMPDIR/dns_results.txt" | cut -d'|' -f1 > "$TMPDIR/dns_ok_domains.txt"
# Extract domains that DON'T resolve
grep '|NO_DNS|' "$TMPDIR/dns_results.txt" | cut -d'|' -f1 > "$TMPDIR/dns_dead_domains.txt"

# ── Phase 2: TCP Connect check (port 443) on resolved domains ──
echo ""
echo -e "${CYAN}[Phase 2/3]${NC} TCP connectivity check (port 443)..."

tcp_check() {
    local domain="$1"
    local idx="$2"
    local total="$3"
    local outfile="$TMPDIR/tcp_$(echo "$domain" | md5sum | cut -c1-8).txt"
    
    # Try TCP connect to port 443
    if timeout "$HTTP_TIMEOUT" bash -c "echo > /dev/tcp/$domain/443" 2>/dev/null; then
        echo "$domain|TCP_OK" > "$outfile"
    else
        # Try port 80
        if timeout "$HTTP_TIMEOUT" bash -c "echo > /dev/tcp/$domain/80" 2>/dev/null; then
            echo "$domain|TCP_80_ONLY" > "$outfile"
        else
            echo "$domain|TCP_DEAD" > "$outfile"
        fi
    fi
    printf "\r  [%d/%d] %-40s" "$idx" "$total" "$domain" >&2
}
export -f tcp_check
export HTTP_TIMEOUT

RESOLVING_COUNT=$(wc -l < "$TMPDIR/dns_ok_domains.txt")
IDX=0
while IFS= read -r domain; do
    ((IDX++)) || true
    tcp_check "$domain" "$IDX" "$RESOLVING_COUNT" &
    if (( IDX % PARALLEL == 0 )); then
        wait
    fi
done < "$TMPDIR/dns_ok_domains.txt"
wait

echo ""

cat "$TMPDIR"/tcp_*.txt 2>/dev/null | sort > "$TMPDIR/tcp_results.txt"
TCP_OK=$(grep '|TCP_OK' "$TMPDIR/tcp_results.txt" | wc -l)
TCP_80=$(grep '|TCP_80_ONLY' "$TMPDIR/tcp_results.txt" | wc -l)
TCP_DEAD=$(grep '|TCP_DEAD' "$TMPDIR/tcp_results.txt" | wc -l)
echo -e "  Port 443 open: ${GREEN}$TCP_OK${NC}  |  Port 80 only: ${YELLOW}$TCP_80${NC}  |  Dead server: ${RED}$TCP_DEAD${NC}"

# ── Phase 3: Classify each domain ──
echo ""
echo -e "${CYAN}[Phase 3/3]${NC} Classifying domains..."

# Classification:
# DNS_DEAD      = Domain doesn't resolve at all (expired/parked/never existed)
# SERVER_DEAD   = DNS resolves but no TCP connection possible (server offline)
# ISP_BLOCKED   = TCP connects but HTTPS times out (ISP DPI blocking TLS)
# SERVER_BLOCKED= Server returns 403/4xx/5xx (server-side geo-block or restriction)
# RATE_LIMITED  = Server returns 429 (too many requests - our test artifact)

> "$TMPDIR/classified.txt"

# DNS dead
while IFS= read -r domain; do
    echo "$domain|DNS_DEAD|Domain does not resolve" >> "$TMPDIR/classified.txt"
done < "$TMPDIR/dns_dead_domains.txt"

# Server dead (DNS ok but TCP fails)
grep '|TCP_DEAD' "$TMPDIR/tcp_results.txt" | cut -d'|' -f1 | while IFS= read -r domain; do
    echo "$domain|SERVER_DEAD|DNS resolves but server unreachable" >> "$TMPDIR/classified.txt"
done

# TCP works but original test timed out = ISP BLOCKED
grep '|TCP_OK\|TCP_80_ONLY' "$TMPDIR/tcp_results.txt" | cut -d'|' -f1 | while IFS= read -r domain; do
    if grep -qx "$domain" "$TIMEOUT_LIST" 2>/dev/null; then
        echo "$domain|ISP_BLOCKED|TCP connects but HTTPS times out (DPI blocking)" >> "$TMPDIR/classified.txt"
    elif grep -qx "$domain" "$BLOCKED_LIST" 2>/dev/null; then
        echo "$domain|SERVER_BLOCKED|Server returns 403 Forbidden" >> "$TMPDIR/classified.txt"
    elif grep -qx "$domain" "$ERROR_LIST" 2>/dev/null; then
        # Check HTTP code from original report
        local_code=$(grep "| \`$domain\`" "$SCRIPT_DIR/BLACKLIST_REPORT.md" | grep -oP '\| \d+' | head -1 | tr -d '| ')
        if [[ "$local_code" == "429" ]]; then
            echo "$domain|RATE_LIMITED|Server returned 429 Too Many Requests" >> "$TMPDIR/classified.txt"
        else
            echo "$domain|SERVER_ERROR|Server returned HTTP $local_code" >> "$TMPDIR/classified.txt"
        fi
    fi
done

sort -t'|' -k2,2 -k1,1 "$TMPDIR/classified.txt" > "$TMPDIR/classified_sorted.txt"

# Count categories
C_DNS_DEAD=$(grep -c '|DNS_DEAD|' "$TMPDIR/classified_sorted.txt" || true)
C_SERVER_DEAD=$(grep -c '|SERVER_DEAD|' "$TMPDIR/classified_sorted.txt" || true)
C_ISP_BLOCKED=$(grep -c '|ISP_BLOCKED|' "$TMPDIR/classified_sorted.txt" || true)
C_SERVER_BLOCKED=$(grep -c '|SERVER_BLOCKED|' "$TMPDIR/classified_sorted.txt" || true)
C_RATE_LIMITED=$(grep -c '|RATE_LIMITED|' "$TMPDIR/classified_sorted.txt" || true)
C_SERVER_ERROR=$(grep -c '|SERVER_ERROR|' "$TMPDIR/classified_sorted.txt" || true)
C_TRULY_DEAD=$((C_DNS_DEAD + C_SERVER_DEAD))

echo ""
echo -e "${CYAN}═══════════════════════════════════════════════${NC}"
echo -e "  🪦 DNS Dead (no resolution):    ${RED}$C_DNS_DEAD${NC}"
echo -e "  💀 Server Dead (no TCP):         ${RED}$C_SERVER_DEAD${NC}"
echo -e "  🔒 ISP Blocked (DPI):            ${YELLOW}$C_ISP_BLOCKED${NC}"
echo -e "  🚫 Server Blocked (403):         ${YELLOW}$C_SERVER_BLOCKED${NC}"
echo -e "  ⏳ Rate Limited (429):            ${YELLOW}$C_RATE_LIMITED${NC}"
echo -e "  ⚠️  Server Error (other):         ${YELLOW}$C_SERVER_ERROR${NC}"
echo -e "  ──────────────────────────────────────"
echo -e "  🗑️  Truly Dead (remove):          ${RED}$C_TRULY_DEAD${NC}"
echo -e "  🔧 Fixable (need bypass):         ${GREEN}$C_ISP_BLOCKED${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════${NC}"

# ── Save lists for later use ──
grep '|DNS_DEAD|' "$TMPDIR/classified_sorted.txt" | cut -d'|' -f1 > /tmp/sites_dns_dead.txt
grep '|SERVER_DEAD|' "$TMPDIR/classified_sorted.txt" | cut -d'|' -f1 > /tmp/sites_server_dead.txt
grep '|ISP_BLOCKED|' "$TMPDIR/classified_sorted.txt" | cut -d'|' -f1 > /tmp/sites_isp_blocked.txt
grep '|SERVER_BLOCKED|' "$TMPDIR/classified_sorted.txt" | cut -d'|' -f1 > /tmp/sites_server_blocked.txt
grep '|RATE_LIMITED|' "$TMPDIR/classified_sorted.txt" | cut -d'|' -f1 > /tmp/sites_rate_limited.txt
grep '|SERVER_ERROR|' "$TMPDIR/classified_sorted.txt" | cut -d'|' -f1 > /tmp/sites_server_error.txt
cp "$TMPDIR/classified_sorted.txt" /tmp/classified_all.txt

echo ""
echo -e "Lists saved to /tmp/sites_*.txt"
echo -e "Full classification: /tmp/classified_all.txt"
