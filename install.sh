#!/bin/bash
# install.sh — CachyDPI one-command installer for CachyOS
#
# Usage: curl -fsSL https://raw.githubusercontent.com/abel0x/cachydpi/main/install.sh | sudo bash
# Or:    sudo ./install.sh
#
# This script:
#   1. Installs build dependencies
#   2. Builds CachyDPI from source
#   3. Installs binary, config, and systemd service
#   4. Enables and starts the service

set -euo pipefail

# ── Colors ──
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[OK]${NC}    $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# ── Root check ──
if [[ $EUID -ne 0 ]]; then
    err "This script must be run as root: sudo ./install.sh"
    exit 1
fi

# ── Detect distribution ──
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    info "Operating system: $PRETTY_NAME"
else
    warn "/etc/os-release not found"
fi

# ── Install dependencies ──
info "Installing dependencies..."
if command -v pacman &>/dev/null; then
    pacman -S --needed --noconfirm \
        rust \
        cargo \
        pkg-config \
        libnetfilter_queue \
        libnfnetlink \
        libmnl \
        nftables \
        base-devel
    ok "Dependencies installed (pacman)"
elif command -v apt &>/dev/null; then
    apt update
    apt install -y \
        rustc \
        cargo \
        pkg-config \
        libnetfilter-queue-dev \
        libnfnetlink-dev \
        libmnl-dev \
        nftables \
        build-essential
    ok "Dependencies installed (apt)"
else
    err "Unsupported package manager. Manual installation required."
    exit 1
fi

# ── Build ──
info "Building CachyDPI..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

export RUSTFLAGS="-C opt-level=3 -C lto=fat -C codegen-units=1 -C strip=symbols"
cargo build --release
ok "Build complete"

# ── Install binary ──
info "Installing files..."
install -Dm755 "target/release/cachydpi" "/usr/bin/cachydpi"
ok "Binary: /usr/bin/cachydpi"

# ── Install config ──
if [[ ! -f /etc/cachydpi/config.toml ]]; then
    install -Dm644 "config/config.toml" "/etc/cachydpi/config.toml"
    ok "Config: /etc/cachydpi/config.toml"
else
    warn "Config already exists, not overwritten"
fi

# ── Install blacklist ──
if [[ ! -f /etc/cachydpi/blacklist.txt ]]; then
    install -Dm644 "config/blacklist.txt" "/etc/cachydpi/blacklist.txt"
    ok "Blacklist: /etc/cachydpi/blacklist.txt"
else
    warn "Blacklist already exists, not overwritten"
fi

# ── Reference copies for recovery ──
# The files under /etc are never overwritten, so a damaged config needs a
# pristine copy to restore from (referenced by the README and by the errors
# the daemon prints when it refuses to start).
install -Dm644 "config/config.toml" "/usr/share/doc/cachydpi/config.toml"
install -Dm644 "CHANGELOG.md" "/usr/share/doc/cachydpi/CHANGELOG.md"
ok "Reference config: /usr/share/doc/cachydpi/config.toml"

# ── Install systemd files ──
install -Dm644 "systemd/cachydpi.service" "/usr/lib/systemd/system/cachydpi.service"
install -Dm644 "systemd/cachydpi.sysusers" "/usr/lib/sysusers.d/cachydpi.conf"
install -Dm644 "systemd/cachydpi.tmpfiles" "/usr/lib/tmpfiles.d/cachydpi.conf"
ok "Systemd files installed"

# ── Create system user ──
systemd-sysusers cachydpi.conf 2>/dev/null || true
systemd-tmpfiles --create cachydpi.conf 2>/dev/null || true
ok "System user and directories created"

# ── Reload systemd ──
systemctl daemon-reload
ok "Systemd reloaded"

# ── Enable and start ──
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║       CachyDPI installed successfully!           ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║                                                  ║${NC}"
echo -e "${GREEN}║  Start the service:                              ║${NC}"
echo -e "${GREEN}║    sudo systemctl enable --now cachydpi          ║${NC}"
echo -e "${GREEN}║                                                  ║${NC}"
echo -e "${GREEN}║  Check status:                                   ║${NC}"
echo -e "${GREEN}║    sudo systemctl status cachydpi                ║${NC}"
echo -e "${GREEN}║                                                  ║${NC}"
echo -e "${GREEN}║  Logs:                                           ║${NC}"
echo -e "${GREEN}║    journalctl -u cachydpi -f                     ║${NC}"
echo -e "${GREEN}║                                                  ║${NC}"
echo -e "${GREEN}║  Configuration:                                  ║${NC}"
echo -e "${GREEN}║    /etc/cachydpi/config.toml                     ║${NC}"
echo -e "${GREEN}║                                                  ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""

if [[ -t 0 ]]; then
    read -p "Start the service now? [Y/n] " -n 1 -r
    echo
else
    REPLY="Y"
fi
if [[ $REPLY =~ ^[Yy]$ ]] || [[ -z $REPLY ]]; then
    systemctl enable --now cachydpi
    ok "CachyDPI service started"
    echo ""
    systemctl status cachydpi --no-pager
else
    info "To start later: sudo systemctl enable --now cachydpi"
fi
