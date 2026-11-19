#!/bin/bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 abel0x <https://github.com/abel0x>
# install.sh — CachyDPI one-command installer for CachyOS
#
# Usage, from a checkout of a release tag:
#   git clone --branch vX.Y.Z https://github.com/abel0x/cachydpi.git
#   cd cachydpi && git verify-tag vX.Y.Z   # tags are signed
#   sudo ./install.sh
#
# It is not meant to be piped from the network into a root shell: that runs
# whatever the branch holds at that moment, unreviewed, and the script needs
# the source tree next to it anyway.
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

# ── Source tree ──
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ ! -f "$SCRIPT_DIR/Cargo.toml" || ! -f "$SCRIPT_DIR/Cargo.lock" ]]; then
    err "Run this from a CachyDPI checkout: Cargo.toml and Cargo.lock were not found next to it."
    err "  git clone https://github.com/abel0x/cachydpi.git && cd cachydpi && sudo ./install.sh"
    exit 1
fi
cd "$SCRIPT_DIR"

# The minimum Rust, as Cargo.toml declares it.
RUST_MIN="$(sed -n 's/^rust-version = "\([0-9.]*\)"/\1/p' Cargo.toml)"

# ── Who builds ──
# Building runs build scripts and proc macros from every dependency, so it
# runs as the user who called sudo, not as root; only installing needs root.
BUILD_USER="${SUDO_USER:-}"
if [[ -z $BUILD_USER || $BUILD_USER == root ]]; then
    BUILD_USER=""
    warn "No unprivileged user to build as (run with sudo from your own account); building as root"
fi
BUILD_HOME=""
[[ -n $BUILD_USER ]] && BUILD_HOME="$(getent passwd "$BUILD_USER" | cut -d: -f6)"
as_builder() {
    if [[ -n $BUILD_USER ]]; then
        # bash whatever the user's login shell is, with a clean environment and
        # ~/.cargo/bin first, so a rustup toolchain is found.
        runuser -u "$BUILD_USER" -- env -i \
            HOME="$BUILD_HOME" USER="$BUILD_USER" TERM="${TERM:-dumb}" \
            PATH="$BUILD_HOME/.cargo/bin:/usr/local/bin:/usr/bin:/bin" \
            bash -c "cd $(printf %q "$SCRIPT_DIR") && $(printf '%q ' "$@")"
    else
        "$@"
    fi
}

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
    # A rustup toolchain the user already has conflicts with the rust package.
    RUST_PKGS=(rust)
    if as_builder cargo --version &>/dev/null; then
        RUST_PKGS=()
    fi
    pacman -S --needed --noconfirm \
        "${RUST_PKGS[@]}" \
        pkg-config \
        libnetfilter_queue \
        libnfnetlink \
        libmnl \
        nftables \
        base-devel
    ok "Dependencies installed (pacman)"
elif command -v apt &>/dev/null; then
    apt update
    # Debian's and Ubuntu's rustc is usually older than the build needs; a
    # rustup toolchain the user already has is used instead of it.
    RUST_PKGS=(rustc cargo)
    if as_builder cargo --version &>/dev/null; then
        RUST_PKGS=()
    fi
    apt install -y \
        "${RUST_PKGS[@]}" \
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

# ── Toolchain ──
RUSTC_VERSION="$(as_builder rustc --version 2>/dev/null | awk '{print $2}')" || true
if [[ -z $RUSTC_VERSION ]]; then
    err "rustc was not found for ${BUILD_USER:-root}."
    exit 1
fi
if [[ -n $RUST_MIN && "$(printf '%s\n%s\n' "$RUST_MIN" "${RUSTC_VERSION%%-*}" | sort -V | head -1)" != "$RUST_MIN" ]]; then
    err "rustc $RUSTC_VERSION is older than the $RUST_MIN this build needs."
    err "Install a current toolchain with rustup (https://rustup.rs) as ${BUILD_USER:-root}, then run this again."
    exit 1
fi
ok "rustc $RUSTC_VERSION (needs $RUST_MIN+)"

# Earlier versions of this script built as root; that target/ is not the
# user's to write to.
if [[ -n $BUILD_USER && -e target && "$(stat -c %U target)" != "$BUILD_USER" ]]; then
    err "target/ belongs to $(stat -c %U target), from an earlier build as root."
    err "Remove it (sudo rm -rf target) and run this again."
    exit 1
fi

# ── Build ──
info "Building CachyDPI as ${BUILD_USER:-root}..."
# --locked builds exactly the dependency versions Cargo.lock records, with the
# checksums it records, instead of resolving newer ones at install time.
as_builder env RUSTFLAGS="-C opt-level=3 -C lto=fat -C codegen-units=1 -C strip=symbols" \
    cargo build --release --locked
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
