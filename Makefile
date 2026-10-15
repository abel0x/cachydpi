# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 abel0x <https://github.com/abel0x>
# CachyDPI Makefile
# Simplified build commands for development and packaging

CARGO := cargo
INSTALL := install
BINARY := cachydpi
PREFIX := /usr
DESTDIR :=
SYSCONFDIR := /etc

.PHONY: all build release debug clean install uninstall test check fmt clippy

all: release

# Development build (fast compile, unoptimized)
debug:
	$(CARGO) build

# Release build (optimized, settings from Cargo.toml profile)
release:
	$(CARGO) build --release

# Full build with all optimizations
build: release

# Run tests
test:
	$(CARGO) test

# Run clippy linter
clippy:
	$(CARGO) clippy -- -W clippy::all

# Run formatter check
fmt:
	$(CARGO) fmt --check

# Check without building
check:
	$(CARGO) check

# Install to system (run 'make release' first, then 'sudo make install')
install:
	$(INSTALL) -Dm755 target/release/$(BINARY) $(DESTDIR)$(PREFIX)/bin/$(BINARY)
	@# The monitor reads the daemon's metrics format, which changes between
	@# releases: one left behind from an older install reports a running
	@# daemon as disconnected. Install it with the daemon whenever it was built.
	@if [ -e target/release/$(BINARY)-monitor ]; then \
		$(INSTALL) -Dm755 target/release/$(BINARY)-monitor $(DESTDIR)$(PREFIX)/bin/$(BINARY)-monitor; \
	else \
		echo "note: $(BINARY)-monitor not built (--no-default-features?); an older one may be left in place"; \
	fi
	@# Never replace a config already in place: it holds operator choices and
	@# an upgrade that resets them changes behaviour without failing loudly.
	@if [ -e $(DESTDIR)$(SYSCONFDIR)/cachydpi/config.toml ]; then \
		echo "config.toml exists, not overwritten"; \
	else \
		$(INSTALL) -Dm644 config/config.toml $(DESTDIR)$(SYSCONFDIR)/cachydpi/config.toml; \
	fi
	@if [ -e $(DESTDIR)$(SYSCONFDIR)/cachydpi/blacklist.txt ]; then \
		echo "blacklist.txt exists, not overwritten"; \
	else \
		$(INSTALL) -Dm644 config/blacklist.txt $(DESTDIR)$(SYSCONFDIR)/cachydpi/blacklist.txt; \
	fi
	@# Reference copies for recovery — the files under $(SYSCONFDIR) are never
	@# replaced, so a damaged one needs something to restore from.
	$(INSTALL) -Dm644 config/config.toml $(DESTDIR)$(PREFIX)/share/doc/cachydpi/config.toml
	$(INSTALL) -Dm644 CHANGELOG.md $(DESTDIR)$(PREFIX)/share/doc/cachydpi/CHANGELOG.md
	$(INSTALL) -Dm644 README.md $(DESTDIR)$(PREFIX)/share/doc/cachydpi/README.md
	$(INSTALL) -Dm644 systemd/cachydpi.service $(DESTDIR)$(PREFIX)/lib/systemd/system/cachydpi.service
	$(INSTALL) -Dm644 systemd/cachydpi.sysusers $(DESTDIR)$(PREFIX)/lib/sysusers.d/cachydpi.conf
	$(INSTALL) -Dm644 systemd/cachydpi.tmpfiles $(DESTDIR)$(PREFIX)/lib/tmpfiles.d/cachydpi.conf
	@echo ""
	@echo "CachyDPI installed. Enable with: sudo systemctl enable --now cachydpi"

# Uninstall from system
uninstall:
	/usr/bin/cachydpi remove-rules 2>/dev/null || true
	systemctl stop cachydpi 2>/dev/null || true
	systemctl disable cachydpi 2>/dev/null || true
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BINARY)
	rm -f $(DESTDIR)$(PREFIX)/bin/$(BINARY)-monitor
	rm -f $(DESTDIR)$(PREFIX)/lib/systemd/system/cachydpi.service
	rm -f $(DESTDIR)$(PREFIX)/lib/sysusers.d/cachydpi.conf
	rm -f $(DESTDIR)$(PREFIX)/lib/tmpfiles.d/cachydpi.conf
	@echo "CachyDPI uninstalled. Config preserved at $(SYSCONFDIR)/cachydpi/"

# Clean build artifacts
clean:
	$(CARGO) clean
