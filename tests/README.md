# CachyDPI Test Suite

## Quick Start

```bash
# Run Rust unit + integration tests (no root needed)
cargo test

# Run full test suite including system tests (requires root)
sudo bash tests/run_all_tests.sh

# Run only non-root tests
bash tests/run_all_tests.sh --skip-root
```

## Test Categories

### Rust Tests

| File | Tests | Description |
|------|-------|-------------|
| `unit_tests.rs` | 33 | TCP checksum, TLS/HTTP/QUIC parsing, domain filtering, IP ID numbering |
| `comprehensive_tests.rs` | 116 | Config loading, strategy logic, edge cases, error handling |
| `strategy_integration_tests.rs` | 97 | Multi-strategy interactions, fragment ordering, domain filtering, checksums |
| `injection_path_tests.rs` | 9 | Verdict and injection order: fragments sent before the original is dropped, fallback on send failure |
| `deploy_preserves_config.rs` | 5 | `deploy.sh` keeps an existing config, run against a sandbox |
| `logging_single_sink.rs` | 3 | Each message reaches the journal once under systemd |
| `no_identifying_fields_leak.rs` | 3 | Identifying log fields always go through the redaction switch |

The modules under `src/` carry another 93 unit tests of their own.

### System Tests (shell scripts, require root)

| Script | Description |
|--------|-------------|
| `test_privilege_escalation.sh` | Capability enforcement, UID drop, systemd hardening |
| `test_crash_safety.sh` | nftables cleanup after SIGTERM/SIGKILL/SIGINT |
| `test_signal_handling.sh` | Graceful shutdown, signal sequence, restart cycles |
| `test_nftables_isolation.sh` | Table isolation, Docker/libvirt coexistence |
| `test_performance.sh` | Memory, CPU, FD count, startup time, resource limits |
| `test_build_reproducibility.sh` | Clippy, reproducible builds, dependency audit |
| `test_isp_bypass.sh` | Live ISP bypass verification (needs internet) |

### Blacklist Utilities

| Script | Description |
|--------|-------------|
| `blacklist_test.sh` | Test blacklist domains for accessibility (`--all`, `--sample N`, `--quick`) |
| `analyze_dead_sites.sh` | Find dead/unreachable domains in the blacklist |

## Running Individual Tests

```bash
# Single Rust test
cargo test tcp_checksum_v4_known_value

# Single system test
sudo bash tests/test_privilege_escalation.sh

# Blacklist quick test (50 domains)
sudo bash tests/blacklist_test.sh --quick

# Blacklist full test (all ~5000 domains)
sudo bash tests/blacklist_test.sh --all
```

## Reports

Test reports are saved to `tests/reports/`. The `run_all_tests.sh` script generates a combined report at `tests/reports/combined_report.txt`.

Historical reports and analysis documents are also kept here for reference:

| File | Description |
|------|-------------|
| `combined_report.txt` | Latest full test suite results |
| `FAILURE_ANALYSIS.md` | Real-world DPI bypass testing results and failure root causes |
| `BLACKLIST_ANALYSIS.md` | Blacklist domain classification (DNS dead, ISP blocked, etc.) |
| `BLACKLIST_REPORT.md` | Full blacklist accessibility test results |
| `REMOVED_SITES.md` | Domains removed from blacklist (dead/unreachable) |

## Fresh Results

Run `sudo bash tests/run_all_tests.sh` to generate results for your system.
