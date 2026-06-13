# Security Policy

## What CachyDPI is — and is not

CachyDPI is a **censorship-circumvention** tool. It manipulates the structure of *your own* outbound packets (fragmentation, fake-packet injection) and drops forged packets injected by an ISP's DPI, so that DPI-based blocking of HTTP/TLS/QUIC fails. That is its entire purpose.

It is explicitly **not**:

- **A privacy or anonymity tool.** It does not encrypt your traffic. Your ISP still sees destination IPs and packet timing. For confidentiality or anonymity use a VPN or Tor.
- **An exfiltration, scanning, or attack tool.** It opens no inbound network service, sends no data anywhere on your behalf, and contains no remote-control channel. Its only IPC is a local, read-only metrics socket (below).
- **A kernel or firewall replacement.** It adds one isolated nftables table and removes it on exit; it does not alter your other firewall rules.

### Legal responsibility

Bypassing ISP or state-mandated network filtering is **regulated or prohibited in some jurisdictions**. You are solely responsible for ensuring that running CachyDPI is lawful where you operate it. The software is provided under the GPL-3.0-or-later **with no warranty** (see `LICENSE`); the authors accept no liability for misuse or for legal consequences in your jurisdiction.

---

## Reporting a vulnerability

**Please do not open a public issue for security problems.** Use private disclosure:

1. **GitHub Security Advisory (preferred)** — open a private advisory at
   `https://github.com/abel0x/cachydpi/security/advisories/new`.
2. **Maintainer contact** — reach the maintainer via the GitHub profile [@abel0x](https://github.com/abel0x).

Include: affected component (e.g. nfqueue handler, TLS/HTTP parser, privilege management, config writer), reproduction steps, an impact assessment (privilege escalation, crash/DoS, information disclosure, config tampering), and a suggested fix if you have one.

| Action | Target (policy) |
|--------|-----------------|
| Acknowledge report | 48 hours |
| Initial assessment | 7 days |
| Patch release | 30 days (critical: 7 days) |

These targets are a best-effort policy for a single-maintainer project, not a contractual SLA.

### Supported versions

| Version | Security updates |
|---------|------------------|
| 1.0.x | ✅ |
| < 1.0 | ❌ |

---

## Privilege model

CachyDPI requires exactly **two** Linux capabilities and nothing else (`src/privileges.rs`):

| Capability | Why |
|------------|-----|
| `CAP_NET_ADMIN` | NFQUEUE interception and nftables rule management |
| `CAP_NET_RAW` | Raw socket for injecting fragments / fake packets |

At startup the daemon **verifies** these are present (`check_capabilities`) and otherwise exits with guidance (`setcap cap_net_admin,cap_net_raw=eip cachydpi`). After it has installed the nftables rules and opened the queues, it reduces privilege:

| Situation | Behaviour (`drop_root`) |
|-----------|-------------------------|
| Already running as the `cachydpi` user | Drop every capability except `NET_ADMIN` + `NET_RAW` |
| Running as root under `NoNewPrivileges` (systemd) | `setuid` is blocked, so it drops capabilities only and logs a notice |
| Running as root manually, `cachydpi` user exists | `PR_SET_KEEPCAPS` → `setgroups([])` → `setgid` → `setuid(cachydpi)` → restore only the two caps → clear keepcaps → assert no longer root |
| Running as root, `cachydpi` user missing | Continue as root with only the two caps, log a warning |

**If dropping unnecessary capabilities fails, the process aborts** — it will not continue with excess privilege (`main.rs`: the `drop_unnecessary_caps()` error is fatal).

Under systemd this is reinforced from outside the process (`systemd/cachydpi.service`):

```ini
User=cachydpi
Group=cachydpi
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=yes
```

The `cachydpi` user is a **system user with no login shell** (`/usr/bin/nologin`), created from `systemd/cachydpi.sysusers` with an **auto-allocated UID** (the sysusers line is `u cachydpi - …`, i.e. the UID is not hard-coded).

---

## systemd hardening

The unit applies the directives below. To see the resulting score on your system, run `systemd-analyze security cachydpi`.

| Area | Directives |
|------|------------|
| Filesystem | `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`, `ReadOnlyPaths=/etc/cachydpi` |
| Kernel | `ProtectKernelTunables=yes`, `ProtectKernelModules=yes`, `ProtectKernelLogs=yes`, `ProtectControlGroups=yes`, `ProtectClock=yes`, `ProtectHostname=yes` |
| Process | `NoNewPrivileges=yes`, `RestrictSUIDSGID=yes`, `RestrictNamespaces=yes`, `LockPersonality=yes`, `RestrictRealtime=yes`, `MemoryDenyWriteExecute=yes`, `SystemCallArchitectures=native` |
| Network | `RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX` (AF_UNIX is needed for the metrics socket; AF_NETLINK for nftables/nfqueue) |
| Runtime dir | `RuntimeDirectory=cachydpi`, `RuntimeDirectoryMode=0755` → `/run/cachydpi/` |

---

## Input validation

### Domain-list path restriction (`is_safe_domain_path`, `src/config.rs`)

Blacklist/whitelist file paths supplied via config or CLI are constrained before being read by the daemon:

1. The **literal** path must start with `/etc/cachydpi` or `/usr/share/cachydpi` (rejects `..` in the path itself).
2. If the file exists, it is **canonicalized** and the resolved path must still start with an allowed prefix (defeats symlinks pointing outside the allowed directories).
3. If it does not exist yet, the literal-prefix check stands.

A rejected path is logged and skipped, not loaded. This stops a malicious or mistaken config from making the root-capable daemon read arbitrary files (e.g. `/etc/shadow`) through the domain loader.

> **Scope note:** this guard lives in the daemon's loader. The interactive `cachydpi settings` command, which reads/counts the configured blacklist for its summary, does not currently re-apply this check — relevant only because `settings` is run by an admin (typically via `sudo`) against a root-owned config. Hardening `settings` to reuse `is_safe_domain_path` is a tracked improvement.

### Argument and packet bounds

- `queue_num` is validated as `0..=65534` so the inbound queue (`queue_num + 1`) cannot overflow; `mode` is validated as `1..=7` (`src/cli.rs`).
- Packet parsers (IP/TCP/TLS/HTTP) bound-check lengths and offsets before indexing; checksum helpers return early on undersized input. Rust's memory safety covers the rest.

---

## Memory safety

The codebase is safe Rust except for narrowly scoped `unsafe` needed for C FFI and syscalls:

| Location | Purpose |
|----------|---------|
| `src/nfqueue/` | FFI to `libnetfilter_queue` (`nfq_*`) — return values checked, null guards |
| `src/privileges.rs` | `prctl` (keepcaps, `PR_SET_NAME`, `NoNewPrivileges` probe), `setuid`/`setgid` |
| `src/rawsocket.rs` / `src/strategies/` | raw packet send; socket created via the safe `socket2` crate and marked `SO_MARK` |

The metrics server and the `cachydpi-monitor` TUI contain no `unsafe` and need no elevated privileges. The release profile compiles with `panic = "abort"` (`Cargo.toml`), removing unwinding machinery.

---

## Crash safety

- **Panic hook** (installed in `main.rs` before any network setup): on panic it prints the message and runs `nft delete table ip cachydpi` (and `ip6` when IPv6 is enabled), then — because the build uses `panic = "abort"` — the process aborts. This keeps a crash from leaving stale queue rules behind.
- **`bypass` flag on every nftables rule** (`queue num … bypass`): if the daemon is not running (crash, stop, restart), packets bypass the queue instead of being dropped. A daemon failure does **not** black-hole traffic.
- **Graceful signals**: `SIGTERM`/`SIGINT`/`SIGHUP` are handled on a dedicated thread (not in an async-signal handler); rules are removed and queues closed on exit.
- **Restart limits** (systemd): `Restart=on-failure`, `RestartSec=5`, `StartLimitBurst=5`, `StartLimitIntervalSec=60` stop crash loops.

---

## Network self-isolation

- **Loop prevention**: injected packets carry `SO_MARK = 0xCACD` (`src/rawsocket.rs`), and the nftables rules begin with `meta mark 0xcacd accept`, so CachyDPI never re-queues its own injected packets.
- **Table isolation**: all rules live in the dedicated `ip cachydpi` / `ip6 cachydpi` tables. Cleanup deletes only those tables; existing firewall rules are untouched.

---

## Metrics socket

| Property | Value |
|----------|-------|
| Path | `/run/cachydpi/metrics.sock` (fallback `/tmp/cachydpi-metrics.sock`) |
| Protocol | JSON over a Unix stream socket |
| Direction | One-way, daemon → monitor (read-only) |
| Permissions | `0666` |
| Exposed | aggregate counters (packets processed, fragments sent, passive drops), timestamps, PID, process CPU/RAM |
| **Not** exposed | packet contents, IP addresses, domain names, config values |

There is no control channel: the monitor can only read counters, never command the daemon. The directory is created by `RuntimeDirectory=cachydpi` and the socket is removed on shutdown / overwritten on restart.

---

## Build security

```toml
[profile.release]
opt-level = 3
lto = "fat"
codegen-units = 1
strip = true        # no debug symbols in the release binary
panic = "abort"     # no unwinding machinery
```

Dependencies are a small set of widely used crates (`clap`, `serde`/`toml`, `serde_json`, `tracing` + `tracing-journald`, `nix`, `libc`, `caps`, `socket2`, `anyhow`/`thiserror`, `signal-hook`, and optional `ratatui`/`crossterm` for the monitor). There is no async runtime and no network-client/TLS crate. CI runs `cargo audit` on every push (`.github/workflows/ci.yml`); run it yourself before building from source.

---

## Verifying release authenticity (SSH-signed)

CachyDPI's git commits and release tags are signed with the maintainer's **SSH** signing key (`id_ed25519_github`) — the project does **not** use GPG. Verify with git's SSH-signature support:

```bash
# Add the maintainer's published SSH signing key, mapped to their commit email:
echo '87727485+abel0x@users.noreply.github.com namespaces="git" ssh-ed25519 AAAA...PUBLICKEY...' \
  >> ~/.config/git/allowed_signers
git config gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers

git verify-tag v1.0.0          # verify a signed release tag
git log --show-signature -1    # verify the tip commit
```

Fetch the exact public key from `https://github.com/abel0x.keys` and confirm it through an independent channel before trusting it. (Source-tarball distributions such as the AUR package do not currently ship a separate detached release signature; trust is anchored on the signed git tag.)

---

## Threat model

### In scope (mitigated)

| Threat | Mitigation |
|--------|-----------|
| Privilege escalation from the daemon | Non-root user, two-cap bounding set, `NoNewPrivileges`, fatal-on-failed-cap-drop |
| Malicious config → arbitrary file read | `is_safe_domain_path` restricts + canonicalizes domain-list paths |
| Malformed packet → crash / overflow | Bounds-checked parsers, Rust memory safety |
| Daemon crash → network black-hole | nftables `bypass` flag + panic-hook cleanup |
| Resource exhaustion | `MemoryMax=64M`, `CPUQuota=25%`, restart limits |
| Info disclosure via metrics socket | Read-only counters only; no packet/IP/domain data |
| Self-interception loop of injected packets | `SO_MARK 0xCACD` + `meta mark` accept rule |
| Code injection via W+X memory | `MemoryDenyWriteExecute=yes` |
| Privilege gain via SUID/exec/namespaces | `NoNewPrivileges`, `RestrictSUIDSGID`, `RestrictNamespaces` |

### Out of scope

- **Traffic confidentiality / anonymity** — CachyDPI does not encrypt; use a VPN or Tor.
- **Server-side and IP-level blocking, DNS poisoning** — outside what client-side packet manipulation can address (see README → Limitations); configure DNS-over-TLS separately.
- **Kernel compromise** — no userspace hardening helps if the kernel is owned.
- **Physical access** to the host.
- **Supply-chain attacks on dependencies** — partially mitigated by `cargo audit`; verify with `cargo vet` if needed.

---

## Deployment hardening checklist

- [ ] Install via the AUR package or `install.sh` so the `cachydpi` system user and runtime dirs are created (`systemd-sysusers` / `systemd-tmpfiles`).
- [ ] Keep config/blacklist root-owned and `0644`; keep `/etc/cachydpi` `0755 root`.
- [ ] Run as the systemd service (all hardening applies): `systemctl enable --now cachydpi`.
- [ ] If running the binary manually, prefer `setcap cap_net_admin,cap_net_raw=eip` over running as root.
- [ ] Configure DNS-over-TLS (README → DNS security).
- [ ] `cargo audit` before building from source; `systemd-analyze security cachydpi` after install.

---

## Acknowledgments

Reporters of valid vulnerabilities are credited in release notes, with their permission.
