# CachyDPI

**System-wide DPI bypass for Linux — a native [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) alternative.**

[![Version](https://img.shields.io/badge/version-1.9.0-blue)](CHANGELOG.md)
[![License: GPL-3.0-or-later](https://img.shields.io/badge/license-GPL--3.0--or--later-green)](LICENSE)
[![Rust 2024](https://img.shields.io/badge/rust-2024_edition-orange)](Cargo.toml)
[![Platform: Linux](https://img.shields.io/badge/platform-Linux-lightgrey)](#requirements)

- **Whole system, no proxy.** Every application is covered; nothing to configure per browser or per app.
- **Seven modes**, from passive defence alone to an adaptive mode that adds techniques per destination when it sees the DPI interfere.
- **Fails open.** If the daemon stops or falls behind, traffic passes through unmodified instead of dropping.
- **Hardened service.** A dedicated non-root user that keeps only `CAP_NET_ADMIN`; addresses are redacted from its logs and kept in its tables only as hashed tags.
- **Measured, not guessed.** 1.9.0 was checked mode by mode against 100 sites; the [results](#field-results) are below.

CachyDPI is a Rust daemon that intercepts outgoing TCP/UDP traffic through **nftables + NFQUEUE** and applies packet-manipulation techniques (fragmentation, fake-packet injection, passive-defense drops) to defeat the Deep Packet Inspection (DPI) systems that some ISPs use for censorship. It was developed and tested primarily against **Turkish ISP DPI**, but the techniques apply to any DPI that inspects HTTP `Host` headers or TLS SNI without full stream reassembly.

It runs as a hardened `systemd` service under a dedicated, non-root user, granted only `CAP_NET_ADMIN` and `CAP_NET_RAW` — and it gives up `CAP_NET_RAW` once its sockets are open.

> **Scope, honestly stated.** CachyDPI is a *client-side* tool. It works against passive DPI (forged RST / redirect / TLS-alert injection) and SNI/Host-based blocking where the DPI does not reassemble the TCP stream. It **cannot** defeat inline DPI that fully reassembles streams, server-side RST injection, or IP-level blocking. DNS poisoning is outside what packet edits can fix; `sudo cachydpi dns enable` turns on encrypted DNS for it (see [DNS security](#dns-security)). See [Limitations](#limitations).

---

## How it works

```
application ──▶ kernel (nftables OUTPUT) ──▶ NFQUEUE 200 ──▶ CachyDPI ──▶ raw socket ──▶ network
                                                              │  (inspect / fragment / inject)
incoming forged RST/redirect/TLS-alert ◀── NFQUEUE 201 ◀── kernel (nftables INPUT)
```

CachyDPI installs an nftables table named `cachydpi` that queues outbound HTTP (80/8080) requests, TCP SYNs, and the first packets of each HTTPS (443) connection — enough to carry the ClientHello — to NFQUEUE `queue_num` (default **200**). QUIC (UDP 443) is queued only when mode 6 has `quic_desync` on, and then only the first packets. Selected inbound packets (RST, SYN-ACK, short HTTP responses, small TLS records early in a connection) go to `queue_num + 1` (default **201**) for passive-DPI detection. Everything else stays in the kernel, so bulk transfers never pass through the daemon. All rules use the `bypass` flag, and the queue is set to fail open, so if the daemon is not running or falls behind, packets pass through unmodified rather than being dropped.

## Requirements

- Linux kernel with `nfnetlink_queue` support (`modprobe nfnetlink_queue` if not auto-loaded)
- `nftables`
- Native libraries: `libnetfilter_queue` (≥ 1.0), `libnfnetlink`, `libmnl`
- To build from source: Rust **1.85+** (the crate uses edition 2024; no exact MSRV is pinned), `cargo`, `pkg-config`
- `CAP_NET_ADMIN` + `CAP_NET_RAW` at runtime (i.e. root, the systemd unit, or `setcap` on the binary)

## Installation

### Arch Linux / CachyOS (AUR)

```bash
yay -S cachydpi      # or: paru -S cachydpi
```

The AUR package installs both binaries (`cachydpi`, `cachydpi-monitor`), the systemd service, the default config and blacklist, and creates the `cachydpi` system user via `sysusers.d`/`tmpfiles.d`.

### From source — one-command installer

`install.sh` installs build dependencies (pacman or apt), builds with release flags, installs the binary/config/systemd units, creates the system user, and offers to start the service:

```bash
git clone https://github.com/abel0x/cachydpi.git
cd cachydpi
sudo ./install.sh
```

### From source — manual

```bash
# Build dependencies — Arch / CachyOS:
sudo pacman -S --needed rust cargo pkg-config libnetfilter_queue libnfnetlink libmnl nftables base-devel
# Build dependencies — Debian / Ubuntu:
sudo apt install rustc cargo pkg-config libnetfilter-queue-dev libnfnetlink-dev libmnl-dev nftables build-essential

git clone https://github.com/abel0x/cachydpi.git
cd cachydpi
make release
sudo make install
```

`make install` installs the `cachydpi` binary, the default config/blacklist, and the systemd unit files, but does **not** create the `cachydpi` user. Create it (and the runtime dirs) before starting the service:

```bash
sudo systemd-sysusers /usr/lib/sysusers.d/cachydpi.conf
sudo systemd-tmpfiles --create /usr/lib/tmpfiles.d/cachydpi.conf
sudo systemctl daemon-reload
```

`make install` installs the `cachydpi-monitor` TUI next to the daemon whenever it was built, which it is by default. Keep the two from the same build: the metrics format changes between releases, and a monitor older than the daemon shows **VERSION MISMATCH**. Build without the monitor entirely with `cargo build --release --no-default-features`.

## nftables rules

By default (`manage_rules = true`) the daemon installs and removes its own nftables rules automatically on start/stop, and a panic hook removes them on a crash. You normally do **not** manage rules by hand. If you set `manage_rules = false` or pass `--no-rules`, manage them explicitly:

```bash
sudo cachydpi install-rules     # create the cachydpi nftables table
sudo cachydpi remove-rules      # delete it
sudo nft list table ip cachydpi # inspect the installed rules
```

CachyDPI only ever touches its own table (`ip cachydpi` and, with IPv6, `ip6 cachydpi`); it does not modify other firewall rules.

## Usage

### As a systemd service (recommended)

```bash
sudo systemctl enable --now cachydpi   # start at boot and now
sudo systemctl status cachydpi
journalctl -u cachydpi -f              # follow logs
sudo cachydpi restart                  # restart via systemctl
```

The unit runs `cachydpi --foreground` as `User=cachydpi` with `NoNewPrivileges` and `AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW`. See [SECURITY.md](SECURITY.md) for the full hardening set.

### Foreground / manual

```bash
sudo cachydpi -m 5 --foreground         # all active techniques (default)
sudo cachydpi -m 1 --foreground         # passive defense only
sudo cachydpi -m 5 -vvv --foreground    # trace logging
sudo cachydpi --dry-run                 # print resolved config and exit
```

If you prefer not to run as root, grant the two capabilities to the binary:

```bash
sudo setcap cap_net_admin,cap_net_raw=eip /usr/bin/cachydpi
```

### Real-time monitor

```bash
cachydpi monitor        # no root required
```

The TUI connects to the daemon's Unix socket (`/run/cachydpi/metrics.sock`, fallback `/tmp/cachydpi-metrics.sock`) and shows packet counters, strategy hits, passive-defense drops, and process CPU/RAM. The socket is read-only (daemon → monitor); the monitor cannot control the daemon.

### Subcommands

| Command | Description |
|---------|-------------|
| `settings` | Interactive domain-filter mode selector (`list` / `all`), writes the choice to the config |
| `monitor` | Real-time TUI dashboard (no root) |
| `status` | Show current status |
| `detect <domain>` | Probe the target (default `www.youtube.com`) to fingerprint the ISP's DPI; **makes real network connections** |
| `dns status` / `dns enable` / `dns disable` | Check or turn on encrypted DNS (see [DNS security](#dns-security)) |
| `restart` | `systemctl restart cachydpi` |
| `install-rules` / `remove-rules` | Manually add/remove the nftables table |

#### Domain filter settings

```bash
sudo cachydpi settings
```

An interactive menu writes the `[domains] mode` line into the config (preserving comments and other keys) and offers to restart the service:

- **list** — bypass applies only to domains in the configured blacklist file (`blacklist_file`, default `/etc/cachydpi/blacklist.txt`, **4935** entries shipped)
- **all** — no domain filter; bypass applies to every site

## Bypass modes

`-m <N>` (or `[general] mode`) selects the strategy. The mode is validated as `1..=7`.

| Mode | Behaviour | When to use |
|:----:|-----------|-------------|
| 1 | Passive defense: drop forged RST / 302 redirect / TLS-alert packets | ISPs that only inject forged packets |
| 2 | HTTP request fragmentation (split at the `Host` header) | Plain-HTTP sites |
| 3 | TLS ClientHello fragmentation at the SNI | HTTPS with simple SNI inspection |
| 4 | Fake-packet injection (wrong TTL, capped by `fake_ttl_max`) | DPI that reassembles split packets |
| **5** | **All active techniques combined (default)** | **Start here** |
| 6 | Aggressive: all techniques + out-of-order delivery, and QUIC desync when `quic_desync = true` | Stubborn DPI (see warning) |
| 7 | Adaptive: mode 5, adding techniques per site where the DPI is seen interfering | Mixed sites, unknown DPI |

> **Mode 7** starts each site on the mode 5 techniques as configured. Each connection to a site that the DPI is seen interfering with — a forged RST, TLS alert or redirect that passive defence drops, a ClientHello the kernel has to send again because nothing answered it, or a reset that arrives before the server has said anything — moves that site up a level: (1) reordered three-way split, (2) plus fake packets, timed from the connection's own SYN-ACK, (3) plus the desync RST, then back to the configured techniques. Several forged packets on one connection count once. It learns from what it sees and does no active probing. Levels are kept per destination address, as hashed tags rather than the addresses themselves, and reset when the daemon restarts. A site served from several addresses (a CDN, for example) learns its level on each address separately.

### Fake-packet TTL

A fake packet has to live long enough to reach the DPI and die before it reaches the server; one that arrives is taken as real data, and the server resets the connection. With `auto_ttl = true` the TTL comes from the hop count of each connection's SYN-ACK. That count measures the path *back*, and on some networks it is several times longer than the path there: in testing, servers 5 hops away answered over 15. A TTL timed from the return path then reached the servers and broke sites that were never blocked.

`fake_ttl_max` (default **4**) caps every auto-detected value. If blocked sites stay blocked with fakes on, your DPI may sit further out: raise it one step at a time. If unblocked sites start failing, lower it. A fixed `fake_packet_ttl` is used as given and is not capped.

> **Mode 6 warning.** Mode 6 can send out-of-order segments and (if `desync_first` is enabled) fake RST packets. On ISPs with aggressive DPI this can cause the DPI to treat the fake RST as a real close and drop the whole connection. Prefer mode 5 unless you have a specific reason.

## Field results

Every mode of 1.9.0, tested on 2026-10-15 from a Turkish residential connection against 100 varied sites (social media, Turkish and international news, shopping, games, developer tools, cloud and education). Each site was requested twice over HTTPS with a normal ClientHello, twice with a small one (X25519 only, as clients without post-quantum key exchange send), and twice over plain HTTP: 600 requests per mode. Default config otherwise (`fake_packet_enabled = false`, `multi_fragment` and `disorder` on).

| Mode | Answered | HTTPS | HTTPS, small ClientHello | HTTP |
|:----:|:--------:|:-----:|:------------------------:|:----:|
| off | 585 / 600 | 195 | 196 | 194 |
| 1 | 584 | 195 | 195 | 194 |
| 2 | 586 | 196 | 196 | 194 |
| 3 | 582 | 193 | 195 | 194 |
| **4** | **597** | **199** | **200** | **198** |
| 5 | 590 | 200 | 196 | 194 |
| 6 | 586 | 197 | 195 | 194 |
| 7 | 588 | 199 | 195 | 194 |

Two of the 100 sites were blocked on that network. What the numbers say about it:

- **Its DPI reassembles split packets sent in order**, so modes 2 and 3 alone change nothing. Modes 5–7 mostly open the blocked sites for browsers by sending the split ClientHello out of order, but not for small ClientHellos or plain HTTP.
- **Fake packets open them for every client**, including small ClientHellos and plain HTTP; mode 4 does this without breaking any other site in the list. Before 1.9.0, its auto-detected TTL reset about 1 in 9 requests to unblocked sites, and nearly every request to those behind Akamai and Google edges (see [Fake-packet TTL](#fake-packet-ttl)).
- The remaining failures are timeouts on two sites that also time out with the daemon off, or under parallel load.

One network on one day is not a guarantee. If the default does not work for you, try the modes in the order 5, 7, 4.

## Configuration

Config file: `/etc/cachydpi/config.toml`. **Precedence: explicit CLI flag > `config.toml` > built-in default.** An unset CLI flag never clobbers a `config.toml` value.

```toml
[general]
queue_num    = 200      # NFQUEUE number (inbound uses queue_num + 1)
ipv6         = true     # also manage the ip6 table
manage_rules = true     # auto-install/remove nftables rules
mode         = 5        # bypass mode 1-7 (see table above)

[strategies]
passive_dpi         = true   # drop forged RST / redirect / TLS-alert
tcp_window_size     = 0      # SYN window override (0 = disabled)
http_split_position = 0      # 0 = auto (Host header)
tls_split_position  = 0      # 0 = auto (split at SNI)
fake_packet_enabled = false  # decoy packets — off by default (can trigger aggressive DPI)
fake_packet_ttl     = 0      # 0 = auto-detect from SYN-ACK
auto_ttl            = true
fake_ttl_max        = 4      # cap on auto-detected fake TTL — raise only if your DPI sits further out
fake_wrong_checksum = false
fake_wrong_seq      = false
quic_desync         = false  # QUIC fragmentation on UDP 443 (IPv4 only)
desync_first        = false  # fake RST + fake ClientHello before real data — off (breaks aggressive-DPI ISPs)
multi_fragment      = true   # split TLS ClientHello into 3 segments instead of 2
disorder            = true   # send fragments in reverse order

[domains]
mode           = "blacklist"                    # "none" | "blacklist" | "exempt"
blacklist_file = "/etc/cachydpi/blacklist.txt"
# exempt_file    = "/etc/cachydpi/exempt.txt"
# blacklist = ["youtube.com", "x.com"]          # inline entries are merged with the file
exempt         = []

[logging]
level    = "info"   # error | warn | info | debug | trace
journald = true
# file   = "/var/log/cachydpi/cachydpi.log"
```

### Domain filtering modes

Domain matching is by **exact domain or a true subdomain** (label-boundary), never by substring — e.g. with `example.com` listed, `api.example.com` matches but `myexample.com` does **not**.

- **`none`** — apply the bypass to every domain.
- **`blacklist`** — apply the bypass **only** to listed domains. This is the shipped default, paired with `blacklist.txt`.
- **`exempt`** — apply the bypass to **everything except** the listed domains. Must not be empty: an empty exemption list would bypass every site, which is what `none` is for. (Called `whitelist` before v1.1.0; that spelling is refused since v1.2.0.)

Domain-list file paths are restricted to `/etc/cachydpi/` and `/usr/share/cachydpi/` and are canonicalized to reject symlink/`..` escapes (see [SECURITY.md](SECURITY.md)).

### CLI options

| Option | Description |
|--------|-------------|
| `-m, --mode <1-7>` | Bypass mode (overrides config) |
| `-c, --config <file>` | Config path (default `/etc/cachydpi/config.toml`) |
| `-q, --queue-num <0-65534>` | NFQUEUE number (overrides config) |
| `--ipv6` / `--no-ipv6` | Force IPv6 on/off (mutually exclusive; unset → config decides) |
| `--set-ttl <N>` | Fixed fake-packet TTL (0 = auto) |
| `--auto-ttl` | Enable auto TTL detection |
| `-w, --window-size <N>` | TCP SYN window size (0 = disabled) |
| `--wrong-chksum` | Fake packets with wrong TCP checksum |
| `--wrong-seq` | Fake packets with wrong TCP sequence |
| `--http-split <N>` / `--tls-split <N>` | Split positions (0 = auto) |
| `--blacklist <file>` / `--exempt <file>` | Domain-list file (also sets the corresponding mode) |
| `--no-desync` / `--no-disorder` / `--no-multi-frag` | Disable the named desync technique |
| `-v` | Verbose: `-v` debug, `-vv`/`-vvv` trace |
| `--log-file <file>` | Log to a file instead of journald |
| `--no-rules` | Do not auto-manage nftables rules |
| `--foreground` | Run in the foreground |
| `--dry-run` | Print resolved config and exit |

## Release verification (SSH-signed)

CachyDPI's git commits and release tags are signed with the maintainer's **SSH** signing key, not GPG. To verify, add the maintainer's public key to an allowed-signers file and check the signature:

```bash
# 1. Save the maintainer's published SSH signing public key, mapped to their commit email:
echo '86494759+abel0x@users.noreply.github.com namespaces="git" ssh-ed25519 AAAA...PUBLICKEY...' \
  >> ~/.config/git/allowed_signers

# 2. Point git at it:
git config gpg.ssh.allowedSignersFile ~/.config/git/allowed_signers

# 3. Verify:
git verify-tag v1.9.0          # a release tag
git log --show-signature -1    # the tip commit
```

Obtain the exact public key from the maintainer's GitHub profile (`https://github.com/abel0x.keys`) and confirm it out of band before trusting it.

## Limitations

CachyDPI manipulates packets on the client only. That bounds what it can do.

**Effective against:** passive DPI that injects forged RST / HTTP-redirect / TLS-alert packets; SNI/Host-based blocking where the DPI inspects but does not reassemble the TCP stream; first-packet SNI inspection.

**Not effective against:**
- **Inline DPI with full TCP stream reassembly** — fragmentation is reassembled before inspection. Some DPI reassembles only segments that arrive in order; against those, `disorder` (on by default) and fake packets can still get through.
- **Server-side RST injection** — if the DPI resets the connection toward the server, the client cannot help.
- **IP-level blocking** — no packet edit reaches a blocked destination IP.
- **DNS poisoning** — packet edits cannot fix a wrong answer; turn on DNS-over-TLS with `sudo cachydpi dns enable` (below).

Field observations against Turkish ISPs (e.g. inline-blocked Cloudflare-fronted domains, IP-blocked sites) are documented in [`tests/reports/FAILURE_ANALYSIS.md`](tests/reports/FAILURE_ANALYSIS.md).

## DNS security

A site blocked by DNS resolves to the ISP's block page before any packet reaches CachyDPI, so no bypass mode helps with it. Encrypted DNS does. CachyDPI checks for it at startup and warns when lookups are not encrypted.

```bash
cachydpi dns status          # encrypted or not, and why
sudo cachydpi dns enable     # DNS-over-TLS via systemd-resolved
sudo cachydpi dns disable    # remove what enable installed
```

`enable` installs the bundled drop-in (`dns-over-tls.conf`: Cloudflare and Google, Quad9 fallback) as `/etc/systemd/resolved.conf.d/cachydpi-dns-over-tls.conf`. It uses the strict `DNSOverTLS=yes`, because opportunistic mode falls back to plaintext — the poisoned path. Strict mode with port 853 blocked would leave the machine without DNS, so `enable` first checks that the servers answer on 853 and changes nothing if none do, then restarts systemd-resolved and rolls back if names stop resolving. It requires `/etc/resolv.conf` to point at systemd-resolved (`127.0.0.53`), which is the default on CachyOS and Arch with systemd-resolved enabled.

## Troubleshooting

### The service refuses to start because of the config

CachyDPI will not start with a config file it cannot honour. Substituting
built-in defaults would silently swap your domain filter for a different one,
so a config that exists but is unreadable, malformed, empty or missing its
`[domains]` section is a hard error. The journal names the file and the
problem:

```bash
journalctl -u cachydpi -e --no-pager   # says which file and what is wrong
```

Recovery, in order of preference:

```bash
# 1. Restore the shipped config (your old one is kept as .bad):
sudo mv /etc/cachydpi/config.toml /etc/cachydpi/config.toml.bad
sudo cp /usr/share/doc/cachydpi/config.toml /etc/cachydpi/config.toml

# 2. Or start from built-in defaults by removing the file entirely.
#    Defaults are restrictive: blacklist mode with no list, so nothing is
#    bypassed until you configure it.
sudo mv /etc/cachydpi/config.toml /etc/cachydpi/config.toml.bad

# 3. After a package upgrade, merge your settings with the new version:
ls /etc/cachydpi/*.pacnew

sudo systemctl restart cachydpi
```

A minimal valid config needs the `[domains]` section with a `mode`:

```toml
[domains]
mode = "blacklist"   # or "exempt", or "none" to bypass every site
```

### Other problems

```bash
# Service won't start — read the journal, then run in the foreground with trace logging:
journalctl -u cachydpi -e --no-pager
sudo cachydpi -m 5 --foreground -vvv

# Inspect / clean nftables state:
sudo nft list table ip cachydpi
sudo cachydpi remove-rules

# Missing capabilities (manual / non-systemd run):
sudo setcap cap_net_admin,cap_net_raw=eip /usr/bin/cachydpi

# Kernel module not loaded:
sudo modprobe nfnetlink_queue

# Monitor can't connect — ensure the daemon is up and the socket exists:
sudo systemctl start cachydpi
ls -l /run/cachydpi/metrics.sock

# Site still blocked — check the blacklist, fingerprint the DPI, and rule out an IP block:
grep <domain> /etc/cachydpi/blacklist.txt
sudo cachydpi detect <domain>
```

## Changelog

What changed in each release, and why: **[CHANGELOG.md](CHANGELOG.md)**.

## Building and testing

```bash
make release            # optimized build (also: make debug, make build)
make test               # cargo test
make clippy             # lints
make fmt                # rustfmt --check
cargo test              # unit + integration tests (no root)
```

System-level test scripts (require root and a live network) live under `tests/` — see [`tests/README.md`](tests/README.md) and [`tests/TEST_PLAN.md`](tests/TEST_PLAN.md).

## Security

The daemon runs as the dedicated, non-root `cachydpi` user, granted only `CAP_NET_ADMIN` + `CAP_NET_RAW` and keeping just `CAP_NET_ADMIN` after startup, behind a systemd unit with extensive hardening (`NoNewPrivileges`, `ProtectSystem=strict`, `MemoryDenyWriteExecute`, capability bounding, namespace/syscall restrictions) and resource limits (`MemoryMax=64M`, `CPUQuota=25%`). It refuses to continue if it cannot drop excess capabilities. Verify the score yourself with `systemd-analyze security cachydpi`.

Full threat model, privilege model, and vulnerability-reporting process: **[SECURITY.md](SECURITY.md)**.

## Credits

- Inspired by [GoodbyeDPI](https://github.com/ValdikSS/GoodbyeDPI) (ValdikSS)
- Techniques informed by [zapret](https://github.com/bol-van/zapret) (bol-van)

## License

Copyright (C) 2026 abel0x <https://github.com/abel0x>

CachyDPI is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

Full license text: [GPL-3.0-or-later](LICENSE)
