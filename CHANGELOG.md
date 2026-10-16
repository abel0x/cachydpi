# Changelog

All notable changes to CachyDPI are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.9.0] — 2026-10-15

### Added

- **`[strategies] fake_ttl_max`** (default 4): the highest TTL auto-detection
  may give a fake packet. A fixed `fake_packet_ttl` is not limited by it.
  Raise it only if your DPI sits further out and blocked sites stay
  blocked. Existing configs get the default without changes.

### Fixed

- **Fake packets no longer reset connections to unblocked sites.**
  Auto-TTL measured the path back from the server, which can be much
  longer than the path there; fakes timed from it reached the server.
  On such a network mode 4 reset about 1 in 9 requests to unblocked
  sites, and nearly every request to those behind Akamai and Google
  edges. This affects mode 4 and mode 7's second level.
- **Mode 7 no longer escalates healthy sites.** It looked for the server's
  answer only in the first 4 reply packets, which the server's ACKs for a
  split ClientHello could fill. A teardown RST then counted as a block.

## [1.8.0] — 2026-x-x

### Added

- **Mode 7 also escalates on blocks that leave no forged packet:** a
  ClientHello the kernel has to send again because nothing answered it, and
  a reset that arrives before the server has sent anything, even when it
  copies the server's TTL. In mode 7 the server's first reply packets are
  queued so that an answer can be seen.

### Fixed

- **`cachydpi monitor` no longer shows DISCONNECTED for a running daemon it
  merely cannot read.** A monitor from an older release cannot parse newer
  metrics; it now shows VERSION MISMATCH with both versions.
- `make install` and `deploy.sh` install `cachydpi-monitor` along with the
  daemon, and `make uninstall` removes it. Before, the monitor was never
  updated, which is how an old one ended up reading a newer daemon.

## [1.7.0] — 2026-x-x

### Changed

- **`cachydpi detect` compares the site with a neutral name on the same
  address.** Only the difference is attributed to the network, reported as
  not blocked, reset by DPI, cut off, silently dropped, or blocked by address.
  Timing is judged against the measured round trip rather than a fixed 100 ms.
- It recommends mode 7 where interference was seen and mode 5 otherwise. It
  used to recommend mode 1 — no fragmentation at all — whenever it saw
  nothing, which a silently dropped site produces.
- The probe sends a ClientHello that servers answer with a ServerHello, the
  output includes the DNS state, and it notes when the service is running.
- The never-filled DPI TTL field and the ISP guess are removed.

## [1.6.0] — 2026-x-x

### Changed

- **Fake packets are timed from their own connection.** Their TTL now comes
  from the SYN-ACK of the connection they belong to, rather than from a table
  of up to 1024 server addresses. It is exact per connection, and no peer
  address is held in memory anywhere in the daemon any more.
- The `ttl_cache_entries` metric and the monitor's cache field are removed
  with the cache.

### Fixed

- Mode 4 (fake packets) measures its fake TTL. It never read SYN-ACKs, since
  that happened only with passive defence on, and always fell back to an
  estimate.

## [1.5.1] — 2026-x-x

### Fixed

- When the segment carrying the SNI of a multi-segment ClientHello was lost,
  its retransmission went out unsplit, showing the DPI the whole name. It is
  now split again.

## [1.5.0] — 2026-x-x

### Added

- **Mode 7 is implemented: adaptive escalation per site.** It was documented
  as not implemented and behaved as mode 5. It now starts each site on the
  techniques the config arms and, each time one of the site's connections
  draws interference that passive defence catches (a forged RST, TLS alert or
  redirect), moves that site up a level: (1) reordered three-way split,
  (2) plus fake packets, (3) plus the desync RST, then back to the configured
  techniques. Several forged packets on one connection count once. Levels are
  kept as hashed tags, not addresses, and reset on restart.
- Fake packets take their TTL from the connection's own SYN-ACK when auto-TTL
  is on and it was seen, which is exact for that server.
- An `escalations` metric, shown in the monitor.

### Removed

- The startup warning that mode 7 is not implemented.

## [1.4.0] — 2026-x-x

### Added

- **`cachydpi dns status | enable | disable`.** A site blocked by DNS resolves
  to the ISP's block page before any packet reaches CachyDPI, so no bypass
  mode helps with it. `status` reports whether lookups are encrypted. `enable`
  turns on strict DNS-over-TLS through systemd-resolved with the bundled
  servers: it first checks they answer on port 853 and changes nothing if
  none do, then rolls back if names stop resolving, so it cannot leave the
  machine without DNS. `disable` removes only the drop-in `enable` installed.
- The daemon warns at startup when DNS is not encrypted, and `cachydpi status`
  shows the DNS state.

## [1.3.1] — 2026-x-x

### Fixed

- **A config carried over from 1.0.x starts again.** The config shipped with
  1.0.x contains an empty `whitelist = []` line, and since 1.2.0 that alone
  stopped the daemon from starting. An empty list is now ignored; the old
  spelling is refused only where it would change behaviour — `mode =
  "whitelist"`, `whitelist_file`, or a `whitelist` list with entries.

## [1.3.0] — 2026-x-x

The daemon now handles only the packets it can act on, and passive defence
stops mistaking a server's own error responses for injected ones.

### Changed

- **Only the start of each connection is queued.** Outbound HTTPS is queued
  for its first 10 packets, enough for the ClientHello; small inbound TLS
  records for the first 16 replies; inbound HTTP only when 1000 bytes or
  shorter. Previously every upload, every plain-HTTP download and every QUIC
  packet went through the daemon to be accepted unchanged, paced by a process
  limited to a quarter of a CPU. These limits use conntrack packet counters,
  which nftables enables for the namespace when the rules are loaded.
- **QUIC is queued only when mode 6 has `quic_desync` on**, and then only its
  first packets.
- **The queue fails open.** If the daemon falls behind and the queue fills,
  packets pass through unmodified instead of being dropped.

### Fixed

- A server's own fatal TLS alert (`handshake_failure`, `protocol_version`,
  `internal_error`) is no longer dropped as forged, so a failed handshake
  fails at once instead of timing out.
- Injected TLS alerts and HTTP redirects are recognised by hop count, like
  RSTs since 1.1.1: one arriving from nearer than the server's SYN-ACK is
  dropped whatever it contains. A block-page redirect to a bare address is now
  caught, and a real redirect whose URL contains a word like "restricted" is
  no longer dropped.

## [1.2.0] — 2026-x-x

Bypass now reaches the browsers that most need it, and the `whitelist`
spelling deprecated in 1.1.0 is gone.

### Breaking changes

- **`whitelist` is refused.** `mode = "whitelist"`, `whitelist_file`,
  `whitelist` and `--whitelist` no longer load. A config still using them stops
  the daemon with a message naming each replacement: `mode = "exempt"`,
  `exempt_file`, `exempt`, `--exempt`. Check with `sudo cachydpi --dry-run`
  before restarting.

### Added

- **A ClientHello spanning several TCP segments is split where its SNI is.**
  With a post-quantum key share a ClientHello is about 1.7 KB, more than one
  segment, and browsers that shuffle extension order put the SNI after the key
  share about half the time. Neither segment was recognised and the connection
  got no bypass at all. The extension walk now continues into the following
  segments, finds the name, and splits that segment around it, domain filter
  included. Fakes are not sent for it, since the start of the ClientHello has
  already gone out. The state kept between segments is a fixed table of hashed
  tags and sequence numbers, with no addresses.

## [1.1.1] — 2026-x-x

A corrective release. Mode 6 was breaking the TLS connections it touched, and
passive defence — on in the default mode — was dropping servers' own resets.

### Fixed

- **Mode 6 no longer breaks TLS connections.** It re-framed the ClientHello as
  two TLS records, which adds five bytes the kernel never sent; since neither
  the later segments nor the server's ACKs pass through the queue, the
  sequence numbers could never be brought back in line and the connection
  stalled. It now sends the ClientHello out of order, byte-for-byte as the
  kernel wrote it.
- **A server's own RST is no longer dropped as forged.** A Linux RST has
  window 0 and no options — every sign the shape check looked for — so refused
  connections hung until a connect timeout and real resets never arrived. An
  RST is now judged against the TTL of its connection's SYN-ACK: one arriving
  from a nearer hop than the server is injected, one at the server's hop count
  is passed, and one answering a SYN that got no SYN-ACK is a refusal and is
  passed. The shape check remains only for connections with no record. The
  per-connection record is a fixed 32 KiB table that holds hashes, not
  addresses.
- IPv6 fake packets keep the real packet's flow label. The IPv4 total length
  was written over its low 16 bits, setting every fake apart from the
  connection it claims to belong to.
- `quic_desync = false` is honoured. Mode 6 fragmented QUIC regardless, while
  the startup report listed QUIC desync as off.
- The systemd crash-loop limit (`StartLimitBurst`, `StartLimitIntervalSec`)
  is in `[Unit]`, where systemd reads it. Under `[Service]` it was ignored and
  a failing daemon was restarted indefinitely.

### Changed

- **Mode 6 users who relied on QUIC desync must now set `quic_desync = true`.**
  It is off by default, as the shipped config always said.
- Mode 7 no longer desyncs QUIC, so it behaves exactly like mode 5 as
  documented.
- Every script, the Makefile, the pacman hooks, the shipped config and the
  systemd files carry the SPDX licence identifier and copyright line.

## [1.1.0] — 2026-08-14

This release tightens how the domain filter is configured. **It can stop an
existing installation from starting**, because `/etc/cachydpi/config.toml` is a
`backup=` file and is deliberately never replaced by an upgrade — a config
written for 1.0.x is left exactly as it was. Read *Breaking changes* below
before restarting the service.

### Breaking changes

- **The `[domains]` section is now required and must state a `mode`.** A config
  without it is rejected instead of being silently completed from built-in
  defaults. A file truncated part-way through is still valid TOML that simply
  loses its later sections, so a defaulted `[domains]` meant an interrupted
  write could quietly swap the operator's domain filter for a different one.
- **`whitelist` is renamed to `exempt`** — `mode = "exempt"`, `exempt_file`,
  `exempt`, and `--exempt`. It always meant "leave these domains alone and
  bypass everything else", which is the opposite of what "whitelist" reads as.
  The old spelling still loads and prints a deprecation warning naming its
  removal; **it is removed in 1.2.0**.
- **`mode = "exempt"` with an empty list is refused.** Exempting nothing means
  bypassing every site, which is what `mode = "none"` is for; reaching the
  widest bypass now requires asking for it.
- **A config that exists but cannot be honoured is fatal.** Unreadable,
  malformed, empty and dangling-symlink configs stop the daemon instead of
  falling back to defaults. Only a genuinely absent file uses defaults.

#### Recovery

If the service does not start after upgrading:

```bash
journalctl -u cachydpi -e --no-pager        # names the file and the problem
sudo cachydpi --dry-run                     # verify a config without starting

# Compare against the shipped reference, or start from it:
diff /etc/cachydpi/config.toml /usr/share/doc/cachydpi/config.toml
sudo cp /etc/cachydpi/config.toml{,.bak}
sudo cp /usr/share/doc/cachydpi/config.toml /etc/cachydpi/config.toml
```

A minimal valid `[domains]` section:

```toml
[domains]
mode = "blacklist"   # or "exempt" (with a non-empty list), or "none"
```

Configs merged from a `.pacnew` need the same section; check for one with
`ls /etc/cachydpi/*.pacnew`.

### Added

- `[logging] log_identifying_fields` (default off). Domains and peer
  addresses are rendered as `<redacted>` in every log line unless it is on,
  whatever the log level.
- Metrics: `forged_rst_sources` (distinct peers that sent a forged RST,
  estimated with a HyperLogLog so no address is kept), `forged_rst_per_tls_split`,
  and `sni_parsed` / `sni_syntax_invalid` (whether extracted SNIs are hostname
  syntax). `domains_loaded` is `null` when no list is in use, so `0` always
  means an empty list.
- The daemon logs at startup which techniques the mode and config actually
  arm, and names the setting responsible for each one that is off.
- The second TLS split point is chosen at random within the SNI, so the
  middle fragment's length is no longer a fixed function of the name.

### Security

- The built-in default domain mode is now `blacklist` (bypasses nothing without
  a list) instead of `none` (bypassed every site). `none` remains available but
  is only ever reached by asking for it explicitly.
- Replacement packets are never reported as sent when nothing was sent, so an
  intercepted packet is no longer dropped without its replacement reaching the
  wire. A partially delivered set of fragments no longer authorises the drop
  either.
- The privilege drop raises `CAP_NET_ADMIN` into the ambient set, so the `nft`
  child process actually receives it, and the result is verified rather than
  assumed. `CAP_NET_RAW` is given up after startup.
- `config.toml` is written atomically by `cachydpi settings`, so an interrupted
  write cannot leave it truncated.
- IPv4 packets with a malformed IHL no longer panic the TTL rewrite.
- HTTP requests carrying a binary body now have their `Host` header fragmented;
  previously they were skipped.

### Fixed

- `deploy.sh` and `make install` no longer overwrite an existing
  `/etc/cachydpi/config.toml`.
- nftables teardown removes both the `ip` and `ip6` tables regardless of the
  `ipv6` setting, so a table left by an earlier IPv6 run no longer survives.
  A partial teardown reports which family is still installed.
- A system without IPv6 (no `AF_INET6`, or `net.ipv6.conf.all.disable_ipv6=1`)
  runs IPv4-only instead of refusing to start.
- `queue_num` from the config file is bounds-checked like the CLI flag.
- The AUR package hooks (`post_install`, `post_upgrade`, `pre_remove`) are wired
  up through an `.install` file; they were previously defined in the PKGBUILD,
  where pacman never ran them.
- Packet contents are no longer written to the log. Each "strategy applied"
  line rendered every fragment as a byte array, putting ClientHellos and their
  SNI into the journal.
- Under systemd each message is logged once; it was recorded both as a
  structured journal entry and as flat text.
- The `whitelist` deprecation notice goes through the logger, with a level and
  timestamp, instead of straight to the process output.
- Capabilities are dropped once at startup; the journal showed the drop twice.
- The IPv6-disabled check ignores loopback, whose `disable_ipv6` is almost
  always 0 and outvoted every real interface.
- A privilege-drop rehearsal killed by a signal is treated as inconclusive
  rather than as proof that `setuid` cannot work, which aborted startup.

## [1.0.0] — 2026-04-11

Initial release.
