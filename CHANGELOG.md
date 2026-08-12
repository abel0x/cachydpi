# Changelog

All notable changes to CachyDPI are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.0] — 2026-08-12

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

## [1.0.0] — 2026-04-11

Initial release.
