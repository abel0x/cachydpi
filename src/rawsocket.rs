// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/rawsocket.rs — Raw socket for injecting crafted packets
//
// Uses AF_INET/SOCK_RAW/IPPROTO_RAW to send hand-crafted IP packets
// directly to the network. This is used for:
// - Sending TCP fragments (when we drop the original and send our own)
// - Injecting fake packets with wrong TTL/checksum
// - QUIC desync fragments

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use anyhow::{Context, Result, bail};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tracing::{debug, trace, warn};

/// Maximum injected decoy packets per second (rate limiter).
/// Fragments carrying real user data are never rate-limited — dropping
/// one would kill the connection it belongs to.
const MAX_DECOYS_PER_SEC: u64 = 5000;

/// Fixed-window (1 second) rate limiter for decoy injection.
struct RateLimiter {
    max_per_window: u64,
    count: AtomicU64,
    window_start: Mutex<Instant>,
}

impl RateLimiter {
    fn new(max_per_window: u64) -> Self {
        RateLimiter {
            max_per_window,
            count: AtomicU64::new(0),
            window_start: Mutex::new(Instant::now()),
        }
    }

    /// Returns true if another packet fits in the current 1-second window.
    fn allow(&self) -> bool {
        let mut start = self.window_start.lock().unwrap();
        let now = Instant::now();
        if now.duration_since(*start).as_secs() >= 1 {
            // New window
            *start = now;
            self.count.store(1, Ordering::Relaxed);
            return true;
        }
        let count = self.count.fetch_add(1, Ordering::Relaxed);
        count < self.max_per_window
    }
}

/// Proof that a packet was actually handed to the kernel.
///
/// Dropping an intercepted packet is only legitimate once its replacement is on
/// the wire, so the send functions return this witness instead of `()`. The
/// field is private, which makes `Sent` unforgeable outside this module: a new
/// early return here cannot quietly answer `Ok(())` without sending, it has to
/// name [`Sent::confirmed`] and claim delivery out loud.
///
/// This is a witness by convention, not a linear type — Rust cannot prove the
/// syscall happened. It converts a silent mistake into a visible, greppable
/// assertion, which is as far as the type system takes us here.
///
/// Deliberately neither `Copy` nor `Clone`: consumers take it by value, so one
/// witness authorises exactly one drop. Deriving either would let a single
/// proof of delivery be reused for packets that were never replaced.
#[must_use = "a Sent witness exists to justify dropping the original packet"]
pub struct Sent(());

impl Sent {
    /// Call only where the kernel has just accepted the packet.
    pub fn confirmed() -> Self {
        Sent(())
    }
}

/// Root of the per-interface IPv6 sysctls.
const IPV6_CONF_ROOT: &str = "/proc/sys/net/ipv6/conf";

fn sysctl_flag_is_set(path: &std::path::Path) -> bool {
    matches!(std::fs::read_to_string(path), Ok(value) if value.trim() == "1")
}

/// Whether IPv6 is administratively switched off.
///
/// Takes the conf root rather than a single file so this can be tested: the
/// real sysctls are not writable from a user namespace.
///
/// `all/disable_ipv6` is the machine-wide switch, but IPv6 is just as often
/// turned off per interface, which leaves `all` reading 0 while nothing can
/// actually carry IPv6. So if every configured interface has it disabled, treat
/// IPv6 as off. Interfaces are the right unit here because CachyDPI is not
/// bound to one — it filters through nftables hooks, which see them all.
///
/// A missing tree is deliberately *not* read as "disabled": its absence alone
/// says nothing (an unusual /proc layout would switch IPv6 off for no reason),
/// and a kernel genuinely built without IPv6 — or booted with `ipv6.disable=1`,
/// where the module never loads — has no AF_INET6, which the socket probe in
/// [`ipv6_available`] catches first.
fn ipv6_disabled_by_sysctl(conf_root: &std::path::Path) -> bool {
    if sysctl_flag_is_set(&conf_root.join("all").join("disable_ipv6")) {
        return true;
    }

    let Ok(entries) = std::fs::read_dir(conf_root) else {
        return false;
    };

    let (mut interfaces, mut disabled) = (0usize, 0usize);
    for entry in entries.flatten() {
        // "all" is the machine-wide switch handled above; "default" only seeds
        // interfaces created later, so neither describes current capability.
        //
        // Loopback is excluded because it is not evidence either way: ::1 stays
        // up on a machine with IPv6 switched off everywhere else, and loopback
        // traffic never crosses a DPI. Counting it would leave the commonest
        // "IPv6 off" setup — every real interface disabled, lo untouched —
        // reading as available.
        let name = entry.file_name();
        if name == "all" || name == "default" || name == "lo" {
            continue;
        }
        let flag = entry.path().join("disable_ipv6");
        if !flag.exists() {
            continue;
        }
        interfaces += 1;
        if sysctl_flag_is_set(&flag) {
            disabled += 1;
        }
    }

    interfaces > 0 && interfaces == disabled
}

/// Whether this system can carry IPv6 at all.
///
/// This separates two failures that deserve different answers. A machine with
/// no IPv6 — kernel built without it, or administratively disabled — should
/// keep working as an IPv4-only bypass rather than refusing to start. A machine
/// that *has* IPv6 but where the injection socket cannot be opened is a genuine
/// startup failure, because ip6 rules would then queue traffic the daemon has
/// to abandon.
///
/// Note that the socket probe alone is not enough: with
/// `net.ipv6.conf.all.disable_ipv6=1` an AF_INET6 socket still opens happily,
/// so the sysctl has to be consulted too.
pub fn ipv6_available() -> bool {
    // A kernel built without IPv6 has no AF_INET6. Probe with UDP, which needs
    // no privileges, unlike the raw socket used for injection.
    if Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP)).is_err() {
        return false;
    }
    !ipv6_disabled_by_sysctl(std::path::Path::new(IPV6_CONF_ROOT))
}

/// A raw socket for sending crafted IP packets
pub struct RawSocket {
    /// IPv4 raw socket
    socket_v4: Socket,
    /// IPv6 raw socket (optional, created if IPv6 is enabled)
    socket_v6: Option<Socket>,
    /// Packet mark to set on injected packets (to avoid re-queueing)
    mark: u32,
    /// Rate limiter for decoy packets (real data is never limited)
    decoy_limiter: RateLimiter,
}

/// Default mark value for packets injected by CachyDPI.
/// Packets with this mark are excluded from NFQUEUE rules.
pub const CACHYDPI_MARK: u32 = 0xCACD;

impl RawSocket {
    /// Create a new raw socket pair for packet injection.
    ///
    /// Requires CAP_NET_RAW capability.
    pub fn new(ipv6: bool) -> Result<Self> {
        // IPv4 raw socket with IP_HDRINCL (we provide our own IP header)
        let socket_v4 = Socket::new(
            Domain::IPV4,
            Type::RAW,
            Some(Protocol::from(libc::IPPROTO_RAW)),
        )
        .context("failed to create IPv4 raw socket — need CAP_NET_RAW")?;

        // IP_HDRINCL: we provide the full IP header
        socket_v4
            .set_header_included_v4(true)
            .context("setsockopt(IP_HDRINCL) failed")?;

        // Set mark on outgoing packets so nftables can skip them
        unsafe {
            let mark_val = CACHYDPI_MARK;
            let ret = libc::setsockopt(
                socket_v4.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_MARK,
                &mark_val as *const u32 as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            );
            if ret < 0 {
                warn!("SO_MARK failed on IPv4 raw socket (non-fatal)");
            }
        }

        // When IPv6 is enabled, nftables steers IPv6 traffic into the queue and
        // the engine will build IPv6 replacement packets for it. Not having a
        // socket to send them on is therefore a startup failure, not a
        // per-packet condition to warn about at line rate: without it every
        // IPv6 fragment would have to be abandoned. The operator can run
        // IPv4-only with --no-ipv6 (or ipv6 = false), which also stops the ip6
        // rules from being installed.
        let socket_v6 = if ipv6 {
            let s = Socket::new(
                Domain::IPV6,
                Type::RAW,
                Some(Protocol::from(libc::IPPROTO_RAW)),
            )
            .context(
                "failed to create IPv6 raw socket — need CAP_NET_RAW, \
                 or run IPv4-only with --no-ipv6",
            )?;

            // Without IPV6_HDRINCL the kernel overwrites our crafted IPv6
            // header, silently mangling every injected packet.
            Self::enable_ipv6_hdrincl(&s).context(
                "IPV6_HDRINCL unavailable — IPv6 header injection needs Linux >= 4.5; \
                 run IPv4-only with --no-ipv6",
            )?;

            // Mark outgoing packets so nftables can skip them
            unsafe {
                let mark_val = CACHYDPI_MARK;
                libc::setsockopt(
                    s.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_MARK,
                    &mark_val as *const u32 as *const libc::c_void,
                    std::mem::size_of::<u32>() as libc::socklen_t,
                );
            }
            Some(s)
        } else {
            None
        };

        debug!(
            "raw socket created (IPv4=yes, IPv6={})",
            socket_v6.is_some()
        );

        Ok(RawSocket {
            socket_v4,
            socket_v6,
            mark: CACHYDPI_MARK,
            decoy_limiter: RateLimiter::new(MAX_DECOYS_PER_SEC),
        })
    }

    /// Enable `IPV6_HDRINCL` on a raw IPv6 socket so the kernel transmits the
    /// IPv6 header we supply, mirroring `IP_HDRINCL` on the v4 socket.
    ///
    /// This is mandatory for IPv6 injection: without it the kernel discards our
    /// crafted IPv6 header (hop-limit, fragment layout, …) and builds its own,
    /// so fake packets and ClientHello fragments are silently mangled. The
    /// option (optname 36, level `IPPROTO_IPV6`) exists since Linux 4.5.
    ///
    /// We call `setsockopt` directly instead of socket2's
    /// `set_header_included_v6()`, which on Linux passes `IP_HDRINCL` (3) at
    /// level `IPPROTO_IPV6` — the wrong option (that maps to `IPV6_2292HOPOPTS`)
    /// — so it never actually enables header inclusion.
    fn enable_ipv6_hdrincl(socket: &Socket) -> io::Result<()> {
        let one: libc::c_int = 1;
        let ret = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_HDRINCL,
                &one as *const libc::c_int as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Test accessor: read `IPV6_HDRINCL` back from the live IPv6 socket.
    /// `None` if there is no IPv6 socket; `Some(true)` only when the kernel
    /// confirms header inclusion is active.
    #[cfg(test)]
    fn ipv6_hdrincl_enabled(&self) -> Option<bool> {
        let socket = self.socket_v6.as_ref()?;
        let mut val: libc::c_int = -1;
        let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
        let ret = unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::IPPROTO_IPV6,
                libc::IPV6_HDRINCL,
                &mut val as *mut libc::c_int as *mut libc::c_void,
                &mut len,
            )
        };
        Some(ret == 0 && val == 1)
    }

    /// Send a raw IP packet immediately, bypassing the decoy rate limiter.
    ///
    /// Used for fragments that carry real user data: an `Ok` return means
    /// the packet was handed to the kernel; failures are returned so the
    /// caller can fall back to accepting the original packet.
    ///
    /// The packet must be a complete IP packet (including IP header).
    /// For IPv4, IP_HDRINCL means the kernel won't add a header.
    pub fn send_unlimited(&self, packet: &[u8]) -> Result<Sent> {
        // Every path that does not reach the kernel must be an error: the
        // caller drops the original packet on `Ok`, so answering `Ok` without
        // sending silently destroys the data it was replacing.
        if packet.is_empty() {
            bail!("refusing to report an empty packet as sent");
        }

        let version = (packet[0] >> 4) & 0x0F;

        match version {
            4 => self.send_ipv4(packet),
            6 => self.send_ipv6(packet),
            _ => bail!("unknown IP version {version}; nothing was sent"),
        }
    }

    /// Send a decoy (fake) packet through the rate limiter.
    ///
    /// When the limit is exceeded the packet is silently dropped (counted
    /// in `rate_limit_drops`): decoys only exist to confuse DPI, losing
    /// one never breaks a connection.
    pub fn send_rate_limited(&self, packet: &[u8]) -> Result<()> {
        if !self.decoy_limiter.allow() {
            crate::metrics::METRICS
                .rate_limit_drops
                .fetch_add(1, Ordering::Relaxed);
            warn!("raw socket rate limit exceeded, dropping injected decoy packet");
            return Ok(());
        }
        // Decoys carry no user data, so the witness is discarded here: nothing
        // is dropped on the strength of a decoy having been sent.
        self.send_unlimited(packet).map(|_| ())
    }

    fn send_ipv4(&self, packet: &[u8]) -> Result<Sent> {
        if packet.len() < 20 {
            bail!("IPv4 packet too short: {} bytes", packet.len());
        }

        // Extract destination IP for sendto()
        let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        let dst_addr = SocketAddrV4::new(dst_ip, 0);
        let sock_addr = SockAddr::from(dst_addr);

        match self.socket_v4.send_to(packet, &sock_addr) {
            Ok(n) => {
                trace!(len = n, dst = %crate::logging::peer(dst_ip), "sent raw IPv4 packet");
                Ok(Sent::confirmed())
            }
            Err(e) => {
                // EPERM can happen if nftables OUTPUT rules block our packet
                if e.kind() == io::ErrorKind::PermissionDenied {
                    warn!("raw socket send blocked (EPERM) — check nftables mark rules");
                }
                Err(e).context("raw socket sendto() failed")
            }
        }
    }

    fn send_ipv6(&self, packet: &[u8]) -> Result<Sent> {
        let socket = match &self.socket_v6 {
            // With IPv6 enabled the socket is created at startup or the daemon
            // refuses to run, so reaching this arm means an IPv6 packet turned
            // up while IPv6 processing was off — most likely a leftover ip6
            // nftables rule. It has to be an error: answering `Ok` would drop
            // the original packet and send nothing in its place, black-holing
            // the connection.
            None => bail!("IPv6 packet but IPv6 injection is disabled; nothing was sent"),
            Some(s) => s,
        };

        if packet.len() < 40 {
            bail!("IPv6 packet too short: {} bytes", packet.len());
        }

        // Extract destination IPv6 address (bytes 24-39)
        let mut dst_bytes = [0u8; 16];
        dst_bytes.copy_from_slice(&packet[24..40]);
        let dst_ip = std::net::Ipv6Addr::from(dst_bytes);
        let dst_addr = std::net::SocketAddrV6::new(dst_ip, 0, 0, 0);
        let sock_addr = SockAddr::from(dst_addr);

        match socket.send_to(packet, &sock_addr) {
            Ok(n) => {
                trace!(len = n, dst = %crate::logging::peer(dst_ip), "sent raw IPv6 packet");
                Ok(Sent::confirmed())
            }
            Err(e) => Err(e).context("raw socket sendto() (IPv6) failed"),
        }
    }

    /// Get the mark value used by this socket
    pub fn mark(&self) -> u32 {
        self.mark
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The sysctl decides between "IPv6 exists" and "IPv6 is switched off",
    /// which is the difference between starting IPv4-only and refusing to
    /// start. It cannot be flipped from a user namespace, so the parsing is
    /// tested against files instead.
    /// Build a fake /proc/sys/net/ipv6/conf tree: (interface, disable_ipv6).
    fn fake_conf_root(entries: &[(&str, &str)]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        for (iface, value) in entries {
            let path = dir.path().join(iface);
            std::fs::create_dir_all(&path).unwrap();
            std::fs::write(path.join("disable_ipv6"), format!("{value}\n")).unwrap();
        }
        dir
    }

    #[test]
    fn ipv6_sysctl_is_read_as_a_disable_switch() {
        // The machine-wide switch.
        let off = fake_conf_root(&[("all", "1"), ("lo", "0"), ("eth0", "0")]);
        assert!(
            ipv6_disabled_by_sysctl(off.path()),
            "all/disable_ipv6=1 means IPv6 is off"
        );

        let on = fake_conf_root(&[("all", "0"), ("lo", "0"), ("eth0", "0")]);
        assert!(!ipv6_disabled_by_sysctl(on.path()));
    }

    /// `all` reading 0 while every interface has IPv6 disabled is common in the
    /// wild, and leaves nothing able to carry IPv6.
    #[test]
    fn ipv6_disabled_on_every_interface_counts_as_disabled() {
        let all_ifaces_off = fake_conf_root(&[("all", "0"), ("lo", "1"), ("eth0", "1")]);
        assert!(
            ipv6_disabled_by_sysctl(all_ifaces_off.path()),
            "every interface disabled means IPv6 is off in practice"
        );

        // One interface still carrying IPv6 is enough to keep it available.
        let one_on = fake_conf_root(&[("all", "0"), ("lo", "1"), ("eth0", "0")]);
        assert!(!ipv6_disabled_by_sysctl(one_on.path()));

        // "default" only seeds interfaces created later, so it must not be
        // mistaken for a live interface and tip the all-disabled verdict.
        let only_default_off = fake_conf_root(&[("all", "0"), ("default", "1"), ("eth0", "0")]);
        assert!(!ipv6_disabled_by_sysctl(only_default_off.path()));
    }

    /// The commonest way IPv6 is switched off in the wild: every real interface
    /// disabled while loopback is left alone. Counting lo — whose disable_ipv6
    /// is almost always 0 — would report IPv6 as available on exactly those
    /// machines.
    #[test]
    fn loopback_alone_does_not_make_ipv6_look_available() {
        let real_ifaces_off = fake_conf_root(&[
            ("all", "0"),
            ("lo", "0"), // untouched, as it usually is
            ("enp6s0", "1"),
            ("wlan0", "1"),
        ]);
        assert!(
            ipv6_disabled_by_sysctl(real_ifaces_off.path()),
            "lo being up must not outvote every real interface being disabled"
        );

        // With no real interfaces at all there is nothing to conclude, so the
        // sysctls must not claim IPv6 is disabled; the socket probe decides.
        let only_loopback = fake_conf_root(&[("all", "0"), ("lo", "0")]);
        assert!(!ipv6_disabled_by_sysctl(only_loopback.path()));
    }

    /// A kernel without IPv6 has no sysctl tree at all. That must not read as
    /// "disabled" on its own — the socket probe is what catches it — and it must
    /// not error either.
    #[test]
    fn a_missing_sysctl_tree_is_not_treated_as_disabled() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!ipv6_disabled_by_sysctl(&dir.path().join("absent")));

        // Present but empty (no interfaces yet) is also not a disable signal.
        assert!(!ipv6_disabled_by_sysctl(dir.path()));
    }

    /// The IPv4-only path has to keep working, since that is where a machine
    /// without IPv6 now lands instead of failing to start.
    #[test]
    fn ipv4_only_raw_socket_builds_without_ipv6() {
        match RawSocket::new(false) {
            Ok(socket) => assert!(
                socket.socket_v6.is_none(),
                "ipv6=false must not create an IPv6 socket"
            ),
            Err(_) => crate::testing::skip_unless_required(
                "no CAP_NET_RAW (try `unshare -Urn`)",
            ),
        }
    }

    #[test]
    fn rate_limiter_allows_up_to_capacity_then_blocks() {
        let limiter = RateLimiter::new(3);
        assert!(limiter.allow());
        assert!(limiter.allow());
        assert!(limiter.allow());
        assert!(!limiter.allow());
        assert!(!limiter.allow());
    }

    /// When CAP_NET_RAW is available (so the IPv4 socket builds), the IPv6
    /// injection socket must exist with `IPV6_HDRINCL` actually enabled —
    /// otherwise IPv6 fake/fragment injection silently no-ops.
    ///
    /// Skipped without CAP_NET_RAW (the v4 socket fails first). To exercise it
    /// for real, run the test under a namespace that grants the capability:
    ///   `unshare --map-root-user --net cargo test ipv6_socket_enables_hdrincl`
    #[test]
    fn ipv6_socket_enables_hdrincl() {
        match RawSocket::new(true) {
            Ok(rs) => match rs.ipv6_hdrincl_enabled() {
                Some(true) => {} // verified: header injection is live
                Some(false) => {
                    panic!("IPv6 socket present but IPV6_HDRINCL is not enabled")
                }
                None => eprintln!(
                    "note: IPv6 injection disabled (kernel without IPV6_HDRINCL); \
                     IPv4 injection still works"
                ),
            },
            Err(_) => eprintln!(
                "skipping ipv6_socket_enables_hdrincl: no CAP_NET_RAW \
                 (run under `unshare --map-root-user --net`)"
            ),
        }
    }
}
