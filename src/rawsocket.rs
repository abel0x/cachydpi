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

        let socket_v6 = if ipv6 {
            match Socket::new(
                Domain::IPV6,
                Type::RAW,
                Some(Protocol::from(libc::IPPROTO_RAW)),
            ) {
                Ok(s) => match Self::enable_ipv6_hdrincl(&s) {
                    Ok(()) => {
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
                    }
                    // Without IPV6_HDRINCL the kernel would overwrite our crafted
                    // IPv6 header, silently mangling every injected packet. Refuse
                    // to keep a socket that can't honestly inject — disable IPv6
                    // rather than pretend it works.
                    Err(e) => {
                        warn!(
                            "IPV6_HDRINCL unavailable ({e}) — IPv6 header injection is \
                             unsupported on this kernel (needs Linux >= 4.5); disabling \
                             IPv6 injection"
                        );
                        None
                    }
                },
                Err(e) => {
                    warn!(
                        "IPv6 raw socket creation failed: {} — IPv6 injection disabled",
                        e
                    );
                    None
                }
            }
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
    pub fn send_unlimited(&self, packet: &[u8]) -> Result<()> {
        if packet.is_empty() {
            return Ok(());
        }

        let version = (packet[0] >> 4) & 0x0F;

        match version {
            4 => self.send_ipv4(packet),
            6 => self.send_ipv6(packet),
            _ => {
                warn!(version = version, "unknown IP version, dropping packet");
                Ok(())
            }
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
        self.send_unlimited(packet)
    }

    fn send_ipv4(&self, packet: &[u8]) -> Result<()> {
        if packet.len() < 20 {
            bail!("IPv4 packet too short: {} bytes", packet.len());
        }

        // Extract destination IP for sendto()
        let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        let dst_addr = SocketAddrV4::new(dst_ip, 0);
        let sock_addr = SockAddr::from(dst_addr);

        match self.socket_v4.send_to(packet, &sock_addr) {
            Ok(n) => {
                trace!(len = n, dst = %dst_ip, "sent raw IPv4 packet");
                Ok(())
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

    fn send_ipv6(&self, packet: &[u8]) -> Result<()> {
        let socket = match &self.socket_v6 {
            Some(s) => s,
            None => {
                warn!("IPv6 packet but no IPv6 raw socket available");
                return Ok(());
            }
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
                trace!(len = n, dst = %dst_ip, "sent raw IPv6 packet");
                Ok(())
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
