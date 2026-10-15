// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/dpi_detect.rs — find out how a site is blocked, from this machine
//
// One TLS handshake to a site says little on its own: a reset could be the
// server, and silence could be packet loss. Two say more. The same address is
// asked twice, once with a neutral SNI and once with the site's own, and only
// the difference is attributed to the network. A reply that arrives sooner
// than one round trip to the server cannot have come from the server, so the
// connect time doubles as the yardstick for an injected reset.

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tracing::debug;

/// The SNI the control handshake uses: a name nobody blocks.
const CONTROL_SNI: &str = "www.example.com";

/// How long to wait for a reply before calling it silence.
const READ_TIMEOUT: Duration = Duration::from_secs(4);

/// What one handshake attempt ran into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsOutcome {
    /// Any bytes came back — a ServerHello or an alert, the server answered.
    Answered,
    /// Reset or closed. `early` means sooner than the server could have
    /// replied, so something on the path did it.
    Cut { early: bool },
    /// Nothing within the timeout.
    Silent,
    /// The TCP connection itself failed.
    Unreachable,
}

/// How the site's name fared against the neutral one on the same address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SniVerdict {
    /// The site's own name was answered: no SNI-based blocking seen.
    NotBlocked,
    /// Cut before the server could reply, where the neutral name was
    /// answered: injected by DPI.
    InjectedReset,
    /// Cut later, where the neutral name was answered: blocked by name,
    /// though the cut could have come from the far side.
    CutByName,
    /// Dropped silently, where the neutral name was answered.
    Blackholed,
    /// The address does not answer even the neutral name: blocked by address,
    /// or the name resolves somewhere it should not.
    AddressBlocked,
    /// Neither handshake gives a clear picture.
    Inconclusive,
}

impl SniVerdict {
    pub fn interference(self) -> bool {
        matches!(
            self,
            SniVerdict::InjectedReset | SniVerdict::CutByName | SniVerdict::Blackholed
        )
    }

    pub fn describe(self) -> &'static str {
        match self {
            SniVerdict::NotBlocked => "not blocked by name",
            SniVerdict::InjectedReset => "reset by DPI as soon as the name was sent",
            SniVerdict::CutByName => "cut off when the name was sent",
            SniVerdict::Blackholed => "silently dropped when the name was sent",
            SniVerdict::AddressBlocked => {
                "the address does not answer at all — blocked by address, or DNS points elsewhere"
            }
            SniVerdict::Inconclusive => "inconclusive",
        }
    }
}

/// Classify a read after sending a ClientHello. `rtt` is how long the TCP
/// connect took: one round trip to the server.
pub fn classify(read: std::io::Result<usize>, since_send: Duration, rtt: Duration) -> TlsOutcome {
    // Allow a little under one round trip: the server cannot have replied by
    // then, but a box on the path can.
    let early = since_send < rtt.mul_f32(0.8);
    match read {
        Ok(0) => TlsOutcome::Cut { early },
        Ok(_) => TlsOutcome::Answered,
        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
            TlsOutcome::Silent
        }
        Err(_) => TlsOutcome::Cut { early },
    }
}

/// Compare the site's handshake with the control's.
pub fn judge(control: TlsOutcome, target: TlsOutcome) -> SniVerdict {
    use TlsOutcome::*;
    match (control, target) {
        (_, Answered) => SniVerdict::NotBlocked,
        (Answered, Cut { early: true }) => SniVerdict::InjectedReset,
        (Answered, Cut { early: false }) => SniVerdict::CutByName,
        (Answered, Silent) => SniVerdict::Blackholed,
        (Unreachable | Silent, _) => SniVerdict::AddressBlocked,
        _ => SniVerdict::Inconclusive,
    }
}

/// The mode to suggest. Never one without fragmentation: a site that showed
/// nothing in one probe can still be blocked another way, and mode 1 would
/// stop the bypass for every site.
pub fn recommend(verdict: SniVerdict) -> u8 {
    if verdict.interference() { 7 } else { 5 }
}

/// Result of probing one site.
#[derive(Debug)]
pub struct DpiFingerprint {
    /// The address both handshakes went to.
    pub address: SocketAddr,
    /// Connect time to that address.
    pub rtt: Duration,
    pub control: TlsOutcome,
    pub target: TlsOutcome,
    pub verdict: SniVerdict,
    /// A plain-HTTP request for the site was answered by a redirect sooner
    /// than the server could have, or with a block page. `None` if port 80
    /// could not be tested.
    pub http_redirect_injected: Option<bool>,
    pub recommended_mode: u8,
}

/// Probe `domain` from this machine.
///
/// WARNING: makes real connections to the site. With CachyDPI running, the
/// results describe the network with the bypass in place.
pub fn detect_dpi(domain: &str) -> Result<DpiFingerprint> {
    let address = (domain, 443)
        .to_socket_addrs()
        .with_context(|| format!("cannot resolve {domain}"))?
        .next()
        .with_context(|| format!("{domain} has no address"))?;

    let (control, rtt) = probe_tls(address, CONTROL_SNI);
    let (target, _) = probe_tls(address, domain);
    let verdict = judge(control, target);
    debug!(
        ?control,
        ?target,
        ?verdict,
        rtt_ms = rtt.as_millis(),
        "TLS probes done"
    );

    let http_redirect_injected = test_http_redirect(domain)
        .map_err(|e| debug!("HTTP test failed: {e}"))
        .ok();

    Ok(DpiFingerprint {
        address,
        rtt,
        control,
        target,
        verdict,
        http_redirect_injected,
        recommended_mode: recommend(verdict),
    })
}

/// One handshake attempt: connect, send a ClientHello for `sni`, read.
fn probe_tls(address: SocketAddr, sni: &str) -> (TlsOutcome, Duration) {
    let start = Instant::now();
    let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_secs(5)) else {
        return (TlsOutcome::Unreachable, start.elapsed());
    };
    let rtt = start.elapsed();
    let _ = stream.set_nodelay(true);
    let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
    let _ = stream.set_read_timeout(Some(READ_TIMEOUT));

    let sent = Instant::now();
    if let Err(e) = stream.write_all(&build_test_client_hello(sni)) {
        return (classify(Err(e), sent.elapsed(), rtt), rtt);
    }
    let mut buf = [0u8; 1024];
    let read = stream.read(&mut buf);
    (classify(read, sent.elapsed(), rtt), rtt)
}

/// Whether a plain-HTTP request for `domain` draws an injected redirect or a
/// block page.
fn test_http_redirect(domain: &str) -> Result<bool> {
    let address = (domain, 80)
        .to_socket_addrs()?
        .next()
        .context("no addresses found")?;
    let start = Instant::now();
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(5))?;
    let rtt = start.elapsed();
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;

    let request = format!("GET / HTTP/1.1\r\nHost: {domain}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes())?;

    let mut response = vec![0u8; 4096];
    let sent = Instant::now();
    let n = stream.read(&mut response)?;
    if n == 0 {
        return Ok(false);
    }
    Ok(looks_injected(&response[..n], sent.elapsed(), rtt))
}

/// A redirect sooner than a round trip to the server, or a page naming a
/// filtering product, did not come from the site.
fn looks_injected(response: &[u8], since_send: Duration, rtt: Duration) -> bool {
    let is_redirect = crate::packet::http::is_http_redirect(response);
    let early = since_send < rtt.mul_f32(0.8);
    let lower = String::from_utf8_lossy(response).to_lowercase();
    let block_page = [
        "blocked",
        "block-page",
        "access-denied",
        "web-filter",
        "content-filter",
        "forcepoint",
        "fortiguard",
        "sandvine",
        "allot",
        "netsweeper",
    ]
    .iter()
    .any(|w| lower.contains(w));
    (is_redirect && early) || block_page
}

/// A ClientHello carrying `domain` as SNI that real servers answer with a
/// ServerHello: TLS 1.3 and 1.2 suites, supported_versions, and an X25519 key
/// share. A bare hello offering no usable cipher draws only a seven-byte
/// alert, which is easy to lose — passive defence before 1.3.0 dropped exactly
/// that alert as forged — and is not what a DPI box sees from a browser.
fn build_test_client_hello(domain: &str) -> Vec<u8> {
    use std::hash::{BuildHasher, Hasher};
    let mut noise = Vec::with_capacity(64);
    let seed = std::collections::hash_map::RandomState::new();
    for i in 0u8..8 {
        let mut h = seed.build_hasher();
        h.write_u8(i);
        noise.extend_from_slice(&h.finish().to_be_bytes());
    }

    fn ext(out: &mut Vec<u8>, kind: u16, data: &[u8]) {
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
    }

    let name = domain.as_bytes();
    let mut sni = ((name.len() + 3) as u16).to_be_bytes().to_vec();
    sni.push(0);
    sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni.extend_from_slice(name);

    let mut key_share = 36u16.to_be_bytes().to_vec(); // one entry: group, len, key
    key_share.extend_from_slice(&[0x00, 0x1d, 0x00, 0x20]); // x25519, 32 bytes
    key_share.extend_from_slice(&noise[32..64]);

    let mut exts = Vec::new();
    ext(&mut exts, 0x0000, &sni);
    ext(
        &mut exts,
        0x000a,
        &[0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18],
    ); // groups
    ext(&mut exts, 0x000b, &[0x01, 0x00]); // ec_point_formats: uncompressed
    ext(
        &mut exts,
        0x000d, // signature_algorithms
        &[0x00, 0x08, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x05, 0x01],
    );
    ext(&mut exts, 0x0010, &[0x00, 0x03, 0x02, b'h', b'2']); // ALPN h2
    ext(&mut exts, 0x002b, &[0x04, 0x03, 0x04, 0x03, 0x03]); // versions 1.3, 1.2
    ext(&mut exts, 0x0033, &key_share);

    let suites: [u16; 6] = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0xc030];
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(&noise[..32]);
    body.push(0); // no session id
    body.extend_from_slice(&((suites.len() * 2) as u16).to_be_bytes());
    for s in suites {
        body.extend_from_slice(&s.to_be_bytes());
    }
    body.extend_from_slice(&[0x01, 0x00]);
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let mut hello = vec![0x01];
    hello.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hello.extend_from_slice(&body);
    let mut record = vec![0x16, 0x03, 0x01];
    record.extend_from_slice(&(hello.len() as u16).to_be_bytes());
    record.extend_from_slice(&hello);
    record
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Error;

    const RTT: Duration = Duration::from_millis(40);

    #[test]
    fn a_cut_sooner_than_a_round_trip_is_early() {
        let reset = || Err(Error::from(ErrorKind::ConnectionReset));
        assert_eq!(
            classify(reset(), Duration::from_millis(5), RTT),
            TlsOutcome::Cut { early: true }
        );
        assert_eq!(
            classify(reset(), Duration::from_millis(45), RTT),
            TlsOutcome::Cut { early: false }
        );
        assert_eq!(
            classify(Ok(0), Duration::from_millis(5), RTT),
            TlsOutcome::Cut { early: true }
        );
        assert_eq!(
            classify(Ok(7), Duration::from_millis(1), RTT),
            TlsOutcome::Answered
        );
        assert_eq!(
            classify(Err(Error::from(ErrorKind::WouldBlock)), READ_TIMEOUT, RTT),
            TlsOutcome::Silent
        );
    }

    #[test]
    fn only_the_difference_from_the_control_is_blamed_on_the_network() {
        use TlsOutcome::*;
        assert_eq!(judge(Answered, Answered), SniVerdict::NotBlocked);
        assert_eq!(
            judge(Answered, Cut { early: true }),
            SniVerdict::InjectedReset
        );
        assert_eq!(judge(Answered, Cut { early: false }), SniVerdict::CutByName);
        assert_eq!(judge(Answered, Silent), SniVerdict::Blackholed);
        assert_eq!(judge(Silent, Silent), SniVerdict::AddressBlocked);
        assert_eq!(judge(Unreachable, Unreachable), SniVerdict::AddressBlocked);
        // A server that resets every name says nothing about the network.
        assert_eq!(
            judge(Cut { early: false }, Cut { early: false }),
            SniVerdict::Inconclusive
        );
    }

    /// The previous detector recommended mode 1 — no fragmentation at all —
    /// whenever it saw nothing, which a silently dropped site produces.
    #[test]
    fn the_recommendation_never_drops_fragmentation() {
        for v in [
            SniVerdict::NotBlocked,
            SniVerdict::InjectedReset,
            SniVerdict::CutByName,
            SniVerdict::Blackholed,
            SniVerdict::AddressBlocked,
            SniVerdict::Inconclusive,
        ] {
            assert!(recommend(v) >= 5, "{v:?}");
        }
        assert_eq!(recommend(SniVerdict::Blackholed), 7);
    }

    #[test]
    fn redirects_are_judged_against_the_round_trip() {
        let redirect = b"HTTP/1.1 302 Found\r\nLocation: http://195.175.254.2/\r\n\r\n";
        assert!(looks_injected(redirect, Duration::from_millis(3), RTT));
        assert!(!looks_injected(redirect, Duration::from_millis(60), RTT));
        assert!(looks_injected(
            b"HTTP/1.1 200 OK\r\n\r\nThis site has been blocked",
            RTT * 2,
            RTT
        ));
    }

    #[test]
    fn the_probe_hello_is_complete_and_carries_its_sni() {
        let hello = build_test_client_hello("discord.com");
        let record_len = u16::from_be_bytes([hello[3], hello[4]]) as usize;
        assert_eq!(
            record_len,
            hello.len() - 5,
            "a short record leaves the server waiting"
        );
        let parsed = crate::packet::tls::TlsClientHello::parse(&hello).unwrap();
        assert_eq!(parsed.sni_domain(), Some("discord.com"));
        assert!(parsed.resume.is_none());
    }
}
