// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/strategies/fake_packet.rs — Fake packet injection
//
// Injects crafted "fake" packets that confuse DPI systems but are
// discarded by the real server. Methods include:
// - Wrong TTL: packet expires before reaching the server
// - Wrong checksum: server drops the packet, DPI doesn't verify
// - Wrong sequence number: server ignores, DPI may process
//
// The fake packet carries a browser-shaped ClientHello or HTTP request naming
// `fake_sni`, which tricks the DPI into thinking the connection goes
// somewhere harmless.

use crate::config::Config;
use crate::packet::bytes::{be16_at, put_be16, put_u8};
use crate::packet::ip::{self, IpHeader};
use crate::packet::tcp::{self, TCP_ACK, TCP_PSH, TCP_RST, TcpHeader};

use tracing::trace;

/// Build a fake RST packet with wrong TTL to break DPI connection tracking.
/// The DPI sees the RST and removes the connection from its tracking table.
/// The fake RST expires before reaching the server (TTL too low).
/// After this, the DPI won't inspect subsequent packets on this connection.
pub fn create_fake_rst_desync(
    real_packet: &[u8],
    ip_hdr: &IpHeader,
    tcp_hdr: &TcpHeader<'_>,
    fake_ttl: u8,
) -> Option<Vec<u8>> {
    // RST+ACK with no payload, at seq+1 so DPI processes it (looks like a
    // response to current data)
    let packet = forge(
        real_packet,
        ip_hdr,
        tcp_hdr,
        &[],
        tcp_hdr.seq_num.wrapping_add(1),
        TCP_RST | TCP_ACK,
        Some(fake_ttl),
    )?;
    trace!(ttl = fake_ttl, "created fake RST desync packet");
    Some(packet)
}

/// A packet cut from `real_packet` that carries `payload` at `seq` with
/// `flags`, and `ttl` as its TTL or hop limit if given; lengths and checksums
/// match. None if `real_packet` does not hold the headers it is said to.
fn forge(
    real_packet: &[u8],
    ip_hdr: &IpHeader,
    tcp_hdr: &TcpHeader<'_>,
    payload: &[u8],
    seq: u32,
    flags: u8,
    ttl: Option<u8>,
) -> Option<Vec<u8>> {
    let ip_hdr_len = ip_hdr.header_len();
    let mut packet = tcp::resegment(real_packet, ip_hdr_len, tcp_hdr.header_len, payload, seq)?;
    put_u8(&mut packet, ip_hdr_len + 13, flags)?;
    let v4 = ip_hdr.is_v4();
    if let Some(ttl) = ttl {
        // IPv4 keeps its TTL at byte 8, IPv6 its hop limit at byte 7.
        put_u8(&mut packet, if v4 { 8 } else { 7 }, ttl)?;
    }
    if v4 {
        ip::refresh_ipv4_checksum(&mut packet)?;
    }
    tcp::refresh_tcp_checksum(&mut packet, ip_hdr_len);
    Some(packet)
}

/// A plain-HTTP request for `host`, with the headers a browser sends.
///
/// A request line and a Host header alone is a shape no browser produces; a
/// DPI could pick the fake out by it.
pub fn build_fake_http_request(host: &str) -> Vec<u8> {
    format!(
        "GET / HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0\r\n\
         Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n\
         Accept-Language: en-US,en;q=0.5\r\n\
         Accept-Encoding: gzip, deflate\r\n\
         Connection: keep-alive\r\n\
         Upgrade-Insecure-Requests: 1\r\n\
         \r\n"
    )
    .into_bytes()
}

/// Whether two TCP checksum values verify alike. Ones' complement has two
/// zeros, 0x0000 and 0xFFFF, and a receiver accepts either where the other is
/// correct.
fn same_checksum(a: u16, b: u16) -> bool {
    let canonical = |x: u16| if x == 0xFFFF { 0 } else { x };
    canonical(a) == canonical(b)
}

/// A random TCP checksum the receiver is certain to reject.
///
/// Random rather than fixed: a constant wrong value is a pattern a DPI can
/// match on, where a corrupted segment's checksum is just some other number.
fn wrong_checksum(correct: u16) -> u16 {
    loop {
        let candidate = crate::random::u32() as u16;
        if !same_checksum(candidate, correct) {
            return candidate;
        }
    }
}

/// How far behind the real data a wrong-SEQ fake starts, as a range.
///
/// At least 65536, more than any segment can carry, so the whole fake lies
/// before the data the server expects and none of it can be taken into the
/// stream. Far below 2^31, so it never reads as data ahead of the window.
const WRONG_SEQ_BACK_MIN: u32 = 1 << 16;
const WRONG_SEQ_BACK_MAX: u32 = 1 << 20;

/// A random distance in that range, so the offset is not a constant either.
fn wrong_seq_back() -> u32 {
    WRONG_SEQ_BACK_MIN + crate::random::u32() % (WRONG_SEQ_BACK_MAX - WRONG_SEQ_BACK_MIN + 1)
}

/// The fake ClientHello: a browser-shaped hello for `sni`. The DPI reads it
/// and classifies the connection by its name; its TTL, checksum or sequence
/// number keeps it from the real server.
pub fn build_fake_client_hello_payload(sni: &str) -> Vec<u8> {
    crate::packet::tls::build_client_hello(sni)
}

/// Create fake packets to inject before the real packet.
///
/// Returns a vector of complete IP packets ready to send via raw socket.
pub fn create_fake_packets(
    real_packet: &[u8],
    ip_hdr: &IpHeader,
    tcp_hdr: &TcpHeader<'_>,
    fake_ttl: u8,
    config: &Config,
) -> Vec<Vec<u8>> {
    let mut fakes = Vec::new();

    // The fake speaks the real packet's protocol, naming the configured host.
    let sni = &config.strategies.fake_sni;
    let fake_payload_owned = if tcp_hdr.dst_port == 80 || tcp_hdr.dst_port == 8080 {
        build_fake_http_request(sni)
    } else {
        build_fake_client_hello_payload(sni)
    };
    let fake_payload: &[u8] = &fake_payload_owned;

    // Strategy 1: Fake packet with wrong TTL (most reliable)
    if config.strategies.fake_packet_ttl > 0 || config.strategies.auto_ttl {
        let fake = build_fake_with_ttl(real_packet, ip_hdr, tcp_hdr, fake_payload, fake_ttl);
        if let Some(pkt) = fake {
            trace!(ttl = fake_ttl, "created fake packet with wrong TTL");
            fakes.push(pkt);
        }
    }

    // Strategy 2: Fake packet with wrong checksum
    if config.strategies.fake_wrong_checksum {
        let fake = build_fake_with_bad_checksum(real_packet, ip_hdr, tcp_hdr, fake_payload);
        if let Some(pkt) = fake {
            trace!("created fake packet with wrong checksum");
            fakes.push(pkt);
        }
    }

    // Strategy 3: Fake packet with wrong sequence number
    if config.strategies.fake_wrong_seq {
        let fake = build_fake_with_wrong_seq(real_packet, ip_hdr, tcp_hdr, fake_payload);
        if let Some(pkt) = fake {
            trace!("created fake packet with wrong SEQ");
            fakes.push(pkt);
        }
    }

    fakes
}

/// Build a fake packet with a TTL that will expire before reaching the server.
/// The DPI box (closer to the client) will see it, but it won't reach the server.
/// Its TCP checksum is correct: some DPI verify checksums.
fn build_fake_with_ttl(
    real_packet: &[u8],
    ip_hdr: &IpHeader,
    tcp_hdr: &TcpHeader<'_>,
    fake_payload: &[u8],
    ttl: u8,
) -> Option<Vec<u8>> {
    let seq = tcp_hdr.seq_num;
    forge(
        real_packet,
        ip_hdr,
        tcp_hdr,
        fake_payload,
        seq,
        TCP_PSH | TCP_ACK,
        Some(ttl),
    )
}

/// Build a fake packet with an intentionally wrong TCP checksum.
/// The server's TCP stack will drop it, but many DPI systems don't verify checksums.
fn build_fake_with_bad_checksum(
    real_packet: &[u8],
    ip_hdr: &IpHeader,
    tcp_hdr: &TcpHeader<'_>,
    fake_payload: &[u8],
) -> Option<Vec<u8>> {
    let seq = tcp_hdr.seq_num;
    let mut packet = forge(
        real_packet,
        ip_hdr,
        tcp_hdr,
        fake_payload,
        seq,
        TCP_PSH | TCP_ACK,
        None,
    )?;

    // The right checksum is in place; put a wrong one where it was.
    let checksum_at = ip_hdr.header_len() + 16;
    let correct = be16_at(&packet, checksum_at)?;
    put_be16(&mut packet, checksum_at, wrong_checksum(correct))?;
    Some(packet)
}

/// Build a fake packet with a wrong TCP sequence number.
/// The server ignores it (out of window), but DPI may still process it.
/// Its checksum is correct for the wrong data.
fn build_fake_with_wrong_seq(
    real_packet: &[u8],
    ip_hdr: &IpHeader,
    tcp_hdr: &TcpHeader<'_>,
    fake_payload: &[u8],
) -> Option<Vec<u8>> {
    // Entirely before the data the server expects
    let wrong_seq = tcp_hdr.seq_num.wrapping_sub(wrong_seq_back());
    forge(
        real_packet,
        ip_hdr,
        tcp_hdr,
        fake_payload,
        wrong_seq,
        TCP_PSH | TCP_ACK,
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// A minimal IPv4 or IPv6 TCP packet carrying `payload`, with a valid
    /// TCP checksum.
    fn packet(v6: bool, seq: u32, payload: &[u8]) -> Vec<u8> {
        let ip_len = if v6 { 40 } else { 20 };
        let mut p = vec![0u8; ip_len + 20];
        if v6 {
            p[0] = 0x60;
            p[4..6].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
            p[6] = 6;
            p[7] = 64;
            p[8..24].copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
            p[24..40]
                .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        } else {
            p[0] = 0x45;
            p[2..4].copy_from_slice(&((40 + payload.len()) as u16).to_be_bytes());
            p[8] = 64;
            p[9] = 6;
            p[12..16].copy_from_slice(&[192, 168, 1, 100]);
            p[16..20].copy_from_slice(&[93, 184, 216, 34]);
        }
        let t = ip_len;
        p[t..t + 2].copy_from_slice(&40000u16.to_be_bytes());
        p[t + 2..t + 4].copy_from_slice(&443u16.to_be_bytes());
        p[t + 4..t + 8].copy_from_slice(&seq.to_be_bytes());
        p[t + 12] = 5 << 4;
        p[t + 13] = TCP_PSH | TCP_ACK;
        p[t + 14..t + 16].copy_from_slice(&64240u16.to_be_bytes());
        p.extend_from_slice(payload);
        tcp::refresh_tcp_checksum(&mut p, ip_len);
        p
    }

    fn checksum_of(p: &[u8], ip_len: usize) -> u16 {
        u16::from_be_bytes([p[ip_len + 16], p[ip_len + 17]])
    }

    fn fakes(
        v6: bool,
        seq: u32,
        build: impl Fn(&[u8], &IpHeader, &TcpHeader<'_>) -> Option<Vec<u8>>,
    ) -> Vec<Vec<u8>> {
        let real = packet(v6, seq, b"real data");
        let ip_hdr = IpHeader::parse(&real).unwrap();
        let ip_len = ip_hdr.header_len();
        let tcp_hdr = TcpHeader::parse(&real[ip_len..]).unwrap();
        (0..64)
            .map(|_| build(&real, &ip_hdr, &tcp_hdr).unwrap())
            .collect()
    }

    #[test]
    fn the_two_zeros_of_ones_complement_count_as_one_value() {
        assert!(same_checksum(0x0000, 0xFFFF));
        assert!(same_checksum(0xFFFF, 0x0000));
        assert!(same_checksum(0x1234, 0x1234));
        assert!(!same_checksum(0x1234, 0x1235));
        for _ in 0..10_000 {
            assert!(!same_checksum(wrong_checksum(0x0000), 0x0000));
            assert!(!same_checksum(wrong_checksum(0xFFFF), 0xFFFF));
        }
    }

    /// The bad-checksum fake must fail verification on both families, and
    /// its checksum must not be one value a DPI could recognise.
    #[test]
    fn bad_checksum_fakes_never_verify_and_do_not_repeat() {
        for v6 in [false, true] {
            let ip_len = if v6 { 40 } else { 20 };
            let built = fakes(v6, 1_000_000, |r, i, t| {
                build_fake_with_bad_checksum(r, i, t, b"fake payload")
            });
            let mut seen = HashSet::new();
            for fake in &built {
                let mut fixed = fake.clone();
                tcp::refresh_tcp_checksum(&mut fixed, ip_len);
                let correct = checksum_of(&fixed, ip_len);
                let sent = checksum_of(fake, ip_len);
                assert!(
                    !same_checksum(sent, correct),
                    "v6={v6}: fake carries a valid checksum"
                );
                seen.insert(sent);
            }
            assert!(
                seen.len() > 32,
                "v6={v6}: only {} distinct checksums in 64 fakes",
                seen.len()
            );
        }
    }

    /// The wrong-SEQ fake must end before the real data, whatever the real
    /// sequence number, so the server cannot take any of it into the stream.
    #[test]
    fn wrong_seq_fakes_lie_wholly_before_the_real_data_and_vary() {
        let payload = b"fake payload";
        for v6 in [false, true] {
            let ip_len = if v6 { 40 } else { 20 };
            for real_seq in [0u32, 70_000, 0x8000_0000, u32::MAX] {
                let built = fakes(v6, real_seq, |r, i, t| {
                    build_fake_with_wrong_seq(r, i, t, payload)
                });
                let mut seen = HashSet::new();
                for fake in &built {
                    let tcp_hdr = TcpHeader::parse(&fake[ip_len..]).unwrap();
                    let back = real_seq.wrapping_sub(tcp_hdr.seq_num);
                    assert!(
                        (WRONG_SEQ_BACK_MIN..=WRONG_SEQ_BACK_MAX).contains(&back),
                        "v6={v6} seq={real_seq}: fake starts {back} behind"
                    );
                    assert!(back as usize > payload.len());
                    seen.insert(back);

                    // Its checksum is right: only the position is wrong.
                    let mut fixed = fake.clone();
                    tcp::refresh_tcp_checksum(&mut fixed, ip_len);
                    assert_eq!(checksum_of(fake, ip_len), checksum_of(&fixed, ip_len));
                }
                assert!(
                    seen.len() > 32,
                    "v6={v6}: only {} distinct offsets in 64 fakes",
                    seen.len()
                );
            }
        }
    }
}
