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
    let ip_hdr_len = ip_hdr.header_len();
    let tcp_hdr_len = tcp_hdr.header_len;

    if real_packet.len() < ip_hdr_len + tcp_hdr_len {
        return None;
    }

    // Build RST packet with no payload
    let total_len = ip_hdr_len + tcp_hdr_len;
    let mut packet = Vec::with_capacity(total_len);

    // Copy IP + TCP headers from original
    packet.extend_from_slice(&real_packet[..total_len]);

    // Fix IP total length
    let version = (packet[0] >> 4) & 0x0F;
    if version == 4 {
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        // Set fake TTL
        packet[8] = fake_ttl;
        // Recalculate IP checksum
        packet[10] = 0;
        packet[11] = 0;
        let cksum = ip::ipv4_checksum(&packet[..ip_hdr_len]);
        packet[10..12].copy_from_slice(&cksum.to_be_bytes());
    } else if version == 6 {
        packet[7] = fake_ttl;
        let payload_len = tcp_hdr_len as u16;
        packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
    }

    // Set TCP flags to RST+ACK
    let tcp_off = ip_hdr_len;
    packet[tcp_off + 13] = TCP_RST | TCP_ACK;

    // Use seq+1 so DPI processes it (looks like response to current data)
    let rst_seq = tcp_hdr.seq_num.wrapping_add(1);
    packet[tcp_off + 4..tcp_off + 8].copy_from_slice(&rst_seq.to_be_bytes());

    // Recalculate TCP checksum
    packet[tcp_off + 16] = 0;
    packet[tcp_off + 17] = 0;
    if version == 4 && packet.len() >= 20 {
        let src_ip: [u8; 4] = packet[12..16].try_into().unwrap_or([0; 4]);
        let dst_ip: [u8; 4] = packet[16..20].try_into().unwrap_or([0; 4]);
        let cksum = tcp::tcp_checksum_v4(&src_ip, &dst_ip, &packet[tcp_off..]);
        packet[tcp_off + 16..tcp_off + 18].copy_from_slice(&cksum.to_be_bytes());
    } else if version == 6 && packet.len() >= 40 {
        let src_ip: [u8; 16] = packet[8..24].try_into().unwrap_or([0; 16]);
        let dst_ip: [u8; 16] = packet[24..40].try_into().unwrap_or([0; 16]);
        let cksum = tcp::tcp_checksum_v6(&src_ip, &dst_ip, &packet[tcp_off..]);
        packet[tcp_off + 16..tcp_off + 18].copy_from_slice(&cksum.to_be_bytes());
    }

    trace!(ttl = fake_ttl, "created fake RST desync packet");
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
fn build_fake_with_ttl(
    real_packet: &[u8],
    ip_hdr: &IpHeader,
    tcp_hdr: &TcpHeader<'_>,
    fake_payload: &[u8],
    ttl: u8,
) -> Option<Vec<u8>> {
    let ip_hdr_len = ip_hdr.header_len();
    let tcp_hdr_len = tcp_hdr.header_len;

    if real_packet.len() < ip_hdr_len + tcp_hdr_len {
        return None;
    }

    let total_len = ip_hdr_len + tcp_hdr_len + fake_payload.len();
    let mut packet = Vec::with_capacity(total_len);

    // Copy IP header from original
    packet.extend_from_slice(&real_packet[..ip_hdr_len]);
    // Copy TCP header from original
    packet.extend_from_slice(&real_packet[ip_hdr_len..ip_hdr_len + tcp_hdr_len]);
    // Add fake payload
    packet.extend_from_slice(fake_payload);

    // Set length and fake TTL. IPv6 keeps its flow label where IPv4 keeps the
    // total length, so the length is written per version.
    let version = (packet[0] >> 4) & 0x0F;
    if version == 4 {
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        packet[8] = ttl;
        // Recalculate IP checksum
        packet[10] = 0;
        packet[11] = 0;
        let cksum = ip::ipv4_checksum(&packet[..ip_hdr_len]);
        packet[10..12].copy_from_slice(&cksum.to_be_bytes());
    } else if version == 6 {
        // Set hop limit for IPv6
        packet[7] = ttl;
        // Fix payload length
        let payload_len = (tcp_hdr_len + fake_payload.len()) as u16;
        packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
    }

    // Fix TCP: use PSH+ACK flags, set same seq/ack as original
    let tcp_off = ip_hdr_len;
    packet[tcp_off + 13] = TCP_PSH | TCP_ACK;

    // Recalculate TCP checksum (must be correct — some DPI verify checksums)
    packet[tcp_off + 16] = 0;
    packet[tcp_off + 17] = 0;
    if version == 4 && packet.len() >= 20 {
        let src_ip: [u8; 4] = packet[12..16].try_into().unwrap_or([0; 4]);
        let dst_ip: [u8; 4] = packet[16..20].try_into().unwrap_or([0; 4]);
        let cksum = tcp::tcp_checksum_v4(&src_ip, &dst_ip, &packet[tcp_off..]);
        packet[tcp_off + 16..tcp_off + 18].copy_from_slice(&cksum.to_be_bytes());
    } else if version == 6 && packet.len() >= 40 {
        let src_ip: [u8; 16] = packet[8..24].try_into().unwrap_or([0; 16]);
        let dst_ip: [u8; 16] = packet[24..40].try_into().unwrap_or([0; 16]);
        let cksum = tcp::tcp_checksum_v6(&src_ip, &dst_ip, &packet[tcp_off..]);
        packet[tcp_off + 16..tcp_off + 18].copy_from_slice(&cksum.to_be_bytes());
    }

    Some(packet)
}

/// Build a fake packet with an intentionally wrong TCP checksum.
/// The server's TCP stack will drop it, but many DPI systems don't verify checksums.
fn build_fake_with_bad_checksum(
    real_packet: &[u8],
    ip_hdr: &IpHeader,
    tcp_hdr: &TcpHeader<'_>,
    fake_payload: &[u8],
) -> Option<Vec<u8>> {
    let ip_hdr_len = ip_hdr.header_len();
    let tcp_hdr_len = tcp_hdr.header_len;

    if real_packet.len() < ip_hdr_len + tcp_hdr_len {
        return None;
    }

    let total_len = ip_hdr_len + tcp_hdr_len + fake_payload.len();
    let mut packet = Vec::with_capacity(total_len);

    packet.extend_from_slice(&real_packet[..ip_hdr_len]);
    packet.extend_from_slice(&real_packet[ip_hdr_len..ip_hdr_len + tcp_hdr_len]);
    packet.extend_from_slice(fake_payload);

    // Fix IP length field
    let version = (packet[0] >> 4) & 0x0F;
    if version == 4 {
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    } else if version == 6 {
        let payload_len = (total_len - ip_hdr_len) as u16;
        packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
    }

    let tcp_off = ip_hdr_len;
    packet[tcp_off + 13] = TCP_PSH | TCP_ACK;

    // Fix IP checksum (must be correct or packet won't be routed)
    if version == 4 {
        packet[10] = 0;
        packet[11] = 0;
        let cksum = ip::ipv4_checksum(&packet[..ip_hdr_len]);
        packet[10..12].copy_from_slice(&cksum.to_be_bytes());
    }

    // Compute the right checksum, then put a wrong one in its place.
    tcp::refresh_tcp_checksum(&mut packet, ip_hdr_len);
    let correct = u16::from_be_bytes([packet[tcp_off + 16], packet[tcp_off + 17]]);
    packet[tcp_off + 16..tcp_off + 18].copy_from_slice(&wrong_checksum(correct).to_be_bytes());

    Some(packet)
}

/// Build a fake packet with a wrong TCP sequence number.
/// The server ignores it (out of window), but DPI may still process it.
fn build_fake_with_wrong_seq(
    real_packet: &[u8],
    ip_hdr: &IpHeader,
    tcp_hdr: &TcpHeader<'_>,
    fake_payload: &[u8],
) -> Option<Vec<u8>> {
    let ip_hdr_len = ip_hdr.header_len();
    let tcp_hdr_len = tcp_hdr.header_len;

    if real_packet.len() < ip_hdr_len + tcp_hdr_len {
        return None;
    }

    let total_len = ip_hdr_len + tcp_hdr_len + fake_payload.len();
    let mut packet = Vec::with_capacity(total_len);

    packet.extend_from_slice(&real_packet[..ip_hdr_len]);
    packet.extend_from_slice(&real_packet[ip_hdr_len..ip_hdr_len + tcp_hdr_len]);
    packet.extend_from_slice(fake_payload);

    // Fix IP length field
    let version = (packet[0] >> 4) & 0x0F;
    if version == 4 {
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    } else if version == 6 {
        let payload_len = (total_len - ip_hdr_len) as u16;
        packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
    }

    let tcp_off = ip_hdr_len;
    packet[tcp_off + 13] = TCP_PSH | TCP_ACK;

    // Set WRONG sequence number: entirely before the data the server expects
    let wrong_seq = tcp_hdr.seq_num.wrapping_sub(wrong_seq_back());
    packet[tcp_off + 4..tcp_off + 8].copy_from_slice(&wrong_seq.to_be_bytes());

    // Fix IP checksum
    if version == 4 {
        packet[10] = 0;
        packet[11] = 0;
        let cksum = ip::ipv4_checksum(&packet[..ip_hdr_len]);
        packet[10..12].copy_from_slice(&cksum.to_be_bytes());
    }

    // Recalculate TCP checksum (must be correct for the wrong data)
    packet[tcp_off + 16] = 0;
    packet[tcp_off + 17] = 0;
    if version == 4 && packet.len() >= 20 {
        let src_ip: [u8; 4] = packet[12..16].try_into().unwrap_or([0; 4]);
        let dst_ip: [u8; 4] = packet[16..20].try_into().unwrap_or([0; 4]);
        let cksum = tcp::tcp_checksum_v4(&src_ip, &dst_ip, &packet[tcp_off..]);
        packet[tcp_off + 16..tcp_off + 18].copy_from_slice(&cksum.to_be_bytes());
    } else if version == 6 && packet.len() >= 40 {
        let src_ip: [u8; 16] = packet[8..24].try_into().unwrap_or([0; 16]);
        let dst_ip: [u8; 16] = packet[24..40].try_into().unwrap_or([0; 16]);
        let cksum = tcp::tcp_checksum_v6(&src_ip, &dst_ip, &packet[tcp_off..]);
        packet[tcp_off + 16..tcp_off + 18].copy_from_slice(&cksum.to_be_bytes());
    }

    Some(packet)
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
