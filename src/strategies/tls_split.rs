// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/strategies/tls_split.rs — TLS ClientHello SNI fragmentation
//
// Splits TLS ClientHello into multiple TCP segments so that the SNI
// (Server Name Indication) extension is split across segments.
// This prevents DPI from reading the target domain in a single pass.
//
// Two strategies:
// 1. TCP-level segmentation: Split the TCP payload across segments
// 2. TLS record-level fragmentation: Split into multiple TLS records

use crate::packet::ip::{self, IpHeader};
use crate::packet::tcp::{self, TcpHeader};
use crate::packet::tls::{self, TlsClientHello};

use tracing::trace;

/// Where the second cut falls, measured from the start of the SNI value.
///
/// Anywhere past the first split and inside the name works: the point of the
/// third fragment is that the rest of the name arrives separately. Choosing it
/// at random keeps the fragment lengths from being a fixed function of the SNI.
/// Names too short to offer a choice keep the previous deterministic point.
fn second_split_offset(sni_length: usize) -> usize {
    const FIRST_CUT: usize = 2;
    let lowest = FIRST_CUT + 1;
    if sni_length <= lowest {
        return ((sni_length * 2) / 3).max(4.min(sni_length));
    }
    lowest + jitter(sni_length - lowest)
}

/// A number in `0..range`, varying per packet and per process.
///
/// Deliberately not cryptographic: it only has to stop the split points being
/// reproducible from the SNI, and it sits on the packet path. Seeded once from
/// the platform's random state so two runs do not share a sequence.
fn jitter(range: usize) -> usize {
    use std::sync::OnceLock;
    use std::sync::atomic::{AtomicU64, Ordering};

    static STATE: OnceLock<AtomicU64> = OnceLock::new();
    let state = STATE.get_or_init(|| {
        use std::hash::{BuildHasher, Hasher};
        let mut h = std::collections::hash_map::RandomState::new().build_hasher();
        h.write_u8(0);
        // xorshift64 stalls on zero.
        AtomicU64::new(h.finish() | 1)
    });

    // xorshift64: one atomic read-modify-write, no lock, no allocation.
    let mut x = state.load(Ordering::Relaxed);
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    state.store(x, Ordering::Relaxed);

    if range == 0 { 0 } else { (x % range as u64) as usize }
}

/// Split a TLS ClientHello packet at the SNI boundary.
///
/// Returns None if:
/// - The packet doesn't contain a ClientHello
/// - No SNI extension found
/// - Cannot determine a valid split point
///
/// # Arguments
/// * `raw_packet` - Complete IP packet
/// * `ip_hdr` - Parsed IP header
/// * `tcp_hdr` - Parsed TCP header
/// * `hello` - Parsed TLS ClientHello
/// * `split_position` - 0=auto (middle of SNI), >0 = fixed offset within TCP payload
pub fn split_tls_client_hello(
    raw_packet: &[u8],
    ip_hdr: &IpHeader,
    tcp_hdr: &TcpHeader<'_>,
    hello: &TlsClientHello<'_>,
    split_position: usize,
) -> Option<Vec<Vec<u8>>> {
    let payload = tcp_hdr.payload;
    if payload.is_empty() || !hello.has_sni() {
        return None;
    }

    // Determine split point
    let split_at = if split_position > 0 && split_position < payload.len() {
        split_position
    } else {
        // Auto: split in the middle of the SNI value
        let (split, _) = tls::find_sni_split_point(payload)?;
        split
    };

    if split_at == 0 || split_at >= payload.len() {
        return None;
    }

    trace!(
        sni = %crate::logging::peer(hello.sni.as_deref().unwrap_or("-")),
        split_at = split_at,
        total = payload.len(),
        "splitting TLS ClientHello at SNI"
    );

    let first_part = &payload[..split_at];
    let second_part = &payload[split_at..];

    let ip_hdr_len = ip_hdr.header_len();
    let tcp_hdr_len = tcp_hdr.header_len;
    let headers = &raw_packet[..ip_hdr_len + tcp_hdr_len];

    // Build fragment 1: up to the SNI split point
    let frag1 = build_tls_fragment(
        headers,
        ip_hdr_len,
        tcp_hdr_len,
        first_part,
        tcp_hdr.seq_num,
        tcp_hdr.ack_num,
        tcp_hdr.flags,
        tcp_hdr.window_size,
    );

    // Build fragment 2: from SNI split point to end
    let frag2 = build_tls_fragment(
        headers,
        ip_hdr_len,
        tcp_hdr_len,
        second_part,
        tcp_hdr.seq_num.wrapping_add(first_part.len() as u32),
        tcp_hdr.ack_num,
        tcp_hdr.flags,
        tcp_hdr.window_size,
    );

    Some(vec![frag1, frag2])
}

/// Alternative: Split using out-of-order delivery (send second fragment first).
/// Some DPI systems process packets in order and fail when fragments arrive
/// out of sequence.
pub fn split_tls_out_of_order(
    raw_packet: &[u8],
    ip_hdr: &IpHeader,
    tcp_hdr: &TcpHeader<'_>,
    hello: &TlsClientHello<'_>,
) -> Option<Vec<Vec<u8>>> {
    let payload = tcp_hdr.payload;
    if payload.is_empty() || !hello.has_sni() {
        return None;
    }

    let (split_at, _) = tls::find_sni_split_point(payload)?;
    if split_at == 0 || split_at >= payload.len() {
        return None;
    }

    let first_part = &payload[..split_at];
    let second_part = &payload[split_at..];

    let ip_hdr_len = ip_hdr.header_len();
    let tcp_hdr_len = tcp_hdr.header_len;
    let headers = &raw_packet[..ip_hdr_len + tcp_hdr_len];

    // Fragment 2 FIRST (out of order)
    let frag2 = build_tls_fragment(
        headers,
        ip_hdr_len,
        tcp_hdr_len,
        second_part,
        tcp_hdr.seq_num.wrapping_add(first_part.len() as u32),
        tcp_hdr.ack_num,
        tcp_hdr.flags,
        tcp_hdr.window_size,
    );

    // Then fragment 1
    let frag1 = build_tls_fragment(
        headers,
        ip_hdr_len,
        tcp_hdr_len,
        first_part,
        tcp_hdr.seq_num,
        tcp_hdr.ack_num,
        tcp_hdr.flags,
        tcp_hdr.window_size,
    );

    trace!(
        sni = %crate::logging::peer(hello.sni.as_deref().unwrap_or("-")),
        "sending TLS fragments out-of-order (frag2 → frag1)"
    );

    // Return in send order: frag2 first, then frag1
    Some(vec![frag2, frag1])
}

/// TLS record-layer fragmentation: split a single TLS Handshake record into
/// two TLS records within a SINGLE TCP segment. This defeats DPI that relies on
/// TCP reassembly but doesn't do TLS record reassembly.
///
/// Original: [TLS Record: type=0x16, len=N, ClientHello...]
/// Result:   [TLS Record: type=0x16, len=X, partial_CH] [TLS Record: type=0x16, len=N-X, rest_of_CH]
pub fn split_tls_record_layer(
    raw_packet: &[u8],
    ip_hdr: &IpHeader,
    tcp_hdr: &TcpHeader<'_>,
    hello: &TlsClientHello<'_>,
    split_position: usize,
) -> Option<Vec<Vec<u8>>> {
    let payload = tcp_hdr.payload;
    // Need at least a TLS record header (5 bytes) + some data
    if payload.len() < 10 || !hello.has_sni() {
        return None;
    }

    // Verify it's a TLS Handshake record (content_type 0x16)
    if payload[0] != 0x16 {
        return None;
    }

    let record_data_start = 5; // After TLS record header
    let record_data_len = ((payload[3] as usize) << 8) | payload[4] as usize;

    if record_data_start + record_data_len > payload.len() {
        return None;
    }

    // Find split point within the TLS record data (after the 5-byte header)
    let split_at_data = if split_position > 0 && split_position < record_data_len {
        split_position
    } else {
        // Auto: find SNI offset within the TLS record data
        let (tcp_split, _) = tls::find_sni_split_point(payload)?;
        // Convert from TCP payload offset to TLS record data offset
        if tcp_split <= record_data_start || tcp_split >= record_data_start + record_data_len {
            return None;
        }
        tcp_split - record_data_start
    };

    if split_at_data == 0 || split_at_data >= record_data_len {
        return None;
    }

    let first_data = &payload[record_data_start..record_data_start + split_at_data];
    let second_data =
        &payload[record_data_start + split_at_data..record_data_start + record_data_len];

    trace!(
        sni = %crate::logging::peer(hello.sni.as_deref().unwrap_or("-")),
        split_at_data = split_at_data,
        first_len = first_data.len(),
        second_len = second_data.len(),
        "splitting TLS record layer at SNI"
    );

    // Build new TLS payload: two concatenated TLS records
    let mut new_tls_payload = Vec::with_capacity(5 + first_data.len() + 5 + second_data.len());

    // First TLS record
    new_tls_payload.push(0x16); // Handshake
    new_tls_payload.push(payload[1]); // version major
    new_tls_payload.push(payload[2]); // version minor
    new_tls_payload.push((first_data.len() >> 8) as u8);
    new_tls_payload.push((first_data.len() & 0xFF) as u8);
    new_tls_payload.extend_from_slice(first_data);

    // Second TLS record
    new_tls_payload.push(0x16); // Handshake
    new_tls_payload.push(payload[1]); // version major
    new_tls_payload.push(payload[2]); // version minor
    new_tls_payload.push((second_data.len() >> 8) as u8);
    new_tls_payload.push((second_data.len() & 0xFF) as u8);
    new_tls_payload.extend_from_slice(second_data);

    // Build single IP packet with the new TLS payload
    let ip_hdr_len = ip_hdr.header_len();
    let tcp_hdr_len = tcp_hdr.header_len;
    let headers = &raw_packet[..ip_hdr_len + tcp_hdr_len];

    let packet = build_tls_fragment(
        headers,
        ip_hdr_len,
        tcp_hdr_len,
        &new_tls_payload,
        tcp_hdr.seq_num,
        tcp_hdr.ack_num,
        tcp_hdr.flags,
        tcp_hdr.window_size,
    );

    Some(vec![packet])
}

/// Split a TLS ClientHello into 3 TCP segments for stronger DPI evasion.
///
/// Strategy:
/// - Fragment 1: Everything before SNI + first 1-2 bytes of SNI name
/// - Fragment 2: Middle portion of SNI name
/// - Fragment 3: Rest of ClientHello
///
/// Splitting very early in the SNI means Fragment 1 has almost no domain
/// data, preventing DPI from making a blocking decision on a partial match.
///
/// If `disorder` is true, fragments are returned in reverse order
/// (frag3 → frag2 → frag1). This forces DPI to handle out-of-order
/// TCP reassembly, which many DPI systems handle poorly.
pub fn split_tls_multi_fragment(
    raw_packet: &[u8],
    ip_hdr: &IpHeader,
    tcp_hdr: &TcpHeader<'_>,
    hello: &TlsClientHello<'_>,
    disorder: bool,
) -> Option<Vec<Vec<u8>>> {
    let payload = tcp_hdr.payload;
    if payload.is_empty() || !hello.has_sni() {
        return None;
    }

    let sni_offset = hello.sni_offset?;
    let sni_length = hello.sni_length?;

    if sni_offset == 0 || sni_length < 4 || sni_offset >= payload.len() {
        return None;
    }

    // Split point 1: 1-2 bytes into the SNI name (cut VERY early).
    //
    // Fixed on purpose. Cutting the name within its first bytes is what stops
    // DPI matching on a prefix, and the fragment that results is the length of
    // everything before the SNI — so it tracks the SNI's position whatever
    // value is chosen here. Randomising it would move that by a byte or two
    // without hiding anything.
    let split1 = sni_offset + 2.min(sni_length);
    // Split point 2: somewhere further inside the name, chosen per packet.
    //
    // This one was a fixed fraction of the SNI length, which made the middle
    // fragment a pure function of it — for ordinary hostnames it landed in a
    // narrow band, the same value for the same site every time. Any cut inside
    // the name serves the strategy equally, so pick one at random.
    let split2 = sni_offset + second_split_offset(sni_length);

    if split1 >= split2 || split2 >= payload.len() {
        // SNI too short for 3-way split, fall back to 2-fragment
        return None;
    }

    let part1 = &payload[..split1];
    let part2 = &payload[split1..split2];
    let part3 = &payload[split2..];

    let ip_hdr_len = ip_hdr.header_len();
    let tcp_hdr_len = tcp_hdr.header_len;
    let headers = &raw_packet[..ip_hdr_len + tcp_hdr_len];

    trace!(
        sni = %crate::logging::peer(hello.sni.as_deref().unwrap_or("-")),
        split1 = split1,
        split2 = split2,
        total = payload.len(),
        disorder = disorder,
        "multi-fragment TLS ClientHello (3 segments)"
    );

    let frag1 = build_tls_fragment(
        headers,
        ip_hdr_len,
        tcp_hdr_len,
        part1,
        tcp_hdr.seq_num,
        tcp_hdr.ack_num,
        tcp_hdr.flags,
        tcp_hdr.window_size,
    );
    let frag2 = build_tls_fragment(
        headers,
        ip_hdr_len,
        tcp_hdr_len,
        part2,
        tcp_hdr.seq_num.wrapping_add(part1.len() as u32),
        tcp_hdr.ack_num,
        tcp_hdr.flags,
        tcp_hdr.window_size,
    );
    let frag3 = build_tls_fragment(
        headers,
        ip_hdr_len,
        tcp_hdr_len,
        part3,
        tcp_hdr
            .seq_num
            .wrapping_add((part1.len() + part2.len()) as u32),
        tcp_hdr.ack_num,
        tcp_hdr.flags,
        tcp_hdr.window_size,
    );

    if disorder {
        // Reverse order: frag3 first, then frag2, then frag1
        // Server reassembles correctly; DPI state machine gets confused
        Some(vec![frag3, frag2, frag1])
    } else {
        Some(vec![frag1, frag2, frag3])
    }
}

/// Build a single TLS fragment as a complete IP packet
#[allow(clippy::too_many_arguments)]
fn build_tls_fragment(
    original_headers: &[u8],
    ip_hdr_len: usize,
    tcp_hdr_len: usize,
    payload: &[u8],
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
) -> Vec<u8> {
    let total_len = ip_hdr_len + tcp_hdr_len + payload.len();
    let mut packet = Vec::with_capacity(total_len);

    // Copy headers
    packet.extend_from_slice(&original_headers[..ip_hdr_len]);
    packet.extend_from_slice(&original_headers[ip_hdr_len..ip_hdr_len + tcp_hdr_len]);
    packet.extend_from_slice(payload);

    // Fix IP length field
    let version = (packet[0] >> 4) & 0x0F;
    if version == 4 {
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    } else if version == 6 {
        let payload_len = (total_len - ip_hdr_len) as u16;
        packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
    }

    // Fix TCP fields
    let tcp_off = ip_hdr_len;
    packet[tcp_off + 4..tcp_off + 8].copy_from_slice(&seq.to_be_bytes());
    packet[tcp_off + 8..tcp_off + 12].copy_from_slice(&ack.to_be_bytes());
    packet[tcp_off + 13] = flags;
    packet[tcp_off + 14..tcp_off + 16].copy_from_slice(&window.to_be_bytes());

    // Recalculate checksums
    packet[tcp_off + 16] = 0;
    packet[tcp_off + 17] = 0;
    if version == 4 {
        // IP checksum
        packet[10] = 0;
        packet[11] = 0;
        let ip_cksum = ip::ipv4_checksum(&packet[..ip_hdr_len]);
        packet[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

        // TCP checksum
        if packet.len() >= 20 {
            let src_ip: [u8; 4] = packet[12..16].try_into().unwrap_or([0; 4]);
            let dst_ip: [u8; 4] = packet[16..20].try_into().unwrap_or([0; 4]);
            let tcp_cksum = tcp::tcp_checksum_v4(&src_ip, &dst_ip, &packet[tcp_off..]);
            packet[tcp_off + 16..tcp_off + 18].copy_from_slice(&tcp_cksum.to_be_bytes());
        }
    } else if version == 6 {
        // TCP checksum (mandatory for IPv6)
        if packet.len() >= 40 {
            let src_ip: [u8; 16] = packet[8..24].try_into().unwrap_or([0; 16]);
            let dst_ip: [u8; 16] = packet[24..40].try_into().unwrap_or([0; 16]);
            let tcp_cksum = tcp::tcp_checksum_v6(&src_ip, &dst_ip, &packet[tcp_off..]);
            packet[tcp_off + 16..tcp_off + 18].copy_from_slice(&tcp_cksum.to_be_bytes());
        }
    }

    packet
}

#[cfg(test)]
mod split_point_tests {
    use super::*;

    /// The second cut used to be a fixed fraction of the SNI length, so the
    /// middle fragment was the same size for the same site every time. It now
    /// varies, while staying inside the name so the split still does its job.
    #[test]
    fn the_second_split_varies_but_stays_inside_the_name() {
        for sni_length in [8usize, 15, 19, 47] {
            let mut seen = std::collections::BTreeSet::new();
            for _ in 0..300 {
                let offset = second_split_offset(sni_length);
                assert!(
                    offset > 2,
                    "must fall past the first cut at offset 2, got {offset}"
                );
                assert!(
                    offset <= sni_length,
                    "must stay within the {sni_length}-byte name, got {offset}"
                );
                seen.insert(offset);
            }
            assert!(
                seen.len() > 1,
                "a {sni_length}-byte name offers room to vary, saw only {seen:?}"
            );
        }
    }

    /// Names too short to offer a choice keep a deterministic cut rather than
    /// collapsing onto the first one or running past the name.
    #[test]
    fn very_short_names_still_get_a_usable_second_split() {
        for sni_length in [1usize, 2, 3] {
            let offset = second_split_offset(sni_length);
            assert!(
                offset >= 1 && offset <= sni_length.max(4),
                "offset {offset} is nonsense for a {sni_length}-byte name"
            );
        }
    }

    /// The jitter source has to actually vary, and stay inside its range.
    #[test]
    fn jitter_stays_in_range_and_is_not_constant() {
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..500 {
            let v = jitter(10);
            assert!(v < 10, "jitter({}) returned {v}", 10);
            seen.insert(v);
        }
        assert!(seen.len() > 5, "jitter barely varies: {seen:?}");
        assert_eq!(jitter(0), 0, "an empty range must not divide by zero");
    }
}
