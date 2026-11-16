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

use crate::packet::ip::IpHeader;
use crate::packet::tcp::{self, TcpHeader};
use crate::packet::tls::TlsClientHello;

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

    if range == 0 {
        0
    } else {
        (x % range as u64) as usize
    }
}

/// The middle of the SNI value, as an offset into the segment's payload.
///
/// Taken from the parsed position rather than by re-parsing the payload, so it
/// also serves a segment that carries the SNI of a ClientHello begun earlier,
/// which does not itself start with a TLS header.
fn sni_midpoint(hello: &TlsClientHello<'_>) -> Option<usize> {
    let offset = hello.sni_offset?;
    let length = hello.sni_length?;
    if offset == 0 || length == 0 {
        return None;
    }
    Some(offset + length / 2)
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
        sni_midpoint(hello)?
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

    let (first_part, second_part) = payload.split_at_checked(split_at)?;
    let seg = |part: &[u8], seq: u32| {
        tcp::resegment(
            raw_packet,
            ip_hdr.header_len(),
            tcp_hdr.header_len,
            part,
            seq,
        )
    };

    // Fragment 1 up to the SNI split point, fragment 2 from there to the end
    let frag1 = seg(first_part, tcp_hdr.seq_num)?;
    let frag2 = seg(
        second_part,
        tcp_hdr.seq_num.wrapping_add(first_part.len() as u32),
    )?;

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

    let split_at = sni_midpoint(hello)?;
    if split_at == 0 || split_at >= payload.len() {
        return None;
    }

    let (first_part, second_part) = payload.split_at_checked(split_at)?;
    let seg = |part: &[u8], seq: u32| {
        tcp::resegment(
            raw_packet,
            ip_hdr.header_len(),
            tcp_hdr.header_len,
            part,
            seq,
        )
    };

    let frag2 = seg(
        second_part,
        tcp_hdr.seq_num.wrapping_add(first_part.len() as u32),
    )?;
    let frag1 = seg(first_part, tcp_hdr.seq_num)?;

    trace!(
        sni = %crate::logging::peer(hello.sni.as_deref().unwrap_or("-")),
        "sending TLS fragments out-of-order (frag2 → frag1)"
    );

    // Return in send order: frag2 first, then frag1
    Some(vec![frag2, frag1])
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

    let (head, part3) = payload.split_at_checked(split2)?;
    let (part1, part2) = head.split_at_checked(split1)?;
    let seg = |part: &[u8], seq: u32| {
        tcp::resegment(
            raw_packet,
            ip_hdr.header_len(),
            tcp_hdr.header_len,
            part,
            seq,
        )
    };

    trace!(
        sni = %crate::logging::peer(hello.sni.as_deref().unwrap_or("-")),
        split1 = split1,
        split2 = split2,
        total = payload.len(),
        disorder = disorder,
        "multi-fragment TLS ClientHello (3 segments)"
    );

    let seq = tcp_hdr.seq_num;
    let frag1 = seg(part1, seq)?;
    let frag2 = seg(part2, seq.wrapping_add(part1.len() as u32))?;
    let frag3 = seg(part3, seq.wrapping_add(head.len() as u32))?;

    if disorder {
        // Reverse order: frag3 first, then frag2, then frag1
        // Server reassembles correctly; DPI state machine gets confused
        Some(vec![frag3, frag2, frag1])
    } else {
        Some(vec![frag1, frag2, frag3])
    }
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
