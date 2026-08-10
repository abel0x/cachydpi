// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/strategies/quic.rs — QUIC/UDP desynchronization
//
// Implements QUIC Initial packet desynchronization to bypass DPI
// that inspects QUIC SNI. QUIC uses UDP, so TCP-based strategies
// don't apply. Instead, we use IP-level fragmentation to split the
// UDP datagram so DPI cannot read the full QUIC Initial in one pass.
//
// Note: IP fragmentation only works with IPv4. IPv6 does not allow
// intermediate fragmentation (only the sender can fragment).

use crate::packet::ip::{self, IpHeader};
use crate::packet::udp::UdpHeader;

use tracing::trace;

/// Minimum QUIC packet size to attempt desync
const MIN_QUIC_PACKET: usize = 100;

/// Desynchronize a QUIC Initial packet using IPv4 fragmentation.
///
/// Strategy: Split the original IP packet into two IP fragments.
/// The UDP header + beginning of QUIC data goes in the first fragment,
/// and the rest of the QUIC data goes in the second fragment.
/// The receiver's IP stack reassembles them before passing to QUIC,
/// but DPI often cannot reassemble IP fragments.
///
/// Returns None if:
/// - Not a QUIC Initial packet
/// - Packet is too small
/// - IPv6 (IP fragmentation not supported for IPv6 in this implementation)
pub fn desync_quic_initial(
    raw_packet: &[u8],
    ip_hdr: &IpHeader,
    udp_hdr: &UdpHeader<'_>,
) -> Option<Vec<Vec<u8>>> {
    let udp_payload = udp_hdr.payload;
    if udp_payload.len() < MIN_QUIC_PACKET {
        return None;
    }

    // Verify QUIC Initial packet
    if !udp_hdr.is_quic_initial() {
        return None;
    }

    // IP fragmentation only works with IPv4
    if ip_hdr.is_v6() {
        trace!("QUIC desync skipped: IPv6 does not support sender-side IP fragmentation");
        return None;
    }

    let ip_hdr_len = ip_hdr.header_len();
    let transport_payload = &raw_packet[ip_hdr_len..]; // UDP header + UDP payload

    // Split point: must be at 8-byte boundary (IP fragmentation requirement)
    // Include the full UDP header (8 bytes) + enough QUIC header to split before SNI
    let split_offset = find_quic_split_point(udp_payload)?;
    // Transport-level offset: UDP header (8) + QUIC split point
    let transport_split = 8 + split_offset;
    // Round up to 8-byte boundary for IP fragmentation
    let frag_boundary = (transport_split + 7) & !7;

    if frag_boundary >= transport_payload.len() || frag_boundary == 0 {
        return None;
    }

    trace!(
        split_at = frag_boundary,
        total_transport = transport_payload.len(),
        "fragmenting QUIC Initial via IP fragmentation"
    );

    let identification = ip_hdr.identification();
    let first_data = &transport_payload[..frag_boundary];
    let second_data = &transport_payload[frag_boundary..];

    // Fragment 1: IP header (MF=1, offset=0) + first part of transport data
    let frag1 = build_ipv4_fragment(
        raw_packet,
        ip_hdr_len,
        first_data,
        identification,
        0,    // fragment offset = 0
        true, // More Fragments = true
    );

    // Fragment 2: IP header (MF=0, offset=frag_boundary/8) + rest of transport data
    let frag2 = build_ipv4_fragment(
        raw_packet,
        ip_hdr_len,
        second_data,
        identification,
        (frag_boundary / 8) as u16, // fragment offset in 8-byte units
        false,                      // More Fragments = false (last fragment)
    );

    Some(vec![frag1, frag2])
}

/// Find the best split point in a QUIC Initial packet.
///
/// We parse the QUIC long header to find where the ClientHello
/// crypto data begins, and split there.
fn find_quic_split_point(data: &[u8]) -> Option<usize> {
    if data.len() < 7 {
        return None;
    }

    // QUIC Long Header format:
    // Byte 0: Header form (1) + Fixed bit (1) + Long Packet Type (2) + Reserved (2) + Packet Number Length (2)
    // Bytes 1-4: Version
    // Byte 5: DCID Length
    let dcid_len = data[5] as usize;
    let mut pos = 6 + dcid_len;

    if pos >= data.len() {
        return None;
    }

    // SCID Length
    let scid_len = data[pos] as usize;
    pos += 1 + scid_len;

    if pos >= data.len() {
        return None;
    }

    // Token Length (variable-length integer)
    let (token_len, token_len_size) = decode_quic_varint(&data[pos..])?;
    pos += token_len_size + token_len as usize;

    if pos + 2 > data.len() {
        return None;
    }

    // Payload Length (variable-length integer)
    let (_payload_len, payload_len_size) = decode_quic_varint(&data[pos..])?;
    pos += payload_len_size;

    // pos now points to the start of the encrypted payload
    // Split roughly in the middle of the packet
    let total = data.len();
    let split = if pos + 10 < total {
        // Split after the header but before full payload
        pos + 10
    } else {
        total / 2
    };

    if split > 0 && split < total {
        Some(split)
    } else {
        None
    }
}

/// Decode a QUIC variable-length integer (RFC 9000 Section 16)
fn decode_quic_varint(data: &[u8]) -> Option<(u64, usize)> {
    if data.is_empty() {
        return None;
    }

    let prefix = data[0] >> 6;
    match prefix {
        0 => Some((data[0] as u64 & 0x3F, 1)),
        1 => {
            if data.len() < 2 {
                return None;
            }
            let val = ((data[0] as u64 & 0x3F) << 8) | data[1] as u64;
            Some((val, 2))
        }
        2 => {
            if data.len() < 4 {
                return None;
            }
            let val = ((data[0] as u64 & 0x3F) << 24)
                | ((data[1] as u64) << 16)
                | ((data[2] as u64) << 8)
                | data[3] as u64;
            Some((val, 4))
        }
        3 => {
            if data.len() < 8 {
                return None;
            }
            let val = ((data[0] as u64 & 0x3F) << 56)
                | ((data[1] as u64) << 48)
                | ((data[2] as u64) << 40)
                | ((data[3] as u64) << 32)
                | ((data[4] as u64) << 24)
                | ((data[5] as u64) << 16)
                | ((data[6] as u64) << 8)
                | data[7] as u64;
            Some((val, 8))
        }
        _ => None,
    }
}

/// Build an IPv4 fragment from the original packet's IP header
fn build_ipv4_fragment(
    original_packet: &[u8],
    ip_hdr_len: usize,
    fragment_data: &[u8],
    identification: u16,
    frag_offset: u16,
    more_fragments: bool,
) -> Vec<u8> {
    let total_len = ip_hdr_len + fragment_data.len();
    let mut packet = Vec::with_capacity(total_len);

    // Copy original IP header
    packet.extend_from_slice(&original_packet[..ip_hdr_len]);
    // Append fragment payload
    packet.extend_from_slice(fragment_data);

    // Fix IP total length
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());

    // Set identification field
    packet[4..6].copy_from_slice(&identification.to_be_bytes());

    // Set flags + fragment offset
    // Bits: [0]=Reserved, [1]=Don't Fragment, [2]=More Fragments
    // Fragment offset is in 8-byte units, occupies bits 3-15
    let mut flags_frag: u16 = frag_offset & 0x1FFF;
    if more_fragments {
        flags_frag |= 0x2000; // MF flag
    }
    // Clear DF flag (we need fragmentation)
    packet[6..8].copy_from_slice(&flags_frag.to_be_bytes());

    // Recalculate IP checksum
    packet[10] = 0;
    packet[11] = 0;
    let cksum = ip::ipv4_checksum(&packet[..ip_hdr_len]);
    packet[10..12].copy_from_slice(&cksum.to_be_bytes());

    packet
}
