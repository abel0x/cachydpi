// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/strategies/http_split.rs — HTTP request fragmentation
//
// Splits an outgoing HTTP request into two or more TCP segments
// so that DPI systems cannot reassemble the Host header in a single pass.
//
// Technique: Drop the original packet, then send two smaller TCP segments
// via raw socket, each containing part of the HTTP request.

use crate::packet::http;
use crate::packet::ip::{self, IpHeader};
use crate::packet::tcp::{self, TcpHeader};

use tracing::trace;

/// Split an HTTP request packet into multiple TCP segments.
///
/// Returns None if the packet cannot/doesn't need to be split.
/// Returns Some(fragments) where each fragment is a complete IP packet ready to send.
///
/// # Arguments
/// * `raw_packet` - The complete original IP packet
/// * `ip_hdr` - Parsed IP header
/// * `tcp_hdr` - Parsed TCP header
/// * `split_position` - Where to split: 0=auto (middle of Host), >0 = fixed offset
pub fn split_http_request(
    raw_packet: &[u8],
    ip_hdr: &IpHeader,
    tcp_hdr: &TcpHeader<'_>,
    split_position: usize,
) -> Option<Vec<Vec<u8>>> {
    let payload = tcp_hdr.payload;
    if payload.is_empty() {
        return None;
    }

    // Verify this is an HTTP request
    if !http::is_http_request(payload) {
        return None;
    }

    // Find split point
    let split_at = if split_position > 0 && split_position < payload.len() {
        split_position
    } else {
        http::find_http_split_point(payload)?
    };

    if split_at == 0 || split_at >= payload.len() {
        return None;
    }

    trace!(
        split_at = split_at,
        total = payload.len(),
        "splitting HTTP request"
    );

    let first_part = &payload[..split_at];
    let second_part = &payload[split_at..];

    // Build two TCP segments
    let ip_hdr_len = ip_hdr.header_len();
    let tcp_hdr_len = tcp_hdr.header_len;
    let ip_and_tcp_header = &raw_packet[..ip_hdr_len + tcp_hdr_len];

    // Fragment 1: IP+TCP headers + first part of payload
    let frag1 = build_fragment(
        ip_and_tcp_header,
        ip_hdr_len,
        tcp_hdr_len,
        first_part,
        tcp_hdr.seq_num,
        tcp_hdr.ack_num,
        tcp_hdr.flags,
        tcp_hdr.window_size,
    );

    // Fragment 2: IP+TCP headers + second part of payload
    // Sequence number advances by first_part length
    let frag2 = build_fragment(
        ip_and_tcp_header,
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

/// Build a single TCP fragment (complete IP packet) from headers + payload
#[allow(clippy::too_many_arguments)]
fn build_fragment(
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

    // Copy original IP header
    packet.extend_from_slice(&original_headers[..ip_hdr_len]);
    // Copy original TCP header (including options)
    packet.extend_from_slice(&original_headers[ip_hdr_len..ip_hdr_len + tcp_hdr_len]);
    // Append payload
    packet.extend_from_slice(payload);

    // Fix IP length field
    let version = (packet[0] >> 4) & 0x0F;
    if version == 4 {
        let ip_total_len = total_len as u16;
        packet[2..4].copy_from_slice(&ip_total_len.to_be_bytes());
    } else if version == 6 {
        let payload_len = (total_len - ip_hdr_len) as u16;
        packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
    }

    // Fix TCP sequence number
    let tcp_offset = ip_hdr_len;
    packet[tcp_offset + 4..tcp_offset + 8].copy_from_slice(&seq.to_be_bytes());
    packet[tcp_offset + 8..tcp_offset + 12].copy_from_slice(&ack.to_be_bytes());
    packet[tcp_offset + 13] = flags;
    packet[tcp_offset + 14..tcp_offset + 16].copy_from_slice(&window.to_be_bytes());

    // Recalculate checksums
    packet[tcp_offset + 16] = 0;
    packet[tcp_offset + 17] = 0;
    if version == 4 {
        // IP checksum
        packet[10] = 0;
        packet[11] = 0;
        let cksum = ip::ipv4_checksum(&packet[..ip_hdr_len]);
        packet[10..12].copy_from_slice(&cksum.to_be_bytes());

        // TCP checksum
        if packet.len() >= 20 {
            let src_ip: [u8; 4] = packet[12..16].try_into().unwrap_or([0; 4]);
            let dst_ip: [u8; 4] = packet[16..20].try_into().unwrap_or([0; 4]);
            let cksum = tcp::tcp_checksum_v4(&src_ip, &dst_ip, &packet[tcp_offset..]);
            packet[tcp_offset + 16..tcp_offset + 18].copy_from_slice(&cksum.to_be_bytes());
        }
    } else if version == 6 {
        // TCP checksum (mandatory for IPv6)
        if packet.len() >= 40 {
            let src_ip: [u8; 16] = packet[8..24].try_into().unwrap_or([0; 16]);
            let dst_ip: [u8; 16] = packet[24..40].try_into().unwrap_or([0; 16]);
            let cksum = tcp::tcp_checksum_v6(&src_ip, &dst_ip, &packet[tcp_offset..]);
            packet[tcp_offset + 16..tcp_offset + 18].copy_from_slice(&cksum.to_be_bytes());
        }
    }

    packet
}
