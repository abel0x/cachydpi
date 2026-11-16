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
use crate::packet::ip::IpHeader;
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

    let (first_part, second_part) = payload.split_at_checked(split_at)?;

    // Two TCP segments; the second's sequence number advances by the first's
    // length.
    let ip_hdr_len = ip_hdr.header_len();
    let tcp_hdr_len = tcp_hdr.header_len;
    let seq = tcp_hdr.seq_num;
    let frag1 = tcp::resegment(raw_packet, ip_hdr_len, tcp_hdr_len, first_part, seq)?;
    let seq2 = seq.wrapping_add(first_part.len() as u32);
    let frag2 = tcp::resegment(raw_packet, ip_hdr_len, tcp_hdr_len, second_part, seq2)?;

    Some(vec![frag1, frag2])
}
