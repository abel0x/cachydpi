// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/packet/tcp.rs — TCP header parsing and manipulation
//
// Provides parsing, flag checking, and reconstruction of TCP headers
// for DPI bypass packet manipulation.

use super::bytes::{array_at, fold, put_be16, sum_words, u8_at};

/// Minimum TCP header length (no options)
const TCP_MIN_HEADER: usize = 20;

/// TCP flag bits
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;
pub const TCP_URG: u8 = 0x20;

/// Parsed TCP header with reference to payload
#[derive(Debug)]
pub struct TcpHeader<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset: u8, // Header length in 32-bit words
    pub flags: u8,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
    pub options: &'a [u8],
    pub payload: &'a [u8],
    /// Byte offset where TCP header starts in the transport slice
    pub header_len: usize,
}

impl<'a> TcpHeader<'a> {
    /// Parse a TCP header from a byte slice (starting right after IP header)
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        let h: [u8; TCP_MIN_HEADER] = array_at(data, 0)?;

        let src_port = u16::from_be_bytes([h[0], h[1]]);
        let dst_port = u16::from_be_bytes([h[2], h[3]]);
        let seq_num = u32::from_be_bytes([h[4], h[5], h[6], h[7]]);
        let ack_num = u32::from_be_bytes([h[8], h[9], h[10], h[11]]);
        let data_offset = (h[12] >> 4) & 0x0F;
        let flags = h[13];
        let window_size = u16::from_be_bytes([h[14], h[15]]);
        let checksum = u16::from_be_bytes([h[16], h[17]]);
        let urgent_ptr = u16::from_be_bytes([h[18], h[19]]);

        let header_len = (data_offset as usize) * 4;
        let options = data.get(TCP_MIN_HEADER..header_len)?;
        let payload = data.get(header_len..)?;

        Some(TcpHeader {
            src_port,
            dst_port,
            seq_num,
            ack_num,
            data_offset,
            flags,
            window_size,
            checksum,
            urgent_ptr,
            options,
            payload,
            header_len,
        })
    }

    // ── Flag helpers ──

    pub fn is_syn(&self) -> bool {
        self.flags & TCP_SYN != 0 && self.flags & TCP_ACK == 0
    }

    pub fn is_syn_ack(&self) -> bool {
        self.flags & (TCP_SYN | TCP_ACK) == (TCP_SYN | TCP_ACK)
    }

    pub fn is_ack(&self) -> bool {
        self.flags & TCP_ACK != 0 && self.flags & (TCP_SYN | TCP_FIN | TCP_RST) == 0
    }

    pub fn is_psh_ack(&self) -> bool {
        self.flags & (TCP_PSH | TCP_ACK) == (TCP_PSH | TCP_ACK)
    }

    pub fn is_rst(&self) -> bool {
        self.flags & TCP_RST != 0
    }

    pub fn is_fin(&self) -> bool {
        self.flags & TCP_FIN != 0
    }

    pub fn has_payload(&self) -> bool {
        !self.payload.is_empty()
    }

    /// Check if this is an HTTP port (80, 8080, etc.)
    pub fn is_http_port(&self) -> bool {
        matches!(self.dst_port, 80 | 8080 | 8888 | 3128)
            || matches!(self.src_port, 80 | 8080 | 8888 | 3128)
    }

    /// Check if this is an HTTPS port (443)
    pub fn is_https_port(&self) -> bool {
        self.dst_port == 443 || self.src_port == 443
    }
}

/// Compute TCP checksum (with IPv4 pseudo-header)
pub fn tcp_checksum_v4(src_ip: &[u8; 4], dst_ip: &[u8; 4], tcp_segment: &[u8]) -> u16 {
    if tcp_segment.len() < 2 {
        return 0;
    }
    // Pseudo-header: addresses, protocol (TCP=6) and TCP length; then the
    // segment, with its checksum field zeroed.
    fold(
        sum_words(src_ip)
            + sum_words(dst_ip)
            + 6
            + tcp_segment.len() as u32
            + sum_words(tcp_segment),
    )
}

/// Compute TCP checksum (with IPv6 pseudo-header)
pub fn tcp_checksum_v6(src_ip: &[u8; 16], dst_ip: &[u8; 16], tcp_segment: &[u8]) -> u16 {
    if tcp_segment.len() < 2 {
        return 0;
    }
    // Pseudo-header: addresses, 32-bit TCP length and next header (TCP=6);
    // then the segment, with its checksum field zeroed by the caller.
    let tcp_len = tcp_segment.len() as u32;
    fold(
        sum_words(src_ip)
            + sum_words(dst_ip)
            + (tcp_len >> 16)
            + (tcp_len & 0xFFFF)
            + 6
            + sum_words(tcp_segment),
    )
}

/// Build a TCP header from scratch
pub fn build_tcp_header(
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    let header_len = TCP_MIN_HEADER;
    let data_offset = (header_len / 4) as u8;

    let mut segment = Vec::with_capacity(header_len + payload.len());
    segment.extend_from_slice(&src_port.to_be_bytes());
    segment.extend_from_slice(&dst_port.to_be_bytes());
    segment.extend_from_slice(&seq.to_be_bytes());
    segment.extend_from_slice(&ack.to_be_bytes());
    segment.push(data_offset << 4);
    segment.push(flags);
    segment.extend_from_slice(&window.to_be_bytes());
    segment.extend_from_slice(&[0u8; 2]); // Checksum placeholder
    segment.extend_from_slice(&[0u8; 2]); // Urgent pointer
    segment.extend_from_slice(payload);

    segment
}

/// A segment cut from `raw_packet`: its IP and TCP headers, options included,
/// carrying `payload` at sequence number `seq`, with lengths and checksums
/// made to match. Every other header field, the IP ID and TTL among them, is
/// the original's; callers that need them different set them afterwards.
///
/// None if `raw_packet` is shorter than the headers it is said to hold, or
/// the result would not fit an IP length field.
pub fn resegment(
    raw_packet: &[u8],
    ip_hdr_len: usize,
    tcp_hdr_len: usize,
    payload: &[u8],
    seq: u32,
) -> Option<Vec<u8>> {
    let headers = raw_packet.get(..ip_hdr_len.checked_add(tcp_hdr_len)?)?;
    let mut packet = Vec::with_capacity(headers.len() + payload.len());
    packet.extend_from_slice(headers);
    packet.extend_from_slice(payload);

    super::ip::set_ip_lengths(&mut packet, ip_hdr_len)?;
    super::bytes::put_be32(&mut packet, ip_hdr_len + 4, seq)?;
    if u8_at(&packet, 0)? >> 4 == 4 {
        super::ip::refresh_ipv4_checksum(&mut packet)?;
    }
    try_refresh_tcp_checksum(&mut packet, ip_hdr_len)?;
    Some(packet)
}

/// Set the TCP checksum field in a TCP segment (must include pseudo-header contribution)
pub fn set_tcp_checksum(segment: &mut [u8], checksum: u16) {
    let _ = put_be16(segment, 16, checksum);
}

/// Modify the window size in a raw packet (IP + TCP) and refresh the TCP
/// checksum to match.
///
/// The checksum cannot be left to the kernel. The queue does not ask for GSO
/// packets, so the kernel completes the checksum before handing the packet
/// over, and a packet given back modified goes out as it is: a stale checksum
/// would make the server drop every SYN.
pub fn modify_window_size(packet: &mut [u8], ip_header_len: usize, new_window: u16) {
    let Some(window_at) = ip_header_len.checked_add(14) else {
        return;
    };
    if packet.len() < window_at + 4 {
        return;
    }
    if put_be16(packet, window_at, new_window).is_some() {
        refresh_tcp_checksum(packet, ip_header_len);
    }
}

/// Recompute the TCP checksum of a whole IPv4 or IPv6 packet in place.
///
/// Leaves the packet untouched when it is too short to hold the addresses and
/// the checksum field, or its IP version is neither 4 nor 6.
pub fn refresh_tcp_checksum(packet: &mut [u8], ip_header_len: usize) {
    let _ = try_refresh_tcp_checksum(packet, ip_header_len);
}

fn try_refresh_tcp_checksum(packet: &mut [u8], tcp_offset: usize) -> Option<()> {
    let checksum_at = tcp_offset.checked_add(16)?;
    if packet.len() < checksum_at + 2 {
        return None;
    }
    let checksum = match u8_at(packet, 0)? >> 4 {
        4 if tcp_offset >= 20 => {
            let src: [u8; 4] = array_at(packet, 12)?;
            let dst: [u8; 4] = array_at(packet, 16)?;
            put_be16(packet, checksum_at, 0)?;
            tcp_checksum_v4(&src, &dst, packet.get(tcp_offset..)?)
        }
        6 if tcp_offset >= 40 => {
            let src: [u8; 16] = array_at(packet, 8)?;
            let dst: [u8; 16] = array_at(packet, 24)?;
            put_be16(packet, checksum_at, 0)?;
            tcp_checksum_v6(&src, &dst, packet.get(tcp_offset..)?)
        }
        _ => return None,
    };
    put_be16(packet, checksum_at, checksum)
}
