// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/packet/tcp.rs — TCP header parsing and manipulation
//
// Provides parsing, flag checking, and reconstruction of TCP headers
// for DPI bypass packet manipulation.

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
        if data.len() < TCP_MIN_HEADER {
            return None;
        }

        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let seq_num = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ack_num = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let data_offset = (data[12] >> 4) & 0x0F;
        let flags = data[13];
        let window_size = u16::from_be_bytes([data[14], data[15]]);
        let checksum = u16::from_be_bytes([data[16], data[17]]);
        let urgent_ptr = u16::from_be_bytes([data[18], data[19]]);

        let header_len = (data_offset as usize) * 4;
        if header_len < TCP_MIN_HEADER || data.len() < header_len {
            return None;
        }

        let options = &data[TCP_MIN_HEADER..header_len];
        let payload = &data[header_len..];

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
    let mut sum: u32 = 0;

    // Pseudo-header: src IP
    sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
    sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
    // Pseudo-header: dst IP
    sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
    sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
    // Pseudo-header: protocol (TCP=6) and TCP length
    sum += 6u32; // TCP protocol
    sum += tcp_segment.len() as u32;

    // TCP segment (with checksum field zeroed)
    let mut i = 0;
    while i < tcp_segment.len() - 1 {
        let word = u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]);
        sum += word as u32;
        i += 2;
    }
    if tcp_segment.len() % 2 == 1 {
        sum += (tcp_segment[tcp_segment.len() - 1] as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

/// Compute TCP checksum (with IPv6 pseudo-header)
pub fn tcp_checksum_v6(src_ip: &[u8; 16], dst_ip: &[u8; 16], tcp_segment: &[u8]) -> u16 {
    if tcp_segment.len() < 2 {
        return 0;
    }
    let mut sum: u32 = 0;

    // Pseudo-header: src IPv6 (16 bytes)
    for i in (0..16).step_by(2) {
        sum += u16::from_be_bytes([src_ip[i], src_ip[i + 1]]) as u32;
    }
    // Pseudo-header: dst IPv6 (16 bytes)
    for i in (0..16).step_by(2) {
        sum += u16::from_be_bytes([dst_ip[i], dst_ip[i + 1]]) as u32;
    }
    // Pseudo-header: TCP length (32-bit) and next header (TCP=6)
    let tcp_len = tcp_segment.len() as u32;
    sum += tcp_len >> 16;
    sum += tcp_len & 0xFFFF;
    sum += 6u32; // Next header: TCP

    // TCP segment (with checksum field zeroed by caller)
    let mut i = 0;
    while i < tcp_segment.len() - 1 {
        let word = u16::from_be_bytes([tcp_segment[i], tcp_segment[i + 1]]);
        sum += word as u32;
        i += 2;
    }
    if tcp_segment.len() % 2 == 1 {
        sum += (tcp_segment[tcp_segment.len() - 1] as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
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

/// Set the TCP checksum field in a TCP segment (must include pseudo-header contribution)
pub fn set_tcp_checksum(segment: &mut [u8], checksum: u16) {
    if segment.len() >= 18 {
        segment[16..18].copy_from_slice(&checksum.to_be_bytes());
    }
}

/// Modify the window size in a raw packet (IP + TCP)
pub fn modify_window_size(packet: &mut [u8], ip_header_len: usize, new_window: u16) {
    let tcp_offset = ip_header_len;
    if packet.len() < tcp_offset + 16 {
        return;
    }
    packet[tcp_offset + 14..tcp_offset + 16].copy_from_slice(&new_window.to_be_bytes());
}
