// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/packet/ip.rs — IPv4 and IPv6 header parsing
//
// Provides zero-copy parsing of IP headers with accessor methods
// for all fields needed by DPI bypass strategies.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// IP protocol numbers
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMP: u8 = 1;
pub const PROTO_ICMPV6: u8 = 58;

/// Minimum IPv4 header size (no options)
const IPV4_MIN_HEADER: usize = 20;
/// Fixed IPv6 header size
const IPV6_HEADER: usize = 40;

/// Parsed IP header (supports both v4 and v6)
#[derive(Debug, Clone)]
pub enum IpHeader {
    V4(Ipv4Header),
    V6(Ipv6Header),
}

#[derive(Debug, Clone)]
pub struct Ipv4Header {
    pub version_ihl: u8,
    pub dscp_ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags_fragment: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub header_length: usize,
}

#[derive(Debug, Clone)]
pub struct Ipv6Header {
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src: Ipv6Addr,
    pub dst: Ipv6Addr,
}

impl IpHeader {
    /// Parse an IP header from a raw byte slice
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.is_empty() {
            return None;
        }

        let version = (data[0] >> 4) & 0x0F;
        match version {
            4 => Ipv4Header::parse(data).map(IpHeader::V4),
            6 => Ipv6Header::parse(data).map(IpHeader::V6),
            _ => None,
        }
    }

    /// Get the total header length in bytes
    pub fn header_len(&self) -> usize {
        match self {
            IpHeader::V4(h) => h.header_length,
            IpHeader::V6(_) => IPV6_HEADER,
        }
    }

    /// Get the transport protocol number
    pub fn protocol(&self) -> u8 {
        match self {
            IpHeader::V4(h) => h.protocol,
            IpHeader::V6(h) => h.next_header,
        }
    }

    /// Get the TTL (IPv4) or Hop Limit (IPv6)
    pub fn ttl(&self) -> u8 {
        match self {
            IpHeader::V4(h) => h.ttl,
            IpHeader::V6(h) => h.hop_limit,
        }
    }

    /// Get source address
    pub fn src_addr(&self) -> IpAddr {
        match self {
            IpHeader::V4(h) => IpAddr::V4(h.src),
            IpHeader::V6(h) => IpAddr::V6(h.src),
        }
    }

    /// Get destination address
    pub fn dst_addr(&self) -> IpAddr {
        match self {
            IpHeader::V4(h) => IpAddr::V4(h.dst),
            IpHeader::V6(h) => IpAddr::V6(h.dst),
        }
    }

    /// Check if this is IPv4
    pub fn is_v4(&self) -> bool {
        matches!(self, IpHeader::V4(_))
    }

    /// Check if this is IPv6
    pub fn is_v6(&self) -> bool {
        matches!(self, IpHeader::V6(_))
    }

    /// Get the total packet length (saturates at u16::MAX for IPv6 jumbo)
    pub fn total_length(&self) -> u16 {
        match self {
            IpHeader::V4(h) => h.total_length,
            IpHeader::V6(h) => {
                let total = h.payload_length as u32 + IPV6_HEADER as u32;
                total.min(u16::MAX as u32) as u16
            }
        }
    }

    /// Get IPv4 identification field (for reassembly tracking)
    pub fn identification(&self) -> u16 {
        match self {
            IpHeader::V4(h) => h.identification,
            IpHeader::V6(_) => 0,
        }
    }
}

impl Ipv4Header {
    fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < IPV4_MIN_HEADER {
            return None;
        }

        let ihl = (data[0] & 0x0F) as usize;
        let header_length = ihl * 4;
        if header_length < IPV4_MIN_HEADER || data.len() < header_length {
            return None;
        }

        let total_length = u16::from_be_bytes([data[2], data[3]]);
        let identification = u16::from_be_bytes([data[4], data[5]]);
        let flags_fragment = u16::from_be_bytes([data[6], data[7]]);

        Some(Ipv4Header {
            version_ihl: data[0],
            dscp_ecn: data[1],
            total_length,
            identification,
            flags_fragment,
            ttl: data[8],
            protocol: data[9],
            checksum: u16::from_be_bytes([data[10], data[11]]),
            src: Ipv4Addr::new(data[12], data[13], data[14], data[15]),
            dst: Ipv4Addr::new(data[16], data[17], data[18], data[19]),
            header_length,
        })
    }
}

impl Ipv6Header {
    fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < IPV6_HEADER {
            return None;
        }

        let traffic_class = ((data[0] & 0x0F) << 4) | ((data[1] >> 4) & 0x0F);
        let flow_label = ((data[1] as u32 & 0x0F) << 16) | ((data[2] as u32) << 8) | data[3] as u32;
        let payload_length = u16::from_be_bytes([data[4], data[5]]);

        let mut src_bytes = [0u8; 16];
        let mut dst_bytes = [0u8; 16];
        src_bytes.copy_from_slice(&data[8..24]);
        dst_bytes.copy_from_slice(&data[24..40]);

        Some(Ipv6Header {
            traffic_class,
            flow_label,
            payload_length,
            next_header: data[6],
            hop_limit: data[7],
            src: Ipv6Addr::from(src_bytes),
            dst: Ipv6Addr::from(dst_bytes),
        })
    }
}

// ── Packet construction helpers ──

/// Compute IPv4 header checksum
pub fn ipv4_checksum(header: &[u8]) -> u16 {
    if header.len() < 2 {
        return 0;
    }
    let mut sum: u32 = 0;
    let len = header.len();
    let mut i = 0;

    while i < len - 1 {
        let word = u16::from_be_bytes([header[i], header[i + 1]]);
        sum += word as u32;
        i += 2;
    }
    if len % 2 == 1 {
        sum += (header[len - 1] as u32) << 8;
    }

    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    !sum as u16
}

/// Build an IPv4 header from scratch
pub fn build_ipv4_header(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: u8,
    ttl: u8,
    payload_len: usize,
    identification: u16,
) -> Vec<u8> {
    let total_len = (IPV4_MIN_HEADER + payload_len) as u16;
    let mut header = vec![0u8; IPV4_MIN_HEADER];

    header[0] = 0x45; // Version 4, IHL 5
    header[1] = 0x00; // DSCP/ECN
    header[2..4].copy_from_slice(&total_len.to_be_bytes());
    header[4..6].copy_from_slice(&identification.to_be_bytes());
    header[6] = 0x40; // Don't Fragment flag
    header[7] = 0x00;
    header[8] = ttl;
    header[9] = protocol;
    // Checksum at [10..12] = 0 for calculation
    header[12..16].copy_from_slice(&src.octets());
    header[16..20].copy_from_slice(&dst.octets());

    // Calculate and set checksum
    let cksum = ipv4_checksum(&header);
    header[10..12].copy_from_slice(&cksum.to_be_bytes());

    header
}

/// Set TTL in a raw IPv4 packet and recalculate checksum
pub fn set_ipv4_ttl(packet: &mut [u8], new_ttl: u8) {
    if packet.len() < IPV4_MIN_HEADER {
        return;
    }
    let version = (packet[0] >> 4) & 0x0F;
    if version != 4 {
        return;
    }

    // The IHL field is attacker-influenced; a header length that exceeds the
    // buffer (or is below the minimum) must not be used to slice, or the
    // ipv4_checksum call below would panic. Bail before mutating so a malformed
    // packet is left untouched rather than TTL-modified with a stale checksum.
    let ihl = (packet[0] & 0x0F) as usize * 4;
    if ihl < IPV4_MIN_HEADER || packet.len() < ihl {
        return;
    }

    packet[8] = new_ttl;
    // Recalculate header checksum
    packet[10] = 0;
    packet[11] = 0;
    let cksum = ipv4_checksum(&packet[..ihl]);
    packet[10..12].copy_from_slice(&cksum.to_be_bytes());
}
