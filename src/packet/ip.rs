// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/packet/ip.rs — IPv4 and IPv6 header parsing
//
// Provides zero-copy parsing of IP headers with accessor methods
// for all fields needed by DPI bypass strategies.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::bytes::{array_at, be16_at, fold, put_be16, sum_words, u8_at};

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
        let version = (u8_at(data, 0)? >> 4) & 0x0F;
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
        let h: [u8; IPV4_MIN_HEADER] = array_at(data, 0)?;

        let ihl = (h[0] & 0x0F) as usize;
        let header_length = ihl * 4;
        if header_length < IPV4_MIN_HEADER || data.len() < header_length {
            return None;
        }

        Some(Ipv4Header {
            version_ihl: h[0],
            dscp_ecn: h[1],
            total_length: u16::from_be_bytes([h[2], h[3]]),
            identification: u16::from_be_bytes([h[4], h[5]]),
            flags_fragment: u16::from_be_bytes([h[6], h[7]]),
            ttl: h[8],
            protocol: h[9],
            checksum: u16::from_be_bytes([h[10], h[11]]),
            src: Ipv4Addr::new(h[12], h[13], h[14], h[15]),
            dst: Ipv4Addr::new(h[16], h[17], h[18], h[19]),
            header_length,
        })
    }
}

impl Ipv6Header {
    fn parse(data: &[u8]) -> Option<Self> {
        let h: [u8; IPV6_HEADER] = array_at(data, 0)?;

        let traffic_class = ((h[0] & 0x0F) << 4) | ((h[1] >> 4) & 0x0F);
        let flow_label = ((h[1] as u32 & 0x0F) << 16) | ((h[2] as u32) << 8) | h[3] as u32;

        Some(Ipv6Header {
            traffic_class,
            flow_label,
            payload_length: u16::from_be_bytes([h[4], h[5]]),
            next_header: h[6],
            hop_limit: h[7],
            src: Ipv6Addr::from(array_at::<16>(&h, 8)?),
            dst: Ipv6Addr::from(array_at::<16>(&h, 24)?),
        })
    }
}

// ── Packet construction helpers ──

/// Compute IPv4 header checksum
pub fn ipv4_checksum(header: &[u8]) -> u16 {
    if header.len() < 2 {
        return 0;
    }
    fold(sum_words(header))
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
    let [l0, l1] = total_len.to_be_bytes();
    let [i0, i1] = identification.to_be_bytes();
    let [s0, s1, s2, s3] = src.octets();
    let [d0, d1, d2, d3] = dst.octets();
    let mut header = [
        0x45, // Version 4, IHL 5
        0x00, // DSCP/ECN
        l0, l1, i0, i1, 0x40, // Don't Fragment flag
        0x00, ttl, protocol, 0, 0, // checksum, zero for calculation
        s0, s1, s2, s3, d0, d1, d2, d3,
    ];

    let [c0, c1] = ipv4_checksum(&header).to_be_bytes();
    header[10] = c0;
    header[11] = c1;

    header.to_vec()
}

/// The header length an IPv4 packet declares, if the packet is IPv4 and
/// actually holds that much header.
///
/// The IHL field is attacker-influenced; a value below the minimum or beyond
/// the buffer must not be used to slice.
fn ipv4_header_len(packet: &[u8]) -> Option<usize> {
    let first = u8_at(packet, 0)?;
    if first >> 4 != 4 {
        return None;
    }
    let ihl = (first & 0x0F) as usize * 4;
    (ihl >= IPV4_MIN_HEADER && packet.len() >= ihl).then_some(ihl)
}

/// Write the length fields of a packet whose IP header is `ip_hdr_len` bytes
/// to match the packet's size: IPv4's total length, IPv6's payload length.
/// The IPv4 header checksum is left for the caller to refresh.
pub fn set_ip_lengths(packet: &mut [u8], ip_hdr_len: usize) -> Option<()> {
    let len = packet.len();
    match u8_at(packet, 0)? >> 4 {
        4 => put_be16(packet, 2, u16::try_from(len).ok()?),
        6 => put_be16(packet, 4, u16::try_from(len.checked_sub(ip_hdr_len)?).ok()?),
        _ => None,
    }
}

/// Recompute the header checksum of an IPv4 packet in place. None, and
/// nothing changed, if the packet is not IPv4 or its header is truncated.
pub fn refresh_ipv4_checksum(packet: &mut [u8]) -> Option<()> {
    let ihl = ipv4_header_len(packet)?;
    put_be16(packet, 10, 0)?;
    let checksum = ipv4_checksum(packet.get(..ihl)?);
    put_be16(packet, 10, checksum)
}

/// Give a burst of injected TCP segments one IPv4 identification each,
/// increasing in the order they go on the wire, as a Linux sender does.
///
/// Every packet of a burst starts as a copy of the intercepted packet's
/// header, so without this they would all carry its ID: several segments of
/// one flow in flight under a single non-zero ID is something no real stack
/// produces, and a DPI can match it on any connection.
///
/// The numbering starts from the ID the first TCP segment already carries. An
/// ID of zero is left alone, because that is what the kernel itself writes on
/// some don't-fragment packets, and a run of zeros is the honest copy of it.
/// Only unfragmented IPv4 TCP packets are renumbered: an IP fragment must keep
/// the ID it shares with its siblings, or the receiver can never reassemble
/// it, and IPv6 has no such field.
pub fn number_tcp_burst<'a>(packets: impl IntoIterator<Item = &'a mut Vec<u8>>) {
    let mut next: Option<u16> = None;
    for packet in packets {
        if ipv4_header_len(packet).is_none() || u8_at(packet, 9) != Some(6) {
            continue;
        }
        // More-fragments flag or a non-zero fragment offset: an IP fragment.
        if be16_at(packet, 6).is_none_or(|f| f & 0x3FFF != 0) {
            continue;
        }
        let id = match next {
            Some(id) => id,
            None => match be16_at(packet, 4) {
                Some(0) | None => return,
                Some(first) => first,
            },
        };
        if put_be16(packet, 4, id).is_none() || refresh_ipv4_checksum(packet).is_none() {
            continue;
        }
        next = Some(id.wrapping_add(1));
    }
}

/// Set TTL in a raw IPv4 packet and recalculate checksum
pub fn set_ipv4_ttl(packet: &mut [u8], new_ttl: u8) {
    // Bail before mutating so a malformed packet is left untouched rather
    // than TTL-modified with a stale checksum.
    if ipv4_header_len(packet).is_none() {
        return;
    }
    if super::bytes::put_u8(packet, 8, new_ttl).is_some() {
        let _ = refresh_ipv4_checksum(packet);
    }
}
