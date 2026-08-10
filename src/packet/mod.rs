// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/packet/mod.rs — Packet parsing module
//
// Provides zero-copy parsing of IP, TCP, UDP, TLS, and HTTP packets.
// All parsers work on byte slices without allocation where possible.

pub mod http;
pub mod ip;
pub mod tcp;
pub mod tls;
pub mod udp;

use std::net::IpAddr;

/// Direction of a packet relative to the client
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Outgoing from client to server
    Outbound,
    /// Incoming from server to client (for passive DPI detection)
    Inbound,
}

/// Parsed representation of a network packet
#[derive(Debug)]
pub struct ParsedPacket<'a> {
    /// Raw packet bytes
    pub raw: &'a [u8],
    /// IP layer info
    pub ip: ip::IpHeader,
    /// Transport layer
    pub transport: TransportLayer<'a>,
    /// Packet direction
    pub direction: Direction,
}

/// Transport layer protocol data
#[derive(Debug)]
pub enum TransportLayer<'a> {
    Tcp(tcp::TcpHeader<'a>),
    Udp(udp::UdpHeader<'a>),
    Other(u8),
}

impl<'a> ParsedPacket<'a> {
    /// Parse a raw IP packet from nfqueue
    pub fn parse(raw: &'a [u8], direction: Direction) -> Option<Self> {
        if raw.is_empty() {
            return None;
        }

        let ip_header = ip::IpHeader::parse(raw)?;
        let transport_offset = ip_header.header_len();
        let transport_data = raw.get(transport_offset..)?;

        let transport = match ip_header.protocol() {
            ip::PROTO_TCP => {
                let tcp = tcp::TcpHeader::parse(transport_data)?;
                TransportLayer::Tcp(tcp)
            }
            ip::PROTO_UDP => {
                let udp = udp::UdpHeader::parse(transport_data)?;
                TransportLayer::Udp(udp)
            }
            proto => TransportLayer::Other(proto),
        };

        Some(ParsedPacket {
            raw,
            ip: ip_header,
            transport,
            direction,
        })
    }

    /// Check if this is a TCP packet
    pub fn is_tcp(&self) -> bool {
        matches!(self.transport, TransportLayer::Tcp(_))
    }

    /// Check if this is a UDP packet
    pub fn is_udp(&self) -> bool {
        matches!(self.transport, TransportLayer::Udp(_))
    }

    /// Get TCP header if available
    pub fn tcp(&self) -> Option<&tcp::TcpHeader<'a>> {
        match &self.transport {
            TransportLayer::Tcp(t) => Some(t),
            _ => None,
        }
    }

    /// Get UDP header if available
    pub fn udp(&self) -> Option<&udp::UdpHeader<'a>> {
        match &self.transport {
            TransportLayer::Udp(u) => Some(u),
            _ => None,
        }
    }

    /// Get source IP address
    pub fn src_addr(&self) -> IpAddr {
        self.ip.src_addr()
    }

    /// Get destination IP address
    pub fn dst_addr(&self) -> IpAddr {
        self.ip.dst_addr()
    }

    /// Get the TTL/hop limit of this packet
    pub fn ttl(&self) -> u8 {
        self.ip.ttl()
    }
}
