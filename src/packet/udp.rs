// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/packet/udp.rs — UDP header parsing
//
// Minimal UDP parsing for QUIC desynchronization support.

/// UDP header size (fixed at 8 bytes)
const UDP_HEADER_LEN: usize = 8;

/// Parsed UDP header
#[derive(Debug)]
pub struct UdpHeader<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub payload: &'a [u8],
}

impl<'a> UdpHeader<'a> {
    /// Parse a UDP header from a byte slice (starting after IP header)
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        if data.len() < UDP_HEADER_LEN {
            return None;
        }

        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let length = u16::from_be_bytes([data[4], data[5]]);
        let checksum = u16::from_be_bytes([data[6], data[7]]);
        let payload = &data[UDP_HEADER_LEN..];

        Some(UdpHeader {
            src_port,
            dst_port,
            length,
            checksum,
            payload,
        })
    }

    /// Check if this is a QUIC port (typically 443/UDP)
    pub fn is_quic_port(&self) -> bool {
        self.dst_port == 443 || self.src_port == 443
    }

    /// Check if the payload looks like a QUIC initial packet
    pub fn is_quic_initial(&self) -> bool {
        if self.payload.len() < 5 {
            return false;
        }
        // QUIC long header: first bit is 1, second bit is 1 (long header form)
        // Initial packet type: bits 4-5 = 0b00
        let first_byte = self.payload[0];
        let is_long_header = first_byte & 0x80 != 0;
        let is_fixed_bit = first_byte & 0x40 != 0;

        if !is_long_header || !is_fixed_bit {
            return false;
        }

        // Check QUIC version (bytes 1-4): should be non-zero for valid QUIC
        let version = u32::from_be_bytes([
            self.payload[1],
            self.payload[2],
            self.payload[3],
            self.payload[4],
        ]);

        // Known QUIC versions (v1 and v2)
        matches!(version, 0x00000001 | 0x6b3343cf)
    }
}
