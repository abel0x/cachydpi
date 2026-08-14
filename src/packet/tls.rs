// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/packet/tls.rs — TLS ClientHello parsing
//
// Parses TLS ClientHello messages to extract the SNI (Server Name Indication)
// extension, which is the primary target for HTTPS DPI bypass.

/// TLS content type: Handshake
const TLS_HANDSHAKE: u8 = 0x16;
/// TLS handshake type: ClientHello
const TLS_CLIENT_HELLO: u8 = 0x01;
/// TLS extension type: server_name (SNI)
const TLS_EXT_SNI: u16 = 0x0000;

/// Result of TLS ClientHello parsing
#[derive(Debug)]
pub struct TlsClientHello<'a> {
    /// The full TLS record (header + payload)
    pub record: &'a [u8],
    /// Server Name Indication value (the domain name)
    pub sni: Option<String>,
    /// Byte offset of SNI within the TCP payload
    pub sni_offset: Option<usize>,
    /// Length of the SNI value
    pub sni_length: Option<usize>,
    /// TLS version from ClientHello
    pub version: u16,
}

impl<'a> TlsClientHello<'a> {
    /// Try to parse a TLS ClientHello from TCP payload.
    /// Returns None if this is not a valid ClientHello.
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        // Minimum TLS record header: 5 bytes
        // Content type (1) + Version (2) + Length (2)
        if data.len() < 5 {
            return None;
        }

        // Check content type is Handshake
        if data[0] != TLS_HANDSHAKE {
            return None;
        }

        let _record_version = u16::from_be_bytes([data[1], data[2]]);
        let record_length = u16::from_be_bytes([data[3], data[4]]) as usize;

        // Allow partial records: when the OS splits a TLS ClientHello across
        // multiple TCP segments, the first segment contains the TLS record
        // header but not the full record. We parse with what we have.
        let available = data.len().min(5 + record_length);

        let record = &data[..available];
        let handshake = &data[5..available];

        // Handshake header: type (1) + length (3)
        if handshake.is_empty() || handshake[0] != TLS_CLIENT_HELLO {
            return None;
        }

        if handshake.len() < 4 {
            return None;
        }

        let hs_length = ((handshake[1] as usize) << 16)
            | ((handshake[2] as usize) << 8)
            | (handshake[3] as usize);

        // Allow partial handshake data (TCP segmentation)
        let hs_available = handshake.len().min(4 + hs_length);
        let hello = &handshake[4..hs_available];

        // ClientHello structure:
        // Version (2) + Random (32) + Session ID length (1) + Session ID (var)
        // + Cipher suites length (2) + Cipher suites (var)
        // + Compression methods length (1) + Compression methods (var)
        // + Extensions length (2) + Extensions (var)

        if hello.len() < 38 {
            return None;
        }

        let client_version = u16::from_be_bytes([hello[0], hello[1]]);
        let mut pos = 2 + 32; // Skip version + random

        // Session ID
        if pos >= hello.len() {
            return None;
        }
        let session_id_len = hello[pos] as usize;
        pos += 1 + session_id_len;
        if pos > hello.len() {
            return None;
        }

        // Cipher suites
        if pos + 2 > hello.len() {
            return None;
        }
        let cipher_suites_len = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
        pos += 2 + cipher_suites_len;
        if pos > hello.len() {
            return None;
        }

        // Compression methods
        if pos >= hello.len() {
            return None;
        }
        let comp_methods_len = hello[pos] as usize;
        pos += 1 + comp_methods_len;
        if pos > hello.len() {
            return None;
        }

        // Extensions
        if pos + 2 > hello.len() {
            return Some(TlsClientHello {
                record,
                sni: None,
                sni_offset: None,
                sni_length: None,
                version: client_version,
            });
        }

        let extensions_len = u16::from_be_bytes([hello[pos], hello[pos + 1]]) as usize;
        pos += 2;

        // Allow partial extensions (TCP may have split the record)
        let extensions_end = (pos + extensions_len).min(hello.len());

        // Parse extensions looking for SNI
        let mut sni: Option<String> = None;
        let mut sni_offset: Option<usize> = None;
        let mut sni_length: Option<usize> = None;

        let mut ext_pos = pos;
        while ext_pos + 4 <= extensions_end {
            let ext_type = u16::from_be_bytes([hello[ext_pos], hello[ext_pos + 1]]);
            let ext_len = u16::from_be_bytes([hello[ext_pos + 2], hello[ext_pos + 3]]) as usize;
            ext_pos += 4;

            if ext_pos + ext_len > extensions_end {
                break;
            }

            if ext_type == TLS_EXT_SNI {
                // SNI extension structure:
                // Server name list length (2)
                // Server name type (1, 0 = hostname)
                // Server name length (2)
                // Server name (var)
                if ext_len >= 5 {
                    let sni_data = &hello[ext_pos..ext_pos + ext_len];
                    let _list_len = u16::from_be_bytes([sni_data[0], sni_data[1]]) as usize;
                    let name_type = sni_data[2];
                    let name_len = u16::from_be_bytes([sni_data[3], sni_data[4]]) as usize;

                    if name_type == 0 && sni_data.len() >= 5 + name_len {
                        let name_bytes = &sni_data[5..5 + name_len];
                        if let Ok(name) = std::str::from_utf8(name_bytes) {
                            // Calculate absolute offset in the TCP payload
                            // 5 (TLS record header) + 4 (handshake header) + offset within hello
                            let abs_offset = 5 + 4 + ext_pos + 5;
                            sni = Some(name.to_lowercase());
                            sni_offset = Some(abs_offset);
                            sni_length = Some(name_len);
                        }
                    }
                }
                break;
            }

            ext_pos += ext_len;
        }

        Some(TlsClientHello {
            record,
            sni,
            sni_offset,
            sni_length,
            version: client_version,
        })
    }

    /// Check if this ClientHello contains an SNI extension
    pub fn has_sni(&self) -> bool {
        self.sni.is_some()
    }

    /// Get the SNI domain name
    pub fn sni_domain(&self) -> Option<&str> {
        self.sni.as_deref()
    }
}

/// Find the byte position where we should split a TLS ClientHello
/// to separate the SNI from the rest of the handshake.
///
/// Returns (first_fragment_len, second_fragment_start) relative to TCP payload.
pub fn find_sni_split_point(tcp_payload: &[u8]) -> Option<(usize, usize)> {
    let hello = TlsClientHello::parse(tcp_payload)?;
    let offset = hello.sni_offset?;
    let length = hello.sni_length?;

    if offset == 0 || length == 0 {
        return None;
    }

    // Split in the middle of the SNI value
    let split_at = offset + length / 2;
    if split_at >= tcp_payload.len() {
        return None;
    }

    Some((split_at, split_at))
}

/// Whether an extracted SNI is syntactically a hostname.
///
/// This is a check on the *parser*, not on the peer. If the extension walk ever
/// locked onto the wrong offset it would still produce a length and a byte
/// range, and the resulting split points would cut somewhere harmless while the
/// DPI still saw the name intact — a silent failure that looks like working
/// fragmentation. Counting how often the extracted value is not a hostname
/// turns that into something measurable without recording any name.
///
/// RFC 6066 requires the SNI to be a DNS hostname: ASCII letters, digits,
/// hyphens and dots, at most 253 bytes, labels at most 63, no empty label (so
/// no leading, trailing or doubled dot). The parser lowercases, so uppercase
/// cannot appear here. Underscores are rejected deliberately — they are not
/// legal in a hostname, and an SNI carrying one is exactly the sort of anomaly
/// worth noticing.
pub fn is_hostname_syntax(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 {
        return false;
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
    {
        return false;
    }
    // A hostname needs at least two labels, and every label must be non-empty
    // and within 63 bytes.
    let labels: Vec<&str> = name.split('.').collect();
    labels.len() >= 2 && labels.iter().all(|l| !l.is_empty() && l.len() <= 63)
}

/// Check if a TCP payload starts with a TLS ClientHello
pub fn is_tls_client_hello(data: &[u8]) -> bool {
    if data.len() < 6 {
        return false;
    }
    data[0] == TLS_HANDSHAKE && data[5] == TLS_CLIENT_HELLO
}
