// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/packet/tls.rs — TLS ClientHello parsing
//
// Parses TLS ClientHello messages to extract the SNI (Server Name Indication)
// extension, which is the primary target for HTTPS DPI bypass.

use super::bytes::{array_at, be16_at, slice_at, u8_at};

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
    /// Where to pick up the extension walk when the SNI was not found because
    /// the ClientHello continues in a later TCP segment.
    pub resume: Option<ExtensionResume>,
}

/// The point an extension walk stopped at because the ClientHello runs past
/// the end of this TCP segment.
///
/// A post-quantum key share makes a ClientHello larger than one segment, and
/// browsers that shuffle extension order put the SNI after it about half the
/// time. The first segment then holds no name at all, and the second does not
/// start with a TLS header, so neither can be recognised on its own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtensionResume {
    /// Offset of the next unread extension header, counted from the start of
    /// this segment's payload. It can lie beyond the payload.
    pub next: usize,
    /// Extension bytes from `next` to the end of the extension block.
    pub remaining: usize,
}

/// Outcome of continuing an extension walk into a later segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Continuation {
    /// The SNI host name lies wholly in this segment.
    Sni {
        /// Offset of the name within this segment's payload.
        offset: usize,
        length: usize,
        name: String,
    },
    /// The walk runs past this segment too.
    Resume(ExtensionResume),
    /// No SNI, a malformed block, or a name split across segments.
    Exhausted,
}

/// Continue an extension walk in a segment that carries the middle or end of
/// a ClientHello. `resume.next` is relative to `data`.
pub fn continue_extension_walk(data: &[u8], resume: ExtensionResume) -> Continuation {
    let mut pos = resume.next;
    let mut remaining = resume.remaining;
    loop {
        if remaining < 4 {
            return Continuation::Exhausted;
        }
        if pos.saturating_add(4) > data.len() {
            return Continuation::Resume(ExtensionResume {
                next: pos,
                remaining,
            });
        }
        let (Some(ext_type), Some(ext_len)) = (be16_at(data, pos), be16_at(data, pos + 2)) else {
            return Continuation::Exhausted;
        };
        let ext_len = ext_len as usize;
        if 4 + ext_len > remaining {
            return Continuation::Exhausted;
        }
        if ext_type == TLS_EXT_SNI {
            // list length (2), name type (1), name length (2), name
            let body = pos + 4;
            let Some([_, _, name_type, l0, l1]) = array_at::<5>(data, body) else {
                return Continuation::Exhausted;
            };
            if ext_len < 5 || name_type != 0 {
                return Continuation::Exhausted;
            }
            let length = u16::from_be_bytes([l0, l1]) as usize;
            let offset = body + 5;
            if 5 + length > ext_len {
                return Continuation::Exhausted;
            }
            return match slice_at(data, offset, length).map(std::str::from_utf8) {
                Some(Ok(name)) => Continuation::Sni {
                    offset,
                    length,
                    name: name.to_lowercase(),
                },
                _ => Continuation::Exhausted,
            };
        }
        pos += 4 + ext_len;
        remaining -= 4 + ext_len;
    }
}

impl<'a> TlsClientHello<'a> {
    /// Try to parse a TLS ClientHello from TCP payload.
    /// Returns None if this is not a valid ClientHello.
    pub fn parse(data: &'a [u8]) -> Option<Self> {
        // Minimum TLS record header: 5 bytes
        // Content type (1) + Version (2) + Length (2)
        let [content_type, _, _, l0, l1] = array_at::<5>(data, 0)?;

        // Check content type is Handshake
        if content_type != TLS_HANDSHAKE {
            return None;
        }

        let record_length = u16::from_be_bytes([l0, l1]) as usize;

        // Allow partial records: when the OS splits a TLS ClientHello across
        // multiple TCP segments, the first segment contains the TLS record
        // header but not the full record. We parse with what we have.
        let available = data.len().min(5 + record_length);

        let record = data.get(..available)?;
        let handshake = data.get(5..available)?;

        // Handshake header: type (1) + length (3)
        if u8_at(handshake, 0) != Some(TLS_CLIENT_HELLO) {
            return None;
        }

        let [_, h1, h2, h3] = array_at::<4>(handshake, 0)?;
        let hs_length = ((h1 as usize) << 16) | ((h2 as usize) << 8) | (h3 as usize);

        // Allow partial handshake data (TCP segmentation)
        let hs_available = handshake.len().min(4 + hs_length);
        let hello = handshake.get(4..hs_available)?;

        // ClientHello structure:
        // Version (2) + Random (32) + Session ID length (1) + Session ID (var)
        // + Cipher suites length (2) + Cipher suites (var)
        // + Compression methods length (1) + Compression methods (var)
        // + Extensions length (2) + Extensions (var)

        if hello.len() < 38 {
            return None;
        }

        let client_version = be16_at(hello, 0)?;
        let mut pos = 2 + 32; // Skip version + random

        // Session ID
        let session_id_len = u8_at(hello, pos)? as usize;
        pos += 1 + session_id_len;
        if pos > hello.len() {
            return None;
        }

        // Cipher suites
        let cipher_suites_len = be16_at(hello, pos)? as usize;
        pos += 2 + cipher_suites_len;
        if pos > hello.len() {
            return None;
        }

        // Compression methods
        let comp_methods_len = u8_at(hello, pos)? as usize;
        pos += 1 + comp_methods_len;
        if pos > hello.len() {
            return None;
        }

        // Extensions
        let Some(extensions_len) = be16_at(hello, pos) else {
            return Some(TlsClientHello {
                record,
                sni: None,
                sni_offset: None,
                sni_length: None,
                version: client_version,
                resume: None,
            });
        };
        let extensions_len = extensions_len as usize;
        pos += 2;

        // Allow partial extensions (TCP may have split the record)
        let declared_end = pos + extensions_len;
        let extensions_end = declared_end.min(hello.len());
        // Offset of `hello` within the TCP payload: record and handshake headers.
        const HELLO_START: usize = 5 + 4;
        let mut resume: Option<ExtensionResume> = None;

        // Parse extensions looking for SNI
        let mut sni: Option<String> = None;
        let mut sni_offset: Option<usize> = None;
        let mut sni_length: Option<usize> = None;

        let mut ext_pos = pos;
        while ext_pos + 4 <= extensions_end {
            let (Some(ext_type), Some(ext_len)) =
                (be16_at(hello, ext_pos), be16_at(hello, ext_pos + 2))
            else {
                break;
            };
            let ext_len = ext_len as usize;
            ext_pos += 4;

            if ext_pos + ext_len > extensions_end {
                // This extension runs into the next segment. Unless it is the
                // SNI itself, its length says where the next one starts.
                if ext_type != TLS_EXT_SNI && ext_pos + ext_len <= declared_end {
                    resume = Some(ExtensionResume {
                        next: HELLO_START + ext_pos + ext_len,
                        remaining: declared_end - (ext_pos + ext_len),
                    });
                }
                ext_pos = usize::MAX;
                break;
            }

            if ext_type == TLS_EXT_SNI {
                // SNI extension structure:
                // Server name list length (2)
                // Server name type (1, 0 = hostname)
                // Server name length (2)
                // Server name (var)
                let sni_data = slice_at(hello, ext_pos, ext_len).unwrap_or_default();
                if let Some([_, _, name_type, n0, n1]) = array_at::<5>(sni_data, 0) {
                    let name_len = u16::from_be_bytes([n0, n1]) as usize;

                    if name_type == 0
                        && let Some(name_bytes) = slice_at(sni_data, 5, name_len)
                        && let Ok(name) = std::str::from_utf8(name_bytes)
                    {
                        // Calculate absolute offset in the TCP payload
                        // 5 (TLS record header) + 4 (handshake header) + offset within hello
                        let abs_offset = 5 + 4 + ext_pos + 5;
                        sni = Some(name.to_lowercase());
                        sni_offset = Some(abs_offset);
                        sni_length = Some(name_len);
                    }
                }
                break;
            }

            ext_pos += ext_len;
        }

        // The walk ran out of data between two extensions.
        if sni.is_none()
            && ext_pos != usize::MAX
            && ext_pos < declared_end
            && declared_end > hello.len()
        {
            resume = Some(ExtensionResume {
                next: HELLO_START + ext_pos,
                remaining: declared_end - ext_pos,
            });
        }

        Some(TlsClientHello {
            record,
            resume: resume.filter(|_| sni.is_none()),
            sni,
            sni_offset,
            sni_length,
            version: client_version,
        })
    }

    /// A segment carrying the SNI of a ClientHello that began in an earlier
    /// segment, described with the name's position in this segment's payload
    /// so the splitters can treat it like a whole one.
    pub fn continuation(segment: &'a [u8], sni: String, offset: usize, length: usize) -> Self {
        TlsClientHello {
            record: segment,
            sni: Some(sni),
            sni_offset: Some(offset),
            sni_length: Some(length),
            version: 0,
            resume: None,
        }
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

/// A complete ClientHello record for `domain`, shaped like a browser's.
///
/// Real servers answer it with a ServerHello: TLS 1.3 and 1.2 suites,
/// supported_versions and an X25519 key share. A bare hello offering no
/// usable cipher draws only a seven-byte alert, which is easy to lose, and is
/// not what a DPI box sees from a browser. The same goes for a decoy: a hello
/// carrying nothing but an SNI is a shape no browser sends, and a DPI can
/// pick the fake out by it.
///
/// The random, the session id and the key share are fresh for every call, as
/// they are in every real handshake; a repeated value would let a DPI match
/// each hello by it.
pub fn build_client_hello(domain: &str) -> Vec<u8> {
    fn ext(out: &mut Vec<u8>, kind: u16, data: &[u8]) {
        out.extend_from_slice(&kind.to_be_bytes());
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
        out.extend_from_slice(data);
    }

    let noise: [u8; 96] = crate::random::bytes();
    let (random, rest) = noise.split_at(32);
    let (session_id, key) = rest.split_at(32);

    let name = domain.as_bytes();
    let mut sni = ((name.len() + 3) as u16).to_be_bytes().to_vec();
    sni.push(0); // host_name
    sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni.extend_from_slice(name);

    let mut key_share = 36u16.to_be_bytes().to_vec(); // one entry: group, len, key
    key_share.extend_from_slice(&[0x00, 0x1d, 0x00, 0x20]); // x25519, 32 bytes
    key_share.extend_from_slice(key);

    let mut exts = Vec::new();
    ext(&mut exts, 0x0000, &sni);
    ext(&mut exts, 0x0017, &[]); // extended_master_secret
    ext(&mut exts, 0xff01, &[0x00]); // renegotiation_info, initial
    ext(
        &mut exts,
        0x000a, // supported_groups: x25519, secp256r1, secp384r1
        &[0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18],
    );
    ext(&mut exts, 0x000b, &[0x01, 0x00]); // ec_point_formats: uncompressed
    ext(&mut exts, 0x0023, &[]); // session_ticket, none held
    ext(
        &mut exts,
        0x0010, // ALPN: h2, http/1.1
        &[
            0x00, 0x0c, 0x02, b'h', b'2', 0x08, b'h', b't', b't', b'p', b'/', b'1', b'.', b'1',
        ],
    );
    ext(&mut exts, 0x0005, &[0x01, 0x00, 0x00, 0x00, 0x00]); // status_request: OCSP
    ext(&mut exts, 0x0033, &key_share);
    ext(&mut exts, 0x002b, &[0x04, 0x03, 0x04, 0x03, 0x03]); // versions 1.3, 1.2
    ext(
        &mut exts,
        0x000d, // signature_algorithms
        &[
            0x00, 0x16, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06,
            0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x03, 0x02, 0x01,
        ],
    );
    ext(&mut exts, 0x002d, &[0x01, 0x01]); // psk_key_exchange_modes: psk_dhe_ke

    let suites: [u16; 15] = [
        0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009,
        0xc013, 0xc014, 0x009c, 0x009d,
    ];
    let mut body = vec![0x03, 0x03];
    body.extend_from_slice(random);
    // A 32-byte legacy session id, as TLS 1.3 clients send for middlebox
    // compatibility; an empty one marks a hello as not from a browser.
    body.push(32);
    body.extend_from_slice(session_id);
    body.extend_from_slice(&((suites.len() * 2) as u16).to_be_bytes());
    for s in suites {
        body.extend_from_slice(&s.to_be_bytes());
    }
    body.extend_from_slice(&[0x01, 0x00]); // compression: null
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let mut hello = vec![TLS_CLIENT_HELLO];
    hello.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hello.extend_from_slice(&body);
    let mut record = vec![TLS_HANDSHAKE, 0x03, 0x01];
    record.extend_from_slice(&(hello.len() as u16).to_be_bytes());
    record.extend_from_slice(&hello);
    record
}

/// Check if a TCP payload starts with a TLS ClientHello
pub fn is_tls_client_hello(data: &[u8]) -> bool {
    u8_at(data, 0) == Some(TLS_HANDSHAKE) && u8_at(data, 5) == Some(TLS_CLIENT_HELLO)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Extension types in a ClientHello record, in order.
    fn extension_types(record: &[u8]) -> Vec<u16> {
        let body = &record[9..];
        let mut at = 2 + 32;
        at += 1 + body[at] as usize; // session id
        at += 2 + u16::from_be_bytes([body[at], body[at + 1]]) as usize; // suites
        at += 1 + body[at] as usize; // compression
        let end = at + 2 + u16::from_be_bytes([body[at], body[at + 1]]) as usize;
        at += 2;
        let mut types = Vec::new();
        while at < end {
            types.push(u16::from_be_bytes([body[at], body[at + 1]]));
            at += 4 + u16::from_be_bytes([body[at + 2], body[at + 3]]) as usize;
        }
        assert_eq!(at, end, "extension lengths do not add up");
        assert_eq!(end, body.len(), "bytes after the extensions");
        types
    }

    #[test]
    fn the_built_hello_is_complete_and_parses() {
        let hello = build_client_hello("discord.com");
        assert_eq!(
            u16::from_be_bytes([hello[3], hello[4]]) as usize,
            hello.len() - 5,
            "a short record leaves the server waiting"
        );
        let hs_len = u32::from_be_bytes([0, hello[6], hello[7], hello[8]]) as usize;
        assert_eq!(hs_len, hello.len() - 9);

        let parsed = TlsClientHello::parse(&hello).unwrap();
        assert_eq!(parsed.sni_domain(), Some("discord.com"));
        assert!(parsed.resume.is_none());
    }

    /// The extensions a TLS 1.3 browser sends: a hello carrying only an SNI is
    /// a shape no browser produces.
    #[test]
    fn the_built_hello_carries_a_browsers_extensions() {
        let types = extension_types(&build_client_hello("example.com"));
        for (kind, name) in [
            (0x0000, "server_name"),
            (0x000a, "supported_groups"),
            (0x000d, "signature_algorithms"),
            (0x0010, "ALPN"),
            (0x002b, "supported_versions"),
            (0x0033, "key_share"),
            (0x002d, "psk_key_exchange_modes"),
        ] {
            assert!(types.contains(&kind), "missing {name}");
        }
        let mut unique = types.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), types.len(), "an extension appears twice");
    }
}
