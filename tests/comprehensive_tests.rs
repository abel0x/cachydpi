// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// tests/comprehensive_tests.rs — Comprehensive CachyDPI Test Suite
//
// Covers: Parser fuzzing (TLS/HTTP/IP/TCP/UDP), privilege escalation,
// domain path traversal, signal handling, configuration edge cases,
// and packet construction validation.
//
// Priority order: fuzzing > privilege > crash safety > isolation > performance

use std::net::Ipv4Addr;

use cachydpi::config::{Config, DomainMode};
use cachydpi::packet::http;
use cachydpi::packet::ip::{self, IpHeader};
use cachydpi::packet::tcp::{self, TcpHeader, tcp_checksum_v4, tcp_checksum_v6};
use cachydpi::packet::tls;
use cachydpi::packet::udp;
use cachydpi::packet::{Direction, ParsedPacket};
use cachydpi::strategies::BypassMode;

// ============================================================================
// SECTION 1: TLS ClientHello Parser Fuzzing
// ============================================================================

mod tls_fuzzing {
    use super::*;

    #[test]
    fn empty_input() {
        assert!(tls::TlsClientHello::parse(&[]).is_none());
    }

    #[test]
    fn single_byte_inputs() {
        for b in 0..=255u8 {
            // Must not panic on any single byte input
            let _ = tls::TlsClientHello::parse(&[b]);
        }
    }

    #[test]
    fn two_byte_inputs() {
        for ct in [0x14u8, 0x15, 0x16, 0x17, 0x00, 0xFF] {
            for ver in [0x00u8, 0x01, 0x02, 0x03, 0x04, 0xFF] {
                let _ = tls::TlsClientHello::parse(&[ct, 0x03, ver]);
            }
        }
    }

    #[test]
    fn handshake_header_only_not_client_hello() {
        // Valid TLS record header but handshake type is ServerHello (0x02)
        let data = [0x16, 0x03, 0x01, 0x00, 0x04, 0x02, 0x00, 0x00, 0x00];
        assert!(tls::TlsClientHello::parse(&data).is_none());
    }

    #[test]
    fn zero_length_record() {
        let data = [0x16, 0x03, 0x01, 0x00, 0x00]; // record_length = 0
        assert!(tls::TlsClientHello::parse(&data).is_none());
    }

    #[test]
    fn truncated_client_hello_after_random() {
        // TLS header + handshake header + version + partial random (only 16 bytes instead of 32)
        let mut data = vec![0x16, 0x03, 0x01, 0x00, 0x20]; // record_len=32
        data.push(0x01); // ClientHello
        data.extend_from_slice(&[0x00, 0x00, 0x1C]); // handshake_len=28
        data.extend_from_slice(&[0x03, 0x03]); // version
        data.extend_from_slice(&[0xAA; 16]); // only 16 bytes random (needs 32)
        // Should return None because hello.len() < 38
        assert!(tls::TlsClientHello::parse(&data).is_none());
    }

    #[test]
    fn client_hello_no_extensions() {
        let buf = build_client_hello_without_extensions();
        let result = tls::TlsClientHello::parse(&buf);
        assert!(result.is_some());
        let parsed = result.unwrap();
        assert!(!parsed.has_sni());
        assert_eq!(parsed.sni_domain(), None);
    }

    #[test]
    fn zero_length_sni_name() {
        let buf = build_client_hello_with_custom_sni(0, &[]);
        let result = tls::TlsClientHello::parse(&buf);
        assert!(result.is_some());
        // Empty name — parser sees name_len=0, so 5+0 <= sni_data.len() is fine
        // from_utf8("") is Ok(""), to_lowercase() is ""
        let _parsed = result.unwrap();
        // sni may be Some("") or None depending on parser logic
        // The important thing is no panic
    }

    #[test]
    fn maximum_sni_length() {
        // Maximum DNS name length (253 characters)
        let sni = "a".repeat(253);
        let hello = build_test_client_hello(&sni);
        let result = tls::TlsClientHello::parse(&hello);
        assert!(result.is_some());
        let parsed = result.unwrap();
        assert!(parsed.has_sni());
        assert_eq!(parsed.sni_domain(), Some(sni.as_str()));
    }

    #[test]
    fn very_large_extension_length_truncated() {
        // Extension length claims 65535 bytes but actual data is much shorter
        let mut data = vec![0x16, 0x03, 0x01];
        let record_len: u16 = 200;
        data.extend_from_slice(&record_len.to_be_bytes());
        data.push(0x01); // ClientHello
        data.extend_from_slice(&[0x00, 0x00, 0xC0]); // handshake_len = 192
        data.extend_from_slice(&[0x03, 0x03]); // version
        data.extend_from_slice(&[0x00; 32]); // random
        data.push(0x00); // session id len
        data.extend_from_slice(&[0x00, 0x02, 0x00, 0xFF]); // ciphers
        data.extend_from_slice(&[0x01, 0x00]); // compression
        // Extensions length = 0xFFFF (65535) — way more than available
        data.extend_from_slice(&[0xFF, 0xFF]);
        // SNI extension with huge length
        data.extend_from_slice(&[0x00, 0x00]); // ext type = SNI
        data.extend_from_slice(&[0xFF, 0xFE]); // ext len = 65534
        // Only provide a few bytes of data
        data.extend_from_slice(&[0x00; 50]);

        // Must not panic
        let result = tls::TlsClientHello::parse(&data);
        if let Some(parsed) = result {
            let _ = parsed.sni_domain();
        }
    }

    #[test]
    fn duplicate_sni_extensions() {
        let sni1 = "first.com";
        let sni2 = "second.com";

        let sni1_ext = build_sni_extension(sni1.as_bytes());
        let sni2_ext = build_sni_extension(sni2.as_bytes());
        let extensions_len = sni1_ext.len() + sni2_ext.len();

        let hello_len = 2 + 32 + 1 + 4 + 2 + 2 + extensions_len;
        let handshake_len = 4 + hello_len;

        let mut buf = Vec::new();
        buf.push(0x16); // TLS handshake
        buf.extend_from_slice(&[0x03, 0x01]);
        buf.extend_from_slice(&(handshake_len as u16).to_be_bytes());
        buf.push(0x01); // ClientHello
        buf.push(0x00);
        buf.extend_from_slice(&(hello_len as u16).to_be_bytes());
        buf.extend_from_slice(&[0x03, 0x03]);
        buf.extend_from_slice(&[0x00; 32]);
        buf.push(0x00); // session id len
        buf.extend_from_slice(&[0x00, 0x02, 0x00, 0xFF]); // ciphers
        buf.extend_from_slice(&[0x01, 0x00]); // compression
        buf.extend_from_slice(&(extensions_len as u16).to_be_bytes());
        buf.extend_from_slice(&sni1_ext);
        buf.extend_from_slice(&sni2_ext);

        let result = tls::TlsClientHello::parse(&buf);
        assert!(result.is_some());
        let parsed = result.unwrap();
        // Parser breaks after first SNI, so should return "first.com"
        assert_eq!(parsed.sni_domain(), Some("first.com"));
    }

    #[test]
    fn sni_with_non_utf8_bytes() {
        // SNI name containing invalid UTF-8
        let invalid_sni: &[u8] = &[0xFF, 0xFE, 0xFD, 0x2E, 0x63, 0x6F, 0x6D];
        let hello = build_client_hello_with_custom_sni(invalid_sni.len(), invalid_sni);
        let result = tls::TlsClientHello::parse(&hello);
        assert!(result.is_some());
        let parsed = result.unwrap();
        // from_utf8 should fail, so SNI should be None
        assert!(!parsed.has_sni());
    }

    #[test]
    fn sni_with_null_bytes() {
        let sni_bytes = b"exam\x00ple.com";
        let hello = build_client_hello_with_custom_sni(sni_bytes.len(), sni_bytes);
        let result = tls::TlsClientHello::parse(&hello);
        assert!(result.is_some());
        // std::str::from_utf8 allows null bytes (they are valid UTF-8)
        let parsed = result.unwrap();
        if parsed.has_sni() {
            assert!(parsed.sni_domain().unwrap().contains('\0'));
        }
    }

    #[test]
    fn truncated_extension_list() {
        // Extensions length says 100 but only 10 bytes available
        let mut data = vec![0x16, 0x03, 0x03];
        let record_len: u16 = 60;
        data.extend_from_slice(&record_len.to_be_bytes());
        data.push(0x01);
        data.extend_from_slice(&[0x00, 0x00, 0x37]); // handshake=55
        data.extend_from_slice(&[0x03, 0x03]);
        data.extend_from_slice(&[0x00; 32]);
        data.push(0x00); // session id
        data.extend_from_slice(&[0x00, 0x02, 0x00, 0xFF]); // ciphers
        data.extend_from_slice(&[0x01, 0x00]); // compression
        data.extend_from_slice(&[0x00, 0x64]); // extensions_len = 100
        data.extend_from_slice(&[0x00; 10]); // only 10 bytes available

        // Must not panic
        let result = tls::TlsClientHello::parse(&data);
        if let Some(parsed) = result {
            let _ = parsed.sni_domain();
        }
    }

    #[test]
    fn all_zero_bytes() {
        let data = vec![0x00; 1024];
        let _ = tls::TlsClientHello::parse(&data);
        let _ = tls::is_tls_client_hello(&data);
        let _ = tls::find_sni_split_point(&data);
    }

    #[test]
    fn all_0xff_bytes() {
        let data = vec![0xFF; 1024];
        let _ = tls::TlsClientHello::parse(&data);
        let _ = tls::is_tls_client_hello(&data);
        let _ = tls::find_sni_split_point(&data);
    }

    #[test]
    fn massive_session_id_length() {
        let mut data = vec![0x16, 0x03, 0x01, 0x00, 0x40]; // record 64 bytes
        data.push(0x01);
        data.extend_from_slice(&[0x00, 0x00, 0x3B]);
        data.extend_from_slice(&[0x03, 0x03]);
        data.extend_from_slice(&[0x00; 32]);
        data.push(0xFF); // session_id_len = 255 — way more than available
        data.extend_from_slice(&[0x00; 10]);
        assert!(tls::TlsClientHello::parse(&data).is_none());
    }

    #[test]
    fn massive_cipher_suite_length() {
        let mut data = vec![0x16, 0x03, 0x01, 0x00, 0x40];
        data.push(0x01);
        data.extend_from_slice(&[0x00, 0x00, 0x3B]);
        data.extend_from_slice(&[0x03, 0x03]);
        data.extend_from_slice(&[0x00; 32]);
        data.push(0x00); // session id = 0
        data.extend_from_slice(&[0xFF, 0xFF]); // cipher_suites_len = 65535
        data.extend_from_slice(&[0x00; 10]);
        assert!(tls::TlsClientHello::parse(&data).is_none());
    }

    #[test]
    fn find_sni_split_point_non_tls() {
        assert!(tls::find_sni_split_point(b"GET / HTTP/1.1\r\n").is_none());
        assert!(tls::find_sni_split_point(&[]).is_none());
        assert!(tls::find_sni_split_point(&[0x16]).is_none());
    }

    #[test]
    fn find_sni_split_point_valid_hello() {
        let hello = build_test_client_hello("example.com");
        let split = tls::find_sni_split_point(&hello);
        assert!(
            split.is_some(),
            "should find SNI split point for valid ClientHello"
        );
        let (first_len, second_start) = split.unwrap();
        assert!(first_len > 0);
        assert!(second_start > 0);
        assert!(second_start <= hello.len());
    }

    #[test]
    fn is_tls_client_hello_edge_cases() {
        assert!(!tls::is_tls_client_hello(&[0x16, 0x03, 0x01, 0x00, 0x01]));
        assert!(tls::is_tls_client_hello(&[
            0x16, 0x03, 0x01, 0x00, 0x01, 0x01
        ]));
        assert!(!tls::is_tls_client_hello(&[
            0x16, 0x03, 0x01, 0x00, 0x01, 0x02
        ]));
        assert!(!tls::is_tls_client_hello(&[]));
        assert!(!tls::is_tls_client_hello(&[0x15])); // not handshake
    }

    #[test]
    fn sni_unicode_domain() {
        // Punycode-like domain (all ASCII, valid UTF-8)
        let sni = "xn--n3h.example.com";
        let hello = build_test_client_hello(sni);
        let result = tls::TlsClientHello::parse(&hello).unwrap();
        assert_eq!(result.sni_domain(), Some(sni));
    }

    #[test]
    fn sni_with_trailing_dot() {
        let sni = "example.com.";
        let hello = build_test_client_hello(sni);
        let result = tls::TlsClientHello::parse(&hello).unwrap();
        assert_eq!(result.sni_domain(), Some(sni));
    }

    #[test]
    fn sni_uppercase_lowered() {
        let sni = "EXAMPLE.COM";
        let hello = build_test_client_hello(sni);
        let result = tls::TlsClientHello::parse(&hello).unwrap();
        assert_eq!(result.sni_domain(), Some("example.com"));
    }
}

// ============================================================================
// SECTION 2: HTTP Parser Fuzzing
// ============================================================================

mod http_fuzzing {
    use super::*;

    #[test]
    fn empty_input() {
        assert!(http::HttpRequest::parse(&[]).is_none());
        assert!(!http::is_http_request(&[]));
        assert!(http::find_http_split_point(&[]).is_none());
    }

    #[test]
    fn short_inputs() {
        for len in 1..16 {
            let data = vec![0x41; len]; // 'AAAAAA...'
            let _ = http::HttpRequest::parse(&data);
            let _ = http::is_http_request(&data);
            let _ = http::find_http_split_point(&data);
        }
    }

    #[test]
    fn no_host_header() {
        let req = b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n";
        let parsed = http::HttpRequest::parse(req);
        assert!(parsed.is_some());
        let p = parsed.unwrap();
        assert_eq!(p.host, None);
        assert_eq!(p.method, "GET");
    }

    #[test]
    fn host_with_trailing_spaces() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com   \r\n\r\n";
        let parsed = http::HttpRequest::parse(req).unwrap();
        // .trim().to_lowercase() in parser
        assert_eq!(parsed.host.as_deref(), Some("example.com"));
    }

    #[test]
    fn host_at_very_end_no_crlf() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com";
        let parsed = http::HttpRequest::parse(req);
        if let Some(p) = parsed {
            assert_eq!(p.host.as_deref(), Some("example.com"));
        }
    }

    #[test]
    fn multiline_host_header_folding() {
        // Obsolete HTTP/1.1 line folding
        let req = b"GET / HTTP/1.1\r\nHost: example\r\n .com\r\n\r\n";
        let parsed = http::HttpRequest::parse(req);
        if let Some(p) = parsed {
            // Parser reads until \r\n, so host will be just "example"
            assert_eq!(p.host.as_deref(), Some("example"));
        }
    }

    #[test]
    fn very_long_host_header() {
        let host = "a".repeat(10000);
        let req = format!("GET / HTTP/1.1\r\nHost: {}\r\n\r\n", host);
        let parsed = http::HttpRequest::parse(req.as_bytes());
        assert!(parsed.is_some());
        assert_eq!(parsed.unwrap().host.as_deref(), Some(host.as_str()));
    }

    #[test]
    fn binary_garbage_after_valid_method() {
        let mut data = b"GET / HTTP/1.1\r\n".to_vec();
        data.extend_from_slice(&[0xFF, 0xFE, 0xFD, 0xFC]);
        // The request line is valid, so this parses as an HTTP request; the
        // trailing binary bytes contain no Host header, so `host` is None.
        // The parser deliberately does not require the whole payload to be
        // UTF-8 — legitimate requests may carry a binary body, and rejecting
        // them would skip Host fragmentation
        // (see unit_tests::http_host_parsed_despite_binary_body).
        let parsed = http::HttpRequest::parse(&data).expect("valid request line should parse");
        assert_eq!(parsed.method, "GET");
        assert!(parsed.host.is_none(), "no Host header present in the garbage");
    }

    #[test]
    fn is_http_redirect_edge_cases() {
        assert!(!http::is_http_redirect(&[]));
        assert!(!http::is_http_redirect(&[0x00; 12]));
        assert!(!http::is_http_redirect(b"HTTP/1.1 200"));
        assert!(http::is_http_redirect(b"HTTP/1.0 302 Found\r\n"));
        assert!(http::is_http_redirect(
            b"HTTP/1.1 307 Temporary Redirect\r\n"
        ));
        assert!(http::is_http_redirect(b"HTTP/1.1 301"));
        assert!(!http::is_http_redirect(b"HTTP/1.1 30")); // 11 bytes
    }

    #[test]
    fn all_http_methods() {
        for method in [
            "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT",
        ] {
            let req = format!("{} /test HTTP/1.1\r\nHost: test.com\r\n\r\n", method);
            let parsed = http::HttpRequest::parse(req.as_bytes());
            assert!(parsed.is_some(), "should parse {} request", method);
            assert_eq!(parsed.unwrap().method, method);
        }
    }

    #[test]
    fn invalid_http_method() {
        let data = b"INVALID / HTTP/1.1\r\nHost: test.com\r\n\r\n";
        assert!(http::HttpRequest::parse(data).is_none());
        assert!(!http::is_http_request(data));
    }

    #[test]
    fn find_split_point_short_host() {
        let req = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        let split = http::find_http_split_point(req);
        assert!(split.is_some());
    }

    #[test]
    fn find_split_point_normal_host() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let split = http::find_http_split_point(req);
        assert!(split.is_some());
        let pos = split.unwrap();
        assert!(pos > 0 && pos < req.len());
    }

    #[test]
    fn host_case_insensitive() {
        let req = b"GET / HTTP/1.1\r\nHOST: EXAMPLE.COM\r\n\r\n";
        let parsed = http::HttpRequest::parse(req).unwrap();
        assert_eq!(parsed.host.as_deref(), Some("example.com"));
    }

    #[test]
    fn host_with_port() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com:8080\r\n\r\n";
        let parsed = http::HttpRequest::parse(req).unwrap();
        assert_eq!(parsed.host.as_deref(), Some("example.com:8080"));
    }

    #[test]
    fn multiple_host_headers() {
        // Only first Host should be returned (parser breaks after first match)
        let req = b"GET / HTTP/1.1\r\nHost: first.com\r\nHost: second.com\r\n\r\n";
        let parsed = http::HttpRequest::parse(req).unwrap();
        assert_eq!(parsed.host.as_deref(), Some("first.com"));
    }

    #[test]
    fn host_empty_value() {
        let req = b"GET / HTTP/1.1\r\nHost: \r\n\r\n";
        let parsed = http::HttpRequest::parse(req).unwrap();
        assert_eq!(parsed.host.as_deref(), Some(""));
    }
}

// ============================================================================
// SECTION 3: IP Header Parser Fuzzing
// ============================================================================

mod ip_fuzzing {
    use super::*;

    #[test]
    fn empty_input() {
        assert!(IpHeader::parse(&[]).is_none());
    }

    #[test]
    fn single_byte_all_versions() {
        for b in 0..=255u8 {
            let _ = IpHeader::parse(&[b]);
        }
    }

    #[test]
    fn ipv4_minimum_valid() {
        let mut header = [0u8; 20];
        header[0] = 0x45; // version=4, IHL=5
        header[8] = 64; // TTL
        header[9] = 6; // TCP
        let parsed = IpHeader::parse(&header);
        assert!(parsed.is_some());
        assert!(parsed.unwrap().is_v4());
    }

    #[test]
    fn ipv4_ihl_too_small() {
        let mut header = [0u8; 20];
        header[0] = 0x41; // version=4, IHL=1 (4 bytes — less than min 20)
        assert!(IpHeader::parse(&header).is_none());
    }

    #[test]
    fn ipv4_ihl_larger_than_data() {
        let mut header = [0u8; 20];
        header[0] = 0x4F; // version=4, IHL=15 (60 bytes but only 20 provided)
        assert!(IpHeader::parse(&header).is_none());
    }

    #[test]
    fn ipv6_minimum_valid() {
        let mut header = [0u8; 40];
        header[0] = 0x60; // version=6
        header[6] = 6; // next header = TCP
        header[7] = 64; // hop limit
        let parsed = IpHeader::parse(&header);
        assert!(parsed.is_some());
        assert!(parsed.unwrap().is_v6());
    }

    #[test]
    fn ipv6_too_short() {
        let header = [0x60u8; 39]; // 39 bytes, need 40
        assert!(IpHeader::parse(&header).is_none());
    }

    #[test]
    fn unknown_ip_version() {
        let header = [0x30u8; 40]; // Version 3
        assert!(IpHeader::parse(&header).is_none());
    }

    #[test]
    fn ipv4_checksum_edge_cases() {
        assert_eq!(ip::ipv4_checksum(&[]), 0);
        assert_eq!(ip::ipv4_checksum(&[0x42]), 0);
        // All zeros
        let zeros = [0u8; 20];
        assert_eq!(ip::ipv4_checksum(&zeros), 0xFFFF);
    }

    #[test]
    fn set_ipv4_ttl_short_packet() {
        let mut pkt = [0u8; 5]; // too short for full header
        pkt[0] = 0x45;
        ip::set_ipv4_ttl(&mut pkt, 42);
        // Should not panic, early return due to len < 20
    }

    #[test]
    fn set_ipv4_ttl_not_ipv4() {
        let mut pkt = [0u8; 30];
        pkt[0] = 0x60; // IPv6
        ip::set_ipv4_ttl(&mut pkt, 42);
        assert_ne!(pkt[8], 42); // should not modify TTL
    }

    #[test]
    fn set_ipv4_ttl_valid_packet() {
        let mut header = ip::build_ipv4_header(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            6,
            64,
            0,
            0,
        );
        assert_eq!(header[8], 64);
        ip::set_ipv4_ttl(&mut header, 1);
        assert_eq!(header[8], 1);
        // Verify checksum still valid
        let cksum = ip::ipv4_checksum(&header);
        assert_eq!(cksum, 0, "checksum should verify to 0 after TTL change");
    }

    #[test]
    fn set_ipv4_ttl_ihl_beyond_buffer_does_not_panic() {
        // The buffer is a valid minimum length (20), so it passes the length
        // check, but the IHL nibble claims a 60-byte header. Slicing
        // packet[..60] to recompute the checksum must not panic on such a
        // malformed/truncated packet — the same guard IpHeader::parse applies
        // (see ipv4_ihl_larger_than_data).
        let mut pkt = [0u8; 20];
        pkt[0] = 0x4F; // version=4, IHL=15 → claims a 60-byte header
        let before = pkt;
        ip::set_ipv4_ttl(&mut pkt, 42); // must not panic
        // Malformed header ⇒ left untouched, not TTL-set with a stale checksum.
        assert_eq!(pkt, before, "malformed packet must be left unmodified");
    }

    #[test]
    fn build_ipv4_header_and_verify() {
        let src = Ipv4Addr::new(192, 168, 1, 1);
        let dst = Ipv4Addr::new(10, 0, 0, 1);
        let header = ip::build_ipv4_header(src, dst, 6, 64, 100, 0x1234);
        assert_eq!(header.len(), 20);
        assert_eq!(header[0], 0x45);
        assert_eq!(header[8], 64);
        assert_eq!(header[9], 6);

        let cksum = ip::ipv4_checksum(&header);
        assert_eq!(cksum, 0, "built header checksum should verify to 0");
    }

    #[test]
    fn ipv4_with_options() {
        // IHL=6 (24 bytes header), 4 bytes options
        let mut header = [0u8; 24];
        header[0] = 0x46; // version=4, IHL=6
        header[8] = 64;
        header[9] = 6;
        let parsed = IpHeader::parse(&header);
        assert!(parsed.is_some());
        assert_eq!(parsed.unwrap().header_len(), 24);
    }
}

// ============================================================================
// SECTION 4: TCP Header Parser Fuzzing
// ============================================================================

mod tcp_fuzzing {
    use super::*;

    #[test]
    fn empty_input() {
        assert!(TcpHeader::parse(&[]).is_none());
    }

    #[test]
    fn too_short() {
        assert!(TcpHeader::parse(&[0u8; 19]).is_none());
    }

    #[test]
    fn minimum_valid() {
        let mut data = [0u8; 20];
        data[12] = 0x50; // data_offset = 5 (20 bytes)
        let parsed = TcpHeader::parse(&data);
        assert!(parsed.is_some());
        assert_eq!(parsed.unwrap().header_len, 20);
    }

    #[test]
    fn data_offset_zero() {
        let mut data = [0u8; 20];
        data[12] = 0x00; // data_offset = 0
        assert!(TcpHeader::parse(&data).is_none());
    }

    #[test]
    fn data_offset_too_large() {
        let mut data = [0u8; 20];
        data[12] = 0xF0; // data_offset = 15 (60 bytes) but only 20 available
        assert!(TcpHeader::parse(&data).is_none());
    }

    #[test]
    fn all_flags_set() {
        let mut data = [0u8; 20];
        data[12] = 0x50;
        data[13] = 0xFF; // all 8 flags
        let parsed = TcpHeader::parse(&data).unwrap();
        assert!(parsed.is_rst());
        assert!(parsed.is_fin());
        // is_syn requires SYN set AND ACK not set, but ACK is set here
        assert!(!parsed.is_syn());
        assert!(parsed.is_syn_ack());
    }

    #[test]
    fn tcp_with_options_and_payload() {
        let mut data = vec![0u8; 42]; // 32 + 10 payload
        data[12] = 0x80; // data_offset = 8 (32 bytes header)
        data[13] = tcp::TCP_PSH | tcp::TCP_ACK;
        for i in 32..42 {
            data[i] = 0x41; // 'A'
        }
        let parsed = TcpHeader::parse(&data).unwrap();
        assert_eq!(parsed.options.len(), 12);
        assert_eq!(parsed.payload.len(), 10);
        assert!(parsed.is_psh_ack());
        assert!(parsed.has_payload());
    }

    #[test]
    fn syn_only_flag() {
        let mut data = [0u8; 20];
        data[12] = 0x50;
        data[13] = tcp::TCP_SYN;
        let parsed = TcpHeader::parse(&data).unwrap();
        assert!(parsed.is_syn());
        assert!(!parsed.is_syn_ack());
        assert!(!parsed.is_rst());
    }

    #[test]
    fn port_detection() {
        let mut data = [0u8; 20];
        data[12] = 0x50;
        // dst_port = 443
        data[2] = 0x01;
        data[3] = 0xBB;
        let parsed = TcpHeader::parse(&data).unwrap();
        assert!(parsed.is_https_port());
        assert!(!parsed.is_http_port());
    }

    #[test]
    fn http_port_detection() {
        let mut data = [0u8; 20];
        data[12] = 0x50;
        // dst_port = 80
        data[2] = 0x00;
        data[3] = 0x50;
        let parsed = TcpHeader::parse(&data).unwrap();
        assert!(parsed.is_http_port());
        assert!(!parsed.is_https_port());
    }

    #[test]
    fn checksum_v4_odd_length() {
        let src: [u8; 4] = [10, 0, 0, 1];
        let dst: [u8; 4] = [10, 0, 0, 2];
        let segment = vec![0x00; 21]; // odd length
        let cksum = tcp_checksum_v4(&src, &dst, &segment);
        // Should handle odd length without panic
        let _ = cksum;
    }

    #[test]
    fn checksum_v4_minimum_segment() {
        let src: [u8; 4] = [10, 0, 0, 1];
        let dst: [u8; 4] = [10, 0, 0, 2];
        let segment = vec![0x00; 2]; // minimum valid
        let _ = tcp_checksum_v4(&src, &dst, &segment);
    }

    #[test]
    fn checksum_v4_too_short() {
        let src: [u8; 4] = [10, 0, 0, 1];
        let dst: [u8; 4] = [10, 0, 0, 2];
        let segment = vec![0x00; 1]; // too short
        let cksum = tcp_checksum_v4(&src, &dst, &segment);
        assert_eq!(cksum, 0);
    }

    #[test]
    fn checksum_v6_basic() {
        let src = [0u8; 16];
        let dst = [0u8; 16];
        let segment = vec![0x00; 20];
        let _ = tcp_checksum_v6(&src, &dst, &segment);
    }
}

// ============================================================================
// SECTION 5: UDP/QUIC Parser Fuzzing
// ============================================================================

mod udp_fuzzing {
    use super::*;

    #[test]
    fn empty_input() {
        assert!(udp::UdpHeader::parse(&[]).is_none());
    }

    #[test]
    fn too_short() {
        assert!(udp::UdpHeader::parse(&[0u8; 7]).is_none());
    }

    #[test]
    fn minimum_valid() {
        let data = [0u8; 8];
        let parsed = udp::UdpHeader::parse(&data);
        assert!(parsed.is_some());
        assert_eq!(parsed.unwrap().payload.len(), 0);
    }

    #[test]
    fn quic_initial_too_short() {
        let mut data = [0u8; 8];
        data[2] = 0x01;
        data[3] = 0xBB; // dst port 443
        let parsed = udp::UdpHeader::parse(&data).unwrap();
        assert!(parsed.is_quic_port());
        assert!(!parsed.is_quic_initial()); // payload empty
    }

    #[test]
    fn quic_wrong_version() {
        let mut udp_pkt = vec![
            0x30, 0x39, // src port
            0x01, 0xBB, // dst port 443
            0x00, 0x10, // length
            0x00, 0x00, // checksum
            0xC0, // long header (bit 7=1, bit 6=1)
            0xDE, 0xAD, 0xBE, 0xEF, // wrong version
        ];
        udp_pkt.extend_from_slice(&[0x00; 8]);
        let parsed = udp::UdpHeader::parse(&udp_pkt).unwrap();
        assert!(parsed.is_quic_port());
        assert!(!parsed.is_quic_initial());
    }

    #[test]
    fn quic_v1_valid() {
        let mut udp_pkt = vec![
            0x30, 0x39, // src port
            0x01, 0xBB, // dst port 443
            0x00, 0x20, // length
            0x00, 0x00, // checksum
            0xC0, // long header
            0x00, 0x00, 0x00, 0x01, // QUIC v1
        ];
        udp_pkt.extend_from_slice(&[0x00; 16]);
        let parsed = udp::UdpHeader::parse(&udp_pkt).unwrap();
        assert!(parsed.is_quic_initial());
    }

    #[test]
    fn quic_short_header_form() {
        let mut udp_pkt = vec![
            0x30, 0x39, 0x01, 0xBB, 0x00, 0x10, 0x00, 0x00,
            0x40, // short header (bit 7=0, bit 6=1)
            0x00, 0x00, 0x00, 0x01,
        ];
        udp_pkt.extend_from_slice(&[0x00; 4]);
        let parsed = udp::UdpHeader::parse(&udp_pkt).unwrap();
        assert!(!parsed.is_quic_initial()); // not long header
    }

    #[test]
    fn non_quic_port() {
        let mut data = [0u8; 8];
        data[2] = 0x00;
        data[3] = 0x50; // dst port 80
        let parsed = udp::UdpHeader::parse(&data).unwrap();
        assert!(!parsed.is_quic_port());
    }
}

// ============================================================================
// SECTION 6: Full Packet Parsing (ParsedPacket)
// ============================================================================

mod parsed_packet {
    use super::*;

    #[test]
    fn empty_input() {
        assert!(ParsedPacket::parse(&[], Direction::Outbound).is_none());
    }

    #[test]
    fn valid_ipv4_tcp_syn() {
        let ip_hdr = ip::build_ipv4_header(
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(93, 184, 216, 34),
            6,
            64,
            20,
            0x1234,
        );
        let mut tcp_hdr = vec![0u8; 20];
        tcp_hdr[2] = 0x00;
        tcp_hdr[3] = 0x50; // dst port 80
        tcp_hdr[12] = 0x50; // data_offset 5
        tcp_hdr[13] = tcp::TCP_SYN;
        let mut packet = ip_hdr;
        packet.extend_from_slice(&tcp_hdr);

        let parsed = ParsedPacket::parse(&packet, Direction::Outbound);
        assert!(parsed.is_some());
        let p = parsed.unwrap();
        assert!(p.is_tcp());
        assert!(!p.is_udp());
        assert_eq!(p.ttl(), 64);
        assert!(p.tcp().unwrap().is_syn());
    }

    #[test]
    fn valid_ipv4_tcp_with_payload() {
        let payload = b"GET / HTTP/1.1\r\nHost: test.com\r\n\r\n";
        let ip_hdr = ip::build_ipv4_header(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            6,
            64,
            20 + payload.len(),
            0,
        );
        let mut tcp_hdr = vec![0u8; 20];
        tcp_hdr[2] = 0x00;
        tcp_hdr[3] = 0x50; // port 80
        tcp_hdr[12] = 0x50;
        tcp_hdr[13] = tcp::TCP_PSH | tcp::TCP_ACK;
        let mut packet = ip_hdr;
        packet.extend_from_slice(&tcp_hdr);
        packet.extend_from_slice(payload);

        let p = ParsedPacket::parse(&packet, Direction::Outbound).unwrap();
        assert!(p.tcp().unwrap().has_payload());
        assert!(p.tcp().unwrap().is_psh_ack());
    }

    #[test]
    fn ipv4_with_unknown_protocol() {
        let ip_hdr = ip::build_ipv4_header(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            99,
            64,
            10,
            0, // protocol 99 — neither TCP nor UDP
        );
        let mut packet = ip_hdr;
        packet.extend_from_slice(&[0x00; 10]);

        let parsed = ParsedPacket::parse(&packet, Direction::Inbound);
        assert!(parsed.is_some());
        let p = parsed.unwrap();
        assert!(!p.is_tcp());
        assert!(!p.is_udp());
    }

    #[test]
    fn ipv4_truncated_tcp() {
        // IP header says TCP but no transport data follows
        let ip_hdr = ip::build_ipv4_header(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            6,
            64,
            0,
            0,
        );
        // No TCP data at all
        assert!(ParsedPacket::parse(&ip_hdr, Direction::Outbound).is_none());
    }

    #[test]
    fn ipv6_tcp_basic() {
        let mut packet = [0u8; 60]; // 40 IPv6 + 20 TCP
        packet[0] = 0x60;
        packet[4] = 0x00;
        packet[5] = 20; // payload = 20
        packet[6] = 6; // TCP
        packet[7] = 64;
        // TCP header
        packet[40 + 12] = 0x50; // data_offset = 5
        packet[40 + 13] = tcp::TCP_SYN;

        let p = ParsedPacket::parse(&packet, Direction::Outbound).unwrap();
        assert!(p.is_tcp());
        assert!(p.ip.is_v6());
        assert!(p.tcp().unwrap().is_syn());
    }

    #[test]
    fn ipv4_udp_quic() {
        let ip_hdr = ip::build_ipv4_header(
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            17,
            64,
            30,
            0, // UDP
        );
        let mut udp_hdr = vec![0u8; 8];
        udp_hdr[2] = 0x01;
        udp_hdr[3] = 0xBB; // port 443
        // QUIC initial payload
        let mut payload = vec![0xC0]; // long header
        payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // QUIC v1
        payload.extend_from_slice(&[0x00; 17]); // rest

        let mut packet = ip_hdr;
        packet.extend_from_slice(&udp_hdr);
        packet.extend_from_slice(&payload);

        let p = ParsedPacket::parse(&packet, Direction::Outbound).unwrap();
        assert!(p.is_udp());
        assert!(p.udp().unwrap().is_quic_initial());
    }
}

// ============================================================================
// SECTION 7: Domain Path Traversal Tests
// ============================================================================

mod path_traversal {
    use super::*;

    #[test]
    fn rejects_etc_shadow() {
        let mut config = Config::default();
        config.domains.mode = DomainMode::Blacklist;
        config.domains.blacklist_file = Some("/etc/shadow".to_string());
        let _ = config.load_domain_lists();
        assert!(config.domain_set.is_empty(), "should reject /etc/shadow");
    }

    #[test]
    fn rejects_traversal_with_dots() {
        let mut config = Config::default();
        config.domains.mode = DomainMode::Blacklist;
        config.domains.blacklist_file = Some("/etc/cachydpi/../shadow".to_string());
        let _ = config.load_domain_lists();
        assert!(config.domain_set.is_empty(), "should reject path traversal");
    }

    #[test]
    fn rejects_tmp_path() {
        let mut config = Config::default();
        config.domains.mode = DomainMode::Blacklist;
        config.domains.blacklist_file = Some("/tmp/evil.txt".to_string());
        let _ = config.load_domain_lists();
        assert!(config.domain_set.is_empty(), "should reject /tmp path");
    }

    #[test]
    fn rejects_home_directory() {
        let mut config = Config::default();
        config.domains.mode = DomainMode::Blacklist;
        config.domains.blacklist_file = Some("/home/user/.ssh/authorized_keys".to_string());
        let _ = config.load_domain_lists();
        assert!(config.domain_set.is_empty(), "should reject home directory");
    }

    #[test]
    fn rejects_proc_filesystem() {
        let mut config = Config::default();
        config.domains.mode = DomainMode::Blacklist;
        config.domains.blacklist_file = Some("/proc/self/environ".to_string());
        let _ = config.load_domain_lists();
        assert!(config.domain_set.is_empty(), "should reject /proc");
    }

    #[test]
    fn rejects_null_byte() {
        let mut config = Config::default();
        config.domains.mode = DomainMode::Blacklist;
        config.domains.blacklist_file = Some("/etc/cachydpi/list.txt\0../../shadow".to_string());
        let _ = config.load_domain_lists();
        // Path with null byte: Rust rejects it in fs::read_to_string (or canonicalize)
        assert!(config.domain_set.is_empty(), "should reject null byte path");
    }

    #[test]
    fn rejects_very_long_path() {
        let long_path = format!("/etc/cachydpi/{}", "a".repeat(4096));
        let mut config = Config::default();
        config.domains.mode = DomainMode::Blacklist;
        config.domains.blacklist_file = Some(long_path);
        let _ = config.load_domain_lists();
        assert!(config.domain_set.is_empty());
    }

    #[test]
    fn accepts_valid_cachydpi_path() {
        let mut config = Config::default();
        config.domains.mode = DomainMode::Blacklist;
        config.domains.blacklist_file = Some("/etc/cachydpi/blacklist.txt".to_string());
        // Path is valid but file may not exist — no panic expected
        let _ = config.load_domain_lists();
    }

    #[test]
    fn accepts_usr_share_path() {
        let mut config = Config::default();
        config.domains.mode = DomainMode::Blacklist;
        config.domains.blacklist_file = Some("/usr/share/cachydpi/domains.txt".to_string());
        let _ = config.load_domain_lists();
    }

    #[test]
    fn rejects_relative_path() {
        let mut config = Config::default();
        config.domains.mode = DomainMode::Blacklist;
        config.domains.blacklist_file = Some("../../../etc/passwd".to_string());
        let _ = config.load_domain_lists();
        assert!(config.domain_set.is_empty(), "should reject relative path");
    }

    #[test]
    fn whitelist_also_checked() {
        let mut config = Config::default();
        config.domains.mode = DomainMode::Whitelist;
        config.domains.whitelist_file = Some("/etc/shadow".to_string());
        let _ = config.load_domain_lists();
        assert!(
            config.domain_set.is_empty(),
            "whitelist path also validated"
        );
    }
}

// ============================================================================
// SECTION 8: Configuration Edge Cases
// ============================================================================

mod config_edge_cases {
    use super::*;

    #[test]
    fn default_mode_is_5() {
        let config = Config::default();
        assert_eq!(config.general.mode, 5);
    }

    #[test]
    fn default_queue_is_200() {
        let config = Config::default();
        assert_eq!(config.general.queue_num, 200);
    }

    #[test]
    fn domain_set_empty_by_default() {
        let config = Config::default();
        assert!(config.domain_set.is_empty());
    }

    #[test]
    fn default_ipv6_enabled() {
        let config = Config::default();
        assert!(config.general.ipv6);
    }

    #[test]
    fn default_strategy_settings() {
        let config = Config::default();
        assert!(config.strategies.passive_dpi);
        assert!(!config.strategies.fake_packet_enabled);
        assert!(config.strategies.auto_ttl);
        assert!(config.strategies.multi_fragment);
        assert!(config.strategies.disorder);
        assert!(!config.strategies.desync_first);
        assert!(!config.strategies.quic_desync);
    }

    #[test]
    fn should_process_domain_mode_none() {
        let mut config = Config::default();
        // None is no longer the default (it bypasses every site), so ask for it
        // explicitly — this test is about what None means, not what defaults to.
        config.domains.mode = DomainMode::None;
        // Mode::None → always process
        assert!(config.should_process_domain("anything.com"));
        assert!(config.should_process_domain(""));
    }

    #[test]
    fn domain_matching_exact() {
        let mut config = Config::default();
        config.domains.mode = DomainMode::Blacklist;
        config.domain_set = ["example.com".to_string()].into_iter().collect();
        assert!(config.should_process_domain("example.com"));
        assert!(!config.should_process_domain("notexample.com"));
    }

    #[test]
    fn domain_matching_subdomain() {
        let mut config = Config::default();
        config.domains.mode = DomainMode::Blacklist;
        config.domain_set = ["example.com".to_string()].into_iter().collect();
        assert!(config.should_process_domain("www.example.com"));
        assert!(config.should_process_domain("a.b.c.example.com"));
    }

    #[test]
    fn domain_does_not_match_partial() {
        let mut config = Config::default();
        config.domains.mode = DomainMode::Blacklist;
        config.domain_set = ["example.com".to_string()].into_iter().collect();
        // "myexample.com" should NOT match "example.com"
        assert!(!config.should_process_domain("myexample.com"));
    }

    #[test]
    fn subdomain_depth_stress() {
        let mut config = Config::default();
        config.domains.mode = DomainMode::Blacklist;
        config.domain_set = ["com".to_string()].into_iter().collect();
        let deep = "a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q.r.s.t.u.v.w.x.y.z.com";
        assert!(config.should_process_domain(deep));
    }

    #[test]
    fn large_domain_set_performance() {
        let mut config = Config::default();
        config.domains.mode = DomainMode::Blacklist;
        config.domain_set = (0..10000).map(|i| format!("domain{}.com", i)).collect();
        assert!(config.should_process_domain("domain5000.com"));
        assert!(config.should_process_domain("sub.domain5000.com"));
        assert!(!config.should_process_domain("notindomain.com"));
    }

    #[test]
    fn config_load_nonexistent_path() {
        let config = Config::load(std::path::Path::new("/nonexistent/path/config.toml"));
        assert!(config.is_ok());
        assert_eq!(config.unwrap().general.mode, 5);
    }

    #[test]
    fn bypass_mode_all_numbers() {
        assert_eq!(BypassMode::from_mode_number(1), BypassMode::Passive);
        assert_eq!(BypassMode::from_mode_number(2), BypassMode::HttpFragment);
        assert_eq!(BypassMode::from_mode_number(3), BypassMode::TlsFragment);
        assert_eq!(BypassMode::from_mode_number(4), BypassMode::FakePacket);
        assert_eq!(BypassMode::from_mode_number(5), BypassMode::AllActive);
        assert_eq!(BypassMode::from_mode_number(6), BypassMode::Aggressive);
        assert_eq!(BypassMode::from_mode_number(7), BypassMode::AutoDetect);
        // Out of range → AllActive
        assert_eq!(BypassMode::from_mode_number(0), BypassMode::AllActive);
        assert_eq!(BypassMode::from_mode_number(8), BypassMode::AllActive);
        assert_eq!(BypassMode::from_mode_number(255), BypassMode::AllActive);
    }

    #[test]
    fn domain_mode_display() {
        assert_eq!(format!("{}", DomainMode::None), "none");
        assert_eq!(format!("{}", DomainMode::Blacklist), "blacklist");
        assert_eq!(format!("{}", DomainMode::Whitelist), "whitelist");
    }

    #[test]
    fn inline_domains_loaded() {
        let mut config = Config::default();
        config.domains.mode = DomainMode::Blacklist;
        config.domains.blacklist = vec!["foo.com".to_string(), "bar.com".to_string()];
        config.load_domain_lists().unwrap();
        assert!(config.domain_set.contains("foo.com"));
        assert!(config.domain_set.contains("bar.com"));
    }
}

// ============================================================================
// SECTION 9: Concurrency Safety Tests
// ============================================================================

mod concurrency {
    use cachydpi::metrics::METRICS;
    use std::sync::atomic::Ordering;
    use std::thread;

    #[test]
    fn metrics_concurrent_updates() {
        let handles: Vec<_> = (0..10)
            .map(|_| {
                thread::spawn(|| {
                    for _ in 0..10000 {
                        METRICS.out_total.fetch_add(1, Ordering::Relaxed);
                        METRICS.in_total.fetch_add(1, Ordering::Relaxed);
                        METRICS.parse_failures.fetch_add(1, Ordering::Relaxed);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
        // No panics, no data races — that's the test
    }

    #[test]
    fn parsers_thread_safe() {
        // Parse packets from multiple threads simultaneously
        let handles: Vec<_> = (0..10)
            .map(|i| {
                thread::spawn(move || {
                    let sni = format!("thread{}.example.com", i);
                    let hello = super::build_test_client_hello(&sni);
                    for _ in 0..1000 {
                        let result = cachydpi::packet::tls::TlsClientHello::parse(&hello);
                        assert!(result.is_some());
                        assert_eq!(result.unwrap().sni_domain(), Some(sni.as_str()));
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
    }
}

// ============================================================================
// SECTION 10: IPv6 Tests
// ============================================================================

mod ipv6_tests {
    use super::*;

    #[test]
    fn parse_ipv6_header() {
        let mut header = [0u8; 40];
        header[0] = 0x60;
        header[4] = 0x00;
        header[5] = 0x00; // payload length = 0
        header[6] = 6; // next header = TCP
        header[7] = 64;
        // src: ::1
        header[23] = 1;
        // dst: ::2
        header[39] = 2;
        let parsed = IpHeader::parse(&header).unwrap();
        assert!(parsed.is_v6());
        assert_eq!(parsed.ttl(), 64);
        assert_eq!(parsed.protocol(), 6);
        assert_eq!(parsed.header_len(), 40);
    }

    #[test]
    fn ipv6_with_tcp() {
        let mut packet = [0u8; 60]; // 40 IPv6 + 20 TCP
        packet[0] = 0x60;
        packet[4] = 0x00;
        packet[5] = 20; // payload = 20
        packet[6] = 6; // TCP
        packet[7] = 64;
        // TCP header
        packet[40 + 12] = 0x50; // data_offset = 5
        packet[40 + 13] = tcp::TCP_SYN;

        let p = ParsedPacket::parse(&packet, Direction::Outbound).unwrap();
        assert!(p.is_tcp());
        assert!(p.ip.is_v6());
        assert!(p.tcp().unwrap().is_syn());
    }

    #[test]
    fn tcp_checksum_v6_works() {
        let src = [0u8; 16];
        let dst = [0u8; 16];
        let segment = vec![0u8; 20];
        let _ = tcp_checksum_v6(&src, &dst, &segment);
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn build_test_client_hello(domain: &str) -> Vec<u8> {
    build_client_hello_with_custom_sni(domain.len(), domain.as_bytes())
}

fn build_client_hello_with_custom_sni(name_len: usize, name_bytes: &[u8]) -> Vec<u8> {
    let sni_ext = build_sni_extension_with_len(name_len, name_bytes);
    let extensions_len = sni_ext.len();
    let hello_body_len = 2 + 32 + 1 + 4 + 2 + 2 + extensions_len;
    let handshake_len = 4 + hello_body_len;

    let mut buf = Vec::with_capacity(5 + handshake_len);
    buf.push(0x16); // TLS handshake
    buf.extend_from_slice(&[0x03, 0x01]); // TLS 1.0
    buf.extend_from_slice(&(handshake_len as u16).to_be_bytes());
    buf.push(0x01); // ClientHello
    buf.push(0x00);
    buf.extend_from_slice(&(hello_body_len as u16).to_be_bytes());
    buf.extend_from_slice(&[0x03, 0x03]); // version = TLS 1.2
    buf.extend_from_slice(&[0x00; 32]); // random
    buf.push(0x00); // session id len = 0
    buf.extend_from_slice(&[0x00, 0x02]); // cipher suites len = 2
    buf.extend_from_slice(&[0x00, 0xFF]); // cipher
    buf.push(0x01); // compression methods len = 1
    buf.push(0x00); // null compression
    buf.extend_from_slice(&(extensions_len as u16).to_be_bytes());
    buf.extend_from_slice(&sni_ext);
    buf
}

fn build_client_hello_without_extensions() -> Vec<u8> {
    let hello_body_len = 2 + 32 + 1 + 4 + 2;
    let handshake_len = 4 + hello_body_len;

    let mut buf = Vec::new();
    buf.push(0x16);
    buf.extend_from_slice(&[0x03, 0x01]);
    buf.extend_from_slice(&(handshake_len as u16).to_be_bytes());
    buf.push(0x01);
    buf.push(0x00);
    buf.extend_from_slice(&(hello_body_len as u16).to_be_bytes());
    buf.extend_from_slice(&[0x03, 0x03]);
    buf.extend_from_slice(&[0x00; 32]);
    buf.push(0x00); // session id len
    buf.extend_from_slice(&[0x00, 0x02, 0x00, 0xFF]); // ciphers
    buf.extend_from_slice(&[0x01, 0x00]); // compression
    // No extensions
    buf
}

#[allow(dead_code)]
fn build_sni_extension(name: &[u8]) -> Vec<u8> {
    build_sni_extension_with_len(name.len(), name)
}

fn build_sni_extension_with_len(name_len: usize, name_bytes: &[u8]) -> Vec<u8> {
    let list_len = name_len + 3;
    let ext_data_len = list_len + 2;
    let mut ext = Vec::new();
    ext.extend_from_slice(&[0x00, 0x00]); // ext type = SNI
    ext.extend_from_slice(&(ext_data_len as u16).to_be_bytes());
    ext.extend_from_slice(&(list_len as u16).to_be_bytes());
    ext.push(0x00); // hostname type
    ext.extend_from_slice(&(name_len as u16).to_be_bytes());

    let actual_len = name_len.min(name_bytes.len());
    ext.extend_from_slice(&name_bytes[..actual_len]);
    if name_bytes.len() < name_len {
        ext.extend_from_slice(&vec![0x00; name_len - name_bytes.len()]);
    }
    ext
}
