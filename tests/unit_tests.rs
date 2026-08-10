// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// tests/unit_tests.rs — Core unit tests for CachyDPI
//
// Covers: TCP checksum, TLS parsing, HTTP parsing, domain filtering,
// QUIC varint decoder, ClientHello builder, DPI detect helpers.

use cachydpi::config::{Config, DomainMode};
use cachydpi::packet::http;
use cachydpi::packet::tcp::{tcp_checksum_v4, tcp_checksum_v6};
use cachydpi::packet::tls;
use cachydpi::packet::udp;

// ── TCP Checksum Tests ──

#[test]
fn tcp_checksum_v4_known_value() {
    // Minimal TCP SYN segment: src_port=12345, dst_port=80, seq=1, ack=0,
    // data_offset=5 (20 bytes), SYN flag
    let src_ip: [u8; 4] = [192, 168, 1, 100];
    let dst_ip: [u8; 4] = [93, 184, 216, 34];
    let mut tcp_segment = vec![
        0x30, 0x39, // src port 12345
        0x00, 0x50, // dst port 80
        0x00, 0x00, 0x00, 0x01, // seq = 1
        0x00, 0x00, 0x00, 0x00, // ack = 0
        0x50, 0x02, // data offset 5, SYN
        0xFF, 0xFF, // window 65535
        0x00, 0x00, // checksum (zeroed for calculation)
        0x00, 0x00, // urgent ptr
    ];

    let cksum = tcp_checksum_v4(&src_ip, &dst_ip, &tcp_segment);
    assert_ne!(cksum, 0, "checksum should not be zero for valid segment");

    // Write checksum back and verify it validates to 0
    tcp_segment[16..18].copy_from_slice(&cksum.to_be_bytes());
    let verify = tcp_checksum_v4(&src_ip, &dst_ip, &tcp_segment);
    assert_eq!(verify, 0, "checksum verification failed");
}

#[test]
fn tcp_checksum_v6_known_value() {
    let src_ip: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x01,
    ];
    let dst_ip: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02,
    ];
    let mut tcp_segment = vec![
        0x30, 0x39, // src port
        0x01, 0xBB, // dst port 443
        0x00, 0x00, 0x00, 0x0A, // seq
        0x00, 0x00, 0x00, 0x00, // ack
        0x50, 0x02, // data offset 5, SYN
        0xFF, 0xFF, // window
        0x00, 0x00, // checksum zeroed
        0x00, 0x00, // urgent
    ];

    let cksum = tcp_checksum_v6(&src_ip, &dst_ip, &tcp_segment);
    assert_ne!(cksum, 0);

    tcp_segment[16..18].copy_from_slice(&cksum.to_be_bytes());
    let verify = tcp_checksum_v6(&src_ip, &dst_ip, &tcp_segment);
    assert_eq!(verify, 0, "IPv6 TCP checksum verification failed");
}

#[test]
fn tcp_checksum_short_segment_returns_zero() {
    let src: [u8; 4] = [0; 4];
    let dst: [u8; 4] = [0; 4];
    assert_eq!(tcp_checksum_v4(&src, &dst, &[]), 0);
    assert_eq!(tcp_checksum_v4(&src, &dst, &[0x42]), 0);

    let src6: [u8; 16] = [0; 16];
    let dst6: [u8; 16] = [0; 16];
    assert_eq!(tcp_checksum_v6(&src6, &dst6, &[]), 0);
    assert_eq!(tcp_checksum_v6(&src6, &dst6, &[0x42]), 0);
}

// ── TLS ClientHello Parsing Tests ──

#[test]
fn tls_is_client_hello() {
    // Valid TLS ClientHello start bytes
    let data = [
        0x16, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x03, 0x03,
    ];
    assert!(tls::is_tls_client_hello(&data));

    // Not TLS
    assert!(!tls::is_tls_client_hello(b"GET / HTTP/1.1"));
    assert!(!tls::is_tls_client_hello(&[]));
    assert!(!tls::is_tls_client_hello(&[0x16, 0x03]));
}

#[test]
fn tls_parse_client_hello_with_sni() {
    let hello = build_test_client_hello("example.com");
    let parsed = tls::TlsClientHello::parse(&hello).expect("should parse");
    assert!(parsed.has_sni());
    assert_eq!(parsed.sni_domain(), Some("example.com"));
}

#[test]
fn tls_find_sni_split_point() {
    let hello = build_test_client_hello("test.example.org");
    let result = tls::find_sni_split_point(&hello);
    assert!(result.is_some(), "should find split point");
    let (split, _) = result.unwrap();
    assert!(split > 0 && split < hello.len());
}

/// Build a minimal TLS ClientHello with SNI (matches dpi_detect.rs)
fn build_test_client_hello(domain: &str) -> Vec<u8> {
    let sni_bytes = domain.as_bytes();
    let sni_len = sni_bytes.len();
    let sni_ext_len = sni_len + 5;
    let extensions_len = sni_ext_len + 4;
    let hello_len = 43 + extensions_len;
    let handshake_len = hello_len + 4;
    let record_len = handshake_len;

    let mut buf = Vec::with_capacity(5 + record_len);
    buf.push(0x16);
    buf.extend_from_slice(&[0x03, 0x01]);
    buf.extend_from_slice(&(record_len as u16).to_be_bytes());
    buf.push(0x01);
    buf.push(0x00);
    buf.extend_from_slice(&(hello_len as u16).to_be_bytes());
    buf.extend_from_slice(&[0x03, 0x03]);
    buf.extend_from_slice(&[0x00; 32]);
    buf.push(0x00);
    buf.extend_from_slice(&[0x00, 0x02]);
    buf.extend_from_slice(&[0x00, 0xff]);
    buf.push(0x01);
    buf.push(0x00);
    buf.extend_from_slice(&(extensions_len as u16).to_be_bytes());
    buf.extend_from_slice(&[0x00, 0x00]);
    buf.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
    buf.extend_from_slice(&((sni_ext_len - 2) as u16).to_be_bytes());
    buf.push(0x00);
    buf.extend_from_slice(&(sni_len as u16).to_be_bytes());
    buf.extend_from_slice(sni_bytes);
    buf
}

// ── HTTP Parsing Tests ──

#[test]
fn http_is_request() {
    assert!(http::is_http_request(b"GET / HTTP/1.1\r\n"));
    assert!(http::is_http_request(b"POST /api HTTP/1.1\r\n"));
    assert!(http::is_http_request(b"HEAD /test HTTP/1.0\r\n"));
    assert!(!http::is_http_request(b"HTTP/1.1 200 OK\r\n"));
    assert!(!http::is_http_request(b""));
    assert!(!http::is_http_request(b"\x16\x03\x01"));
}

#[test]
fn http_parse_host() {
    let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    let parsed = http::HttpRequest::parse(req).expect("should parse");
    assert_eq!(parsed.host.as_deref(), Some("example.com"));
    assert_eq!(parsed.method, "GET");
}

#[test]
fn http_host_case_insensitive() {
    let req = b"GET / HTTP/1.1\r\nhOsT: Example.COM\r\n\r\n";
    let parsed = http::HttpRequest::parse(req).expect("should parse");
    assert_eq!(parsed.host.as_deref(), Some("example.com"));
}

#[test]
fn http_find_split_point() {
    let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let split = http::find_http_split_point(req);
    assert!(split.is_some());
    let sp = split.unwrap();
    assert!(sp > 0 && sp < req.len());
}

#[test]
fn http_is_redirect() {
    assert!(http::is_http_redirect(b"HTTP/1.1 302 Found\r\n"));
    assert!(http::is_http_redirect(b"HTTP/1.1 301 Moved\r\n"));
    assert!(http::is_http_redirect(b"HTTP/1.1 307 Temp\r\n"));
    assert!(!http::is_http_redirect(b"HTTP/1.1 200 OK\r\n"));
    assert!(!http::is_http_redirect(b"GET /"));
}

#[test]
fn http_host_parsed_despite_binary_body() {
    // A POST whose first TCP segment carries ASCII request line + headers
    // followed by a binary (non-UTF-8) body — e.g. a file/octet-stream upload.
    // The Host header is plain ASCII and must still be extracted; the body
    // must not defeat parsing. Requiring the whole payload to be valid UTF-8
    // wrongly rejected such requests, so their Host was never fragmented.
    let mut req: Vec<u8> =
        b"POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\n".to_vec();
    req.extend_from_slice(&[0xff, 0xfe, 0xfd, 0x80]); // binary body bytes
    assert!(
        std::str::from_utf8(&req).is_err(),
        "test payload must contain non-UTF-8 body bytes to exercise the bug",
    );

    let parsed =
        http::HttpRequest::parse(&req).expect("HTTP request with a binary body should still parse");
    assert_eq!(parsed.method, "POST");
    assert_eq!(parsed.host.as_deref(), Some("example.com"));
}

#[test]
fn http_split_point_found_despite_binary_body() {
    // The user-visible effect of the bug: with a binary body, the auto split
    // path (find_http_split_point) returned None, so the Host travelled in a
    // single segment fully readable by DPI. It must instead split inside the
    // Host value.
    let mut req: Vec<u8> = b"POST /u HTTP/1.1\r\nHost: blocked-site.com\r\n\r\n".to_vec();
    req.extend_from_slice(&[0x00, 0xff, 0x80, 0xfe]); // binary body bytes
    let req = req.as_slice();
    let split = http::find_http_split_point(req)
        .expect("split point should be found for a POST with a binary body");

    // The split must fall strictly inside the Host value so neither segment
    // carries the whole domain.
    let host_start = req
        .windows(6)
        .position(|w| w.eq_ignore_ascii_case(b"host: "))
        .map(|p| p + 6)
        .expect("Host header present");
    let host_end = host_start
        + req[host_start..]
            .windows(2)
            .position(|w| w == b"\r\n")
            .expect("Host header terminated");
    assert!(
        split > host_start && split < host_end,
        "split {split} should land within the Host value [{host_start}, {host_end})",
    );
}

// ── Domain Filtering Tests ──

#[test]
fn domain_filter_blacklist() {
    let mut config = Config::default();
    config.domains.mode = DomainMode::Blacklist;
    config.domain_set = ["example.com", "test.org"]
        .iter()
        .map(|s| s.to_string())
        .collect();

    assert!(config.should_process_domain("example.com"));
    assert!(config.should_process_domain("sub.example.com"));
    assert!(!config.should_process_domain("notlisted.com"));
}

#[test]
fn domain_filter_whitelist() {
    let mut config = Config::default();
    config.domains.mode = DomainMode::Whitelist;
    config.domain_set = ["safe.com"].iter().map(|s| s.to_string()).collect();

    // Whitelist is an exception list: listed (trusted) domains are SKIPPED,
    // everything else gets the bypass. This is the genuine opposite of
    // blacklist mode — not a copy of it.
    assert!(!config.should_process_domain("safe.com"));
    assert!(!config.should_process_domain("sub.safe.com"));
    // Not in the whitelist → bypass IS applied.
    assert!(config.should_process_domain("blocked.com"));
}

#[test]
fn whitelist_and_blacklist_are_opposites() {
    // Same domain set, opposite modes → opposite verdicts for every domain.
    let domains: std::collections::HashSet<String> =
        ["listed.com"].iter().map(|s| s.to_string()).collect();

    let mut black = Config::default();
    black.domains.mode = DomainMode::Blacklist;
    black.domain_set = domains.clone();

    let mut white = Config::default();
    white.domains.mode = DomainMode::Whitelist;
    white.domain_set = domains;

    for domain in ["listed.com", "sub.listed.com", "other.com"] {
        assert_ne!(
            black.should_process_domain(domain),
            white.should_process_domain(domain),
            "blacklist and whitelist must disagree on {domain}"
        );
    }
}

#[test]
fn whitelist_partial_match_is_not_excluded() {
    // A domain that merely *contains* a whitelisted string is not a real
    // subdomain of it, so the bypass must still apply. This is the whitelist
    // analog of the blacklist partial-match guard.
    let mut config = Config::default();
    config.domains.mode = DomainMode::Whitelist;
    config.domain_set = ["example.com".to_string()].into_iter().collect();

    // Exact whitelist hit → excluded from bypass.
    assert!(!config.should_process_domain("example.com"));
    // Substring, not a real subdomain → bypass still applies.
    assert!(config.should_process_domain("myexample.com"));
    // Whitelisted label appears, but the registrable parent differs → bypass.
    assert!(config.should_process_domain("example.com.evil.net"));
}

#[test]
fn whitelist_built_from_inline_list_via_load() {
    // Exercise the production path: load_domain_lists() must build domain_set
    // from the inline whitelist vec (lowercasing entries), after which
    // filtering treats listed domains and their subdomains as trusted.
    let mut config = Config::default();
    config.domains.mode = DomainMode::Whitelist;
    config.domains.whitelist = vec!["Safe.COM".to_string(), "trusted.org".to_string()];

    config.load_domain_lists().expect("load_domain_lists should succeed");

    // Set was built from the inline list and lowercased.
    assert_eq!(config.domain_set.len(), 2);
    assert!(config.domain_set.contains("safe.com"));

    // Listed domains and their subdomains are trusted → bypass skipped.
    assert!(!config.should_process_domain("safe.com"));
    assert!(!config.should_process_domain("api.safe.com"));
    assert!(!config.should_process_domain("trusted.org"));
    // Everything else still gets the bypass.
    assert!(config.should_process_domain("blocked.com"));
}

#[test]
fn domain_filter_none_passes_all() {
    let mut config = Config::default();
    // None is no longer the default; request it explicitly.
    config.domains.mode = DomainMode::None;
    assert!(config.should_process_domain("anything.com"));
    assert!(config.should_process_domain(""));
}

#[test]
fn domain_subdomain_matching() {
    let mut config = Config::default();
    config.domains.mode = DomainMode::Blacklist;
    config.domain_set = ["youtube.com".to_string()].into_iter().collect();

    assert!(config.should_process_domain("youtube.com"));
    assert!(config.should_process_domain("www.youtube.com"));
    assert!(config.should_process_domain("m.youtube.com"));
    assert!(config.should_process_domain("a.b.c.youtube.com"));
    assert!(!config.should_process_domain("notyoutube.com"));
}

// ── QUIC Varint Decoder Tests (RFC 9000 Section 16 examples) ──

#[test]
fn udp_quic_initial_detection() {
    // QUIC v1 Initial: long header (0xC0), version 0x00000001
    let mut data = vec![
        0xC3, // Header form=1, Fixed bit=1, type=0b00, reserved+pn_len
        0x00, 0x00, 0x00, 0x01, // QUIC v1
        0x08, // DCID len = 8
    ];
    data.extend_from_slice(&[0xAA; 8]); // DCID
    data.extend_from_slice(&[0x00]); // SCID len = 0
    data.extend_from_slice(&[0x00]); // token len = 0
    data.extend_from_slice(&[0x41, 0x00]); // payload len = 256 (varint)
    data.extend_from_slice(&[0x00; 256]); // dummy payload

    // Wrap in UDP header
    let udp_len = 8 + data.len();
    let mut udp_pkt = vec![
        0x30, 0x39, // src port 12345
        0x01, 0xBB, // dst port 443
    ];
    udp_pkt.extend_from_slice(&(udp_len as u16).to_be_bytes());
    udp_pkt.extend_from_slice(&[0x00, 0x00]); // checksum
    udp_pkt.extend_from_slice(&data);

    let parsed = udp::UdpHeader::parse(&udp_pkt).expect("should parse");
    assert!(parsed.is_quic_port());
    assert!(parsed.is_quic_initial());
}

// ── Config Default Tests ──

#[test]
fn default_config_auto_ttl_is_true() {
    let config = Config::default();
    assert!(
        config.strategies.auto_ttl,
        "default auto_ttl should be true"
    );
}

#[test]
fn default_config_desync_options() {
    let config = Config::default();
    assert!(
        !config.strategies.desync_first,
        "default desync_first should be false"
    );
    assert!(
        !config.strategies.fake_packet_enabled,
        "default fake_packet_enabled should be false"
    );
    assert!(
        config.strategies.multi_fragment,
        "default multi_fragment should be true"
    );
    assert!(
        config.strategies.disorder,
        "default disorder should be true"
    );
}

/// The built-in default must be the restrictive mode. `DomainMode::None`
/// bypasses every site, so it may only be reached by an explicit
/// `mode = "none"`, never by defaulting or by a failed config load.
#[test]
fn default_config_domain_mode_is_restrictive() {
    let config = Config::default();
    assert_eq!(config.domains.mode, DomainMode::Blacklist);
    assert_ne!(
        config.domains.mode,
        DomainMode::None,
        "the default must never bypass every domain"
    );
}

// ── Fake ClientHello Tests ──

#[test]
fn fake_client_hello_is_valid_tls() {
    use cachydpi::strategies::fake_packet::build_fake_client_hello_payload;
    let payload = build_fake_client_hello_payload("www.google.com");

    // Must be a valid TLS ClientHello that our parser can parse
    assert!(
        tls::is_tls_client_hello(&payload),
        "fake CH must be valid TLS ClientHello"
    );

    let hello = tls::TlsClientHello::parse(&payload).expect("fake CH must parse as TlsClientHello");
    assert!(hello.has_sni(), "fake CH must have SNI");
    assert_eq!(
        hello.sni_domain(),
        Some("www.google.com"),
        "fake CH must have correct SNI"
    );
}

#[test]
fn fake_client_hello_different_sni() {
    use cachydpi::strategies::fake_packet::build_fake_client_hello_payload;
    let payload = build_fake_client_hello_payload("example.com");

    let hello = tls::TlsClientHello::parse(&payload).expect("fake CH must parse");
    assert_eq!(hello.sni_domain(), Some("example.com"));
}

// ── Path Safety Tests ──

#[test]
fn safe_path_rejects_outside_directories() {
    // We can't call the private is_safe_domain_path directly,
    // but we test through load_domain_lists behavior
    let mut config = Config::default();
    config.domains.mode = DomainMode::Blacklist;
    config.domains.blacklist_file = Some("/tmp/evil.txt".to_string());
    // Should warn and skip, not load
    let _ = config.load_domain_lists();
    assert!(config.domain_set.is_empty());
}
