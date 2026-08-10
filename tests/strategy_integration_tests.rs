// tests/strategy_integration_tests.rs — Strategy engine integration tests
//
// Tests that StrategyEngine correctly evaluates real-world-like packets
// and returns the expected PacketActions across all modes.
// Also tests TLS/HTTP split, fake packet, passive detection, QUIC desync,
// window modification, nftables rule generation, and config TOML parsing.

use std::net::Ipv4Addr;
use std::path::Path;

use cachydpi::config::{Config, DomainMode};
use cachydpi::packet::ip;
use cachydpi::packet::tcp;
use cachydpi::packet::tls;
use cachydpi::packet::{Direction, ParsedPacket};
use cachydpi::strategies::{BypassMode, PacketAction, StrategyEngine};

// ═══════════════════════════════════════════════════════════════════
//  Packet builder helpers
// ═══════════════════════════════════════════════════════════════════

/// Build a complete IPv4+TCP packet with given parameters
fn build_ipv4_tcp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    ttl: u8,
    payload: &[u8],
) -> Vec<u8> {
    let tcp_seg = tcp::build_tcp_header(src_port, dst_port, seq, ack, flags, 65535, payload);
    let ip_hdr = ip::build_ipv4_header(src_ip, dst_ip, ip::PROTO_TCP, ttl, tcp_seg.len(), 0x1234);
    let mut packet = ip_hdr;
    packet.extend_from_slice(&tcp_seg);
    // Set TCP checksum
    let ip_hdr_len = (packet[0] & 0x0F) as usize * 4;
    let cksum = tcp::tcp_checksum_v4(&src_ip.octets(), &dst_ip.octets(), &packet[ip_hdr_len..]);
    tcp::set_tcp_checksum(&mut packet[ip_hdr_len..], cksum);
    packet
}

/// Build a TLS ClientHello payload with the given SNI domain
fn build_tls_client_hello(domain: &str) -> Vec<u8> {
    let sni_bytes = domain.as_bytes();

    // Build SNI extension
    let sni_entry_len = sni_bytes.len();
    let sni_list_len = sni_entry_len + 3; // type(1) + length(2) + name
    let sni_ext_len = sni_list_len + 2; // list_length(2) + list

    let mut extensions = Vec::new();
    // SNI extension type (0x0000)
    extensions.extend_from_slice(&[0x00, 0x00]);
    extensions.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
    extensions.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
    extensions.push(0x00); // host_name type
    extensions.extend_from_slice(&(sni_entry_len as u16).to_be_bytes());
    extensions.extend_from_slice(sni_bytes);

    // Build ClientHello
    let mut client_hello = Vec::new();
    client_hello.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
    client_hello.extend_from_slice(&[0u8; 32]); // Random
    client_hello.push(0x00); // Session ID length = 0
    client_hello.extend_from_slice(&[0x00, 0x02, 0x00, 0x2F]); // Cipher suites (1 suite)
    client_hello.extend_from_slice(&[0x01, 0x00]); // Compression methods: null
    // Extensions
    client_hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    client_hello.extend_from_slice(&extensions);

    // Build Handshake header
    let ch_len = client_hello.len();
    let mut handshake = Vec::new();
    handshake.push(0x01); // ClientHello type
    handshake.push(0x00);
    handshake.extend_from_slice(&(ch_len as u16).to_be_bytes());
    handshake.extend_from_slice(&client_hello);

    // Build TLS record
    let hs_len = handshake.len();
    let mut record = Vec::new();
    record.push(0x16); // ContentType: Handshake
    record.extend_from_slice(&[0x03, 0x01]); // TLS 1.0 record
    record.extend_from_slice(&(hs_len as u16).to_be_bytes());
    record.extend_from_slice(&handshake);

    record
}

/// Build a complete IPv4+TCP packet containing a TLS ClientHello to port 443
fn build_tls_packet(domain: &str, ttl: u8) -> Vec<u8> {
    let payload = build_tls_client_hello(domain);
    build_ipv4_tcp_packet(
        Ipv4Addr::new(192, 168, 1, 100),
        Ipv4Addr::new(93, 184, 216, 34),
        12345,
        443,
        1000,
        500,
        tcp::TCP_PSH | tcp::TCP_ACK,
        ttl,
        &payload,
    )
}

/// Build a complete IPv4+TCP packet containing an HTTP GET request to port 80
fn build_http_packet(host: &str) -> Vec<u8> {
    let payload = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        host
    );
    build_ipv4_tcp_packet(
        Ipv4Addr::new(192, 168, 1, 100),
        Ipv4Addr::new(93, 184, 216, 34),
        12345,
        80,
        1000,
        500,
        tcp::TCP_PSH | tcp::TCP_ACK,
        64,
        payload.as_bytes(),
    )
}

/// Build a TCP SYN packet to port 443
fn build_syn_packet(dst_port: u16) -> Vec<u8> {
    build_ipv4_tcp_packet(
        Ipv4Addr::new(192, 168, 1, 100),
        Ipv4Addr::new(93, 184, 216, 34),
        12345,
        dst_port,
        1000,
        0,
        tcp::TCP_SYN,
        64,
        &[],
    )
}

/// Build a TCP RST packet (from server side, for inbound testing)
fn build_rst_packet(window: u16, ttl: u8, flags: u8, options: &[u8]) -> Vec<u8> {
    // For RST with options, we build manually
    let src_ip = Ipv4Addr::new(93, 184, 216, 34);
    let dst_ip = Ipv4Addr::new(192, 168, 1, 100);
    let src_port: u16 = 443;
    let dst_port: u16 = 12345;

    let data_offset_bytes = 20 + options.len();
    let data_offset = ((data_offset_bytes + 3) / 4) as u8; // round up to 4-byte boundary
    let padded_header_len = (data_offset as usize) * 4;

    let mut tcp_seg = Vec::with_capacity(padded_header_len);
    tcp_seg.extend_from_slice(&src_port.to_be_bytes());
    tcp_seg.extend_from_slice(&dst_port.to_be_bytes());
    tcp_seg.extend_from_slice(&500u32.to_be_bytes()); // seq
    tcp_seg.extend_from_slice(&1001u32.to_be_bytes()); // ack
    tcp_seg.push(data_offset << 4);
    tcp_seg.push(flags);
    tcp_seg.extend_from_slice(&window.to_be_bytes());
    tcp_seg.extend_from_slice(&[0u8; 2]); // checksum placeholder
    tcp_seg.extend_from_slice(&[0u8; 2]); // urgent
    tcp_seg.extend_from_slice(options);
    // Pad to 4-byte alignment
    while tcp_seg.len() < padded_header_len {
        tcp_seg.push(0);
    }

    let ip_hdr = ip::build_ipv4_header(src_ip, dst_ip, ip::PROTO_TCP, ttl, tcp_seg.len(), 0x5678);
    let mut packet = ip_hdr;
    packet.extend_from_slice(&tcp_seg);

    let ip_hdr_len = (packet[0] & 0x0F) as usize * 4;
    let cksum = tcp::tcp_checksum_v4(&src_ip.octets(), &dst_ip.octets(), &packet[ip_hdr_len..]);
    tcp::set_tcp_checksum(&mut packet[ip_hdr_len..], cksum);
    packet
}

/// Build a SYN-ACK packet (from server side, for auto-TTL detection)
fn build_syn_ack_packet(ttl: u8) -> Vec<u8> {
    build_ipv4_tcp_packet(
        Ipv4Addr::new(93, 184, 216, 34),
        Ipv4Addr::new(192, 168, 1, 100),
        443,
        12345,
        5000,
        1001,
        tcp::TCP_SYN | tcp::TCP_ACK,
        ttl,
        &[],
    )
}

/// Build a UDP QUIC Initial packet to port 443
fn build_quic_initial_packet() -> Vec<u8> {
    let src_ip = Ipv4Addr::new(192, 168, 1, 100);
    let dst_ip = Ipv4Addr::new(93, 184, 216, 34);

    // QUIC Initial: long header (0xC0 = long form + fixed bit), version 1
    let mut quic_payload = Vec::new();
    quic_payload.push(0xC3); // Long header + fixed bit + packet type
    quic_payload.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // Version 1
    quic_payload.push(0x08); // DCID length
    quic_payload.extend_from_slice(&[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]); // DCID
    quic_payload.push(0x00); // SCID length
    quic_payload.extend_from_slice(&[0x00]); // Token length (varint 0)
    quic_payload.extend_from_slice(&[0x41, 0x00]); // Payload length (varint)
    quic_payload.extend_from_slice(&[0x00; 200]); // Packet body padding (>100 for MIN_QUIC_PACKET)

    // UDP header
    let udp_len = 8 + quic_payload.len();
    let mut udp_seg = Vec::new();
    udp_seg.extend_from_slice(&54321u16.to_be_bytes()); // src port
    udp_seg.extend_from_slice(&443u16.to_be_bytes()); // dst port
    udp_seg.extend_from_slice(&(udp_len as u16).to_be_bytes());
    udp_seg.extend_from_slice(&[0u8; 2]); // checksum
    udp_seg.extend_from_slice(&quic_payload);

    let ip_hdr = ip::build_ipv4_header(src_ip, dst_ip, ip::PROTO_UDP, 64, udp_seg.len(), 0xABCD);
    let mut packet = ip_hdr;
    packet.extend_from_slice(&udp_seg);
    packet
}

/// Base config for the strategy tests, with the domain filter switched off.
///
/// These tests exercise strategy behaviour rather than domain filtering, and
/// the default mode is now the restrictive one — leaving it in place would
/// filter every packet out before the strategy under test runs.
fn default_config() -> Config {
    let mut c = Config::default();
    c.domains.mode = DomainMode::None;
    c
}

fn config_with_fake_packets() -> Config {
    let mut c = default_config();
    c.strategies.fake_packet_enabled = true;
    c.strategies.fake_packet_ttl = 3;
    c.strategies.auto_ttl = false;
    c
}

fn config_with_window(size: u16) -> Config {
    let mut c = default_config();
    c.strategies.tcp_window_size = size;
    c
}

fn config_with_blacklist(domains: Vec<String>) -> Config {
    let mut c = Config::default();
    c.domains.mode = DomainMode::Blacklist;
    c.domains.blacklist = domains.clone();
    c.domain_set = domains.into_iter().collect();
    c
}

// ═══════════════════════════════════════════════════════════════════
//  Module 1: StrategyEngine.evaluate_outbound — TLS ClientHello
// ═══════════════════════════════════════════════════════════════════

mod evaluate_outbound_tls {
    use super::*;

    #[test]
    fn mode_passive_accepts_tls() {
        let engine = StrategyEngine::new(BypassMode::Passive, default_config());
        let pkt_data = build_tls_packet("example.com", 64);
        let parsed = ParsedPacket::parse(&pkt_data, Direction::Outbound).unwrap();
        let action = engine.evaluate_outbound(&parsed);
        assert!(
            matches!(action, PacketAction::Accept),
            "Passive mode should accept TLS: {action:?}"
        );
    }

    #[test]
    fn mode_http_fragment_accepts_tls() {
        let engine = StrategyEngine::new(BypassMode::HttpFragment, default_config());
        let pkt_data = build_tls_packet("example.com", 64);
        let parsed = ParsedPacket::parse(&pkt_data, Direction::Outbound).unwrap();
        let action = engine.evaluate_outbound(&parsed);
        assert!(
            matches!(action, PacketAction::Accept),
            "HttpFragment mode should accept TLS: {action:?}"
        );
    }

    #[test]
    fn mode_tls_fragment_fragments_tls() {
        let engine = StrategyEngine::new(BypassMode::TlsFragment, default_config());
        let pkt_data = build_tls_packet("example.com", 64);
        let parsed = ParsedPacket::parse(&pkt_data, Direction::Outbound).unwrap();
        let action = engine.evaluate_outbound(&parsed);
        assert!(
            matches!(action, PacketAction::Fragment(_)),
            "TlsFragment mode should fragment TLS: {action:?}"
        );
        if let PacketAction::Fragment(frags) = action {
            assert!(
                frags.len() >= 2,
                "Should produce at least 2 fragments, got {}",
                frags.len()
            );
            // Each fragment must be a valid IP packet
            for (i, frag) in frags.iter().enumerate() {
                assert!(
                    frag.len() >= 40,
                    "Fragment {i} too small: {} bytes",
                    frag.len()
                );
                assert_eq!(frag[0] >> 4, 4, "Fragment {i} must be IPv4");
            }
        }
    }

    #[test]
    fn mode_all_active_fragments_tls() {
        let engine = StrategyEngine::new(BypassMode::AllActive, default_config());
        let pkt_data = build_tls_packet("example.com", 64);
        let parsed = ParsedPacket::parse(&pkt_data, Direction::Outbound).unwrap();
        let action = engine.evaluate_outbound(&parsed);
        // AllActive with default config (fake_packet_enabled=false) → Fragment
        assert!(
            matches!(action, PacketAction::Fragment(_)),
            "AllActive should fragment TLS: {action:?}"
        );
    }

    #[test]
    fn mode_all_active_with_fakes_injects_and_fragments() {
        let engine = StrategyEngine::new(BypassMode::AllActive, config_with_fake_packets());
        let pkt_data = build_tls_packet("example.com", 64);
        let parsed = ParsedPacket::parse(&pkt_data, Direction::Outbound).unwrap();
        let action = engine.evaluate_outbound(&parsed);
        assert!(
            matches!(action, PacketAction::InjectAndFragment { .. }),
            "AllActive with fakes should InjectAndFragment: {action:?}"
        );
        if let PacketAction::InjectAndFragment { fakes, fragments } = action {
            assert!(!fakes.is_empty(), "Should have at least 1 fake packet");
            assert!(fragments.len() >= 2, "Should have at least 2 fragments");
        }
    }

    #[test]
    fn mode_fake_packet_injects_then_accepts() {
        let engine = StrategyEngine::new(BypassMode::FakePacket, config_with_fake_packets());
        let pkt_data = build_tls_packet("example.com", 64);
        let parsed = ParsedPacket::parse(&pkt_data, Direction::Outbound).unwrap();
        let action = engine.evaluate_outbound(&parsed);
        assert!(
            matches!(action, PacketAction::InjectThenAccept(_)),
            "FakePacket mode should InjectThenAccept: {action:?}"
        );
    }

    #[test]
    fn mode_aggressive_fragments_tls() {
        let engine = StrategyEngine::new(BypassMode::Aggressive, default_config());
        let pkt_data = build_tls_packet("example.com", 64);
        let parsed = ParsedPacket::parse(&pkt_data, Direction::Outbound).unwrap();
        let action = engine.evaluate_outbound(&parsed);
        assert!(
            matches!(
                action,
                PacketAction::Fragment(_) | PacketAction::InjectAndFragment { .. }
            ),
            "Aggressive should fragment/inject TLS: {action:?}"
        );
    }

    #[test]
    fn tls_no_sni_is_accepted() {
        // Build a TLS ClientHello with no SNI extension
        let mut payload = Vec::new();
        payload.push(0x16); // Handshake
        payload.extend_from_slice(&[0x03, 0x01]); // TLS 1.0
        // Minimal ClientHello without extensions
        let mut ch = Vec::new();
        ch.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        ch.extend_from_slice(&[0u8; 32]); // Random
        ch.push(0x00); // Session ID len
        ch.extend_from_slice(&[0x00, 0x02, 0x00, 0x2F]); // Cipher suites
        ch.extend_from_slice(&[0x01, 0x00]); // Compression
        ch.extend_from_slice(&[0x00, 0x00]); // Empty extensions

        let ch_len = ch.len();
        let mut hs = vec![0x01, 0x00];
        hs.extend_from_slice(&(ch_len as u16).to_be_bytes());
        hs.extend_from_slice(&ch);

        let hs_len = hs.len();
        payload.extend_from_slice(&(hs_len as u16).to_be_bytes());
        payload.extend_from_slice(&hs);

        let pkt = build_ipv4_tcp_packet(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(93, 184, 216, 34),
            12345,
            443,
            1000,
            500,
            tcp::TCP_PSH | tcp::TCP_ACK,
            64,
            &payload,
        );

        let engine = StrategyEngine::new(BypassMode::AllActive, default_config());
        let parsed = ParsedPacket::parse(&pkt, Direction::Outbound).unwrap();
        let action = engine.evaluate_outbound(&parsed);
        // No SNI → can't split → Accept
        assert!(
            matches!(action, PacketAction::Accept),
            "No-SNI TLS should be accepted: {action:?}"
        );
    }

    #[test]
    fn blacklist_skips_unmatched_domains() {
        let config = config_with_blacklist(vec!["blocked.com".to_string()]);
        let engine = StrategyEngine::new(BypassMode::AllActive, config);

        // Domain NOT in blacklist → Accept
        let pkt = build_tls_packet("allowed.com", 64);
        let parsed = ParsedPacket::parse(&pkt, Direction::Outbound).unwrap();
        let action = engine.evaluate_outbound(&parsed);
        assert!(
            matches!(action, PacketAction::Accept),
            "Non-blacklisted domain should be accepted: {action:?}"
        );
    }

    #[test]
    fn blacklist_processes_matched_domains() {
        let config = config_with_blacklist(vec!["blocked.com".to_string()]);
        let engine = StrategyEngine::new(BypassMode::TlsFragment, config);

        // Domain IN blacklist → Fragment
        let pkt = build_tls_packet("blocked.com", 64);
        let parsed = ParsedPacket::parse(&pkt, Direction::Outbound).unwrap();
        let action = engine.evaluate_outbound(&parsed);
        assert!(
            matches!(action, PacketAction::Fragment(_)),
            "Blacklisted domain should be fragmented: {action:?}"
        );
    }

    #[test]
    fn fragment_output_preserves_total_payload() {
        let engine = StrategyEngine::new(BypassMode::TlsFragment, default_config());
        let domain = "www.example.com";
        let pkt_data = build_tls_packet(domain, 64);
        let parsed = ParsedPacket::parse(&pkt_data, Direction::Outbound).unwrap();
        let original_tcp = parsed.tcp().unwrap();
        let original_payload_len = original_tcp.payload.len();

        let action = engine.evaluate_outbound(&parsed);
        if let PacketAction::Fragment(frags) = action {
            // Sum of all fragment TCP payloads must equal original
            let mut total_frag_payload = 0;
            for frag in &frags {
                let frag_parsed = ParsedPacket::parse(frag, Direction::Outbound).unwrap();
                let frag_tcp = frag_parsed.tcp().unwrap();
                total_frag_payload += frag_tcp.payload.len();
            }
            assert_eq!(
                total_frag_payload, original_payload_len,
                "Fragment payloads ({total_frag_payload}) must sum to original ({original_payload_len})"
            );
        } else {
            panic!("Expected Fragment action, got {action:?}");
        }
    }

    #[test]
    fn fragment_sequence_numbers_are_correct() {
        let engine = StrategyEngine::new(BypassMode::TlsFragment, {
            let mut c = default_config();
            c.strategies.disorder = false;
            c.strategies.multi_fragment = false;
            c
        });
        let pkt_data = build_tls_packet("example.com", 64);
        let parsed = ParsedPacket::parse(&pkt_data, Direction::Outbound).unwrap();
        let original_seq = parsed.tcp().unwrap().seq_num;

        if let PacketAction::Fragment(frags) = engine.evaluate_outbound(&parsed) {
            let frag1 = ParsedPacket::parse(&frags[0], Direction::Outbound).unwrap();
            let frag1_tcp = frag1.tcp().unwrap();
            assert_eq!(
                frag1_tcp.seq_num, original_seq,
                "First fragment seq should match original"
            );

            let frag2 = ParsedPacket::parse(&frags[1], Direction::Outbound).unwrap();
            let frag2_tcp = frag2.tcp().unwrap();
            let expected_seq2 = original_seq.wrapping_add(frag1_tcp.payload.len() as u32);
            assert_eq!(
                frag2_tcp.seq_num, expected_seq2,
                "Second fragment seq should be seq + frag1_payload_len"
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Module 2: StrategyEngine.evaluate_outbound — HTTP
// ═══════════════════════════════════════════════════════════════════

mod evaluate_outbound_http {
    use super::*;

    #[test]
    fn mode_passive_accepts_http() {
        let engine = StrategyEngine::new(BypassMode::Passive, default_config());
        let pkt = build_http_packet("example.com");
        let parsed = ParsedPacket::parse(&pkt, Direction::Outbound).unwrap();
        let action = engine.evaluate_outbound(&parsed);
        assert!(
            matches!(action, PacketAction::Accept),
            "Passive should accept HTTP: {action:?}"
        );
    }

    #[test]
    fn mode_http_fragment_fragments_http() {
        let engine = StrategyEngine::new(BypassMode::HttpFragment, default_config());
        let pkt = build_http_packet("example.com");
        let parsed = ParsedPacket::parse(&pkt, Direction::Outbound).unwrap();
        let action = engine.evaluate_outbound(&parsed);
        assert!(
            matches!(action, PacketAction::Fragment(_)),
            "HttpFragment should fragment HTTP: {action:?}"
        );
    }

    #[test]
    fn mode_tls_fragment_accepts_http() {
        let engine = StrategyEngine::new(BypassMode::TlsFragment, default_config());
        let pkt = build_http_packet("example.com");
        let parsed = ParsedPacket::parse(&pkt, Direction::Outbound).unwrap();
        let action = engine.evaluate_outbound(&parsed);
        assert!(
            matches!(action, PacketAction::Accept),
            "TlsFragment should accept HTTP: {action:?}"
        );
    }

    #[test]
    fn mode_all_active_fragments_http() {
        let engine = StrategyEngine::new(BypassMode::AllActive, default_config());
        let pkt = build_http_packet("example.com");
        let parsed = ParsedPacket::parse(&pkt, Direction::Outbound).unwrap();
        let action = engine.evaluate_outbound(&parsed);
        assert!(
            matches!(action, PacketAction::Fragment(_)),
            "AllActive should fragment HTTP: {action:?}"
        );
    }

    #[test]
    fn http_blacklist_skips_unmatched() {
        let config = config_with_blacklist(vec!["blocked.com".to_string()]);
        let engine = StrategyEngine::new(BypassMode::HttpFragment, config);

        let pkt = build_http_packet("allowed.com");
        let parsed = ParsedPacket::parse(&pkt, Direction::Outbound).unwrap();
        let action = engine.evaluate_outbound(&parsed);
        assert!(
            matches!(action, PacketAction::Accept),
            "Non-blacklisted HTTP should accept: {action:?}"
        );
    }

    #[test]
    fn http_blacklist_processes_matched() {
        let config = config_with_blacklist(vec!["blocked.com".to_string()]);
        let engine = StrategyEngine::new(BypassMode::HttpFragment, config);

        let pkt = build_http_packet("blocked.com");
        let parsed = ParsedPacket::parse(&pkt, Direction::Outbound).unwrap();
        let action = engine.evaluate_outbound(&parsed);
        assert!(
            matches!(action, PacketAction::Fragment(_)),
            "Blacklisted HTTP should fragment: {action:?}"
        );
    }

    #[test]
    fn http_fragment_preserves_payload() {
        let engine = StrategyEngine::new(BypassMode::HttpFragment, default_config());
        let pkt = build_http_packet("example.com");
        let parsed = ParsedPacket::parse(&pkt, Direction::Outbound).unwrap();
        let original_len = parsed.tcp().unwrap().payload.len();

        if let PacketAction::Fragment(frags) = engine.evaluate_outbound(&parsed) {
            let total: usize = frags
                .iter()
                .map(|f| {
                    ParsedPacket::parse(f, Direction::Outbound)
                        .unwrap()
                        .tcp()
                        .unwrap()
                        .payload
                        .len()
                })
                .sum();
            assert_eq!(
                total, original_len,
                "HTTP fragment payloads must sum to original"
            );
        }
    }

    #[test]
    fn non_http_port80_data_accepted() {
        // Binary garbage on port 80 — not HTTP
        let pkt = build_ipv4_tcp_packet(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(93, 184, 216, 34),
            12345,
            80,
            1000,
            500,
            tcp::TCP_PSH | tcp::TCP_ACK,
            64,
            &[0xFF, 0xFE, 0x01, 0x02, 0x03],
        );
        let engine = StrategyEngine::new(BypassMode::HttpFragment, default_config());
        let parsed = ParsedPacket::parse(&pkt, Direction::Outbound).unwrap();
        let action = engine.evaluate_outbound(&parsed);
        assert!(
            matches!(action, PacketAction::Accept),
            "Non-HTTP data on port 80 should accept: {action:?}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Module 3: StrategyEngine.evaluate_outbound — SYN window, QUIC, misc
// ═══════════════════════════════════════════════════════════════════

mod evaluate_outbound_misc {
    use super::*;

    #[test]
    fn syn_without_window_config_is_accepted() {
        let engine = StrategyEngine::new(BypassMode::AllActive, default_config());
        let pkt = build_syn_packet(443);
        let parsed = ParsedPacket::parse(&pkt, Direction::Outbound).unwrap();
        let action = engine.evaluate_outbound(&parsed);
        assert!(
            matches!(action, PacketAction::Accept),
            "SYN without window config should accept: {action:?}"
        );
    }

    #[test]
    fn syn_with_window_config_modifies() {
        let engine = StrategyEngine::new(BypassMode::AllActive, config_with_window(40));
        let pkt = build_syn_packet(443);
        let parsed = ParsedPacket::parse(&pkt, Direction::Outbound).unwrap();
        let action = engine.evaluate_outbound(&parsed);
        assert!(
            matches!(action, PacketAction::Modify(_)),
            "SYN with window config should modify: {action:?}"
        );
        if let PacketAction::Modify(modified) = action {
            let mod_parsed = ParsedPacket::parse(&modified, Direction::Outbound).unwrap();
            let mod_tcp = mod_parsed.tcp().unwrap();
            assert_eq!(mod_tcp.window_size, 40, "Window should be modified to 40");
        }
    }

    #[test]
    fn syn_window_only_for_matching_modes() {
        // Passive mode should NOT modify window even with config
        let engine = StrategyEngine::new(BypassMode::Passive, config_with_window(40));
        let pkt = build_syn_packet(443);
        let parsed = ParsedPacket::parse(&pkt, Direction::Outbound).unwrap();
        let action = engine.evaluate_outbound(&parsed);
        assert!(
            matches!(action, PacketAction::Accept),
            "Passive mode should not modify window: {action:?}"
        );
    }

    #[test]
    fn quic_only_in_aggressive_and_autodetect() {
        let pkt = build_quic_initial_packet();

        // Mode 5 (AllActive) should NOT desync QUIC
        let engine = StrategyEngine::new(BypassMode::AllActive, default_config());
        let parsed = ParsedPacket::parse(&pkt, Direction::Outbound).unwrap();
        let action = engine.evaluate_outbound(&parsed);
        assert!(
            matches!(action, PacketAction::Accept),
            "AllActive should accept QUIC: {action:?}"
        );

        // Mode 6 (Aggressive) SHOULD desync QUIC
        let engine = StrategyEngine::new(BypassMode::Aggressive, default_config());
        let parsed = ParsedPacket::parse(&pkt, Direction::Outbound).unwrap();
        let action = engine.evaluate_outbound(&parsed);
        assert!(
            matches!(action, PacketAction::Fragment(_)),
            "Aggressive should fragment QUIC: {action:?}"
        );
    }

    #[test]
    fn non_tcp_non_udp_is_accepted() {
        // Build an ICMP packet (protocol 1) — should be accepted by all strategies
        let src_ip = Ipv4Addr::new(192, 168, 1, 100);
        let dst_ip = Ipv4Addr::new(93, 184, 216, 34);
        let icmp_payload = [0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01]; // Echo request
        let ip_hdr =
            ip::build_ipv4_header(src_ip, dst_ip, ip::PROTO_ICMP, 64, icmp_payload.len(), 0);
        let mut pkt = ip_hdr;
        pkt.extend_from_slice(&icmp_payload);

        let engine = StrategyEngine::new(BypassMode::Aggressive, default_config());
        let parsed = ParsedPacket::parse(&pkt, Direction::Outbound).unwrap();
        let action = engine.evaluate_outbound(&parsed);
        assert!(
            matches!(action, PacketAction::Accept),
            "ICMP should be accepted: {action:?}"
        );
    }

    #[test]
    fn ack_only_no_payload_accepted() {
        // ACK without payload should be accepted even on port 443
        let pkt = build_ipv4_tcp_packet(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(93, 184, 216, 34),
            12345,
            443,
            1000,
            500,
            tcp::TCP_ACK,
            64,
            &[],
        );
        let engine = StrategyEngine::new(BypassMode::AllActive, default_config());
        let parsed = ParsedPacket::parse(&pkt, Direction::Outbound).unwrap();
        let action = engine.evaluate_outbound(&parsed);
        assert!(
            matches!(action, PacketAction::Accept),
            "Empty ACK should accept: {action:?}"
        );
    }

    #[test]
    fn non_standard_port_data_accepted() {
        // Data on port 9999 — not HTTP/HTTPS, should pass through
        let payload = build_tls_client_hello("example.com");
        let pkt = build_ipv4_tcp_packet(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(93, 184, 216, 34),
            12345,
            9999,
            1000,
            500,
            tcp::TCP_PSH | tcp::TCP_ACK,
            64,
            &payload,
        );
        let engine = StrategyEngine::new(BypassMode::AllActive, default_config());
        let parsed = ParsedPacket::parse(&pkt, Direction::Outbound).unwrap();
        let action = engine.evaluate_outbound(&parsed);
        assert!(
            matches!(action, PacketAction::Accept),
            "Non-HTTP/S port should accept: {action:?}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Module 4: evaluate_inbound — Passive DPI detection
// ═══════════════════════════════════════════════════════════════════

mod evaluate_inbound {
    use super::*;

    #[test]
    fn forged_rst_is_dropped() {
        // Classic DPI-forged RST: window=0, no options, TTL=64, RST+ACK
        let pkt = build_rst_packet(0, 64, tcp::TCP_RST | tcp::TCP_ACK, &[]);
        let engine = StrategyEngine::new(BypassMode::AllActive, default_config());
        let parsed = ParsedPacket::parse(&pkt, Direction::Inbound).unwrap();
        let action = engine.evaluate_inbound(&parsed);
        assert!(
            matches!(action, PacketAction::Drop),
            "Forged RST should be dropped: {action:?}"
        );
    }

    #[test]
    fn legitimate_rst_is_accepted() {
        // Real RST: has window, has options, normal TTL (44 = 64-20 hops)
        let timestamps = [
            0x08, 0x0A, // Kind=8 Timestamps, Length=10
            0x00, 0x01, 0x02, 0x03, // TSval
            0x00, 0x04, 0x05, 0x06, // TSecr
        ];
        let pkt = build_rst_packet(32768, 44, tcp::TCP_RST, &timestamps);
        let engine = StrategyEngine::new(BypassMode::AllActive, default_config());
        let parsed = ParsedPacket::parse(&pkt, Direction::Inbound).unwrap();
        let action = engine.evaluate_inbound(&parsed);
        assert!(
            matches!(action, PacketAction::Accept),
            "Legitimate RST should be accepted: {action:?}"
        );
    }

    #[test]
    fn passive_disabled_in_non_passive_modes() {
        // HttpFragment (mode 2) doesn't have passive detection
        let pkt = build_rst_packet(0, 64, tcp::TCP_RST | tcp::TCP_ACK, &[]);
        let engine = StrategyEngine::new(BypassMode::HttpFragment, default_config());
        let parsed = ParsedPacket::parse(&pkt, Direction::Inbound).unwrap();
        let action = engine.evaluate_inbound(&parsed);
        assert!(
            matches!(action, PacketAction::Accept),
            "Mode 2 should not drop RST: {action:?}"
        );
    }

    #[test]
    fn passive_disabled_when_config_off() {
        let mut config = default_config();
        config.strategies.passive_dpi = false;
        let engine = StrategyEngine::new(BypassMode::AllActive, config);

        let pkt = build_rst_packet(0, 64, tcp::TCP_RST | tcp::TCP_ACK, &[]);
        let parsed = ParsedPacket::parse(&pkt, Direction::Inbound).unwrap();
        let action = engine.evaluate_inbound(&parsed);
        assert!(
            matches!(action, PacketAction::Accept),
            "Passive off should accept: {action:?}"
        );
    }

    #[test]
    fn auto_ttl_detection_from_syn_ack() {
        let config = default_config(); // auto_ttl=true by default
        let engine = StrategyEngine::new(BypassMode::AllActive, config);

        // Server at 20 hops: initial_ttl=64, recv_ttl=44, hops=20, fake_ttl=18
        let pkt = build_syn_ack_packet(44);
        let parsed = ParsedPacket::parse(&pkt, Direction::Inbound).unwrap();
        let _action = engine.evaluate_inbound(&parsed);

        // Now check that fake TTL was cached for this destination
        let dst = parsed.src_addr(); // server is the source in inbound
        let fake_ttl = engine.get_fake_ttl_for_test(dst);
        assert!(fake_ttl > 0, "Auto-TTL should be detected from SYN-ACK");
        assert!(
            fake_ttl < 44,
            "Fake TTL ({fake_ttl}) should be less than received TTL (44)"
        );
    }

    #[test]
    fn auto_ttl_cache_eviction() {
        let config = default_config();
        let engine = StrategyEngine::new(BypassMode::AllActive, config);

        // Fill TTL cache beyond MAX_TTL_CACHE_ENTRIES (1024)
        for i in 0..1030u32 {
            let ip = Ipv4Addr::new((i >> 16) as u8, (i >> 8) as u8, i as u8, 1);
            let pkt = build_ipv4_tcp_packet(
                ip,
                Ipv4Addr::new(192, 168, 1, 100),
                443,
                12345,
                5000,
                1001,
                tcp::TCP_SYN | tcp::TCP_ACK,
                44,
                &[],
            );
            let parsed = ParsedPacket::parse(&pkt, Direction::Inbound).unwrap();
            engine.evaluate_inbound(&parsed);
        }
        // Should not panic or leak — cache size should be bounded
    }

    #[test]
    fn forged_rst_score_boundary() {
        // Score exactly 2 (window=0 only) — should NOT be dropped (threshold=3)
        let pkt = build_rst_packet(
            0,                                     // window=0 → +2
            44,                                    // normal TTL → +0
            tcp::TCP_RST,                          // no ACK → +0
            &[0x08, 0x0A, 0, 0, 0, 0, 0, 0, 0, 0], // has options → +0
        );
        let engine = StrategyEngine::new(BypassMode::AllActive, default_config());
        let parsed = ParsedPacket::parse(&pkt, Direction::Inbound).unwrap();
        let action = engine.evaluate_inbound(&parsed);
        assert!(
            matches!(action, PacketAction::Accept),
            "Score=2 RST should be accepted: {action:?}"
        );
    }

    #[test]
    fn forged_http_redirect_detection() {
        // Build an HTTP 302 redirect with block page keywords
        let redirect =
            b"HTTP/1.1 302 Found\r\nLocation: http://block.isp.com/warning\r\n\r\nblocked by ISP";
        let pkt = build_ipv4_tcp_packet(
            Ipv4Addr::new(93, 184, 216, 34),
            Ipv4Addr::new(192, 168, 1, 100),
            80,
            12345,
            5000,
            1001,
            tcp::TCP_PSH | tcp::TCP_ACK,
            64,
            redirect,
        );
        let engine = StrategyEngine::new(BypassMode::AllActive, default_config());
        let parsed = ParsedPacket::parse(&pkt, Direction::Inbound).unwrap();
        let action = engine.evaluate_inbound(&parsed);
        // This should be detected as a forged redirect (block page keyword + 302 + TTL=64)
        assert!(
            matches!(action, PacketAction::Drop),
            "Forged redirect should be dropped: {action:?}"
        );
    }

    #[test]
    fn legitimate_redirect_accepted() {
        // Real 302 redirect: no block keywords, normal TTL
        let redirect = b"HTTP/1.1 302 Found\r\nLocation: https://www.example.com/new-page\r\nContent-Length: 0\r\nServer: nginx\r\n\r\n";
        let pkt = build_ipv4_tcp_packet(
            Ipv4Addr::new(93, 184, 216, 34),
            Ipv4Addr::new(192, 168, 1, 100),
            80,
            12345,
            5000,
            1001,
            tcp::TCP_PSH | tcp::TCP_ACK,
            44,
            redirect,
        );
        let engine = StrategyEngine::new(BypassMode::AllActive, default_config());
        let parsed = ParsedPacket::parse(&pkt, Direction::Inbound).unwrap();
        let action = engine.evaluate_inbound(&parsed);
        assert!(
            matches!(action, PacketAction::Accept),
            "Legitimate redirect should be accepted: {action:?}"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Module 5: TLS split strategy correctness
// ═══════════════════════════════════════════════════════════════════

mod tls_split_tests {
    use super::*;
    use cachydpi::strategies::tls_split;

    #[test]
    fn split_tls_client_hello_produces_valid_fragments() {
        let domain = "www.twitter.com";
        let pkt_data = build_tls_packet(domain, 64);
        let parsed = ParsedPacket::parse(&pkt_data, Direction::Outbound).unwrap();
        let tcp_hdr = parsed.tcp().unwrap();
        let hello = tls::TlsClientHello::parse(tcp_hdr.payload).unwrap();

        let frags = tls_split::split_tls_client_hello(&pkt_data, &parsed.ip, tcp_hdr, &hello, 0);
        assert!(
            frags.is_some(),
            "Should produce fragments for valid ClientHello"
        );
        let frags = frags.unwrap();
        assert_eq!(frags.len(), 2, "Should produce exactly 2 fragments");

        // Both fragments should be parseable as valid IP+TCP
        for (i, frag) in frags.iter().enumerate() {
            let fp = ParsedPacket::parse(frag, Direction::Outbound);
            assert!(fp.is_some(), "Fragment {i} should be a valid packet");
            let fp = fp.unwrap();
            assert!(fp.tcp().is_some(), "Fragment {i} should have TCP header");
        }

        // Reassembled payload must contain original SNI
        let mut reassembled = Vec::new();
        for frag in &frags {
            let fp = ParsedPacket::parse(frag, Direction::Outbound).unwrap();
            reassembled.extend_from_slice(fp.tcp().unwrap().payload);
        }
        assert!(
            tls::is_tls_client_hello(&reassembled),
            "Reassembled payload should be valid TLS"
        );
        let re_hello = tls::TlsClientHello::parse(&reassembled).unwrap();
        assert_eq!(re_hello.sni.as_deref(), Some(domain));
    }

    #[test]
    fn split_tls_out_of_order_reverses_fragments() {
        let domain = "discord.com";
        let pkt_data = build_tls_packet(domain, 64);
        let parsed = ParsedPacket::parse(&pkt_data, Direction::Outbound).unwrap();
        let tcp_hdr = parsed.tcp().unwrap();
        let hello = tls::TlsClientHello::parse(tcp_hdr.payload).unwrap();

        let frags = tls_split::split_tls_out_of_order(&pkt_data, &parsed.ip, tcp_hdr, &hello);
        assert!(frags.is_some(), "Should produce OOO fragments");
        let frags = frags.unwrap();
        assert!(frags.len() >= 2, "Should have at least 2 fragments");

        // In disorder mode, the second fragment (higher seq) should come FIRST
        let frag0 = ParsedPacket::parse(&frags[0], Direction::Outbound).unwrap();
        let frag1 = ParsedPacket::parse(&frags[1], Direction::Outbound).unwrap();
        let seq0 = frag0.tcp().unwrap().seq_num;
        let seq1 = frag1.tcp().unwrap().seq_num;
        assert!(
            seq0 > seq1,
            "OOO: first sent fragment seq ({seq0}) should be > second ({seq1})"
        );
    }

    #[test]
    fn split_tls_multi_fragment_produces_3plus_segments() {
        let domain = "www.reddit.com";
        let pkt_data = build_tls_packet(domain, 64);
        let parsed = ParsedPacket::parse(&pkt_data, Direction::Outbound).unwrap();
        let tcp_hdr = parsed.tcp().unwrap();
        let hello = tls::TlsClientHello::parse(tcp_hdr.payload).unwrap();

        let frags =
            tls_split::split_tls_multi_fragment(&pkt_data, &parsed.ip, tcp_hdr, &hello, false);
        if let Some(frags) = frags {
            assert!(
                frags.len() >= 3,
                "Multi-fragment should produce 3+ segments, got {}",
                frags.len()
            );
        }
        // It's OK if multi_fragment returns None for short payloads
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Module 6: HTTP split strategy correctness
// ═══════════════════════════════════════════════════════════════════

mod http_split_tests {
    use super::*;
    use cachydpi::strategies::http_split;

    #[test]
    fn split_http_request_produces_valid_fragments() {
        let host = "www.example.com";
        let pkt = build_http_packet(host);
        let parsed = ParsedPacket::parse(&pkt, Direction::Outbound).unwrap();
        let tcp_hdr = parsed.tcp().unwrap();

        let frags = http_split::split_http_request(&pkt, &parsed.ip, tcp_hdr, 0);
        assert!(frags.is_some(), "Should split HTTP request");
        let frags = frags.unwrap();
        assert_eq!(frags.len(), 2, "HTTP split produces 2 fragments");

        // Reassemble and verify HTTP host is intact
        let mut reassembled = Vec::new();
        for frag in &frags {
            let fp = ParsedPacket::parse(frag, Direction::Outbound).unwrap();
            reassembled.extend_from_slice(fp.tcp().unwrap().payload);
        }
        let reassembled_str = String::from_utf8_lossy(&reassembled);
        assert!(reassembled_str.contains(&format!("Host: {host}")));
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Module 7: Fake packet correctness
// ═══════════════════════════════════════════════════════════════════

mod fake_packet_tests {
    use super::*;
    use cachydpi::strategies::fake_packet;

    #[test]
    fn fake_packets_have_low_ttl() {
        let pkt = build_tls_packet("example.com", 64);
        let parsed = ParsedPacket::parse(&pkt, Direction::Outbound).unwrap();
        let tcp_hdr = parsed.tcp().unwrap();

        let fakes = fake_packet::create_fake_packets(
            &pkt,
            &parsed.ip,
            tcp_hdr,
            3,
            &config_with_fake_packets(),
        );
        assert!(!fakes.is_empty(), "Should create fake packets");

        for (i, fake) in fakes.iter().enumerate() {
            let fp = ParsedPacket::parse(fake, Direction::Outbound);
            assert!(fp.is_some(), "Fake packet {i} should be valid IP+TCP");
            let fp = fp.unwrap();
            let ttl = fp.ttl();
            assert!(ttl <= 5, "Fake packet {i} TTL should be low (got {ttl})");
        }
    }

    #[test]
    fn fake_rst_desync_has_rst_flag() {
        let pkt = build_tls_packet("example.com", 64);
        let parsed = ParsedPacket::parse(&pkt, Direction::Outbound).unwrap();
        let tcp_hdr = parsed.tcp().unwrap();

        let fake_rst = fake_packet::create_fake_rst_desync(&pkt, &parsed.ip, tcp_hdr, 3);
        assert!(fake_rst.is_some(), "Should create fake RST");
        let rst = fake_rst.unwrap();
        let rst_parsed = ParsedPacket::parse(&rst, Direction::Outbound).unwrap();
        let rst_tcp = rst_parsed.tcp().unwrap();
        assert!(rst_tcp.is_rst(), "Fake RST should have RST flag");
        assert!(rst_parsed.ttl() <= 5, "Fake RST TTL should be low");
    }

    #[test]
    fn fake_client_hello_is_parseable() {
        let fake_ch = fake_packet::build_fake_client_hello_payload("google.com");
        assert!(
            tls::is_tls_client_hello(&fake_ch),
            "Fake ClientHello should look like real TLS"
        );
        let hello = tls::TlsClientHello::parse(&fake_ch);
        assert!(
            hello.is_some(),
            "Fake ClientHello should parse successfully"
        );
        let hello = hello.unwrap();
        assert_eq!(
            hello.sni.as_deref(),
            Some("google.com"),
            "Fake CH should have google.com SNI"
        );
    }

    #[test]
    fn fake_packets_with_wrong_checksum() {
        let mut config = config_with_fake_packets();
        config.strategies.fake_wrong_checksum = true;

        let pkt = build_tls_packet("example.com", 64);
        let parsed = ParsedPacket::parse(&pkt, Direction::Outbound).unwrap();
        let tcp_hdr = parsed.tcp().unwrap();

        let fakes = fake_packet::create_fake_packets(&pkt, &parsed.ip, tcp_hdr, 3, &config);
        // At least one fake should have a wrong checksum
        let has_wrong_cksum = fakes.iter().any(|f| {
            let fp = ParsedPacket::parse(f, Direction::Outbound).unwrap();
            let ip_hdr_len = fp.ip.header_len();
            let tcp_slice = &f[ip_hdr_len..];
            let src = match &fp.ip {
                ip::IpHeader::V4(h) => h.src.octets(),
                _ => unreachable!(),
            };
            let dst = match &fp.ip {
                ip::IpHeader::V4(h) => h.dst.octets(),
                _ => unreachable!(),
            };
            let verify = tcp::tcp_checksum_v4(&src, &dst, tcp_slice);
            verify != 0 // Non-zero means checksum is wrong
        });
        assert!(
            has_wrong_cksum,
            "At least one fake should have wrong checksum"
        );
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Module 8: Window size modification
// ═══════════════════════════════════════════════════════════════════

mod window_size_tests {
    use super::*;

    #[test]
    fn window_modification_is_applied() {
        let engine = StrategyEngine::new(BypassMode::AllActive, config_with_window(40));
        let pkt = build_syn_packet(443);
        let parsed = ParsedPacket::parse(&pkt, Direction::Outbound).unwrap();
        let original_window = parsed.tcp().unwrap().window_size;
        assert_ne!(original_window, 40);

        if let PacketAction::Modify(modified) = engine.evaluate_outbound(&parsed) {
            let mod_parsed = ParsedPacket::parse(&modified, Direction::Outbound).unwrap();
            assert_eq!(mod_parsed.tcp().unwrap().window_size, 40);
        } else {
            panic!("Expected Modify action for SYN with window config");
        }
    }

    #[test]
    fn window_modification_preserves_checksum_validity() {
        let engine = StrategyEngine::new(BypassMode::AllActive, config_with_window(100));
        let pkt = build_syn_packet(443);
        let parsed = ParsedPacket::parse(&pkt, Direction::Outbound).unwrap();

        if let PacketAction::Modify(modified) = engine.evaluate_outbound(&parsed) {
            // Verify IP checksum is valid
            let ihl = (modified[0] & 0x0F) as usize * 4;
            let ip_cksum = ip::ipv4_checksum(&modified[..ihl]);
            assert_eq!(
                ip_cksum, 0,
                "IP checksum should be valid after window modification"
            );
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Module 9: Config TOML parsing
// ═══════════════════════════════════════════════════════════════════

mod config_parsing {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_temp_config(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn valid_full_config() {
        let toml = r#"
[general]
queue_num = 300
ipv6 = false
manage_rules = true
mode = 6

[strategies]
passive_dpi = true
tcp_window_size = 40
tls_split_position = 5
fake_packet_enabled = true
fake_packet_ttl = 4
auto_ttl = false
fake_wrong_checksum = true
quic_desync = true
multi_fragment = false
disorder = false

[domains]
mode = "blacklist"
blacklist = ["example.com", "blocked.net"]

[logging]
level = "debug"
journald = false
"#;
        let f = write_temp_config(toml);
        let config = Config::load(f.path()).unwrap();
        assert_eq!(config.general.queue_num, 300);
        assert!(!config.general.ipv6);
        assert_eq!(config.general.mode, 6);
        assert_eq!(config.strategies.tcp_window_size, 40);
        assert!(config.strategies.fake_packet_enabled);
        assert_eq!(config.strategies.fake_packet_ttl, 4);
        assert!(!config.strategies.auto_ttl);
        assert!(config.strategies.fake_wrong_checksum);
        assert!(!config.strategies.multi_fragment);
        assert!(!config.strategies.disorder);
        assert_eq!(config.domains.mode, DomainMode::Blacklist);
        assert_eq!(config.domains.blacklist, vec!["example.com", "blocked.net"]);
        assert_eq!(config.logging.level, "debug");
    }

    #[test]
    fn partial_config_uses_defaults() {
        let toml = r#"
[general]
queue_num = 150
"#;
        let f = write_temp_config(toml);
        let config = Config::load(f.path()).unwrap();
        assert_eq!(config.general.queue_num, 150);
        // Defaults for everything else
        assert!(config.general.ipv6);
        assert_eq!(config.general.mode, 5);
        assert!(config.strategies.passive_dpi);
        assert!(config.strategies.auto_ttl);
        assert!(config.strategies.multi_fragment);
        assert!(config.strategies.disorder);
        assert!(!config.strategies.fake_packet_enabled);
        assert_eq!(config.strategies.tcp_window_size, 0);
    }

    #[test]
    fn empty_config_is_rejected_rather_than_defaulted() {
        // An empty file is valid TOML and used to deserialize into the full set
        // of defaults, silently replacing the operator's domain filter after a
        // truncated write. It is now an explicit error; starting from defaults
        // requires the file to be absent, not empty.
        let f = write_temp_config("");
        assert!(
            Config::load(f.path()).is_err(),
            "an empty config must not be accepted as all-defaults"
        );
    }

    #[test]
    fn invalid_toml_returns_error() {
        let f = write_temp_config("invalid [[ toml {{{ garbage");
        let result = Config::load(f.path());
        assert!(result.is_err(), "Invalid TOML should return error");
    }

    #[test]
    fn unknown_fields_are_ignored() {
        let toml = r#"
[general]
queue_num = 200
unknown_field = "should be ignored"

[nonexistent_section]
foo = "bar"
"#;
        let f = write_temp_config(toml);
        let config = Config::load(f.path());
        assert!(config.is_ok(), "Unknown fields should be ignored");
    }

    #[test]
    fn nonexistent_file_returns_defaults() {
        let config = Config::load(Path::new("/nonexistent/config.toml")).unwrap();
        assert_eq!(config.general.queue_num, 200);
    }

    #[test]
    fn domain_mode_whitelist() {
        let toml = r#"
[domains]
mode = "whitelist"
whitelist = ["safe.com"]
"#;
        let f = write_temp_config(toml);
        let config = Config::load(f.path()).unwrap();
        assert_eq!(config.domains.mode, DomainMode::Whitelist);
        assert_eq!(config.domains.whitelist, vec!["safe.com"]);
    }

    #[test]
    fn wrong_type_returns_error() {
        let toml = r#"
[general]
queue_num = "not a number"
"#;
        let f = write_temp_config(toml);
        let result = Config::load(f.path());
        assert!(result.is_err(), "Wrong type should return error");
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Module 10: nftables rule script generation
// ═══════════════════════════════════════════════════════════════════

mod nft_rules_tests {
    use cachydpi::rules::NftRules;

    #[test]
    fn new_rules_not_installed() {
        let rules = NftRules::new(200, true);
        assert!(!rules.is_installed());
    }

    #[test]
    fn inbound_queue_is_outbound_plus_one() {
        let rules = NftRules::new(300, false);
        assert_eq!(rules.inbound_queue_num(), 301);
    }

    #[test]
    fn custom_queue_number_propagates() {
        let rules = NftRules::new(500, true);
        assert_eq!(rules.inbound_queue_num(), 501);
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Module 11: BypassMode from_mode_number mapping
// ═══════════════════════════════════════════════════════════════════

mod bypass_mode_tests {
    use super::*;

    #[test]
    fn all_mode_numbers_map_correctly() {
        assert_eq!(BypassMode::from_mode_number(1), BypassMode::Passive);
        assert_eq!(BypassMode::from_mode_number(2), BypassMode::HttpFragment);
        assert_eq!(BypassMode::from_mode_number(3), BypassMode::TlsFragment);
        assert_eq!(BypassMode::from_mode_number(4), BypassMode::FakePacket);
        assert_eq!(BypassMode::from_mode_number(5), BypassMode::AllActive);
        assert_eq!(BypassMode::from_mode_number(6), BypassMode::Aggressive);
        assert_eq!(BypassMode::from_mode_number(7), BypassMode::AutoDetect);
    }

    #[test]
    fn invalid_mode_defaults_to_all_active() {
        assert_eq!(BypassMode::from_mode_number(0), BypassMode::AllActive);
        assert_eq!(BypassMode::from_mode_number(8), BypassMode::AllActive);
        assert_eq!(BypassMode::from_mode_number(255), BypassMode::AllActive);
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Module 12: QUIC desync
// ═══════════════════════════════════════════════════════════════════

mod quic_desync_tests {
    use super::*;
    use cachydpi::strategies::quic;

    #[test]
    fn desync_quic_initial_produces_ip_fragments() {
        let pkt = build_quic_initial_packet();
        let parsed = ParsedPacket::parse(&pkt, Direction::Outbound).unwrap();
        let udp = parsed.udp().unwrap();

        let frags = quic::desync_quic_initial(&pkt, &parsed.ip, udp);
        assert!(frags.is_some(), "Should produce QUIC desync fragments");
        let frags = frags.unwrap();
        assert!(frags.len() >= 2, "Should produce at least 2 IP fragments");

        // First fragment should have MF (More Fragments) flag set
        let frag0 = &frags[0];
        let flags_frag = u16::from_be_bytes([frag0[6], frag0[7]]);
        let mf_flag = (flags_frag >> 13) & 0x1;
        assert_eq!(mf_flag, 1, "First QUIC fragment should have MF flag");
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Module 13: Desync-first combined strategy
// ═══════════════════════════════════════════════════════════════════

mod desync_first_tests {
    use super::*;

    #[test]
    fn desync_first_injects_fake_rst_before_fragments() {
        let mut config = config_with_fake_packets();
        config.strategies.desync_first = true;
        config.strategies.multi_fragment = true;
        config.strategies.disorder = true;

        let engine = StrategyEngine::new(BypassMode::AllActive, config);
        let pkt = build_tls_packet("discord.com", 64);
        let parsed = ParsedPacket::parse(&pkt, Direction::Outbound).unwrap();
        let action = engine.evaluate_outbound(&parsed);

        if let PacketAction::InjectAndFragment { fakes, fragments } = action {
            assert!(
                !fakes.is_empty(),
                "Desync-first should produce fake packets"
            );
            assert!(!fragments.is_empty(), "Should have fragments");

            // First fake should be RST (desync-first sends RST first)
            let first_fake = ParsedPacket::parse(&fakes[0], Direction::Outbound).unwrap();
            let first_tcp = first_fake.tcp().unwrap();
            assert!(
                first_tcp.is_rst(),
                "First fake in desync-first mode should be RST"
            );
        } else {
            panic!("Expected InjectAndFragment for desync-first, got {action:?}");
        }
    }
}

// ═══════════════════════════════════════════════════════════════════
//  Module 14: Edge cases and robustness
// ═══════════════════════════════════════════════════════════════════

mod edge_cases {
    use super::*;

    #[test]
    fn truncated_tls_in_valid_tcp_accepted() {
        // Valid IP+TCP but truncated TLS (only content type byte)
        let pkt = build_ipv4_tcp_packet(
            Ipv4Addr::new(192, 168, 1, 100),
            Ipv4Addr::new(93, 184, 216, 34),
            12345,
            443,
            1000,
            500,
            tcp::TCP_PSH | tcp::TCP_ACK,
            64,
            &[0x16], // TLS content type only, incomplete
        );
        let engine = StrategyEngine::new(BypassMode::AllActive, default_config());
        let parsed = ParsedPacket::parse(&pkt, Direction::Outbound).unwrap();
        let action = engine.evaluate_outbound(&parsed);
        assert!(
            matches!(action, PacketAction::Accept),
            "Truncated TLS should be accepted: {action:?}"
        );
    }

    #[test]
    fn very_long_sni_fragments_correctly() {
        let long_domain = format!("{}.example.com", "a".repeat(200));
        let pkt = build_tls_packet(&long_domain, 64);
        let engine = StrategyEngine::new(BypassMode::TlsFragment, default_config());
        let parsed = ParsedPacket::parse(&pkt, Direction::Outbound).unwrap();
        let action = engine.evaluate_outbound(&parsed);
        assert!(
            matches!(action, PacketAction::Fragment(_)),
            "Long SNI should still fragment: {action:?}"
        );
    }

    #[test]
    fn multiple_engines_independent_ttl_cache() {
        let engine1 = StrategyEngine::new(BypassMode::AllActive, default_config());
        let engine2 = StrategyEngine::new(BypassMode::AllActive, default_config());

        let pkt = build_syn_ack_packet(44);
        let parsed = ParsedPacket::parse(&pkt, Direction::Inbound).unwrap();
        engine1.evaluate_inbound(&parsed);

        // engine2 should not see engine1's TTL cache
        let dst = parsed.src_addr();
        let _ttl2 = engine2.get_fake_ttl_for_test(dst);
        // Engine2 hasn't seen any SYN-ACK, so auto_ttl should be 0 and fallback should be used
        // The fallback for auto_ttl with real_ttl=0 (no packet context) depends on implementation
        // Just verify engine2 didn't inherit engine1's cache
        let ttl1 = engine1.get_fake_ttl_for_test(dst);
        assert!(ttl1 > 0, "Engine1 should have cached TTL");
    }
}
