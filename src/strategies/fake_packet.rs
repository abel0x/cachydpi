// src/strategies/fake_packet.rs — Fake packet injection
//
// Injects crafted "fake" packets that confuse DPI systems but are
// discarded by the real server. Methods include:
// - Wrong TTL: packet expires before reaching the server
// - Wrong checksum: server drops the packet, DPI doesn't verify
// - Wrong sequence number: server ignores, DPI may process
//
// The fake packet carries a dummy payload that tricks BPI into
// thinking the connection goes somewhere harmless.

use crate::config::Config;
use crate::packet::ip::{self, IpHeader};
use crate::packet::tcp::{self, TCP_ACK, TCP_PSH, TCP_RST, TcpHeader};

use tracing::trace;

/// Build a fake RST packet with wrong TTL to break DPI connection tracking.
/// The DPI sees the RST and removes the connection from its tracking table.
/// The fake RST expires before reaching the server (TTL too low).
/// After this, the DPI won't inspect subsequent packets on this connection.
pub fn create_fake_rst_desync(
    real_packet: &[u8],
    ip_hdr: &IpHeader,
    tcp_hdr: &TcpHeader<'_>,
    fake_ttl: u8,
) -> Option<Vec<u8>> {
    let ip_hdr_len = ip_hdr.header_len();
    let tcp_hdr_len = tcp_hdr.header_len;

    if real_packet.len() < ip_hdr_len + tcp_hdr_len {
        return None;
    }

    // Build RST packet with no payload
    let total_len = ip_hdr_len + tcp_hdr_len;
    let mut packet = Vec::with_capacity(total_len);

    // Copy IP + TCP headers from original
    packet.extend_from_slice(&real_packet[..total_len]);

    // Fix IP total length
    let version = (packet[0] >> 4) & 0x0F;
    if version == 4 {
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        // Set fake TTL
        packet[8] = fake_ttl;
        // Recalculate IP checksum
        packet[10] = 0;
        packet[11] = 0;
        let cksum = ip::ipv4_checksum(&packet[..ip_hdr_len]);
        packet[10..12].copy_from_slice(&cksum.to_be_bytes());
    } else if version == 6 {
        packet[7] = fake_ttl;
        let payload_len = tcp_hdr_len as u16;
        packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
    }

    // Set TCP flags to RST+ACK
    let tcp_off = ip_hdr_len;
    packet[tcp_off + 13] = TCP_RST | TCP_ACK;

    // Use seq+1 so DPI processes it (looks like response to current data)
    let rst_seq = tcp_hdr.seq_num.wrapping_add(1);
    packet[tcp_off + 4..tcp_off + 8].copy_from_slice(&rst_seq.to_be_bytes());

    // Recalculate TCP checksum
    packet[tcp_off + 16] = 0;
    packet[tcp_off + 17] = 0;
    if version == 4 && packet.len() >= 20 {
        let src_ip: [u8; 4] = packet[12..16].try_into().unwrap_or([0; 4]);
        let dst_ip: [u8; 4] = packet[16..20].try_into().unwrap_or([0; 4]);
        let cksum = tcp::tcp_checksum_v4(&src_ip, &dst_ip, &packet[tcp_off..]);
        packet[tcp_off + 16..tcp_off + 18].copy_from_slice(&cksum.to_be_bytes());
    } else if version == 6 && packet.len() >= 40 {
        let src_ip: [u8; 16] = packet[8..24].try_into().unwrap_or([0; 16]);
        let dst_ip: [u8; 16] = packet[24..40].try_into().unwrap_or([0; 16]);
        let cksum = tcp::tcp_checksum_v6(&src_ip, &dst_ip, &packet[tcp_off..]);
        packet[tcp_off + 16..tcp_off + 18].copy_from_slice(&cksum.to_be_bytes());
    }

    trace!(ttl = fake_ttl, "created fake RST desync packet");
    Some(packet)
}

/// Fake payload for HTTP requests — looks like a request to a benign host
const FAKE_HTTP_PAYLOAD: &[u8] = b"GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n";

/// Default SNI used in fake ClientHello packets for desync.
/// DPI processes this and classifies the connection as going to an allowed domain.
const FAKE_SNI_DOMAIN: &str = "www.google.com";

/// Build a realistic TLS ClientHello payload with a given SNI domain.
/// This is the key desync technique: DPI processes this fake ClientHello
/// and enters the "allowed" state for this connection. The fake packet
/// has a wrong TTL so it never reaches the real server.
pub fn build_fake_client_hello_payload(sni: &str) -> Vec<u8> {
    let sni_bytes = sni.as_bytes();
    let sni_name_list_len = 3 + sni_bytes.len(); // type(1) + name_len(2) + name
    let sni_ext_data_len = 2 + sni_name_list_len; // list_len(2) + list
    let extensions_total_len = 4 + sni_ext_data_len; // ext_type(2) + ext_len(2) + data

    // Common cipher suites that look realistic
    let cipher_suites: &[u8] = &[
        0x13, 0x01, // TLS_AES_128_GCM_SHA256
        0x13, 0x02, // TLS_AES_256_GCM_SHA384
        0x13, 0x03, // TLS_CHACHA20_POLY1305_SHA256
        0xc0, 0x2c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
        0xc0, 0x2b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
        0xc0, 0x30, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        0xc0, 0x2f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    ];

    let client_hello_body_len = 2       // version
        + 32                             // random
        + 1                              // session_id_len
        + 2 + cipher_suites.len()        // cipher_suites_len + suites
        + 2                              // compression (len + null)
        + 2 + extensions_total_len; // extensions_len + extensions

    let handshake_body_len = client_hello_body_len;
    let record_payload_len = 4 + handshake_body_len; // hs_type(1) + hs_len(3) + body

    let mut payload = Vec::with_capacity(5 + record_payload_len);

    // TLS Record Header
    payload.push(0x16); // content_type: Handshake
    payload.push(0x03);
    payload.push(0x01); // version: TLS 1.0 (record layer)
    payload.push((record_payload_len >> 8) as u8);
    payload.push((record_payload_len & 0xFF) as u8);

    // Handshake Header
    payload.push(0x01); // type: ClientHello
    payload.push(((handshake_body_len >> 16) & 0xFF) as u8);
    payload.push(((handshake_body_len >> 8) & 0xFF) as u8);
    payload.push((handshake_body_len & 0xFF) as u8);

    // ClientHello Body
    payload.push(0x03);
    payload.push(0x03); // version: TLS 1.2

    // 32 bytes random (use non-zero deterministic values)
    payload.extend_from_slice(&[
        0x42, 0x13, 0x37, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, 0x01, 0x02, 0x03, 0x04,
        0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15,
    ]);

    payload.push(0x00); // session_id_len = 0

    // Cipher suites
    payload.push((cipher_suites.len() >> 8) as u8);
    payload.push((cipher_suites.len() & 0xFF) as u8);
    payload.extend_from_slice(cipher_suites);

    // Compression methods
    payload.push(0x01); // length = 1
    payload.push(0x00); // null compression

    // Extensions total length
    payload.push((extensions_total_len >> 8) as u8);
    payload.push((extensions_total_len & 0xFF) as u8);

    // SNI Extension (type 0x0000)
    payload.push(0x00);
    payload.push(0x00); // ext_type: server_name
    payload.push((sni_ext_data_len >> 8) as u8);
    payload.push((sni_ext_data_len & 0xFF) as u8);

    // Server Name List
    payload.push((sni_name_list_len >> 8) as u8);
    payload.push((sni_name_list_len & 0xFF) as u8);
    payload.push(0x00); // name_type: hostname
    payload.push((sni_bytes.len() >> 8) as u8);
    payload.push((sni_bytes.len() & 0xFF) as u8);
    payload.extend_from_slice(sni_bytes);

    payload
}

/// Get the default fake TLS payload (proper ClientHello with google.com SNI)
fn fake_tls_payload() -> Vec<u8> {
    build_fake_client_hello_payload(FAKE_SNI_DOMAIN)
}

/// Create fake packets to inject before the real packet.
///
/// Returns a vector of complete IP packets ready to send via raw socket.
pub fn create_fake_packets(
    real_packet: &[u8],
    ip_hdr: &IpHeader,
    tcp_hdr: &TcpHeader<'_>,
    fake_ttl: u8,
    config: &Config,
) -> Vec<Vec<u8>> {
    let mut fakes = Vec::new();

    // Determine fake payload based on destination port
    let fake_payload_owned;
    let fake_payload: &[u8] = if tcp_hdr.dst_port == 80 || tcp_hdr.dst_port == 8080 {
        FAKE_HTTP_PAYLOAD
    } else {
        // Use proper ClientHello with google.com SNI for desync
        fake_payload_owned = fake_tls_payload();
        &fake_payload_owned
    };

    // Strategy 1: Fake packet with wrong TTL (most reliable)
    if config.strategies.fake_packet_ttl > 0 || config.strategies.auto_ttl {
        let fake = build_fake_with_ttl(real_packet, ip_hdr, tcp_hdr, fake_payload, fake_ttl);
        if let Some(pkt) = fake {
            trace!(ttl = fake_ttl, "created fake packet with wrong TTL");
            fakes.push(pkt);
        }
    }

    // Strategy 2: Fake packet with wrong checksum
    if config.strategies.fake_wrong_checksum {
        let fake = build_fake_with_bad_checksum(real_packet, ip_hdr, tcp_hdr, fake_payload);
        if let Some(pkt) = fake {
            trace!("created fake packet with wrong checksum");
            fakes.push(pkt);
        }
    }

    // Strategy 3: Fake packet with wrong sequence number
    if config.strategies.fake_wrong_seq {
        let fake = build_fake_with_wrong_seq(real_packet, ip_hdr, tcp_hdr, fake_payload);
        if let Some(pkt) = fake {
            trace!("created fake packet with wrong SEQ");
            fakes.push(pkt);
        }
    }

    fakes
}

/// Build a fake packet with a TTL that will expire before reaching the server.
/// The DPI box (closer to the client) will see it, but it won't reach the server.
fn build_fake_with_ttl(
    real_packet: &[u8],
    ip_hdr: &IpHeader,
    tcp_hdr: &TcpHeader<'_>,
    fake_payload: &[u8],
    ttl: u8,
) -> Option<Vec<u8>> {
    let ip_hdr_len = ip_hdr.header_len();
    let tcp_hdr_len = tcp_hdr.header_len;

    if real_packet.len() < ip_hdr_len + tcp_hdr_len {
        return None;
    }

    let total_len = ip_hdr_len + tcp_hdr_len + fake_payload.len();
    let mut packet = Vec::with_capacity(total_len);

    // Copy IP header from original
    packet.extend_from_slice(&real_packet[..ip_hdr_len]);
    // Copy TCP header from original
    packet.extend_from_slice(&real_packet[ip_hdr_len..ip_hdr_len + tcp_hdr_len]);
    // Add fake payload
    packet.extend_from_slice(fake_payload);

    // Fix IP total length
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());

    // Set fake TTL
    let version = (packet[0] >> 4) & 0x0F;
    if version == 4 {
        packet[8] = ttl;
        // Recalculate IP checksum
        packet[10] = 0;
        packet[11] = 0;
        let cksum = ip::ipv4_checksum(&packet[..ip_hdr_len]);
        packet[10..12].copy_from_slice(&cksum.to_be_bytes());
    } else if version == 6 {
        // Set hop limit for IPv6
        packet[7] = ttl;
        // Fix payload length
        let payload_len = (tcp_hdr_len + fake_payload.len()) as u16;
        packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
    }

    // Fix TCP: use PSH+ACK flags, set same seq/ack as original
    let tcp_off = ip_hdr_len;
    packet[tcp_off + 13] = TCP_PSH | TCP_ACK;

    // Recalculate TCP checksum (must be correct — some DPI verify checksums)
    packet[tcp_off + 16] = 0;
    packet[tcp_off + 17] = 0;
    if version == 4 && packet.len() >= 20 {
        let src_ip: [u8; 4] = packet[12..16].try_into().unwrap_or([0; 4]);
        let dst_ip: [u8; 4] = packet[16..20].try_into().unwrap_or([0; 4]);
        let cksum = tcp::tcp_checksum_v4(&src_ip, &dst_ip, &packet[tcp_off..]);
        packet[tcp_off + 16..tcp_off + 18].copy_from_slice(&cksum.to_be_bytes());
    } else if version == 6 && packet.len() >= 40 {
        let src_ip: [u8; 16] = packet[8..24].try_into().unwrap_or([0; 16]);
        let dst_ip: [u8; 16] = packet[24..40].try_into().unwrap_or([0; 16]);
        let cksum = tcp::tcp_checksum_v6(&src_ip, &dst_ip, &packet[tcp_off..]);
        packet[tcp_off + 16..tcp_off + 18].copy_from_slice(&cksum.to_be_bytes());
    }

    Some(packet)
}

/// Build a fake packet with an intentionally wrong TCP checksum.
/// The server's TCP stack will drop it, but many DPI systems don't verify checksums.
fn build_fake_with_bad_checksum(
    real_packet: &[u8],
    ip_hdr: &IpHeader,
    tcp_hdr: &TcpHeader<'_>,
    fake_payload: &[u8],
) -> Option<Vec<u8>> {
    let ip_hdr_len = ip_hdr.header_len();
    let tcp_hdr_len = tcp_hdr.header_len;

    if real_packet.len() < ip_hdr_len + tcp_hdr_len {
        return None;
    }

    let total_len = ip_hdr_len + tcp_hdr_len + fake_payload.len();
    let mut packet = Vec::with_capacity(total_len);

    packet.extend_from_slice(&real_packet[..ip_hdr_len]);
    packet.extend_from_slice(&real_packet[ip_hdr_len..ip_hdr_len + tcp_hdr_len]);
    packet.extend_from_slice(fake_payload);

    // Fix IP length field
    let version = (packet[0] >> 4) & 0x0F;
    if version == 4 {
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    } else if version == 6 {
        let payload_len = (total_len - ip_hdr_len) as u16;
        packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
    }

    let tcp_off = ip_hdr_len;
    packet[tcp_off + 13] = TCP_PSH | TCP_ACK;

    // Fix IP checksum (must be correct or packet won't be routed)
    if version == 4 {
        packet[10] = 0;
        packet[11] = 0;
        let cksum = ip::ipv4_checksum(&packet[..ip_hdr_len]);
        packet[10..12].copy_from_slice(&cksum.to_be_bytes());
    }

    // Set WRONG TCP checksum (0xDEAD)
    packet[tcp_off + 16] = 0xDE;
    packet[tcp_off + 17] = 0xAD;

    Some(packet)
}

/// Build a fake packet with a wrong TCP sequence number.
/// The server ignores it (out of window), but DPI may still process it.
fn build_fake_with_wrong_seq(
    real_packet: &[u8],
    ip_hdr: &IpHeader,
    tcp_hdr: &TcpHeader<'_>,
    fake_payload: &[u8],
) -> Option<Vec<u8>> {
    let ip_hdr_len = ip_hdr.header_len();
    let tcp_hdr_len = tcp_hdr.header_len;

    if real_packet.len() < ip_hdr_len + tcp_hdr_len {
        return None;
    }

    let total_len = ip_hdr_len + tcp_hdr_len + fake_payload.len();
    let mut packet = Vec::with_capacity(total_len);

    packet.extend_from_slice(&real_packet[..ip_hdr_len]);
    packet.extend_from_slice(&real_packet[ip_hdr_len..ip_hdr_len + tcp_hdr_len]);
    packet.extend_from_slice(fake_payload);

    // Fix IP length field
    let version = (packet[0] >> 4) & 0x0F;
    if version == 4 {
        packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    } else if version == 6 {
        let payload_len = (total_len - ip_hdr_len) as u16;
        packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
    }

    let tcp_off = ip_hdr_len;
    packet[tcp_off + 13] = TCP_PSH | TCP_ACK;

    // Set WRONG sequence number (far out of window)
    let wrong_seq = tcp_hdr.seq_num.wrapping_sub(100_000);
    packet[tcp_off + 4..tcp_off + 8].copy_from_slice(&wrong_seq.to_be_bytes());

    // Fix IP checksum
    if version == 4 {
        packet[10] = 0;
        packet[11] = 0;
        let cksum = ip::ipv4_checksum(&packet[..ip_hdr_len]);
        packet[10..12].copy_from_slice(&cksum.to_be_bytes());
    }

    // Recalculate TCP checksum (must be correct for the wrong data)
    packet[tcp_off + 16] = 0;
    packet[tcp_off + 17] = 0;
    if version == 4 && packet.len() >= 20 {
        let src_ip: [u8; 4] = packet[12..16].try_into().unwrap_or([0; 4]);
        let dst_ip: [u8; 4] = packet[16..20].try_into().unwrap_or([0; 4]);
        let cksum = tcp::tcp_checksum_v4(&src_ip, &dst_ip, &packet[tcp_off..]);
        packet[tcp_off + 16..tcp_off + 18].copy_from_slice(&cksum.to_be_bytes());
    } else if version == 6 && packet.len() >= 40 {
        let src_ip: [u8; 16] = packet[8..24].try_into().unwrap_or([0; 16]);
        let dst_ip: [u8; 16] = packet[24..40].try_into().unwrap_or([0; 16]);
        let cksum = tcp::tcp_checksum_v6(&src_ip, &dst_ip, &packet[tcp_off..]);
        packet[tcp_off + 16..tcp_off + 18].copy_from_slice(&cksum.to_be_bytes());
    }

    Some(packet)
}
