// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/strategies/passive.rs — Passive DPI detection and blocking
//
// Detects and drops forged packets injected by DPI systems:
// - TCP RST packets with suspicious characteristics
// - HTTP 302/301 redirects that arrive too fast
// - ICMP unreachable messages

use crate::packet::{ParsedPacket, http};
use tracing::trace;

/// Check if a TCP RST packet looks forged by DPI.
///
/// Forged RSTs typically have these characteristics:
/// - TTL significantly different from established connection
/// - Window size is 0
/// - No TCP options
/// - Often arrive very quickly after the request
pub fn is_forged_rst(packet: &ParsedPacket<'_>) -> bool {
    let tcp = match packet.tcp() {
        Some(t) => t,
        None => return false,
    };

    if !tcp.is_rst() {
        return false;
    }

    let mut score: u32 = 0;

    // Indicator 1: RST with window size 0 (very common for DPI-forged RSTs)
    if tcp.window_size == 0 {
        score += 2;
    }

    // Indicator 2: No TCP options (most real RSTs have timestamps)
    if tcp.options.is_empty() {
        score += 1;
    }

    // Indicator 3: Suspicious TTL values
    // DPI boxes often use a fixed TTL like 64 or 128, OR a TTL that doesn't
    // match the expected server TTL. Real server RSTs have TTL consistent
    // with previous packets from the same server.
    let ttl = packet.ttl();
    if ttl == 64 || ttl == 128 {
        score += 1;
    }
    // TTL that's significantly higher than typical server response indicates
    // a closer device (DPI) sent it. Servers at 20 hops give TTL ~44,
    // DPI at 8-10 hops gives TTL ~54-56 or ~118.
    if ttl > 100 && ttl < 128 {
        // TTL in range 101-127: likely initial_ttl=128 with only a few hops
        // (DPI appliance closer than the real server)
        score += 1;
    }

    // Indicator 4: RST+ACK (some DPI systems send RST with ACK set)
    if tcp.flags & (super::super::packet::tcp::TCP_RST | super::super::packet::tcp::TCP_ACK)
        == (super::super::packet::tcp::TCP_RST | super::super::packet::tcp::TCP_ACK)
    {
        score += 1;
    }

    // Threshold: lowered to 3 — the combination of window=0 + no options + any
    // TTL anomaly or RST+ACK is sufficient. Score 4 was too strict: observed
    // DPI RSTs with TTL=118 (not 128) were only caught when all 4 other
    // indicators fired.
    let forged = score >= 3;
    if forged {
        trace!(
            ttl = ttl,
            window = tcp.window_size,
            score = score,
            "RST packet scored as forged"
        );
    }

    forged
}

/// Check if an HTTP response looks like a forged DPI redirect.
///
/// Forged redirects typically:
/// - Are 301/302/307 responses
/// - Redirect to a block page or ISP warning
/// - Arrive suspiciously fast (before real server can respond)
/// - Have minimal headers
pub fn is_forged_redirect(payload: &[u8], packet: &ParsedPacket<'_>) -> bool {
    if !http::is_http_redirect(payload) {
        return false;
    }

    let mut score: u32 = 0;

    // Check for known block page indicators (byte-level case-insensitive, no allocation)
    // Generic patterns common across ISP DPI systems worldwide
    {
        let block_indicators: &[&[u8]] = &[
            b"blocked",
            b"block-page",
            b"block_page",
            b"access-denied",
            b"access denied",
            b"web-filter",
            b"content-filter",
            b"restricted",
            b"forcepoint",
            b"fortiguard",
            b"sandvine",
            b"allot",
            b"netsweeper",
            b"websense",
            b"bluecoat",
            b"barracuda",
        ];

        for indicator in block_indicators {
            if contains_case_insensitive(payload, indicator) {
                score += 3;
                break;
            }
        }

        // Short response (DPI forged responses are usually small)
        if payload.len() < 512 {
            score += 1;
        }

        // Check for Location header pointing to block page
        if contains_case_insensitive(payload, b"location:")
            && contains_case_insensitive(payload, b"http")
        {
            score += 1;
        }
    }

    // TTL analysis: forged packets often have different TTL than real traffic
    let ttl = packet.ttl();
    if ttl == 64 || ttl == 128 || ttl == 255 {
        score += 1;
    }

    let forged = score >= 3;
    if forged {
        trace!(
            ttl = packet.ttl(),
            len = payload.len(),
            score = score,
            "HTTP redirect scored as forged"
        );
    }

    forged
}

/// Check if an ICMP unreachable message looks forged.
///
/// Some DPI systems send ICMP unreachable to kill connections.
pub fn is_forged_icmp_unreachable(raw_packet: &[u8]) -> bool {
    if raw_packet.len() < 28 {
        return false;
    }

    // Check if IPv4
    let version = (raw_packet[0] >> 4) & 0x0F;
    if version != 4 {
        return false;
    }

    let protocol = raw_packet[9];
    // ICMP protocol = 1
    if protocol != 1 {
        return false;
    }

    let ip_hdr_len = ((raw_packet[0] & 0x0F) as usize) * 4;
    if raw_packet.len() < ip_hdr_len + 4 {
        return false;
    }

    let icmp_type = raw_packet[ip_hdr_len];
    let icmp_code = raw_packet[ip_hdr_len + 1];

    // Type 3 = Destination Unreachable
    // Code 1 = Host Unreachable, Code 3 = Port Unreachable
    // Code 9 = Communication Administratively Prohibited
    // Code 10 = Communication Prohibited
    if icmp_type == 3 && matches!(icmp_code, 1 | 3 | 9 | 10 | 13) {
        trace!(
            icmp_type = icmp_type,
            icmp_code = icmp_code,
            "suspicious ICMP unreachable detected"
        );
        return true;
    }

    false
}

/// Check if an incoming TLS packet looks like a forged TLS alert from DPI.
///
/// DPI systems may inject fake TLS alerts (e.g., decode_error, handshake_failure)
/// to kill connections when they detect a blocked SNI. Characteristics:
/// - Very small payload (TLS alert is only 7 bytes)
/// - Content type 0x15 (Alert)
/// - Alert level = fatal (2)
/// - Suspicious TTL
pub fn is_forged_tls_alert(payload: &[u8], packet: &ParsedPacket<'_>) -> bool {
    // TLS Alert record: content_type(1) + version(2) + length(2) + level(1) + description(1)
    // Minimum 7 bytes
    if payload.len() < 7 {
        return false;
    }

    // Check TLS Alert content type (0x15 = 21)
    if payload[0] != 0x15 {
        return false;
    }

    // Check TLS version (0x03, 0x01-0x04)
    if payload[1] != 0x03 || payload[2] == 0 || payload[2] > 0x04 {
        return false;
    }

    // Check record length (should be 2 for a single alert, but DPI may pad)
    let record_len = ((payload[3] as u16) << 8) | payload[4] as u16;
    if !(2..=10).contains(&record_len) {
        return false;
    }

    let alert_level = payload[5];
    let alert_desc = payload[6];

    // Only consider fatal alerts as potentially forged
    if alert_level != 2 {
        return false;
    }

    let mut score: u32 = 0;

    // Common DPI-injected alert descriptions:
    // 50 = decode_error, 40 = handshake_failure, 70 = protocol_version,
    // 80 = internal_error, 86 = inappropriate_fallback
    if matches!(alert_desc, 50 | 40 | 70 | 80 | 86) {
        score += 2;
    }

    // Small payload (real servers usually send more data)
    if payload.len() < 20 {
        score += 1;
    }

    // TTL analysis — check for DPI-characteristic TTL values
    let ttl = packet.ttl();
    if ttl == 64 || ttl == 128 || ttl == 255 {
        score += 1;
    }
    // TTL significantly higher than expected server response:
    // DPI is closer than the server, so its packets have higher TTL
    if ttl > 50 && ttl < 64 {
        // Likely initial_ttl=64 with only ~8-14 hops (DPI appliance)
        score += 1;
    }
    if ttl > 100 && ttl < 128 {
        // Likely initial_ttl=128 with only a few hops
        score += 1;
    }

    let forged = score >= 3;
    if forged {
        trace!(
            ttl = ttl,
            alert_level = alert_level,
            alert_desc = alert_desc,
            payload_len = payload.len(),
            score = score,
            "TLS alert scored as forged"
        );
    }

    forged
}

/// Case-insensitive byte-level substring search (zero allocation).
fn contains_case_insensitive(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return needle.is_empty();
    }
    haystack.windows(needle.len()).any(|window| {
        window
            .iter()
            .zip(needle.iter())
            .all(|(h, n)| h.eq_ignore_ascii_case(n))
    })
}
