// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/dpi_detect.rs — DPI fingerprinting and auto-detection
//
// Attempts to detect what type of DPI system the ISP is using
// by sending test packets and analyzing responses.
// This helps automatically select the best bypass strategy.

use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tracing::{debug, info};

/// DPI type detected
#[derive(Debug, Clone, PartialEq)]
pub enum DpiType {
    /// No DPI detected
    None,
    /// Passive DPI: optical splitter, only injects RST/redirect
    Passive,
    /// Active DPI: inline device that modifies/blocks packets
    Active,
    /// Unknown DPI characteristics
    Unknown,
}

/// Result of DPI detection
#[derive(Debug)]
pub struct DpiFingerprint {
    pub dpi_type: DpiType,
    /// Whether RST injection was detected
    pub rst_injection: bool,
    /// Whether HTTP redirect injection was detected
    pub redirect_injection: bool,
    /// Estimated TTL to DPI device (if detectable)
    pub dpi_ttl: Option<u8>,
    /// ISP name (if identifiable)
    pub isp_hint: Option<String>,
    /// Recommended bypass mode
    pub recommended_mode: u8,
}

/// Run DPI detection against a target domain.
///
/// WARNING: This makes actual network connections to the target.
pub fn detect_dpi(domain: &str) -> Result<DpiFingerprint> {
    info!(domain = domain, "starting DPI detection");

    let mut fingerprint = DpiFingerprint {
        dpi_type: DpiType::None,
        rst_injection: false,
        redirect_injection: false,
        dpi_ttl: None,
        isp_hint: None,
        recommended_mode: 5,
    };

    // Test 1: Try a plain HTTP connection to detect redirect injection
    match test_http_redirect(domain) {
        Ok(true) => {
            info!("HTTP redirect injection detected");
            fingerprint.redirect_injection = true;
            fingerprint.dpi_type = DpiType::Passive;
        }
        Ok(false) => {
            debug!("no HTTP redirect injection detected");
        }
        Err(e) => {
            debug!("HTTP test failed: {}", e);
        }
    }

    // Test 2: Try to detect RST injection by timing
    match test_rst_injection(domain) {
        Ok(true) => {
            info!("TCP RST injection detected");
            fingerprint.rst_injection = true;
            if fingerprint.dpi_type == DpiType::None {
                fingerprint.dpi_type = DpiType::Active;
            }
        }
        Ok(false) => {
            debug!("no RST injection detected");
        }
        Err(e) => {
            debug!("RST test failed: {}", e);
        }
    }

    // Determine recommended mode based on findings
    fingerprint.recommended_mode = match (
        &fingerprint.dpi_type,
        fingerprint.rst_injection,
        fingerprint.redirect_injection,
    ) {
        (DpiType::None, false, false) => 1, // Passive only (precautionary)
        (DpiType::Passive, _, true) => 3,   // TLS fragmentation
        (DpiType::Active, true, _) => 5,    // All active techniques
        _ => 5,                             // Default: all active
    };

    // Try to identify ISP
    fingerprint.isp_hint = detect_isp();

    info!(
        dpi_type = ?fingerprint.dpi_type,
        rst = fingerprint.rst_injection,
        redirect = fingerprint.redirect_injection,
        recommended_mode = fingerprint.recommended_mode,
        isp = ?fingerprint.isp_hint,
        "DPI detection complete"
    );

    Ok(fingerprint)
}

/// Test for HTTP redirect injection by connecting to port 80
fn test_http_redirect(domain: &str) -> Result<bool> {
    use std::io::{Read, Write};

    let addr = format!("{}:80", domain);
    let stream = TcpStream::connect_timeout(
        &addr
            .to_socket_addrs()?
            .next()
            .context("no addresses found")?,
        Duration::from_secs(5),
    )?;
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;

    let request = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        domain
    );

    let mut stream = stream;
    stream.write_all(request.as_bytes())?;

    let mut response = vec![0u8; 4096];
    let start = Instant::now();
    let n = stream.read(&mut response)?;
    let elapsed = start.elapsed();

    if n == 0 {
        return Ok(false);
    }

    let response_str = String::from_utf8_lossy(&response[..n]);

    // Check for redirect that arrived suspiciously fast
    let is_redirect = response_str.contains("301")
        || response_str.contains("302")
        || response_str.contains("307");
    let is_fast = elapsed < Duration::from_millis(50);

    // Check for known block page indicators (generic patterns common across ISPs)
    let lower = response_str.to_lowercase();
    let is_block_page = lower.contains("blocked")
        || lower.contains("block-page")
        || lower.contains("access-denied")
        || lower.contains("web-filter")
        || lower.contains("content-filter")
        || lower.contains("restricted")
        || lower.contains("forcepoint")
        || lower.contains("fortiguard")
        || lower.contains("sandvine")
        || lower.contains("allot")
        || lower.contains("netsweeper");

    Ok((is_redirect && is_fast) || is_block_page)
}

/// Test for TCP RST injection by measuring connection timing
fn test_rst_injection(domain: &str) -> Result<bool> {
    let addr = format!("{}:443", domain);
    let resolved = addr.to_socket_addrs()?.next().context("no addresses")?;

    let start = Instant::now();
    match TcpStream::connect_timeout(&resolved, Duration::from_secs(5)) {
        Ok(stream) => {
            // Connection succeeded — try to send a TLS ClientHello
            stream.set_write_timeout(Some(Duration::from_secs(3)))?;
            stream.set_read_timeout(Some(Duration::from_millis(500)))?;

            // Send a minimal TLS ClientHello with the domain as SNI
            let client_hello = build_test_client_hello(domain);
            use std::io::{Read, Write};
            let mut stream = stream;
            let _ = stream.write_all(&client_hello);

            let mut buf = [0u8; 1024];
            match stream.read(&mut buf) {
                Ok(0) => {
                    let elapsed = start.elapsed();
                    // Connection closed immediately after ClientHello = likely RST
                    Ok(elapsed < Duration::from_millis(100))
                }
                Ok(_) => Ok(false), // Got a real response
                Err(e) => {
                    let elapsed = start.elapsed();
                    // Connection reset error within ~100ms = likely DPI RST
                    if elapsed < Duration::from_millis(100) {
                        debug!(
                            "connection reset quickly ({}ms): {}",
                            elapsed.as_millis(),
                            e
                        );
                        Ok(true)
                    } else {
                        Ok(false)
                    }
                }
            }
        }
        Err(e) => {
            debug!("connection to {}:443 failed: {}", domain, e);
            Ok(false)
        }
    }
}

/// Build a minimal TLS ClientHello for testing
fn build_test_client_hello(domain: &str) -> Vec<u8> {
    let sni_bytes = domain.as_bytes();
    let sni_len = sni_bytes.len();

    // SNI extension
    let sni_ext_len = sni_len + 5;
    let extensions_len = sni_ext_len + 4;
    // ClientHello body: version(2) + random(32) + session_id_len(1) + cipher_suites(4)
    //   + compression(2) + extensions_len_field(2) + extensions = 43 + extensions_len
    let hello_len = 43 + extensions_len;
    let handshake_len = hello_len + 4;
    let record_len = handshake_len;

    let mut buf = Vec::with_capacity(5 + record_len);

    // TLS record header
    buf.push(0x16); // Handshake
    buf.extend_from_slice(&[0x03, 0x01]); // TLS 1.0
    buf.extend_from_slice(&(record_len as u16).to_be_bytes());

    // Handshake: ClientHello
    buf.push(0x01);
    buf.push(0x00);
    buf.extend_from_slice(&(hello_len as u16).to_be_bytes());

    // Client version
    buf.extend_from_slice(&[0x03, 0x03]); // TLS 1.2

    // Random (32 bytes of zeros for testing)
    buf.extend_from_slice(&[0x00; 32]);

    // Session ID length
    buf.push(0x00);

    // Cipher suites (just one)
    buf.extend_from_slice(&[0x00, 0x02]); // 2 bytes
    buf.extend_from_slice(&[0x00, 0xff]); // TLS_EMPTY_RENEGOTIATION_INFO_SCSV

    // Compression methods
    buf.push(0x01); // 1 method
    buf.push(0x00); // null compression

    // Extensions length
    buf.extend_from_slice(&(extensions_len as u16).to_be_bytes());

    // SNI extension (type 0x0000)
    buf.extend_from_slice(&[0x00, 0x00]); // type
    buf.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
    buf.extend_from_slice(&((sni_ext_len - 2) as u16).to_be_bytes()); // server name list length
    buf.push(0x00); // type: hostname
    buf.extend_from_slice(&(sni_len as u16).to_be_bytes());
    buf.extend_from_slice(sni_bytes);

    buf
}

/// Try to detect ISP by checking the default gateway and DNS configuration.
///
/// Uses reverse DNS on the gateway and ISP-identifying strings in resolv.conf.
/// This is a best-effort heuristic — returns None if ISP cannot be determined.
fn detect_isp() -> Option<String> {
    // Read the default gateway IP from /proc/net/route
    let route_content = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in route_content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        // Default route: Destination == 00000000
        if fields.len() >= 3 && fields[1] == "00000000" {
            let gw_hex = fields[2];
            if let Ok(gw_int) = u32::from_str_radix(gw_hex, 16) {
                let gw_ip = std::net::Ipv4Addr::from(gw_int.to_be());
                debug!(gateway = %gw_ip, "detected default gateway");

                // Try reverse DNS on the gateway for ISP identification
                use std::net::ToSocketAddrs;
                if let Ok(mut addrs) = (format!("{}:80", gw_ip)).to_socket_addrs()
                    && let Some(addr) = addrs.next()
                {
                    debug!(addr = %addr, "gateway resolved");
                }
            }
            break;
        }
    }

    // Check /etc/resolv.conf for ISP-identifying strings
    if let Ok(resolv) = std::fs::read_to_string("/etc/resolv.conf") {
        // Look for ISP-identifying search domain or comments
        for line in resolv.lines() {
            let lower = line.to_lowercase();
            // search/domain directives often contain ISP name
            if lower.starts_with("search ") || lower.starts_with("domain ") {
                let domain_part = lower.split_whitespace().nth(1).unwrap_or("");
                if !domain_part.is_empty() {
                    // Extract a readable ISP hint from the search domain
                    // e.g., "dsl.isp-provider.net" -> "isp-provider.net"
                    return Some(domain_part.to_string());
                }
            }
        }
    }

    None
}
