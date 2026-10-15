// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/strategies/mod.rs — DPI bypass strategy engine
//
// Orchestrates all DPI circumvention techniques. Each strategy module
// implements a specific bypass method. The engine evaluates packets
// and applies the appropriate combination of strategies based on the
// configured mode.

pub mod fake_packet;
pub mod http_split;
pub mod passive;
pub mod quic;
pub mod tls_split;
pub mod window_size;

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, Ordering};

use anyhow::{Context, Result, bail};
use tracing::{debug, info, trace, warn};

use crate::config::Config;
use crate::metrics::{EventLevel, METRICS, epoch_ms};
use crate::nfqueue::NfQueue;
use crate::packet::{self, Direction, ParsedPacket};
use crate::rawsocket::{RawSocket, Sent};

/// Log-safe description of a [`PacketAction`].
///
/// `PacketAction`'s own `Debug` renders every fragment as a decimal byte array,
/// so logging it wrote the TLS ClientHello — SNI included — into the journal for
/// each packet. Formatting is done through `Display` so it only happens when the
/// event is actually recorded.
pub struct ActionSummary<'a>(&'a PacketAction);

impl std::fmt::Display for ActionSummary<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fn lengths(f: &mut std::fmt::Formatter<'_>, packets: &[Vec<u8>]) -> std::fmt::Result {
            write!(f, "n={} lens=[", packets.len())?;
            for (i, p) in packets.iter().enumerate() {
                if i > 0 {
                    write!(f, ",")?;
                }
                write!(f, "{}", p.len())?;
            }
            write!(f, "]")
        }

        match self.0 {
            PacketAction::Accept => write!(f, "accept"),
            PacketAction::Drop => write!(f, "drop"),
            PacketAction::Modify(data) => write!(f, "modify len={}", data.len()),
            PacketAction::Fragment(fragments) => {
                write!(f, "fragment ")?;
                lengths(f, fragments)
            }
            PacketAction::InjectThenAccept(fakes) => {
                write!(f, "inject-then-accept ")?;
                lengths(f, fakes)
            }
            PacketAction::InjectAndFragment { fakes, fragments } => {
                write!(f, "inject fakes ")?;
                lengths(f, fakes)?;
                write!(f, " + fragment ")?;
                lengths(f, fragments)
            }
        }
    }
}

/// Action to take for a packet after strategy evaluation
#[derive(Debug)]
pub enum PacketAction {
    /// Accept the packet unmodified
    Accept,
    /// Drop the packet (DPI forged response detected)
    Drop,
    /// Accept with modified payload (e.g., window size change)
    Modify(Vec<u8>),
    /// Drop original and send fragments via raw socket instead
    Fragment(Vec<Vec<u8>>),
    /// Inject fake packet(s) before accepting the original
    InjectThenAccept(Vec<Vec<u8>>),
    /// Drop original, inject fake + fragments
    InjectAndFragment {
        fakes: Vec<Vec<u8>>,
        fragments: Vec<Vec<u8>>,
    },
}

impl PacketAction {
    /// Describe this action for logs without revealing packet contents.
    pub fn summary(&self) -> ActionSummary<'_> {
        ActionSummary(self)
    }
}

/// DPI bypass mode (matches GoodbyeDPI -1 through -6 + extras)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BypassMode {
    /// Mode 1: Passive only — drop forged RST/302 packets
    Passive,
    /// Mode 2: HTTP request fragmentation
    HttpFragment,
    /// Mode 3: TLS ClientHello SNI fragmentation
    TlsFragment,
    /// Mode 4: Fake packets with wrong TTL
    FakePacket,
    /// Mode 5: All active techniques combined
    AllActive,
    /// Mode 6: Aggressive — all techniques, always out-of-order, QUIC desync
    /// when `quic_desync` is set
    Aggressive,
    /// Mode 7: Adaptive — mode 5, escalated per destination.
    ///
    /// Starts every destination on the configured techniques. Each connection
    /// to it that the DPI is seen interfering with — a forged RST, TLS alert or
    /// redirect dropped by passive defence — moves it up a level: reordered
    /// three-way split, then fakes, then the desync RST, then round again. It
    /// does no active probing; the `dpi_detect` module is separate.
    AutoDetect,
    /// Custom mode from config file
    Custom,
}

impl BypassMode {
    pub fn from_mode_number(n: u8) -> Self {
        match n {
            1 => BypassMode::Passive,
            2 => BypassMode::HttpFragment,
            3 => BypassMode::TlsFragment,
            4 => BypassMode::FakePacket,
            5 => BypassMode::AllActive,
            6 => BypassMode::Aggressive,
            7 => BypassMode::AutoDetect,
            _ => BypassMode::AllActive,
        }
    }
}

/// Whether QUIC Initials are desynced: mode 6 with `quic_desync` set.
///
/// Mode 7 escalates TCP techniques only and, like mode 5, leaves QUIC alone. The nftables rules use the same answer to decide whether QUIC
/// is queued at all.
pub fn quic_desync_active(mode: BypassMode, config: &Config) -> bool {
    matches!(mode, BypassMode::Aggressive) && config.strategies.quic_desync
}

/// The initial TTL a server most likely used: 64, 128 or 255.
fn initial_ttl_of(received: u8) -> u8 {
    if received <= 64 {
        64
    } else if received <= 128 {
        128
    } else {
        255
    }
}

/// A fake packet's TTL from the TTL the server's packets arrive with: enough
/// to pass the DPI, which sits a hop or few before the server, and expire
/// before the server itself.
fn fake_ttl_from_server_ttl(received: u8) -> u8 {
    let hops = initial_ttl_of(received).saturating_sub(received);
    if hops > 3 { hops - 2 } else { hops.max(1) }
}

/// Maximum entries in per-destination TTL cache
const MAX_TTL_CACHE_ENTRIES: usize = 1024;

/// Main strategy engine that evaluates packets and decides on actions
pub struct StrategyEngine {
    pub mode: BypassMode,
    pub config: Config,
    /// Fallback auto-detected TTL for fake packets (0 = not yet detected)
    auto_ttl: AtomicU8,
    /// Per-destination TTL cache: maps destination IP → detected fake TTL
    ttl_cache: Mutex<HashMap<IpAddr, u8>>,
    /// How many distinct peers sent a forged RST — estimated, not remembered.
    ///
    /// The totals cannot separate "one host resetting a connection repeatedly"
    /// from "the DPI resetting many different destinations", and those call for
    /// opposite conclusions. Answering it with a set would mean holding peer
    /// addresses in memory, which is the same data this daemon keeps out of its
    /// logs and can still reach disk through swap, a core dump or
    /// /proc/pid/mem. The estimator keeps 2 KiB of small integers instead: no
    /// address is retained, the state cannot grow, and with nothing to exhaust
    /// there is no saturation to report.
    forged_rst_sources: Mutex<crate::cardinality::DistinctCounter>,
    /// The hop count each connection's server answered from, to tell its own
    /// RST from one injected on the path.
    flows: crate::flow_ttl::FlowTtlTable,
    /// Where a ClientHello spanning segments continues, for the segment that
    /// carries its SNI.
    hello_resume: crate::hello_resume::HelloResumeTable,
    /// Mode 7's per-destination strategy level.
    escalation: crate::escalation::EscalationTable,
}

impl StrategyEngine {
    pub fn new(mode: BypassMode, config: Config) -> Self {
        StrategyEngine {
            mode,
            config,
            auto_ttl: AtomicU8::new(0),
            ttl_cache: Mutex::new(HashMap::new()),
            forged_rst_sources: Mutex::new(crate::cardinality::DistinctCounter::new()),
            flows: crate::flow_ttl::FlowTtlTable::new(),
            hello_resume: crate::hello_resume::HelloResumeTable::new(),
            escalation: crate::escalation::EscalationTable::new(),
        }
    }

    /// Note that a forged RST came from `source`, for the distinct-source count.
    ///
    /// The address is hashed into the estimator and dropped; it is never
    /// stored, logged, published or derived from. Only the estimate reaches the
    /// metrics snapshot, which is world-readable.
    fn record_forged_rst_source(&self, source: IpAddr) {
        if let Ok(mut sources) = self.forged_rst_sources.lock() {
            sources.insert(&source);
            METRICS
                .forged_rst_sources
                .store(sources.estimate(), Ordering::Relaxed);
        }
    }

    /// Evaluate an outbound packet and determine what action to take.
    ///
    /// This is the core decision function called for every queued packet.
    pub fn evaluate_outbound(&self, packet: &ParsedPacket<'_>) -> PacketAction {
        let tcp = match packet.tcp() {
            Some(t) => t,
            None => {
                // Check UDP/QUIC
                if let Some(udp) = packet.udp() {
                    return self.evaluate_quic(packet, udp);
                }
                return PacketAction::Accept;
            }
        };

        if tcp.is_syn() && self.passive_enabled() {
            self.flows.syn_sent(&crate::flow_ttl::FlowKey {
                server: packet.dst_addr(),
                client: packet.src_addr(),
                server_port: tcp.dst_port,
                client_port: tcp.src_port,
            });
        }

        // — SYN packets: optionally modify window size —
        if tcp.is_syn() && self.should_modify_window() {
            return self.apply_window_strategy(packet);
        }

        // — Data-bearing packets (ACK with payload): check for HTTP/TLS —
        // TCP may split large payloads into segments where intermediate
        // segments have only ACK (no PSH). The TLS ClientHello can appear
        // in such a segment. Check any ACK packet with payload.
        let has_data =
            (tcp.is_psh_ack() || (tcp.is_ack() && tcp.has_payload())) && tcp.has_payload();
        if has_data {
            // HTTP (port 80)
            if tcp.is_http_port() && packet::http::is_http_request(tcp.payload) {
                debug!(
                    dport = tcp.dst_port,
                    payload_len = tcp.payload.len(),
                    "HTTP request detected, applying strategy"
                );
                return self.apply_http_strategy(packet, tcp);
            }

            // TLS ClientHello (port 443)
            if tcp.is_https_port() && packet::tls::is_tls_client_hello(tcp.payload) {
                debug!(
                    dport = tcp.dst_port,
                    payload_len = tcp.payload.len(),
                    "TLS ClientHello detected, applying strategy"
                );
                return self.apply_tls_strategy(packet, tcp);
            }

            // A later segment of a ClientHello whose SNI was not in the first
            if tcp.is_https_port()
                && let Some(action) = self.continue_client_hello(packet, tcp)
            {
                return action;
            }

            // Log unmatched data packets for diagnostics
            if tcp.dst_port == 80 || tcp.dst_port == 443 {
                trace!(
                    dport = tcp.dst_port,
                    payload_len = tcp.payload.len(),
                    is_http = packet::http::is_http_request(tcp.payload),
                    is_tls = packet::tls::is_tls_client_hello(tcp.payload),
                    first_byte = tcp.payload.first().copied().unwrap_or(0),
                    "data packet to HTTP/S port but not recognized as HTTP/TLS"
                );
            }
        }

        PacketAction::Accept
    }

    /// Evaluate an inbound packet for passive DPI detection
    pub fn evaluate_inbound(&self, packet: &ParsedPacket<'_>) -> PacketAction {
        if !self.passive_enabled() {
            return PacketAction::Accept;
        }

        let tcp = match packet.tcp() {
            Some(t) => t,
            None => return PacketAction::Accept,
        };

        let flow = crate::flow_ttl::FlowKey {
            server: packet.src_addr(),
            client: packet.dst_addr(),
            server_port: tcp.src_port,
            client_port: tcp.dst_port,
        };
        if tcp.is_syn_ack() {
            self.flows.syn_ack_received(&flow, packet.ttl());
        }
        let flow = self.flows.lookup(&flow);

        // Check for forged RST packets
        if tcp.is_rst() && passive::is_forged_rst_on_flow(packet, flow) {
            self.note_interference(packet, tcp);
            METRICS.forged_rst_drops.fetch_add(1, Ordering::Relaxed);
            self.record_forged_rst_source(packet.src_addr());
            METRICS.push_event(
                EventLevel::Warning,
                format!(
                    "forged RST from {}",
                    crate::logging::peer(packet.src_addr())
                ),
            );
            debug!(
                src = %crate::logging::peer(packet.src_addr()),
                "dropping forged RST packet from DPI"
            );
            return PacketAction::Drop;
        }

        // Check for forged HTTP redirects
        if tcp.is_psh_ack() && tcp.has_payload() {
            if passive::is_forged_redirect_on_flow(tcp.payload, packet, flow) {
                self.note_interference(packet, tcp);
                METRICS
                    .forged_redirect_drops
                    .fetch_add(1, Ordering::Relaxed);
                METRICS.push_event(
                    EventLevel::Warning,
                    format!(
                        "forged redirect from {}",
                        crate::logging::peer(packet.src_addr())
                    ),
                );
                debug!(
                    src = %crate::logging::peer(packet.src_addr()),
                    "dropping forged HTTP redirect from DPI"
                );
                return PacketAction::Drop;
            }

            // Check for forged TLS alerts (DPI may inject fake alerts to kill connections)
            if (tcp.src_port == 443 || tcp.src_port == 8080)
                && passive::is_forged_tls_alert_on_flow(tcp.payload, packet, flow)
            {
                self.note_interference(packet, tcp);
                METRICS.forged_alert_drops.fetch_add(1, Ordering::Relaxed);
                METRICS.push_event(
                    EventLevel::Warning,
                    format!(
                        "forged TLS alert from {}",
                        crate::logging::peer(packet.src_addr())
                    ),
                );
                debug!(
                    src = %crate::logging::peer(packet.src_addr()),
                    "dropping forged TLS alert from DPI"
                );
                return PacketAction::Drop;
            }
        }

        // Auto-TTL detection from SYN-ACK responses
        // The SYN-ACK TTL reveals the server's initial TTL (usually 64 or 128).
        // Subtracting from the common initial value gives us the hop count.
        // DPI is typically 1-2 hops before the server, so fake TTL = hops - 2.
        // This works universally across ISPs — no hardcoded values needed.
        // Only detect when a fake packet will actually use the result. With
        // fakes disabled this ran on every SYN-ACK and filled a cache keyed by
        // peer address that nothing ever read.
        if tcp.is_syn_ack() && self.config.strategies.auto_ttl && self.fake_ttl_is_used() {
            let recv_ttl = packet.ttl();
            let initial_ttl = initial_ttl_of(recv_ttl);
            let hops = initial_ttl.saturating_sub(recv_ttl);
            let fake_ttl = fake_ttl_from_server_ttl(recv_ttl);

            // Store per-destination TTL
            let src_ip = packet.src_addr();
            if let Ok(mut cache) = self.ttl_cache.lock() {
                // Evict oldest entries if cache is full
                if cache.len() >= MAX_TTL_CACHE_ENTRIES && !cache.contains_key(&src_ip) {
                    // Simple eviction: clear half the cache
                    let keys: Vec<IpAddr> = cache
                        .keys()
                        .take(MAX_TTL_CACHE_ENTRIES / 2)
                        .copied()
                        .collect();
                    for k in keys {
                        cache.remove(&k);
                    }
                }
                cache.insert(src_ip, fake_ttl);
                METRICS
                    .ttl_cache_size
                    .store(cache.len() as u64, Ordering::Relaxed);
            }

            METRICS.ttl_detections.fetch_add(1, Ordering::Relaxed);

            // Also update global fallback
            let current = self.auto_ttl.load(Ordering::Relaxed);
            if current == 0 {
                self.auto_ttl.store(fake_ttl, Ordering::Relaxed);
                METRICS.push_event(
                    EventLevel::Info,
                    format!(
                        "auto-TTL {} for {} (hops={})",
                        fake_ttl,
                        crate::logging::peer(src_ip),
                        hops
                    ),
                );
                info!(
                    recv_ttl = recv_ttl,
                    initial_ttl = initial_ttl,
                    hops = hops,
                    fake_ttl = fake_ttl,
                    src = %crate::logging::peer(src_ip),
                    "auto-TTL detected from SYN-ACK"
                );
            } else {
                debug!(
                    recv_ttl = recv_ttl,
                    hops = hops,
                    fake_ttl = fake_ttl,
                    src = %crate::logging::peer(src_ip),
                    "per-destination TTL cached"
                );
            }
        }

        PacketAction::Accept
    }

    // ── Private strategy application methods ──

    fn apply_http_strategy(
        &self,
        packet: &ParsedPacket<'_>,
        tcp: &packet::tcp::TcpHeader<'_>,
    ) -> PacketAction {
        // Check domain filter for HTTP
        if let Some(http_req) = packet::http::HttpRequest::parse(tcp.payload)
            && let Some(ref host) = http_req.host
        {
            if !self.config.should_process_domain(host) {
                METRICS.domains_skipped.fetch_add(1, Ordering::Relaxed);
                debug!(
                    domain = %crate::logging::peer(host.as_str()),
                    "HTTP domain not in filter list, skipping"
                );
                return PacketAction::Accept;
            }
            METRICS.domains_matched.fetch_add(1, Ordering::Relaxed);
        }

        match self.mode {
            BypassMode::Passive => PacketAction::Accept,
            BypassMode::HttpFragment
            | BypassMode::AllActive
            | BypassMode::Aggressive
            | BypassMode::AutoDetect
            | BypassMode::Custom => {
                // Try HTTP fragmentation first
                if let Some(fragments) = http_split::split_http_request(
                    packet.raw,
                    &packet.ip,
                    tcp,
                    self.config.strategies.http_split_position,
                ) {
                    METRICS.http_splits.fetch_add(1, Ordering::Relaxed);
                    // If fake packets are enabled, inject them too
                    if self.fake_enabled() {
                        let fake_ttl = self.get_fake_ttl(packet.dst_addr(), packet.ttl());
                        let mut fakes = Vec::new();

                        // Desync-first for HTTP too: fake RST first
                        if self.config.strategies.desync_first
                            && matches!(
                                self.mode,
                                BypassMode::AllActive
                                    | BypassMode::Aggressive
                                    | BypassMode::AutoDetect
                                    | BypassMode::Custom
                            )
                            && let Some(fake_rst) = fake_packet::create_fake_rst_desync(
                                packet.raw, &packet.ip, tcp, fake_ttl,
                            )
                        {
                            fakes.push(fake_rst);
                        }

                        fakes.extend(fake_packet::create_fake_packets(
                            packet.raw,
                            &packet.ip,
                            tcp,
                            fake_ttl,
                            &self.config,
                        ));

                        return PacketAction::InjectAndFragment { fakes, fragments };
                    }
                    return PacketAction::Fragment(fragments);
                }
                PacketAction::Accept
            }
            BypassMode::TlsFragment => PacketAction::Accept,
            BypassMode::FakePacket => {
                if let Some(fakes) = self.create_fakes_for(packet, tcp) {
                    return PacketAction::InjectThenAccept(fakes);
                }
                PacketAction::Accept
            }
        }
    }

    fn apply_tls_strategy(
        &self,
        packet: &ParsedPacket<'_>,
        tcp: &packet::tcp::TcpHeader<'_>,
    ) -> PacketAction {
        match self.mode {
            BypassMode::Passive | BypassMode::HttpFragment => PacketAction::Accept,
            BypassMode::TlsFragment
            | BypassMode::AllActive
            | BypassMode::Aggressive
            | BypassMode::AutoDetect
            | BypassMode::Custom => {
                // Parse the ClientHello to find SNI
                let hello = match packet::tls::TlsClientHello::parse(tcp.payload) {
                    Some(h) if h.has_sni() => h,
                    Some(h) => {
                        if let Some(resume) = h.resume {
                            self.remember_hello_resume(packet, tcp, resume);
                            debug!("TLS ClientHello continues past this segment, SNI not in it");
                        } else {
                            debug!("TLS ClientHello has no SNI, skipping");
                        }
                        return PacketAction::Accept;
                    }
                    _ => {
                        debug!("TLS ClientHello parse failed, skipping");
                        return PacketAction::Accept;
                    }
                };

                self.split_client_hello(packet, tcp, &hello, false)
            }
            BypassMode::FakePacket => {
                if let Some(fakes) = self.create_fakes_for(packet, tcp) {
                    return PacketAction::InjectThenAccept(fakes);
                }
                PacketAction::Accept
            }
        }
    }

    /// In mode 7, move the destination of an inbound forged packet up a level.
    fn note_interference(&self, packet: &ParsedPacket<'_>, tcp: &packet::tcp::TcpHeader<'_>) {
        if !matches!(self.mode, BypassMode::AutoDetect) {
            return;
        }
        let server = packet.src_addr();
        let connection = (packet.dst_addr(), tcp.dst_port, tcp.src_port);
        if let Some(level) = self.escalation.note_interference(server, &connection) {
            METRICS.escalations.fetch_add(1, Ordering::Relaxed);
            info!(
                dst = %crate::logging::peer(server),
                level = level,
                "DPI interference seen; changing techniques for this destination"
            );
        }
    }

    /// TTL for a fake packet on this connection.
    ///
    /// With auto-TTL on and the connection's SYN-ACK seen, the hop count comes
    /// from that SYN-ACK: exact for this server, and available whether or not
    /// fakes were enabled when the SYN-ACK arrived — which in mode 7 they
    /// usually were not.
    fn fake_ttl_for(&self, packet: &ParsedPacket<'_>, tcp: &packet::tcp::TcpHeader<'_>) -> u8 {
        if self.config.strategies.auto_ttl
            && let crate::flow_ttl::FlowTtl::Server(ttl) =
                self.flows.lookup(&Self::outbound_flow(packet, tcp))
        {
            return fake_ttl_from_server_ttl(ttl);
        }
        self.get_fake_ttl(packet.dst_addr(), packet.ttl())
    }

    fn outbound_flow(
        packet: &ParsedPacket<'_>,
        tcp: &packet::tcp::TcpHeader<'_>,
    ) -> crate::flow_ttl::FlowKey {
        crate::flow_ttl::FlowKey {
            server: packet.dst_addr(),
            client: packet.src_addr(),
            server_port: tcp.dst_port,
            client_port: tcp.src_port,
        }
    }

    /// Note where this ClientHello's extension walk continues, in sequence
    /// space, for the segment that will carry the rest.
    fn remember_hello_resume(
        &self,
        packet: &ParsedPacket<'_>,
        tcp: &packet::tcp::TcpHeader<'_>,
        resume: packet::tls::ExtensionResume,
    ) {
        let Ok(remaining) = u16::try_from(resume.remaining) else {
            return;
        };
        let next_seq = tcp.seq_num.wrapping_add(resume.next as u32);
        self.hello_resume
            .store(&Self::outbound_flow(packet, tcp), next_seq, remaining);
    }

    /// Find the SNI in a segment that continues a ClientHello and split around
    /// it. `None` hands the segment back to the normal path.
    fn continue_client_hello(
        &self,
        packet: &ParsedPacket<'_>,
        tcp: &packet::tcp::TcpHeader<'_>,
    ) -> Option<PacketAction> {
        let (next_seq, remaining) = self.hello_resume.take(&Self::outbound_flow(packet, tcp))?;
        // A header before this segment's start means a retransmission or a
        // reordered segment; there is nothing here to resume from.
        let next = next_seq.wrapping_sub(tcp.seq_num);
        if (next as i32) < 0 {
            return None;
        }
        let resume = packet::tls::ExtensionResume {
            next: next as usize,
            remaining: remaining as usize,
        };
        match packet::tls::continue_extension_walk(tcp.payload, resume) {
            packet::tls::Continuation::Sni {
                offset,
                length,
                name,
            } => {
                debug!("TLS ClientHello SNI found in a continuation segment");
                let hello =
                    packet::tls::TlsClientHello::continuation(tcp.payload, name, offset, length);
                Some(self.split_client_hello(packet, tcp, &hello, true))
            }
            packet::tls::Continuation::Resume(next) => {
                self.remember_hello_resume(packet, tcp, next);
                None
            }
            packet::tls::Continuation::Exhausted => None,
        }
    }

    /// Apply the TLS strategy to a segment whose SNI is known: check the domain
    /// filter, split, and add fakes.
    ///
    /// `continuation` marks a segment that carries the SNI of a ClientHello
    /// whose first segment has already gone out. Fakes and the desync RST are
    /// left out there — they are built to precede the start of a ClientHello —
    /// and a fixed split position, which counts from that start, does not apply.
    fn split_client_hello(
        &self,
        packet: &ParsedPacket<'_>,
        tcp: &packet::tcp::TcpHeader<'_>,
        hello: &packet::tls::TlsClientHello<'_>,
        continuation: bool,
    ) -> PacketAction {
        let split_position = if continuation {
            0
        } else {
            self.config.strategies.tls_split_position
        };

        // Check domain filter
        if let Some(ref sni) = hello.sni {
            // Measure whether the parser is extracting hostnames at all.
            METRICS.sni_parsed.fetch_add(1, Ordering::Relaxed);
            if !packet::tls::is_hostname_syntax(sni) {
                METRICS.sni_syntax_invalid.fetch_add(1, Ordering::Relaxed);
            }

            if !self.config.should_process_domain(sni) {
                METRICS.domains_skipped.fetch_add(1, Ordering::Relaxed);
                debug!(
                    domain = %crate::logging::peer(sni.as_str()),
                    "domain not in filter list, skipping"
                );
                return PacketAction::Accept;
            }
            METRICS.domains_matched.fetch_add(1, Ordering::Relaxed);
            debug!(
                domain = %crate::logging::peer(sni.as_str()),
                "domain matched, applying TLS strategy"
            );
        }

        // ── Desync-first approach (Mode 5+): fake CH → multi-fragment → disorder ──
        // This is the primary bypass technique against advanced DPI systems.
        //
        // Strategy:
        // 1. Send fake RST with wrong TTL → DPI tears down connection tracking
        // 2. Send fake ClientHello with google.com SNI → DPI reclassifies as "safe"
        // 3. Send real ClientHello split into 3 fragments, in reverse order (disorder)
        //
        // DPI sees: RST(fake) → ClientHello(google.com, fake) → data fragments
        // Server sees: ClientHello fragments (correct order, reassembled)
        // Mode 7 adds techniques per destination as the DPI is seen to
        // interfere: 1 reorders and splits in three, 2 adds fakes, 3 adds the
        // desync RST. 0 is the configuration as written.
        let level = if matches!(self.mode, BypassMode::AutoDetect) {
            self.escalation.level(packet.dst_addr())
        } else {
            0
        };

        let use_desync = !continuation
            && (level >= 3 || self.config.strategies.desync_first)
            && matches!(
                self.mode,
                BypassMode::AllActive
                    | BypassMode::Aggressive
                    | BypassMode::AutoDetect
                    | BypassMode::Custom
            );

        let use_multi_fragment = (level >= 1 || self.config.strategies.multi_fragment)
            && matches!(
                self.mode,
                BypassMode::AllActive
                    | BypassMode::Aggressive
                    | BypassMode::AutoDetect
                    | BypassMode::Custom
            );

        let use_disorder = (level >= 1 || self.config.strategies.disorder)
            && matches!(
                self.mode,
                BypassMode::AllActive
                    | BypassMode::Aggressive
                    | BypassMode::AutoDetect
                    | BypassMode::Custom
            );

        // Try multi-fragment splitting first (3 segments)
        let fragments = if use_multi_fragment {
            tls_split::split_tls_multi_fragment(packet.raw, &packet.ip, tcp, hello, use_disorder)
                .or_else(|| {
                    // Fall back to 2-fragment with disorder
                    if use_disorder {
                        tls_split::split_tls_out_of_order(packet.raw, &packet.ip, tcp, hello)
                    } else {
                        tls_split::split_tls_client_hello(
                            packet.raw,
                            &packet.ip,
                            tcp,
                            hello,
                            split_position,
                        )
                    }
                })
        } else if use_disorder || matches!(self.mode, BypassMode::Aggressive) {
            // Aggressive always reorders. It used to re-frame the
            // ClientHello as two TLS records instead, which adds a
            // 5-byte header the kernel never sent; with neither the
            // later segments nor the server's ACKs passing through
            // here, nothing could shift sequence numbers to match,
            // and every such connection broke.
            tls_split::split_tls_out_of_order(packet.raw, &packet.ip, tcp, hello)
        } else {
            tls_split::split_tls_client_hello(packet.raw, &packet.ip, tcp, hello, split_position)
        };

        if let Some(fragments) = fragments {
            METRICS.tls_splits.fetch_add(1, Ordering::Relaxed);
            if (self.fake_enabled() || level >= 2) && !continuation {
                let fake_ttl = self.fake_ttl_for(packet, tcp);
                let mut fakes = Vec::new();

                // Desync-first: inject fake RST + fake ClientHello with harmless SNI
                // before the real fragments. This is the key technique against
                // advanced DPI (Sandvine/ProcERA class):
                //
                // 1. Fake RST → DPI tears down connection tracking for this 5-tuple
                // 2. Fake ClientHello(google.com) → DPI creates NEW tracking entry
                //    classifying this connection as going to google.com (allowed)
                // 3. Real fragments arrive → DPI treats as continuation of "google.com"
                if use_desync {
                    // Fake RST to break DPI connection tracking
                    if let Some(fake_rst) =
                        fake_packet::create_fake_rst_desync(packet.raw, &packet.ip, tcp, fake_ttl)
                    {
                        fakes.push(fake_rst);
                    }
                }

                // Standard fakes (includes fake ClientHello with google.com SNI)
                fakes.extend(fake_packet::create_fake_packets(
                    packet.raw,
                    &packet.ip,
                    tcp,
                    fake_ttl,
                    &self.config,
                ));

                // In Aggressive mode, add extra fake RST at end too
                if matches!(self.mode, BypassMode::Aggressive)
                    && let Some(fake_rst) =
                        fake_packet::create_fake_rst_desync(packet.raw, &packet.ip, tcp, fake_ttl)
                {
                    fakes.push(fake_rst);
                }

                return PacketAction::InjectAndFragment { fakes, fragments };
            }
            return PacketAction::Fragment(fragments);
        }
        PacketAction::Accept
    }

    fn evaluate_quic(
        &self,
        packet: &ParsedPacket<'_>,
        udp: &packet::udp::UdpHeader<'_>,
    ) -> PacketAction {
        if !quic_desync_active(self.mode, &self.config) {
            return PacketAction::Accept;
        }

        if !udp.is_quic_port() || !udp.is_quic_initial() {
            return PacketAction::Accept;
        }

        // Apply QUIC desynchronization
        if let Some(fragments) = quic::desync_quic_initial(packet.raw, &packet.ip, udp) {
            METRICS.quic_desyncs.fetch_add(1, Ordering::Relaxed);
            return PacketAction::Fragment(fragments);
        }

        PacketAction::Accept
    }

    fn apply_window_strategy(&self, packet: &ParsedPacket<'_>) -> PacketAction {
        METRICS.window_mods.fetch_add(1, Ordering::Relaxed);
        let mut modified = packet.raw.to_vec();
        let ip_hdr_len = packet.ip.header_len();
        let new_window = self.config.strategies.tcp_window_size;
        packet::tcp::modify_window_size(&mut modified, ip_hdr_len, new_window);

        // Recalculate IP checksum if IPv4
        if packet.ip.is_v4() {
            let ttl = modified[8];
            packet::ip::set_ipv4_ttl(&mut modified, ttl);
        }

        PacketAction::Modify(modified)
    }

    fn create_fakes_for(
        &self,
        packet: &ParsedPacket<'_>,
        tcp: &packet::tcp::TcpHeader<'_>,
    ) -> Option<Vec<Vec<u8>>> {
        let fakes = fake_packet::create_fake_packets(
            packet.raw,
            &packet.ip,
            tcp,
            self.get_fake_ttl(packet.dst_addr(), packet.ttl()),
            &self.config,
        );
        if fakes.is_empty() { None } else { Some(fakes) }
    }

    // ── Helper methods ──

    fn passive_enabled(&self) -> bool {
        matches!(
            self.mode,
            BypassMode::Passive
                | BypassMode::AllActive
                | BypassMode::Aggressive
                | BypassMode::AutoDetect
                | BypassMode::Custom
        ) && self.config.strategies.passive_dpi
    }

    fn fake_enabled(&self) -> bool {
        matches!(
            self.mode,
            BypassMode::FakePacket
                | BypassMode::AllActive
                | BypassMode::Aggressive
                | BypassMode::AutoDetect
        ) && self.config.strategies.fake_packet_enabled
    }

    /// Whether anything will actually consume a detected TTL.
    ///
    /// Auto-TTL exists for one purpose: choosing the TTL of a fake packet so it
    /// dies past the DPI and before the server. If no fake packet will be built,
    /// every detection is work whose result nothing reads — and it keeps a cache
    /// keyed by peer address for no benefit. Mode 4 builds fakes whatever
    /// `fake_packet_enabled` says, since that is the mode's entire point; the
    /// other modes honour the flag.
    fn fake_ttl_is_used(&self) -> bool {
        self.fake_enabled() || matches!(self.mode, BypassMode::FakePacket)
    }

    /// Log which techniques this run will actually apply.
    ///
    /// A mode permits techniques; the config arms them, and several ship
    /// disabled on purpose. "All active techniques" with `fake_packet_enabled =
    /// false` and `tcp_window_size = 0` applies exactly one, which is easy to
    /// mistake for a malfunction when the counters stay at zero. State it at
    /// startup instead of leaving it to be inferred from metrics.
    pub fn log_active_techniques(&self) {
        let s = &self.config.strategies;
        let quic_active = quic_desync_active(self.mode, &self.config);

        info!(
            mode = ?self.mode,
            tls_fragmentation = true,
            http_fragmentation = true,
            passive_defence = self.passive_enabled(),
            fake_packets = self.fake_enabled(),
            window_size = self.should_modify_window(),
            quic_desync = quic_active,
            auto_ttl = s.auto_ttl && self.fake_ttl_is_used(),
            "active techniques"
        );

        for (name, reason) in [
            (
                "fake packets",
                (!self.fake_enabled()).then_some({
                    if s.fake_packet_enabled {
                        "not applied in this mode"
                    } else {
                        "[strategies] fake_packet_enabled = false"
                    }
                }),
            ),
            (
                "TCP window size",
                (!self.should_modify_window()).then_some({
                    if s.tcp_window_size > 0 {
                        "not applied in this mode"
                    } else {
                        "[strategies] tcp_window_size = 0"
                    }
                }),
            ),
            (
                "QUIC desync",
                (!quic_active).then_some({
                    if s.quic_desync {
                        "only applied in mode 6 (aggressive)"
                    } else {
                        "[strategies] quic_desync = false"
                    }
                }),
            ),
        ] {
            if let Some(reason) = reason {
                info!(technique = name, reason = reason, "technique not active");
            }
        }
    }

    fn should_modify_window(&self) -> bool {
        self.config.strategies.tcp_window_size > 0
            && matches!(
                self.mode,
                BypassMode::AllActive
                    | BypassMode::Aggressive
                    | BypassMode::AutoDetect
                    | BypassMode::Custom
            )
    }

    fn get_fake_ttl(&self, dst_ip: IpAddr, real_ttl: u8) -> u8 {
        if self.config.strategies.auto_ttl {
            // First try per-destination cache
            if let Ok(cache) = self.ttl_cache.lock()
                && let Some(&ttl) = cache.get(&dst_ip)
            {
                return ttl;
            }
            // Fall back to global auto-TTL
            let detected = self.auto_ttl.load(Ordering::Relaxed);
            if detected > 0 {
                detected
            } else {
                // Fallback: not yet detected from SYN-ACK, estimate from outbound TTL
                if real_ttl > 64 {
                    real_ttl - 64 + 1
                } else if real_ttl > 10 {
                    (real_ttl / 3).max(1)
                } else {
                    1
                }
            }
        } else {
            self.config.strategies.fake_packet_ttl
        }
    }

    /// Test-only accessor: look up the cached fake TTL for a destination IP.
    /// Returns the cached value or 0 if no entry exists.
    pub fn get_fake_ttl_for_test(&self, dst_ip: IpAddr) -> u8 {
        if let Ok(cache) = self.ttl_cache.lock() {
            cache.get(&dst_ip).copied().unwrap_or(0)
        } else {
            0
        }
    }
}

// ── Injection & verdict abstractions ──
//
// `process_packet` talks to the kernel through these two traits instead of
// the concrete `NfQueue`/`RawSocket` types, so the verdict/injection
// sequencing can be exercised in tests with mock implementations.

/// Sink for NFQUEUE verdicts. Implemented by `NfQueue`; mockable in tests.
pub trait VerdictSink {
    fn verdict_accept(&self, packet_id: u32) -> Result<()>;
    fn verdict_drop(&self, packet_id: u32) -> Result<()>;
    fn verdict_accept_modified(&self, packet_id: u32, data: &[u8]) -> Result<()>;
}

/// Raw-socket packet injection as used by the strategy engine.
///
/// The two methods carry different delivery contracts:
/// - `send_data` carries real user bytes (ClientHello/HTTP fragments).
///   `Ok` means the packet was handed to the kernel; any failure must
///   surface as `Err` so the caller can fall back to accepting the
///   original packet instead of losing data.
/// - `send_decoy` carries fake packets that only exist to confuse DPI.
///   Implementations may drop them (e.g. rate limiting) and still
///   return `Ok`.
pub trait PacketInjector {
    /// Returns proof of delivery, which is what makes dropping the original
    /// packet legitimate. See [`Sent`].
    fn send_data(&self, packet: &[u8]) -> Result<Sent>;
    fn send_decoy(&self, packet: &[u8]) -> Result<()>;
}

impl VerdictSink for NfQueue {
    fn verdict_accept(&self, packet_id: u32) -> Result<()> {
        NfQueue::verdict_accept(self, packet_id)
    }
    fn verdict_drop(&self, packet_id: u32) -> Result<()> {
        NfQueue::verdict_drop(self, packet_id)
    }
    fn verdict_accept_modified(&self, packet_id: u32, data: &[u8]) -> Result<()> {
        NfQueue::verdict_accept_modified(self, packet_id, data)
    }
}

impl PacketInjector for RawSocket {
    fn send_data(&self, packet: &[u8]) -> Result<Sent> {
        self.send_unlimited(packet)
    }
    fn send_decoy(&self, packet: &[u8]) -> Result<()> {
        self.send_rate_limited(packet)
    }
}

/// Send every fragment carrying real user data, failing fast on the first error.
///
/// Yields the [`Sent`] witness of the last fragment, which is what lets the
/// caller drop the original. An empty fragment list produces no witness and is
/// an error: there is nothing replacing the original, so it must not be dropped.
fn send_fragments<I: PacketInjector>(injector: &I, fragments: &[Vec<u8>]) -> Result<Sent> {
    let mut delivered: Option<Sent> = None;
    let mut count = 0usize;
    for frag in fragments {
        delivered = Some(injector.send_data(frag)?);
        count += 1;
    }

    // The returned witness has to stand for *every* replacement, not merely
    // for the last successful send. The `?` above already aborts on the first
    // failure, so a partial run cannot get here today; this check keeps that
    // meaning if the loop is ever made tolerant of individual failures, which
    // would otherwise hand back a witness for a partial delivery.
    if count != fragments.len() {
        bail!(
            "only {count} of {} replacement fragments were delivered; \
             the original packet must not be dropped",
            fragments.len()
        );
    }

    delivered.context("no fragments to send in place of the original packet")
}

/// Drop the intercepted packet now that its replacement is on the wire.
///
/// Taking the [`Sent`] witness by value is the point: the only way to reach a
/// `verdict_drop` on the fragmenting paths is to hand over proof that something
/// was actually sent instead.
fn drop_replaced_original<Q: VerdictSink>(
    queue: &Q,
    packet_id: u32,
    _delivered: Sent,
) -> Result<()> {
    queue.verdict_drop(packet_id)?;
    METRICS.out_fragmented.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

/// Fragment injection failed: keep the connection alive by accepting the
/// original packet unfragmented. No bypass for this packet, but no outage —
/// and the failure is visible via the log and the `socket_errors` counter.
fn accept_unfragmented<Q: VerdictSink>(
    queue: &Q,
    packet_id: u32,
    err: anyhow::Error,
) -> Result<()> {
    METRICS.socket_errors.fetch_add(1, Ordering::Relaxed);
    METRICS.last_error_ms.store(epoch_ms(), Ordering::Relaxed);
    warn!(
        id = packet_id,
        "fragment injection failed ({:#}); accepting original packet unfragmented", err
    );
    queue.verdict_accept(packet_id)?;
    METRICS.out_accepted.fetch_add(1, Ordering::Relaxed);
    Ok(())
}

/// Process a single packet through the strategy engine and execute the action.
///
/// This is the main entry point called from the packet processing loop.
pub fn process_packet<Q: VerdictSink, I: PacketInjector>(
    engine: &StrategyEngine,
    queue: &Q,
    raw_socket: &I,
    packet_id: u32,
    raw_data: &[u8],
    direction: Direction,
) -> Result<()> {
    let parsed = match ParsedPacket::parse(raw_data, direction) {
        Some(p) => p,
        None => {
            METRICS.parse_failures.fetch_add(1, Ordering::Relaxed);
            trace!(id = packet_id, "unparseable packet, accepting");
            queue.verdict_accept(packet_id)?;
            return Ok(());
        }
    };

    // Update packet totals and timestamps
    match direction {
        Direction::Outbound => {
            METRICS.out_total.fetch_add(1, Ordering::Relaxed);
            METRICS
                .last_out_packet_ms
                .store(epoch_ms(), Ordering::Relaxed);
        }
        Direction::Inbound => {
            METRICS.in_total.fetch_add(1, Ordering::Relaxed);
            METRICS
                .last_in_packet_ms
                .store(epoch_ms(), Ordering::Relaxed);
        }
    }

    // Log packet details at trace level
    if let Some(tcp) = parsed.tcp() {
        trace!(
            id = packet_id,
            src = %crate::logging::peer(parsed.src_addr()),
            dst = %crate::logging::peer(parsed.dst_addr()),
            sport = tcp.src_port,
            dport = tcp.dst_port,
            flags = tcp.flags,
            payload_len = tcp.payload.len(),
            syn = tcp.is_syn(),
            psh_ack = tcp.is_psh_ack(),
            rst = tcp.is_rst(),
            "TCP packet"
        );
    }

    let action = match direction {
        Direction::Outbound => engine.evaluate_outbound(&parsed),
        Direction::Inbound => engine.evaluate_inbound(&parsed),
    };

    // Log non-Accept actions at debug level.
    //
    // Only a summary: rendering the action itself writes every fragment out as
    // a byte array, which puts the TLS ClientHello — SNI and all — into the
    // journal for every packet. That is a durable record of which sites were
    // visited, written by a tool whose whole purpose is keeping that off the
    // wire, and it dwarfs everything else in the log.
    match &action {
        PacketAction::Accept => {}
        other => {
            debug!(
                id = packet_id,
                action = %other.summary(),
                src = %crate::logging::peer(parsed.src_addr()),
                dst = %crate::logging::peer(parsed.dst_addr()),
                "strategy applied"
            );
            // The bytes themselves stay behind a second, explicit switch, so
            // raising the log level alone can never start recording traffic.
            if engine.config.logging.log_packet_bytes {
                trace!(
                    id = packet_id,
                    action = ?other,
                    "strategy applied (packet contents)"
                );
            }
        }
    }

    match action {
        PacketAction::Accept => {
            queue.verdict_accept(packet_id)?;
            match direction {
                Direction::Outbound => {
                    METRICS.out_accepted.fetch_add(1, Ordering::Relaxed);
                }
                Direction::Inbound => {
                    METRICS.in_accepted.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        PacketAction::Drop => {
            queue.verdict_drop(packet_id)?;
            match direction {
                Direction::Outbound => {
                    METRICS.out_dropped.fetch_add(1, Ordering::Relaxed);
                }
                Direction::Inbound => {
                    METRICS.in_dropped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        PacketAction::Modify(data) => {
            queue.verdict_accept_modified(packet_id, &data)?;
            METRICS.out_modified.fetch_add(1, Ordering::Relaxed);
        }
        PacketAction::Fragment(fragments) => {
            // Deliver replacement fragments BEFORE issuing a verdict: the
            // original packet is held by the kernel until we answer, so if
            // injection fails we can still fall back to accepting it instead
            // of silently losing the data.
            match send_fragments(raw_socket, &fragments) {
                Ok(delivered) => drop_replaced_original(queue, packet_id, delivered)?,
                Err(e) => accept_unfragmented(queue, packet_id, e)?,
            }
        }
        PacketAction::InjectThenAccept(fakes) => {
            // Send fake packets first, then accept the original. Decoys are
            // best-effort: a failed decoy must not block the real packet.
            METRICS
                .fake_packets_sent
                .fetch_add(fakes.len() as u64, Ordering::Relaxed);
            for fake in &fakes {
                if let Err(e) = raw_socket.send_decoy(fake) {
                    METRICS.socket_errors.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        id = packet_id,
                        "decoy injection failed (continuing): {:#}", e
                    );
                }
            }
            queue.verdict_accept(packet_id)?;
            METRICS.out_accepted.fetch_add(1, Ordering::Relaxed);
        }
        PacketAction::InjectAndFragment { fakes, fragments } => {
            // Send fakes first, then fragments, then drop the original.
            //
            // For desync: send ALL fakes before any fragment. This ensures
            // DPI processes the fake RST (breaks tracking) and fake ClientHello
            // (reclassifies as "safe") before seeing any real data. Then the
            // real fragments arrive and DPI treats them as safe traffic.
            //
            // Sequence: fake_rst → fake_ch → frag3 → frag2 → frag1
            //
            // The fragments are already in the correct order (disorder=reverse
            // is applied by the splitting function). The original packet is
            // dropped only AFTER all real-data fragments were handed to the
            // raw socket; if any of them fails, the original is accepted
            // instead so the connection survives. Decoys are best-effort.
            METRICS
                .fake_packets_sent
                .fetch_add(fakes.len() as u64, Ordering::Relaxed);
            for fake in &fakes {
                if let Err(e) = raw_socket.send_decoy(fake) {
                    METRICS.socket_errors.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        id = packet_id,
                        "decoy injection failed (continuing): {:#}", e
                    );
                }
            }

            match send_fragments(raw_socket, &fragments) {
                Ok(delivered) => drop_replaced_original(queue, packet_id, delivered)?,
                Err(e) => accept_unfragmented(queue, packet_id, e)?,
            }
        }
    }

    Ok(())
}
