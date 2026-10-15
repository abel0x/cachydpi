// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/metrics.rs — Global performance metrics for CachyDPI
//
// All counters use AtomicU64 with Relaxed ordering for zero-overhead
// instrumentation. No locks on the packet processing hot path.
//
// Metrics are exposed via a Unix socket as JSON snapshots for the
// monitoring TUI (cachydpi-monitor).

use std::collections::VecDeque;
use std::fs;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering::Relaxed};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

/// Default Unix socket path for metrics
pub const DEFAULT_METRICS_SOCKET: &str = "/run/cachydpi/metrics.sock";
/// Fallback socket path when /run/cachydpi doesn't exist
pub const FALLBACK_METRICS_SOCKET: &str = "/tmp/cachydpi-metrics.sock";

/// Sentinel meaning "the configured mode does not consult a domain list".
const NO_DOMAIN_LIST: u64 = u64::MAX;

/// Ratio helper for the snapshot: 0.0 rather than NaN when nothing happened.
fn ratio(numerator: u64, denominator: u64) -> f64 {
    if denominator == 0 {
        0.0
    } else {
        numerator as f64 / denominator as f64
    }
}

/// Maximum recent events kept in ring buffer
const MAX_RECENT_EVENTS: usize = 50;

/// Global metrics instance — all atomic, zero-cost on hot path
pub static METRICS: Metrics = Metrics::new();

pub struct Metrics {
    // ── Startup info (written once) ──
    pub start_epoch_ms: AtomicU64,
    pub pid: AtomicU64,
    pub mode: AtomicU8,
    config_file: OnceLock<String>,
    domain_mode: OnceLock<String>,
    /// Domains in the active list. `u64::MAX` is the sentinel for "the mode
    /// does not use a list", which the snapshot turns back into `None` —
    /// an atomic cannot hold an Option and the value is written once at startup.
    pub domains_loaded: AtomicU64,

    // ── Outbound packet counters ──
    pub out_total: AtomicU64,
    pub out_accepted: AtomicU64,
    pub out_dropped: AtomicU64,
    pub out_modified: AtomicU64,
    pub out_fragmented: AtomicU64,

    // ── Inbound packet counters ──
    pub in_total: AtomicU64,
    pub in_accepted: AtomicU64,
    pub in_dropped: AtomicU64,

    // ── Strategy hits ──
    pub tls_splits: AtomicU64,
    pub http_splits: AtomicU64,
    pub quic_desyncs: AtomicU64,
    pub fake_packets_sent: AtomicU64,
    pub window_mods: AtomicU64,

    // ── Passive defense ──
    pub forged_rst_drops: AtomicU64,
    /// How many *distinct* peers sent a forged RST, estimated.
    ///
    /// 45 resets from one host and 45 from 45 hosts mean very different
    /// things, and the total alone cannot tell them apart. Counted by a
    /// HyperLogLog rather than a set, so no address is retained anywhere:
    /// approximate to roughly 2%, exact at the small counts that matter here,
    /// and non-decreasing.
    pub forged_rst_sources: AtomicU64,
    pub forged_alert_drops: AtomicU64,
    pub forged_redirect_drops: AtomicU64,

    // ── Domain filter ──
    pub domains_matched: AtomicU64,
    pub domains_skipped: AtomicU64,

    // ── Auto-TTL ──
    /// TLS ClientHellos whose SNI the parser extracted.
    pub sni_parsed: AtomicU64,
    /// …of which the extracted value was not hostname syntax.
    ///
    /// A check on the parser rather than on the peer: a non-zero count means
    /// the extension walk is reading the wrong offset for some layout, which
    /// would put the split points somewhere harmless while the DPI still saw
    /// the name whole. Counts only — no name is recorded.
    pub sni_syntax_invalid: AtomicU64,
    pub ttl_detections: AtomicU64,
    /// Mode 7: times a destination was moved to another strategy level.
    pub escalations: AtomicU64,

    // ── Error counters ──
    pub parse_failures: AtomicU64,
    pub queue_errors: AtomicU64,
    pub rate_limit_drops: AtomicU64,
    pub socket_errors: AtomicU64,

    // ── Health timestamps (epoch ms) ──
    pub last_out_packet_ms: AtomicU64,
    pub last_in_packet_ms: AtomicU64,
    pub last_error_ms: AtomicU64,

    // ── Recent events (Mutex only touched on rare events, never on hot path) ──
    events: Mutex<VecDeque<MetricEvent>>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    pub const fn new() -> Self {
        Self {
            start_epoch_ms: AtomicU64::new(0),
            pid: AtomicU64::new(0),
            mode: AtomicU8::new(0),
            config_file: OnceLock::new(),
            domain_mode: OnceLock::new(),
            domains_loaded: AtomicU64::new(0),

            out_total: AtomicU64::new(0),
            out_accepted: AtomicU64::new(0),
            out_dropped: AtomicU64::new(0),
            out_modified: AtomicU64::new(0),
            out_fragmented: AtomicU64::new(0),

            in_total: AtomicU64::new(0),
            in_accepted: AtomicU64::new(0),
            in_dropped: AtomicU64::new(0),

            tls_splits: AtomicU64::new(0),
            http_splits: AtomicU64::new(0),
            quic_desyncs: AtomicU64::new(0),
            fake_packets_sent: AtomicU64::new(0),
            window_mods: AtomicU64::new(0),

            forged_rst_drops: AtomicU64::new(0),
            forged_rst_sources: AtomicU64::new(0),
            forged_alert_drops: AtomicU64::new(0),
            forged_redirect_drops: AtomicU64::new(0),

            domains_matched: AtomicU64::new(0),
            domains_skipped: AtomicU64::new(0),

            sni_parsed: AtomicU64::new(0),
            sni_syntax_invalid: AtomicU64::new(0),
            ttl_detections: AtomicU64::new(0),
            escalations: AtomicU64::new(0),

            parse_failures: AtomicU64::new(0),
            queue_errors: AtomicU64::new(0),
            rate_limit_drops: AtomicU64::new(0),
            socket_errors: AtomicU64::new(0),

            last_out_packet_ms: AtomicU64::new(0),
            last_in_packet_ms: AtomicU64::new(0),
            last_error_ms: AtomicU64::new(0),

            events: Mutex::new(VecDeque::new()),
        }
    }

    /// Initialize metrics at daemon startup.
    ///
    /// `domain_count` is `None` when the configured mode does not consult a
    /// list, which is not the same as a list that loaded zero domains.
    pub fn init(
        &self,
        mode: u8,
        config_file: &str,
        domain_mode: &str,
        domain_count: Option<usize>,
    ) {
        self.start_epoch_ms.store(epoch_ms(), Relaxed);
        self.pid.store(std::process::id() as u64, Relaxed);
        self.mode.store(mode, Relaxed);
        let _ = self.config_file.set(config_file.to_string());
        let _ = self.domain_mode.set(domain_mode.to_string());
        self.domains_loaded
            .store(domain_count.map_or(NO_DOMAIN_LIST, |c| c as u64), Relaxed);
    }

    /// Push a notable event into the ring buffer.
    /// Only call from rare code paths (errors, forged detections, TTL learns).
    pub fn push_event(&self, level: EventLevel, message: String) {
        if let Ok(mut events) = self.events.lock() {
            if events.len() >= MAX_RECENT_EVENTS {
                events.pop_front();
            }
            events.push_back(MetricEvent {
                timestamp_ms: epoch_ms(),
                level,
                message,
            });
        }
    }

    /// Take a consistent snapshot of all metrics for serialization.
    pub fn snapshot(&self) -> MetricsSnapshot {
        let now = epoch_ms();
        let start = self.start_epoch_ms.load(Relaxed);
        let uptime_secs = if start > 0 {
            (now.saturating_sub(start)) / 1000
        } else {
            0
        };

        let events = self
            .events
            .lock()
            .map(|e| e.iter().cloned().collect())
            .unwrap_or_default();

        let resources = read_process_resources();

        MetricsSnapshot {
            version: crate::VERSION.to_string(),
            timestamp_ms: now,
            uptime_secs,
            service: ServiceSnapshot {
                pid: self.pid.load(Relaxed) as u32,
                mode: self.mode.load(Relaxed),
                mode_name: mode_name(self.mode.load(Relaxed)),
                config_file: self.config_file.get().cloned().unwrap_or_default(),
                domain_mode: self.domain_mode.get().cloned().unwrap_or_default(),
                domains_loaded: match self.domains_loaded.load(Relaxed) {
                    NO_DOMAIN_LIST => None,
                    count => Some(count),
                },
            },
            resources,
            outbound: OutboundSnapshot {
                total: self.out_total.load(Relaxed),
                accepted: self.out_accepted.load(Relaxed),
                dropped: self.out_dropped.load(Relaxed),
                modified: self.out_modified.load(Relaxed),
                fragmented: self.out_fragmented.load(Relaxed),
            },
            inbound: InboundSnapshot {
                total: self.in_total.load(Relaxed),
                accepted: self.in_accepted.load(Relaxed),
                dropped: self.in_dropped.load(Relaxed),
                forged_rst: self.forged_rst_drops.load(Relaxed),
                forged_rst_sources: self.forged_rst_sources.load(Relaxed),
                forged_rst_per_tls_split: ratio(
                    self.forged_rst_drops.load(Relaxed),
                    self.tls_splits.load(Relaxed),
                ),
                forged_alert: self.forged_alert_drops.load(Relaxed),
                forged_redirect: self.forged_redirect_drops.load(Relaxed),
            },
            strategies: StrategySnapshot {
                tls_splits: self.tls_splits.load(Relaxed),
                http_splits: self.http_splits.load(Relaxed),
                quic_desyncs: self.quic_desyncs.load(Relaxed),
                fake_packets: self.fake_packets_sent.load(Relaxed),
                window_mods: self.window_mods.load(Relaxed),
                domains_matched: self.domains_matched.load(Relaxed),
                domains_skipped: self.domains_skipped.load(Relaxed),
                sni_parsed: self.sni_parsed.load(Relaxed),
                sni_syntax_invalid: self.sni_syntax_invalid.load(Relaxed),
                ttl_detections: self.ttl_detections.load(Relaxed),
                escalations: self.escalations.load(Relaxed),
            },
            errors: ErrorSnapshot {
                parse_failures: self.parse_failures.load(Relaxed),
                queue_errors: self.queue_errors.load(Relaxed),
                rate_limit_drops: self.rate_limit_drops.load(Relaxed),
                socket_errors: self.socket_errors.load(Relaxed),
            },
            health: HealthSnapshot {
                last_out_packet_ms: self.last_out_packet_ms.load(Relaxed),
                last_in_packet_ms: self.last_in_packet_ms.load(Relaxed),
                last_error_ms: self.last_error_ms.load(Relaxed),
            },
            recent_events: events,
        }
    }
}

// ── Snapshot types (Serialize for daemon, Deserialize for monitor) ──

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub version: String,
    pub timestamp_ms: u64,
    pub uptime_secs: u64,
    pub service: ServiceSnapshot,
    pub resources: ResourceSnapshot,
    pub outbound: OutboundSnapshot,
    pub inbound: InboundSnapshot,
    pub strategies: StrategySnapshot,
    pub errors: ErrorSnapshot,
    pub health: HealthSnapshot,
    pub recent_events: Vec<MetricEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceSnapshot {
    pub pid: u32,
    pub mode: u8,
    pub mode_name: String,
    pub config_file: String,
    pub domain_mode: String,
    /// Domains in the active filter list, or `null` when the configured mode
    /// does not consult one.
    ///
    /// Reporting 0 for both cases reads as "the list failed to load" to
    /// anything watching this, when the truth is that no list applies.
    pub domains_loaded: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceSnapshot {
    pub rss_bytes: u64,
    pub threads: u32,
    pub open_fds: u32,
    pub cpu_secs: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundSnapshot {
    pub total: u64,
    pub accepted: u64,
    pub dropped: u64,
    pub modified: u64,
    pub fragmented: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InboundSnapshot {
    pub total: u64,
    pub accepted: u64,
    pub dropped: u64,
    pub forged_rst: u64,
    /// Distinct peers that sent a forged RST — see Metrics::forged_rst_sources.
    pub forged_rst_sources: u64,
    /// Forged RSTs per TLS split: the share of handshakes the DPI still
    /// reacted to after fragmentation. A tracked health signal rather than
    /// something to work out by hand from two counters.
    pub forged_rst_per_tls_split: f64,
    pub forged_alert: u64,
    pub forged_redirect: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StrategySnapshot {
    pub tls_splits: u64,
    pub http_splits: u64,
    pub quic_desyncs: u64,
    pub fake_packets: u64,
    pub window_mods: u64,
    pub domains_matched: u64,
    pub domains_skipped: u64,
    pub sni_parsed: u64,
    pub sni_syntax_invalid: u64,
    pub ttl_detections: u64,
    #[serde(default)]
    pub escalations: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorSnapshot {
    pub parse_failures: u64,
    pub queue_errors: u64,
    pub rate_limit_drops: u64,
    pub socket_errors: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthSnapshot {
    pub last_out_packet_ms: u64,
    pub last_in_packet_ms: u64,
    pub last_error_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricEvent {
    pub timestamp_ms: u64,
    pub level: EventLevel,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EventLevel {
    Info,
    Warning,
    Error,
}

// ── Helpers ──

/// Current epoch in milliseconds
pub fn epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn mode_name(mode: u8) -> String {
    match mode {
        1 => "Passive",
        2 => "HttpFragment",
        3 => "TlsFragment",
        4 => "FakePacket",
        5 => "AllActive",
        6 => "Aggressive",
        7 => "AutoDetect",
        _ => "Unknown",
    }
    .to_string()
}

// ── /proc readers (graceful failures return defaults) ──

fn read_process_resources() -> ResourceSnapshot {
    ResourceSnapshot {
        rss_bytes: read_proc_rss().unwrap_or(0),
        threads: read_proc_threads().unwrap_or(0),
        open_fds: read_proc_fds().unwrap_or(0),
        cpu_secs: read_proc_cpu_secs().unwrap_or(0.0),
    }
}

fn read_proc_rss() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb * 1024);
        }
    }
    None
}

fn read_proc_threads() -> Option<u32> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Threads:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

fn read_proc_fds() -> Option<u32> {
    Some(fs::read_dir("/proc/self/fd").ok()?.count() as u32)
}

fn read_proc_cpu_secs() -> Option<f64> {
    let stat = fs::read_to_string("/proc/self/stat").ok()?;
    // comm field is in parens and may contain spaces — skip past it
    let after_comm = stat.find(')')? + 2;
    let fields: Vec<&str> = stat.get(after_comm..)?.split_whitespace().collect();
    // Fields after comm: state(0) ppid(1) ... utime(11) stime(12)
    if fields.len() < 13 {
        return None;
    }
    let utime: u64 = fields[11].parse().ok()?;
    let stime: u64 = fields[12].parse().ok()?;
    let ticks_per_sec = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if ticks_per_sec <= 0 {
        return None;
    }
    Some((utime + stime) as f64 / ticks_per_sec as f64)
}
