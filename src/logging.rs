// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/logging.rs — Logging initialization
//
// Sets up tracing/logging to journald and/or file output.

use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::config::LogConfig;

/// Whether values that reveal where the user is connecting may be logged.
///
/// A process-wide switch rather than a parameter because the fields are emitted
/// from places that have no access to the config — the raw socket and the
/// splitting routines take packets, not settings — and the policy is a property
/// of the run, not of a call site.
static LOG_IDENTIFYING_FIELDS: AtomicBool = AtomicBool::new(false);

/// Written in place of an identifying value when logging it is not allowed.
pub const REDACTED: &str = "<redacted>";

/// A value that is only shown when identifying fields may be logged.
pub enum Redactable<T> {
    Shown(T),
    Hidden,
}

impl<T: std::fmt::Display> std::fmt::Display for Redactable<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Redactable::Shown(value) => value.fmt(f),
            Redactable::Hidden => f.write_str(REDACTED),
        }
    }
}

/// Wrap a value that says where the user is connecting — a domain, an SNI, a
/// peer address.
///
/// The field keeps its place in the event either way, so a log consumer sees a
/// consistent shape and an operator can tell the value was withheld rather than
/// wondering why the field vanished.
pub fn peer<T>(value: T) -> Redactable<T> {
    if LOG_IDENTIFYING_FIELDS.load(Ordering::Relaxed) {
        Redactable::Shown(value)
    } else {
        Redactable::Hidden
    }
}

/// Enable or disable identifying fields for the rest of the run.
pub fn set_identifying_fields(enabled: bool) {
    LOG_IDENTIFYING_FIELDS.store(enabled, Ordering::Relaxed);
}

/// Say out loud that this run is recording sensitive data.
///
/// Both switches are meant to be turned on briefly while debugging, and the
/// failure mode is leaving one on: nothing else in the log would reveal that
/// browsing data is being written. Call once logging is up.
pub fn warn_about_sensitive_logging(config: &LogConfig) {
    if config.log_identifying_fields {
        tracing::warn!(
            "[logging] log_identifying_fields is ON — the domain or SNI of every \
             processed connection and its peer addresses are being written to the log. \
             On a persistent journal that is a lasting record of sites visited. Turn it \
             off when done debugging"
        );
    }
    if config.log_packet_bytes {
        tracing::warn!(
            "[logging] log_packet_bytes is ON — intercepted packet contents, including \
             the TLS ClientHello, are being written to the log at TRACE level. Turn it \
             off when done debugging"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The switch is what decides, not the log level: raising the level while
    /// debugging must not start recording where the user connects.
    #[test]
    fn peer_values_are_withheld_unless_the_switch_is_on() {
        set_identifying_fields(false);
        assert_eq!(peer("example.com").to_string(), REDACTED);
        assert_eq!(peer("2600:1901:0:5e8a::").to_string(), REDACTED);

        set_identifying_fields(true);
        assert_eq!(peer("example.com").to_string(), "example.com");

        // Leave the process-wide default as it starts.
        set_identifying_fields(false);
        assert_eq!(peer("example.com").to_string(), REDACTED);
    }
}

/// Initialize the logging subsystem based on config
pub fn init(config: &LogConfig, verbose: u8) -> Result<()> {
    set_identifying_fields(config.log_identifying_fields);

    let level_str = match verbose {
        0 => config.level.as_str(),
        1 => "debug",
        _ => "trace",
    };

    let env_filter = EnvFilter::new(format!("cachydpi={}", level_str));

    // Try journald if configured
    if config.journald {
        match tracing_journald::layer() {
            Ok(journald_layer) => {
                // Adding a stderr layer as well duplicates every message when
                // stderr is itself the journal, which is how the systemd unit
                // runs: one structured entry with fields, and one flat copy of
                // the same text carrying none of them. The two are buffered
                // independently, so they can even land out of order, and a
                // multi-line message is split differently in each.
                //
                // systemd sets JOURNAL_STREAM when it has connected stdout or
                // stderr to the journal, so it is the signal for "the journald
                // layer already covers this". Without it — a foreground run
                // from a terminal — the stderr layer is what the operator
                // actually reads, so it stays.
                let stream_is_the_journal = std::env::var_os("JOURNAL_STREAM").is_some();

                let registry = tracing_subscriber::registry()
                    .with(env_filter)
                    .with(journald_layer);

                if stream_is_the_journal {
                    registry.init();
                } else {
                    registry
                        .with(tracing_subscriber::fmt::layer().with_target(true).compact())
                        .init();
                }
                return Ok(());
            }
            Err(e) => {
                eprintln!(
                    "warning: journald logging not available ({}), falling back to stderr",
                    e
                );
            }
        }
    }

    // File logging
    if let Some(ref log_path) = config.file {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log_path)?;

        let file_layer = tracing_subscriber::fmt::layer()
            .with_writer(std::sync::Mutex::new(file))
            .with_ansi(false)
            .compact();

        tracing_subscriber::registry()
            .with(env_filter)
            .with(file_layer)
            .init();
        return Ok(());
    }

    // Default: stderr only
    let fmt_layer = tracing_subscriber::fmt::layer().with_target(true).compact();

    tracing_subscriber::registry()
        .with(env_filter)
        .with(fmt_layer)
        .init();

    Ok(())
}
