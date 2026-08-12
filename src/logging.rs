// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/logging.rs — Logging initialization
//
// Sets up tracing/logging to journald and/or file output.

use anyhow::Result;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

use crate::config::LogConfig;

/// Initialize the logging subsystem based on config
pub fn init(config: &LogConfig, verbose: u8) -> Result<()> {
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
