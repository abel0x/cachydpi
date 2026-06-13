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
                let fmt_layer = tracing_subscriber::fmt::layer().with_target(true).compact();

                tracing_subscriber::registry()
                    .with(env_filter)
                    .with(journald_layer)
                    .with(fmt_layer)
                    .init();
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
