// src/lib.rs — CachyDPI library root
//
// Exports all modules for the CachyDPI DPI bypass engine.

pub mod cli;
pub mod config;
pub mod dpi_detect;
pub mod logging;
pub mod metrics;
pub mod metrics_server;
pub mod nfqueue;
pub mod packet;
pub mod privileges;
pub mod rawsocket;
pub mod rules;
pub mod settings;
pub mod strategies;

/// CachyDPI version string
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Application name
pub const APP_NAME: &str = "cachydpi";
