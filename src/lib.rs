// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/lib.rs — CachyDPI library root
//
// Exports all modules for the CachyDPI DPI bypass engine.

pub mod cardinality;
pub mod cli;
pub mod config;
pub mod dns;
pub mod dpi_detect;
pub mod flow_ttl;
pub mod helix;
pub mod hello_resume;
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

/// Test-support helpers.
///
/// Lives in the library rather than a test module so the integration tests
/// under `tests/` can reach it too. Not part of the public API.
#[doc(hidden)]
pub mod testing {
    /// Environment switch that forbids skipping environment-dependent tests.
    pub const REQUIRE_NETNS_TESTS: &str = "CACHYDPI_REQUIRE_NETNS_TESTS";

    /// Report that a test cannot run here.
    ///
    /// Tests that need a privileged network namespace normally skip, which on
    /// an unconfigured CI turns into a silently green suite that proves
    /// nothing. Setting `CACHYDPI_REQUIRE_NETNS_TESTS=1` turns every such skip
    /// into a failure, so a runner that is supposed to provide the namespace
    /// says so when it does not.
    pub fn skip_unless_required(reason: &str) {
        let required = std::env::var_os(REQUIRE_NETNS_TESTS).is_some_and(|v| v != "0");
        assert!(
            !required,
            "{REQUIRE_NETNS_TESTS} is set, so this test may not be skipped: {reason}"
        );
        eprintln!("skipping: {reason}");
    }
}

/// CachyDPI version string
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Application name
pub const APP_NAME: &str = "cachydpi";
