// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/main.rs — CachyDPI entry point
//
// System-wide DPI bypass tool for CachyOS Linux.
// A native implementation of GoodbyeDPI optimized for linux-cachyos kernels.
//
// Architecture:
//   1. Parse CLI arguments and load config
//   2. Check capabilities and drop privileges
//   3. Install nftables rules to queue packets
//   4. Open nfqueue and raw socket
//   5. Run packet processing loop
//   6. Clean up on shutdown

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};
use clap::Parser;
use tracing::{error, info, warn};

use cachydpi::cli::{Cli, Commands};
use cachydpi::config::Config;
use cachydpi::metrics::METRICS;
use cachydpi::nfqueue::NfQueue;
use cachydpi::packet::Direction;
use cachydpi::rawsocket::RawSocket;
use cachydpi::rules::{self, NftRules};
use cachydpi::settings;
use cachydpi::strategies::{self, BypassMode, StrategyEngine};

/// Global shutdown flag
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

fn main() -> Result<()> {
    // Parse CLI arguments
    let cli = Cli::parse();

    // Load config and apply CLI overrides.
    //
    // A config that exists but cannot be read or parsed is fatal: substituting
    // the built-in defaults would silently swap the operator's domain filter
    // for a different one, so refuse to start instead. Config::load only falls
    // back to defaults when the file is genuinely absent.
    let mut config = Config::load(&cli.config)?;
    config.apply_cli_overrides(&cli);

    // Reject invalid values that the config-file path can smuggle past clap
    // (e.g. queue_num = 65535, whose inbound queue would wrap to 0).
    config.validate().context("invalid configuration")?;

    // Handle subcommands early — they don't need logging, metrics, or privileges
    if let Some(cmd) = &cli.command {
        return handle_command(cmd, &config, &cli.config);
    }

    // Initialize logging
    cachydpi::logging::init(&config.logging, cli.verbose)
        .context("failed to initialize logging")?;

    // Load domain lists from external files.
    //
    // Runs after logging is up so its diagnostics are actually visible, and its
    // failures are fatal: this is where a domain filter that would bypass every
    // site is rejected, so swallowing the error would reinstate exactly the
    // fail-open it exists to prevent.
    config
        .load_domain_lists()
        .context("failed to load domain lists")?;

    info!(
        version = cachydpi::VERSION,
        mode = config.general.mode,
        mode_desc = Cli::mode_description(config.general.mode),
        "CachyDPI starting"
    );

    // Anything the config loader wanted to say had to wait for this point:
    // loading it is what tells us how to log.
    config.log_deferred_notices(&cli.config);

    // Mode 7 (auto-detect) is advertised but not wired to the dpi_detect engine:
    // it falls through to the same arm as mode 5. Say so out loud instead of
    // pretending runtime probing happens.
    if config.general.mode == 7 {
        warn!(
            "mode 7 (auto-detect) is NOT IMPLEMENTED — no runtime DPI probing is \
             performed; it currently behaves exactly like mode 5 (all active \
             techniques). Select a specific mode (1-6) for predictable behavior."
        );
    }

    // Initialize performance metrics
    METRICS.init(
        config.general.mode,
        &cli.config.display().to_string(),
        &config.domains.mode.to_string(),
        config.domain_set.len(),
    );

    // Check prerequisites
    cachydpi::privileges::check_capabilities().context("capability check failed")?;

    // Validate the privilege drop before any nftables rules exist: failing
    // afterwards would exit with rules already installed, leaving behind the
    // stale ruleset that teardown is meant to prevent.
    cachydpi::privileges::preflight_drop_root().context("privilege drop preflight failed")?;

    rules::check_nft_available().context("nftables not available")?;

    // Install panic hook to clean up nftables rules on crash
    // (panic = "abort" skips Drop handlers but runs panic hooks)
    {
        let ipv6 = config.general.ipv6;
        std::panic::set_hook(Box::new(move |info| {
            eprintln!("FATAL PANIC: {}", info);
            // Best-effort nftables cleanup
            let _ = std::process::Command::new("nft")
                .args(["delete", "table", "ip", "cachydpi"])
                .status();
            if ipv6 {
                let _ = std::process::Command::new("nft")
                    .args(["delete", "table", "ip6", "cachydpi"])
                    .status();
            }
            eprintln!("nftables rules cleaned up after panic");
        }));
    }

    // Set process name
    cachydpi::privileges::set_process_name();

    // Install signal handlers
    setup_signal_handlers()?;

    // Dry run mode
    if cli.dry_run {
        info!("dry run mode — showing configuration and exiting");
        println!(
            "Mode: {} ({})",
            config.general.mode,
            Cli::mode_description(config.general.mode)
        );
        println!("Queue: {}", config.general.queue_num);
        println!("IPv6: {}", config.general.ipv6);
        println!("Passive DPI: {}", config.strategies.passive_dpi);
        println!("Fake packets: {}", config.strategies.fake_packet_enabled);
        println!("Auto TTL: {}", config.strategies.auto_ttl);
        println!("Desync-first: {}", config.strategies.desync_first);
        println!("Multi-fragment: {}", config.strategies.multi_fragment);
        println!("Disorder: {}", config.strategies.disorder);
        println!("QUIC desync: {}", config.strategies.quic_desync);
        return Ok(());
    }

    // Settle IPv6 before anything is installed. A machine with no IPv6 should
    // run as an IPv4-only bypass rather than refuse to start, but the decision
    // has to happen here: installing ip6 rules and only then discovering there
    // is no IPv6 injection socket would queue traffic the daemon can do nothing
    // with. Failing to open the socket on a machine that *does* have IPv6 stays
    // fatal, in RawSocket::new.
    if config.general.ipv6 && !cachydpi::rawsocket::ipv6_available() {
        warn!(
            "IPv6 is unavailable on this system (no AF_INET6, or disabled via \
             net.ipv6.conf.all.disable_ipv6) — continuing IPv4-only: no ip6 rules \
             and no IPv6 injection"
        );
        config.general.ipv6 = false;
    }

    // Install nftables rules
    let mut nft_rules = NftRules::new(config.general.queue_num, config.general.ipv6);
    if config.general.manage_rules {
        nft_rules
            .install()
            .context("failed to install nftables rules")?;
    }

    // Open raw socket for packet injection.
    //
    // This must stay ahead of the privilege drop below: CAP_NET_RAW is given
    // up there for the rest of the process lifetime (see RETAINED_CAPS), and
    // the socket only keeps working because it is already open. Anything that
    // creates a raw socket later — a reconnect or retry path, say — needs the
    // capability back, and would fail in production only.
    let raw_socket = RawSocket::new(config.general.ipv6).context("failed to create raw socket")?;

    // Open nfqueue for outbound packets
    let mut outbound_queue = NfQueue::open(config.general.queue_num, config.general.ipv6)
        .context("failed to open outbound nfqueue")?;

    // Open nfqueue for inbound packets (passive DPI detection)
    let mut inbound_queue = NfQueue::open(config.general.queue_num + 1, config.general.ipv6)
        .context("failed to open inbound nfqueue")?;

    // Drop privileges after setup.
    //
    // drop_root() reduces to RETAINED_CAPS on every path it can take — the
    // three that stay put call drop_unnecessary_caps() themselves, and the
    // setuid path rebuilds the sets from RETAINED_CAPS after the uid change.
    // Calling drop_unnecessary_caps() here as well only repeated the work and
    // logged the same "dropped capabilities" line twice, which made the order
    // of the drop ambiguous in exactly the file where it should be clearest.
    //
    // Switch to a non-root user where that is possible. The preflight above
    // already established which path applies and that it can succeed, so a
    // failure here is a real one: continuing would mean running with an
    // unclear privilege state.
    cachydpi::privileges::drop_root().context("FATAL: failed to drop root privileges")?;

    // Initialize strategy engine
    let mode = BypassMode::from_mode_number(config.general.mode);
    let engine = StrategyEngine::new(mode, config.clone());

    // Start metrics server (Unix socket for cachydpi-monitor)
    let _metrics_handle = std::thread::Builder::new()
        .name("cachydpi-metrics".to_string())
        .spawn(|| {
            cachydpi::metrics_server::run_metrics_server(&SHUTDOWN);
        })
        .context("failed to spawn metrics server thread")?;

    info!(
        mode = ?mode,
        queue_out = outbound_queue.queue_num(),
        queue_in = inbound_queue.queue_num(),
        "packet processing started"
    );

    // ── Main packet processing loop ──
    //
    // We use two threads: one for outbound, one for inbound.
    // This avoids blocking on one queue while the other has packets.

    let engine_out = Arc::new(engine);
    let engine_in = engine_out.clone();
    let raw_socket = Arc::new(raw_socket);
    let raw_socket_in = raw_socket.clone();

    let outbound_handle = std::thread::Builder::new()
        .name("cachydpi-out".to_string())
        .spawn(move || {
            run_queue_loop(
                &mut outbound_queue,
                &raw_socket,
                &engine_out,
                Direction::Outbound,
            )
        })
        .context("failed to spawn outbound thread")?;

    let inbound_handle = std::thread::Builder::new()
        .name("cachydpi-in".to_string())
        .spawn(move || {
            run_queue_loop(
                &mut inbound_queue,
                &raw_socket_in,
                &engine_in,
                Direction::Inbound,
            )
        })
        .context("failed to spawn inbound thread")?;

    // Wait for threads to finish (they check SHUTDOWN via poll timeout)
    let _ = outbound_handle.join();
    let _ = inbound_handle.join();

    // nft_rules drop handler will clean up nftables rules
    drop(nft_rules);

    info!("CachyDPI stopped cleanly");
    Ok(())
}

/// Run the packet processing loop for a single nfqueue
fn run_queue_loop(
    queue: &mut NfQueue,
    raw_socket: &RawSocket,
    engine: &StrategyEngine,
    direction: Direction,
) {
    let dir_name = match direction {
        Direction::Outbound => "outbound",
        Direction::Inbound => "inbound",
    };

    while !SHUTDOWN.load(Ordering::Relaxed) {
        match queue.recv() {
            Ok(packets) => {
                for pkt in packets {
                    if let Err(e) = strategies::process_packet(
                        engine,
                        queue,
                        raw_socket,
                        pkt.id,
                        &pkt.payload,
                        direction,
                    ) {
                        warn!(
                            dir = dir_name,
                            id = pkt.id,
                            "packet processing error: {}",
                            e
                        );
                        METRICS.queue_errors.fetch_add(1, Ordering::Relaxed);
                        METRICS
                            .last_error_ms
                            .store(cachydpi::metrics::epoch_ms(), Ordering::Relaxed);
                        // On error, try to accept the packet to avoid blocking
                        let _ = queue.verdict_accept(pkt.id);
                    }
                }
            }
            Err(e) => {
                if SHUTDOWN.load(Ordering::Relaxed) {
                    break;
                }
                // ENOBUFS is normal under load — kernel drops packets from queue
                let is_enobufs = e.to_string().contains("No buffer space");
                if is_enobufs {
                    METRICS.queue_errors.fetch_add(1, Ordering::Relaxed);
                    warn!(
                        dir = dir_name,
                        "nfqueue buffer overrun (ENOBUFS) — consider increasing queue length"
                    );
                } else {
                    METRICS.queue_errors.fetch_add(1, Ordering::Relaxed);
                    METRICS
                        .last_error_ms
                        .store(cachydpi::metrics::epoch_ms(), Ordering::Relaxed);
                    error!(dir = dir_name, "nfqueue recv error: {}", e);
                }
            }
        }
    }
}

/// Handle subcommands (install-rules, remove-rules, status, detect, settings)
fn handle_command(cmd: &Commands, config: &Config, config_path: &std::path::Path) -> Result<()> {
    match cmd {
        Commands::InstallRules => {
            let mut rules = NftRules::new(config.general.queue_num, config.general.ipv6);
            rules.install()?;
            // Don't remove on drop — the user wants them to persist
            rules.set_persistent();
            println!(
                "nftables rules installed (queue={})",
                config.general.queue_num
            );
            Ok(())
        }
        Commands::RemoveRules => {
            let mut rules = NftRules::new(config.general.queue_num, config.general.ipv6);
            rules.remove()?;
            println!("nftables rules removed");
            Ok(())
        }
        Commands::Status => {
            println!("CachyDPI v{}", cachydpi::VERSION);
            println!("Config: {:?}", config.general);
            // Check if systemd service is running
            let output = std::process::Command::new("systemctl")
                .args(["is-active", "cachydpi"])
                .output();
            match output {
                Ok(o) => {
                    let status = String::from_utf8_lossy(&o.stdout);
                    println!("Service: {}", status.trim());
                }
                Err(_) => println!("Service: unknown (systemctl not available)"),
            }
            Ok(())
        }
        Commands::Detect { domain } => {
            println!("Running DPI detection against {}...", domain);
            let result = cachydpi::dpi_detect::detect_dpi(domain)?;
            println!("\n── DPI Detection Results ──");
            println!("DPI Type:           {:?}", result.dpi_type);
            println!("RST Injection:      {}", result.rst_injection);
            println!("Redirect Injection: {}", result.redirect_injection);
            println!("Estimated TTL:      {:?}", result.dpi_ttl);
            println!("ISP Hint:           {:?}", result.isp_hint);
            println!("Recommended Mode:   -m {}", result.recommended_mode);
            Ok(())
        }
        Commands::Monitor { socket } => {
            // Build args for cachydpi-monitor binary
            let exe = std::env::current_exe().unwrap_or_default();
            let monitor_path = exe.with_file_name("cachydpi-monitor");

            // Check if monitor binary exists next to us
            let program = if monitor_path.exists() {
                monitor_path
            } else {
                // Fall back to PATH lookup
                std::path::PathBuf::from("cachydpi-monitor")
            };

            let mut cmd = std::process::Command::new(&program);
            if let Some(sock) = socket {
                cmd.arg(sock);
            }

            let status = cmd.status().with_context(|| {
                format!(
                    "failed to run {:?} — is cachydpi-monitor installed?",
                    program
                )
            })?;

            std::process::exit(status.code().unwrap_or(1));
        }
        Commands::Restart => {
            println!("Restarting CachyDPI service...");
            let status = std::process::Command::new("systemctl")
                .args(["restart", "cachydpi"])
                .status()
                .context("failed to run systemctl — is systemd available?")?;

            if status.success() {
                println!("CachyDPI restarted successfully");
            } else {
                anyhow::bail!("systemctl restart failed (exit code: {:?})", status.code());
            }
            Ok(())
        }
        Commands::Settings => settings::run_settings(config, config_path),
        Commands::Helix => {
            print!("{}", cachydpi::helix::render());
            Ok(())
        }
    }
}

/// Set up signal handlers for graceful shutdown
fn setup_signal_handlers() -> Result<()> {
    // Use a dedicated thread for signal handling
    std::thread::Builder::new()
        .name("cachydpi-sig".to_string())
        .spawn(move || {
            let mut signals = signal_hook::iterator::Signals::new([
                signal_hook::consts::SIGINT,
                signal_hook::consts::SIGTERM,
            ])
            .expect("failed to register signal handlers");

            for sig in signals.forever() {
                info!(signal = sig, "received signal");
                SHUTDOWN.store(true, Ordering::Relaxed);
            }
        })
        .context("failed to spawn signal handler thread")?;

    Ok(())
}
