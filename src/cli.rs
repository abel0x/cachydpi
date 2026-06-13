// src/cli.rs — Command-line interface
//
// Provides GoodbyeDPI-compatible CLI modes (-1 through -6) plus
// CachyOS-specific options.

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// CachyDPI — System-wide DPI bypass tool for CachyOS Linux
///
/// A native Linux implementation of GoodbyeDPI, optimized for
/// CachyOS with linux-cachyos kernels.
#[derive(Parser, Debug)]
#[command(name = "cachydpi", version, about, long_about = None)]
pub struct Cli {
    /// DPI bypass mode (1-7), overrides config.toml [general] mode:
    ///   1 = Passive only (drop forged RST/302)
    ///   2 = HTTP request fragmentation
    ///   3 = TLS ClientHello SNI fragmentation
    ///   4 = Fake packet injection (wrong TTL)
    ///   5 = All active techniques combined
    ///   6 = Aggressive (all + QUIC desync)
    ///   7 = Auto-detect — NOT IMPLEMENTED, currently behaves like mode 5
    ///
    /// When unset, the value from config.toml (or the built-in default) is used.
    #[arg(short = 'm', long, value_parser = clap::value_parser!(u8).range(1..=7))]
    pub mode: Option<u8>,

    /// Config file path
    #[arg(short, long, default_value = "/etc/cachydpi/config.toml")]
    pub config: PathBuf,

    /// NFQUEUE number (must match nftables rules).
    /// When unset, the value from config.toml (or the built-in default) is used.
    #[arg(short = 'q', long, value_parser = clap::value_parser!(u16).range(0..=65534))]
    pub queue_num: Option<u16>,

    /// Enable IPv6 support (overrides config.toml). Use --no-ipv6 to disable.
    #[arg(long)]
    pub ipv6: bool,

    /// Disable IPv6 support (overrides config.toml).
    #[arg(long = "no-ipv6", conflicts_with = "ipv6")]
    pub no_ipv6: bool,

    /// Set fake packet TTL (0 = auto-detect)
    #[arg(long, default_value_t = 0)]
    pub set_ttl: u8,

    /// Enable auto TTL detection
    #[arg(long)]
    pub auto_ttl: bool,

    /// TCP window size for SYN packets (0 = disabled)
    #[arg(short = 'w', long, default_value_t = 0)]
    pub window_size: u16,

    /// Enable wrong checksum fake packets
    #[arg(long)]
    pub wrong_chksum: bool,

    /// Enable wrong SEQ number fake packets
    #[arg(long)]
    pub wrong_seq: bool,

    /// HTTP split position (0 = auto)
    #[arg(long, default_value_t = 0)]
    pub http_split: usize,

    /// TLS split position (0 = auto, split at SNI)
    #[arg(long, default_value_t = 0)]
    pub tls_split: usize,

    /// Domain blacklist file (one domain per line)
    #[arg(long)]
    pub blacklist: Option<PathBuf>,

    /// Domain whitelist file (only process these domains)
    #[arg(long)]
    pub whitelist: Option<PathBuf>,

    /// Verbose logging level (-v, -vv, -vvv)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Log to file instead of journald
    #[arg(long)]
    pub log_file: Option<PathBuf>,

    /// Don't install/remove nftables rules automatically
    #[arg(long)]
    pub no_rules: bool,

    /// Run in foreground (don't daemonize)
    #[arg(long)]
    pub foreground: bool,

    /// Dry run: show what would be done without actually processing
    #[arg(long)]
    pub dry_run: bool,

    /// Disable desync-first strategy (fake RST + fake ClientHello before real data)
    #[arg(long)]
    pub no_desync: bool,

    /// Disable disorder (out-of-order fragment delivery)
    #[arg(long)]
    pub no_disorder: bool,

    /// Disable multi-fragment splitting (use 2 fragments instead of 3)
    #[arg(long)]
    pub no_multi_frag: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Install nftables rules and exit
    InstallRules,
    /// Remove nftables rules and exit
    RemoveRules,
    /// Show current status
    Status,
    /// Run DPI fingerprint detection
    Detect {
        /// Target domain to test
        #[arg(default_value = "www.youtube.com")]
        domain: String,
    },
    /// Open real-time performance monitor TUI
    Monitor {
        /// Unix socket path (auto-detected if omitted)
        #[arg(long)]
        socket: Option<String>,
    },
    /// Restart the CachyDPI systemd service
    Restart,
    /// Interactively configure the domain filter mode (list / all)
    Settings,
    // Not advertised in help, the README, or mode_description.
    #[command(hide = true)]
    Helix,
}

impl Cli {
    /// Human-readable description of a bypass mode number.
    pub fn mode_description(mode: u8) -> &'static str {
        match mode {
            1 => "Passive: drop forged RST/302",
            2 => "HTTP request fragmentation",
            3 => "TLS ClientHello SNI fragmentation",
            4 => "Fake packet injection",
            5 => "All active techniques",
            6 => "Aggressive (all + QUIC)",
            7 => "Auto-detect (not implemented — same as mode 5)",
            _ => "Unknown",
        }
    }

    /// Resolve the IPv6 override expressed by `--ipv6` / `--no-ipv6`.
    ///
    /// `None` means neither flag was given, so config.toml (or the built-in
    /// default) decides. Precedence: explicit CLI flag > config.toml > default.
    pub fn ipv6_override(&self) -> Option<bool> {
        if self.no_ipv6 {
            Some(false)
        } else if self.ipv6 {
            Some(true)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    fn parse(args: &[&str]) -> Cli {
        Cli::parse_from(std::iter::once("cachydpi").chain(args.iter().copied()))
    }

    #[test]
    fn mode_and_queue_are_none_when_not_passed() {
        let cli = parse(&[]);
        assert_eq!(cli.mode, None);
        assert_eq!(cli.queue_num, None);
    }

    #[test]
    fn explicit_mode_and_queue_parse() {
        let cli = parse(&["-m", "6", "-q", "250"]);
        assert_eq!(cli.mode, Some(6));
        assert_eq!(cli.queue_num, Some(250));
    }

    #[test]
    fn ipv6_override_tri_state() {
        assert_eq!(parse(&[]).ipv6_override(), None);
        assert_eq!(parse(&["--ipv6"]).ipv6_override(), Some(true));
        assert_eq!(parse(&["--no-ipv6"]).ipv6_override(), Some(false));
    }

    #[test]
    fn ipv6_and_no_ipv6_conflict() {
        // Passing both contradictory flags must be rejected by clap.
        assert!(Cli::try_parse_from(["cachydpi", "--ipv6", "--no-ipv6"]).is_err());
    }

    #[test]
    fn mode_description_marks_mode7_unimplemented() {
        let desc = Cli::mode_description(7);
        assert!(
            desc.contains("not implemented"),
            "mode 7 description must admit it is unimplemented, got: {desc:?}"
        );
    }

    #[test]
    fn hidden_subcommand_still_parses() {
        let cli = parse(&["helix"]);
        assert!(matches!(cli.command, Some(Commands::Helix)));
    }

    #[test]
    fn hidden_subcommand_absent_from_help() {
        use clap::CommandFactory;
        let help = Cli::command().render_long_help().to_string();
        assert!(
            !help.to_lowercase().contains("helix"),
            "hidden subcommand leaked into help output"
        );
    }
}
