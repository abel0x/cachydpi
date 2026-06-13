// src/config.rs — Configuration management
//
// Loads configuration from /etc/cachydpi/config.toml with sensible
// defaults. CLI arguments override config file values.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// Main configuration structure
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// General settings
    pub general: GeneralConfig,
    /// DPI bypass strategy settings
    pub strategies: StrategyConfig,
    /// Domain filtering
    pub domains: DomainConfig,
    /// Logging configuration
    pub logging: LogConfig,
    /// Compiled domain set for O(1) lookup (not serialized)
    #[serde(skip)]
    pub domain_set: HashSet<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GeneralConfig {
    /// NFQUEUE number
    pub queue_num: u16,
    /// Enable IPv6 support
    pub ipv6: bool,
    /// Automatically install/remove nftables rules
    pub manage_rules: bool,
    /// Bypass mode (1-7)
    pub mode: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StrategyConfig {
    /// Enable passive DPI detection (drop forged RST/302)
    pub passive_dpi: bool,
    /// TCP window size for SYN packets (0 = disabled)
    pub tcp_window_size: u16,
    /// HTTP request split position (0 = auto)
    pub http_split_position: usize,
    /// TLS ClientHello split position (0 = auto, split at SNI)
    pub tls_split_position: usize,
    /// Enable fake packet injection
    pub fake_packet_enabled: bool,
    /// TTL for fake packets (0 = auto)
    pub fake_packet_ttl: u8,
    /// Enable auto TTL detection
    pub auto_ttl: bool,
    /// Send fake packets with wrong TCP checksum
    pub fake_wrong_checksum: bool,
    /// Send fake packets with wrong TCP sequence number
    pub fake_wrong_seq: bool,
    /// Enable QUIC desynchronization
    pub quic_desync: bool,
    /// Desync-first: send fake RST + fake ClientHello (with harmless SNI) before
    /// real ClientHello fragments.  Disabled by default because many ISP DPIs
    /// interpret the fake RST as a real connection close and DROP all subsequent
    /// traffic on the 5-tuple, breaking the connection entirely.
    /// Enable only if your ISP's DPI ignores RSTs on established connections.
    pub desync_first: bool,
    /// Multi-fragment: split TLS ClientHello into 3+ TCP segments instead of 2.
    /// Splits at 1-2 bytes into SNI name, making DPI pattern matching much harder.
    pub multi_fragment: bool,
    /// Disorder: send TLS fragments in reverse order (frag3 → frag2 → frag1).
    /// Forces DPI to perform out-of-order TCP reassembly, which many DPI handle poorly.
    pub disorder: bool,
}

/// Domain filtering mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DomainMode {
    #[default]
    None,
    Blacklist,
    Whitelist,
}

impl std::fmt::Display for DomainMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DomainMode::None => write!(f, "none"),
            DomainMode::Blacklist => write!(f, "blacklist"),
            DomainMode::Whitelist => write!(f, "whitelist"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DomainConfig {
    /// Mode: none, blacklist, or whitelist
    pub mode: DomainMode,
    /// Path to blacklist file
    pub blacklist_file: Option<String>,
    /// Path to whitelist file
    pub whitelist_file: Option<String>,
    /// Inline blacklist domains
    pub blacklist: Vec<String>,
    /// Inline whitelist domains
    pub whitelist: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LogConfig {
    /// Log level: "error", "warn", "info", "debug", "trace"
    pub level: String,
    /// Log to journald
    pub journald: bool,
    /// Optional log file path
    pub file: Option<String>,
}

// ── Default implementations ──

impl Default for GeneralConfig {
    fn default() -> Self {
        GeneralConfig {
            queue_num: 200,
            ipv6: true,
            manage_rules: true,
            mode: 5,
        }
    }
}

impl Default for StrategyConfig {
    fn default() -> Self {
        StrategyConfig {
            passive_dpi: true,
            tcp_window_size: 0,
            http_split_position: 0,
            tls_split_position: 0,
            fake_packet_enabled: false,
            fake_packet_ttl: 0,
            auto_ttl: true,
            fake_wrong_checksum: false,
            fake_wrong_seq: false,
            quic_desync: false,
            desync_first: false,
            multi_fragment: true,
            disorder: true,
        }
    }
}

impl Default for DomainConfig {
    fn default() -> Self {
        DomainConfig {
            mode: DomainMode::None,
            blacklist_file: None,
            whitelist_file: None,
            blacklist: Vec::new(),
            whitelist: Vec::new(),
        }
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        LogConfig {
            level: "info".to_string(),
            journald: true,
            file: None,
        }
    }
}

impl Config {
    /// Load configuration from a TOML file.
    /// Falls back to defaults if file doesn't exist.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            info!(
                "config file not found at {}, using defaults",
                path.display()
            );
            return Ok(Config::default());
        }

        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read config file: {}", path.display()))?;

        let config: Config = toml::from_str(&content)
            .with_context(|| format!("failed to parse config file: {}", path.display()))?;

        debug!("loaded config from {}", path.display());
        Ok(config)
    }

    /// Apply CLI overrides to the config.
    ///
    /// Precedence for mode / queue_num / ipv6: an explicitly-passed CLI flag
    /// wins, otherwise the config.toml value is kept, otherwise the built-in
    /// default. A CLI flag that was not given must NOT clobber config.toml —
    /// that is what made `[general]` settings dead when the service ran
    /// without flags.
    pub fn apply_cli_overrides(&mut self, cli: &crate::cli::Cli) {
        if let Some(mode) = cli.mode {
            self.general.mode = mode;
        }
        if let Some(queue_num) = cli.queue_num {
            self.general.queue_num = queue_num;
        }
        if let Some(ipv6) = cli.ipv6_override() {
            self.general.ipv6 = ipv6;
        }

        if cli.no_rules {
            self.general.manage_rules = false;
        }

        if cli.set_ttl > 0 {
            self.strategies.fake_packet_ttl = cli.set_ttl;
            self.strategies.auto_ttl = false;
        }

        if cli.auto_ttl {
            self.strategies.auto_ttl = true;
        }

        if cli.window_size > 0 {
            self.strategies.tcp_window_size = cli.window_size;
        }

        if cli.wrong_chksum {
            self.strategies.fake_wrong_checksum = true;
        }

        if cli.wrong_seq {
            self.strategies.fake_wrong_seq = true;
        }

        if cli.http_split > 0 {
            self.strategies.http_split_position = cli.http_split;
        }

        if cli.tls_split > 0 {
            self.strategies.tls_split_position = cli.tls_split;
        }

        // Desync/disorder/multi-fragment CLI overrides
        if cli.no_desync {
            self.strategies.desync_first = false;
        }
        if cli.no_disorder {
            self.strategies.disorder = false;
        }
        if cli.no_multi_frag {
            self.strategies.multi_fragment = false;
        }

        if let Some(ref blacklist) = cli.blacklist {
            self.domains.mode = DomainMode::Blacklist;
            self.domains.blacklist_file = Some(blacklist.to_string_lossy().to_string());
        }

        if let Some(ref whitelist) = cli.whitelist {
            self.domains.mode = DomainMode::Whitelist;
            self.domains.whitelist_file = Some(whitelist.to_string_lossy().to_string());
        }

        // Apply verbose logging
        match cli.verbose {
            0 => {} // Keep config default
            1 => self.logging.level = "debug".to_string(),
            _ => self.logging.level = "trace".to_string(),
        }
    }

    /// Load domain lists from external files (blacklist_file / whitelist_file).
    /// Merges file contents into the inline blacklist/whitelist vectors,
    /// then builds a HashSet for O(1) lookup.
    pub fn load_domain_lists(&mut self) -> Result<()> {
        if let Some(ref path) = self.domains.blacklist_file {
            if !Self::is_safe_domain_path(path) {
                warn!(
                    "blacklist path rejected (must be under /etc/cachydpi/ or /usr/share/cachydpi/): {}",
                    path
                );
            } else {
                let p = Path::new(path);
                if p.exists() {
                    let content = fs::read_to_string(p)
                        .with_context(|| format!("failed to read blacklist file: {}", path))?;
                    let count_before = self.domains.blacklist.len();
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if !trimmed.is_empty() && !trimmed.starts_with('#') {
                            self.domains.blacklist.push(trimmed.to_lowercase());
                        }
                    }
                    info!(
                        file = path.as_str(),
                        domains = self.domains.blacklist.len() - count_before,
                        "loaded blacklist file"
                    );
                } else {
                    debug!("blacklist file not found: {}", path);
                }
            }
        }

        if let Some(ref path) = self.domains.whitelist_file {
            if !Self::is_safe_domain_path(path) {
                warn!(
                    "whitelist path rejected (must be under /etc/cachydpi/ or /usr/share/cachydpi/): {}",
                    path
                );
            } else {
                let p = Path::new(path);
                if p.exists() {
                    let content = fs::read_to_string(p)
                        .with_context(|| format!("failed to read whitelist file: {}", path))?;
                    let count_before = self.domains.whitelist.len();
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if !trimmed.is_empty() && !trimmed.starts_with('#') {
                            self.domains.whitelist.push(trimmed.to_lowercase());
                        }
                    }
                    info!(
                        file = path.as_str(),
                        domains = self.domains.whitelist.len() - count_before,
                        "loaded whitelist file"
                    );
                } else {
                    debug!("whitelist file not found: {}", path);
                }
            }
        }

        // Build the HashSet for fast lookup
        let list = match self.domains.mode {
            DomainMode::Blacklist => &self.domains.blacklist,
            DomainMode::Whitelist => &self.domains.whitelist,
            DomainMode::None => return Ok(()),
        };
        self.domain_set = list.iter().map(|d| d.to_lowercase()).collect();
        info!(domains = self.domain_set.len(), mode = %self.domains.mode, "domain filter ready");

        Ok(())
    }

    /// Check whether DPI bypass should be applied to `domain`.
    ///
    /// The two list modes are genuine opposites:
    /// - `Blacklist`: the listed domains are the ISP-blocked sites we want to
    ///   rescue — apply the bypass ONLY to them. This is the shipped default,
    ///   paired with blacklist.txt.
    /// - `Whitelist`: the listed domains are trusted/excepted — apply the
    ///   bypass to everything EXCEPT them.
    /// - `None`: apply the bypass to every domain.
    pub fn should_process_domain(&self, domain: &str) -> bool {
        match self.domains.mode {
            DomainMode::Blacklist => self.domain_in_set(domain),
            DomainMode::Whitelist => !self.domain_in_set(domain),
            DomainMode::None => true,
        }
    }

    fn domain_in_set(&self, domain: &str) -> bool {
        // Domain is already lowercased by TLS/HTTP parsers
        // Exact match (O(1))
        if self.domain_set.contains(domain) {
            return true;
        }

        // Subdomain match: check each parent domain
        // e.g., for "a.b.example.com" check "b.example.com", "example.com", "com"
        let mut pos = 0;
        while let Some(dot) = domain[pos..].find('.') {
            pos += dot + 1;
            if self.domain_set.contains(&domain[pos..]) {
                return true;
            }
        }

        false
    }

    /// Validate that a domain list file path is under an allowed directory.
    /// Prevents reading arbitrary files when running as root.
    fn is_safe_domain_path(path: &str) -> bool {
        let p = Path::new(path);

        // First check: literal path must be under allowed directories
        // (prevents ../ traversal in the path itself)
        if !p.starts_with("/etc/cachydpi") && !p.starts_with("/usr/share/cachydpi") {
            return false;
        }

        // Second check: if the file exists, canonicalize to resolve symlinks
        // This catches symlinks that point outside allowed directories
        if p.exists() {
            match p.canonicalize() {
                Ok(canonical) => {
                    return canonical.starts_with("/etc/cachydpi")
                        || canonical.starts_with("/usr/share/cachydpi");
                }
                Err(_) => return false,
            }
        }

        true
    }
}

#[cfg(test)]
mod override_tests {
    use super::*;
    use crate::cli::Cli;
    use clap::Parser;

    fn cli(args: &[&str]) -> Cli {
        Cli::parse_from(std::iter::once("cachydpi").chain(args.iter().copied()))
    }

    /// Precedence rung 1: an explicitly-passed CLI flag wins over config.toml.
    #[test]
    fn explicit_cli_flag_overrides_config() {
        let mut config = Config::default();
        config.general.mode = 3;
        config.general.queue_num = 111;
        config.general.ipv6 = false;

        config.apply_cli_overrides(&cli(&["-m", "6", "-q", "250", "--ipv6"]));

        assert_eq!(config.general.mode, 6);
        assert_eq!(config.general.queue_num, 250);
        assert!(config.general.ipv6);
    }

    /// Precedence rung 2: with no CLI flags, config.toml values survive.
    /// They used to be clobbered by the always-applied CLI defaults.
    #[test]
    fn config_values_survive_when_no_cli_flag() {
        let mut config = Config::default();
        config.general.mode = 3;
        config.general.queue_num = 111;
        config.general.ipv6 = false;

        config.apply_cli_overrides(&cli(&[]));

        assert_eq!(config.general.mode, 3);
        assert_eq!(config.general.queue_num, 111);
        assert!(!config.general.ipv6);
    }

    /// Precedence rung 3: built-in defaults apply when neither CLI nor config
    /// override them.
    #[test]
    fn builtin_defaults_when_nothing_set() {
        let mut config = Config::default();
        config.apply_cli_overrides(&cli(&[]));
        assert_eq!(config.general.mode, 5);
        assert_eq!(config.general.queue_num, 200);
        assert!(config.general.ipv6);
    }

    /// IPv6 can now be turned off from the CLI via `--no-ipv6` (was impossible).
    #[test]
    fn no_ipv6_flag_disables_ipv6() {
        let mut config = Config::default(); // ipv6 = true
        assert!(config.general.ipv6);
        config.apply_cli_overrides(&cli(&["--no-ipv6"]));
        assert!(!config.general.ipv6);
    }

    /// IPv6 can be turned off from config.toml and a flagless run keeps it off.
    #[test]
    fn config_can_disable_ipv6() {
        let mut config = Config::default();
        config.general.ipv6 = false;
        config.apply_cli_overrides(&cli(&[]));
        assert!(!config.general.ipv6);
    }
}
