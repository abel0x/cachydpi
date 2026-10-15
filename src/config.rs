// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/config.rs — Configuration management
//
// Loads configuration from /etc/cachydpi/config.toml with sensible
// defaults. CLI arguments override config file values.

use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

/// Main configuration structure
///
/// Every section defaults except `[domains]`, which is required on purpose.
/// A config truncated part-way through — the most likely way one gets damaged —
/// stays valid TOML and simply loses its later sections, so a defaulted
/// `[domains]` would silently replace the operator's domain filter with a
/// built-in one. Requiring the section turns all of those into one clear
/// deserialization error instead.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Config {
    /// General settings
    #[serde(default)]
    pub general: GeneralConfig,
    /// DPI bypass strategy settings
    #[serde(default)]
    pub strategies: StrategyConfig,
    /// Domain filtering — required, see above
    pub domains: DomainConfig,
    /// Logging configuration
    #[serde(default)]
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
///
/// The default is deliberately `Blacklist`, the most restrictive mode: with no
/// list loaded it bypasses nothing. `None` bypasses *every* site, so it must
/// only ever be reached by an explicit `mode = "none"` in the config — never by
/// falling back. Do not make `None` the default again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DomainMode {
    None,
    #[default]
    Blacklist,
    /// Exemption list: the listed domains are left alone and everything else
    /// gets the bypass.
    ///
    /// Spelled `whitelist` before 1.1.0, which described the opposite of what
    /// it does — a whitelist reads as "only these", so an operator writing
    /// `mode = "whitelist"` with a short list would expect a narrow bypass and
    /// get the widest one. The old spelling is refused since 1.2.0.
    #[serde(rename = "exempt")]
    Exempt,
}

impl std::fmt::Display for DomainMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DomainMode::None => write!(f, "none"),
            DomainMode::Blacklist => write!(f, "blacklist"),
            DomainMode::Exempt => write!(f, "exempt"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainConfig {
    /// Mode: none, blacklist, or exempt.
    ///
    /// Required rather than defaulted: which traffic gets rewritten is the
    /// security-relevant decision in this file, so it has to be stated, not
    /// inferred from a half-written config.
    pub mode: DomainMode,
    /// Path to blacklist file
    #[serde(default)]
    pub blacklist_file: Option<String>,
    /// Path to the exemption list
    #[serde(default)]
    pub exempt_file: Option<String>,
    /// Inline blacklist domains
    #[serde(default)]
    pub blacklist: Vec<String>,
    /// Inline exempt domains
    #[serde(default)]
    pub exempt: Vec<String>,
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
    /// Log the values that say where the user is connecting: the domain or SNI
    /// being processed, and peer addresses.
    ///
    /// Off by default and deliberately independent of the log level. Raising
    /// the level is an ordinary troubleshooting step and must not have "starts
    /// recording browsing history" as a side effect — on a persistent journal
    /// those fields are a lasting record of every site visited. With this off
    /// the fields are still emitted, carrying `<redacted>`, so the shape of the
    /// log does not change.
    pub log_identifying_fields: bool,
    /// Write intercepted packet contents to the log at TRACE level.
    ///
    /// Off by default and deliberately separate from the log level: the dump
    /// contains the TLS ClientHello, so it records the SNI of every site
    /// visited, alongside source and destination addresses. On a persistent
    /// journal that is a lasting history of browsing, produced by a tool whose
    /// purpose is to keep exactly that off the wire. Only turn it on to debug
    /// packet construction, and only for as long as that takes.
    pub log_packet_bytes: bool,
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
            // Restrictive by default — see DomainMode.
            mode: DomainMode::Blacklist,
            blacklist_file: None,
            exempt_file: None,
            blacklist: Vec::new(),
            exempt: Vec::new(),
        }
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        LogConfig {
            level: "info".to_string(),
            journald: true,
            file: None,
            log_identifying_fields: false,
            log_packet_bytes: false,
        }
    }
}

/// Release that removed the `whitelist` spelling, quoted in the refusal.
const WHITELIST_REMOVED_IN: &str = "1.2.0";

/// Whether a config still spells the exemption list the pre-1.1.0 way.
///
/// Checked on the raw text before parsing: with the aliases gone, serde would
/// otherwise report only an unknown variant or field, and say nothing of what
/// it became.
fn config_uses_removed_whitelist_spelling(content: &str) -> bool {
    content.lines().any(|line| {
        let line = line.trim();
        if line.starts_with('#') {
            return false;
        }
        line.contains("whitelist_file")
            || line.starts_with("whitelist")
            || (line.starts_with("mode") && line.contains("\"whitelist\""))
    })
}

impl Config {
    /// Load configuration from a TOML file.
    /// Falls back to defaults if file doesn't exist.
    /// Load configuration from a TOML file.
    ///
    /// Exactly one failure mode is tolerated: the file being absent, which is a
    /// normal first install and yields the (restrictive) built-in defaults.
    /// Every other outcome is an error, because substituting defaults for a
    /// config that exists but could not be honoured silently changes the domain
    /// filter — and the defaults must never be reached by accident.
    ///
    /// `fs::read_to_string` is used to probe for the file instead of
    /// `Path::exists()`, which also answers "false" when the file is there but
    /// the directory is not searchable — that would turn a permission problem
    /// into a silent fallback.
    pub fn load(path: &Path) -> Result<Self> {
        let content = match fs::read_to_string(path) {
            Ok(content) => content,
            // Only a genuinely absent file may fall back. This arm is a
            // whitelist of exactly one error kind; everything else — EACCES,
            // ENOTDIR, EIO — lands below and is fatal.
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                // A dangling symlink reports NotFound too, but the path is
                // there and the installation is broken, which is not the same
                // as never having been configured.
                if fs::symlink_metadata(path).is_ok() {
                    bail!(
                        "config path {} exists but does not resolve (dangling symlink?) — \
                         fix the link or remove it to start from built-in defaults",
                        path.display()
                    );
                }
                info!(
                    "config file not found at {}, using defaults",
                    path.display()
                );
                return Ok(Config::default());
            }
            Err(e) => {
                return Err(e).with_context(|| {
                    format!(
                        "cannot read config file {} — check that it exists and is readable \
                         by the cachydpi user",
                        path.display()
                    )
                });
            }
        };

        // Required fields already reject an empty file (`[domains]` would be
        // missing), but "missing field `domains`" is a poor description of a
        // truncated write. Keep the dedicated check purely for the message.
        if content.trim().is_empty() {
            bail!(
                "config file {} is empty — it was probably truncated by an interrupted \
                 write; restore it from /usr/share/doc/cachydpi/, or delete it to start \
                 from built-in defaults",
                path.display()
            );
        }

        if config_uses_removed_whitelist_spelling(&content) {
            bail!(
                "config file {} uses \"whitelist\", which was renamed to \"exempt\" in 1.1.0 \
                 and removed in {} — rename mode = \"whitelist\" to mode = \"exempt\", \
                 whitelist_file to exempt_file, and whitelist to exempt. The listed domains \
                 are the ones left alone; it never meant \"bypass only these\"",
                path.display(),
                WHITELIST_REMOVED_IN
            );
        }

        let config: Config = toml::from_str(&content).with_context(|| {
            format!(
                "config file {} is not valid — the daemon will not start with settings it \
                 cannot honour; fix the reported field, or move the file aside to fall \
                 back to built-in defaults (mv {} {}.bad)",
                path.display(),
                path.display(),
                path.display()
            )
        })?;

        debug!("loaded config from {}", path.display());
        Ok(config)
    }

    /// Validate configuration invariants that serde/toml cannot express.
    ///
    /// The CLI parser bounds `queue_num` to `0..=65534`, but values read from
    /// config.toml bypass that check. Enforce the same bound here: the inbound
    /// NFQUEUE uses `queue_num + 1`, which for 65535 would wrap past `u16` and
    /// silently queue inbound traffic to queue 0.
    pub fn validate(&self) -> Result<()> {
        if self.general.queue_num > 65534 {
            anyhow::bail!(
                "general.queue_num must be <= 65534 (got {}) — the inbound NFQUEUE uses queue_num + 1",
                self.general.queue_num
            );
        }
        Ok(())
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

        if let Some(ref exempt) = cli.exempt {
            self.domains.mode = DomainMode::Exempt;
            self.domains.exempt_file = Some(exempt.to_string_lossy().to_string());
        }

        // Apply verbose logging
        match cli.verbose {
            0 => {} // Keep config default
            1 => self.logging.level = "debug".to_string(),
            _ => self.logging.level = "trace".to_string(),
        }
    }

    /// Load domain lists from external files (blacklist_file / exempt_file).
    /// Merges file contents into the inline blacklist/exempt vectors,
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

        if let Some(ref path) = self.domains.exempt_file {
            if !Self::is_safe_domain_path(path) {
                warn!(
                    "exempt list path rejected (must be under /etc/cachydpi/ or /usr/share/cachydpi/): {}",
                    path
                );
            } else {
                let p = Path::new(path);
                if p.exists() {
                    let content = fs::read_to_string(p)
                        .with_context(|| format!("failed to read exempt list file: {}", path))?;
                    let count_before = self.domains.exempt.len();
                    for line in content.lines() {
                        let trimmed = line.trim();
                        if !trimmed.is_empty() && !trimmed.starts_with('#') {
                            self.domains.exempt.push(trimmed.to_lowercase());
                        }
                    }
                    info!(
                        file = path.as_str(),
                        domains = self.domains.exempt.len() - count_before,
                        "loaded exempt list file"
                    );
                } else {
                    debug!("exempt list file not found: {}", path);
                }
            }
        }

        // Build the HashSet for fast lookup
        let list = match self.domains.mode {
            DomainMode::Blacklist => &self.domains.blacklist,
            DomainMode::Exempt => &self.domains.exempt,
            DomainMode::None => return Ok(()),
        };
        self.domain_set = list.iter().map(|d| d.to_lowercase()).collect();
        info!(domains = self.domain_set.len(), mode = %self.domains.mode, "domain filter ready");

        if self.domain_set.is_empty() && self.domain_filter_is_used() {
            match self.domains.mode {
                // Nothing listed to rescue means no active technique ever
                // fires: the sites the operator installed this to reach stay
                // blocked while the service reports itself healthy. That is
                // indistinguishable from a broken tool, so refuse it the same
                // way an empty exemption list is refused — both are "you chose
                // this mode and did not configure it".
                DomainMode::Blacklist => bail!(
                    "[domains] mode = \"blacklist\" with an empty list would bypass \
                     nothing, so every blocked site stays blocked. Check that the \
                     blacklist file exists and is under /etc/cachydpi/, add domains to \
                     it, or set mode = \"none\" to bypass every site"
                ),
                // Nothing exempted means everything is bypassed, which is
                // exactly mode = "none" — an unconfigured list must not be the
                // way to reach the widest possible bypass.
                DomainMode::Exempt => bail!(
                    "[domains] mode = \"exempt\" with an empty list would bypass every \
                     site, which is what mode = \"none\" means. List the domains to leave \
                     alone, or say mode = \"none\" explicitly if that is the intent"
                ),
                DomainMode::None => {}
            }
        }

        Ok(())
    }

    /// Number of domains in the list that is actually in effect, or `None` when
    /// no list applies — either because the bypass mode never consults one, or
    /// because the domain mode is `none`.
    ///
    /// The distinction matters to anything watching the metrics: reporting 0 for
    /// "no list is used" is indistinguishable from "the list failed to load".
    pub fn active_domain_list_size(&self) -> Option<usize> {
        if !self.domain_filter_is_used() || matches!(self.domains.mode, DomainMode::None) {
            return None;
        }
        Some(self.domain_set.len())
    }

    /// Whether the configured bypass mode ever consults the domain filter.
    ///
    /// Mode 1 is passive-only: outbound packets are accepted whatever the list
    /// says, and the inbound side that drops DPI-forged RSTs, redirects and TLS
    /// alerts never looks at the list at all. An empty list is therefore not a
    /// misconfiguration there, and refusing to start would kill a passive
    /// defence that works perfectly.
    ///
    /// Kept in step with `BypassMode::from_mode_number` by
    /// `passive_is_the_only_mode_without_the_domain_filter`.
    fn domain_filter_is_used(&self) -> bool {
        self.general.mode != 1
    }

    /// Check whether DPI bypass should be applied to `domain`.
    ///
    /// The two list modes are genuine opposites:
    /// - `Blacklist`: the listed domains are the ISP-blocked sites we want to
    ///   rescue — apply the bypass ONLY to them. This is the shipped default,
    ///   paired with blacklist.txt.
    /// - `Exempt`: the listed domains are left alone — apply the bypass to
    ///   everything EXCEPT them.
    /// - `None`: apply the bypass to every domain.
    pub fn should_process_domain(&self, domain: &str) -> bool {
        match self.domains.mode {
            DomainMode::Blacklist => self.domain_in_set(domain),
            DomainMode::Exempt => !self.domain_in_set(domain),
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
mod load_tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    /// Case 1 of 4: the file is genuinely absent (first install). This is the
    /// only tolerated failure, and the defaults it yields must be restrictive.
    #[test]
    fn missing_config_falls_back_to_restrictive_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.toml");

        let config = Config::load(&path).expect("a missing config is not an error");
        assert_eq!(
            config.domains.mode,
            DomainMode::Blacklist,
            "fallback defaults must not bypass every site"
        );
    }

    /// Case 2 of 4: the file exists but cannot be read. Must be fatal — an
    /// unreadable config used to be indistinguishable from a missing one.
    #[test]
    fn unreadable_config_is_a_hard_error() {
        if nix::unistd::geteuid().is_root() {
            eprintln!("skipping: root bypasses file permission checks");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "[domains]\nmode = \"blacklist\"\n").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();

        assert!(
            Config::load(&path).is_err(),
            "an unreadable config must not silently become the defaults"
        );
    }

    /// Case 3 of 4: the file exists but is not valid TOML. Must be fatal.
    #[test]
    fn malformed_config_is_a_hard_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "[domains]\nmode = \"blackl").unwrap();

        assert!(
            Config::load(&path).is_err(),
            "a malformed config must not silently become the defaults"
        );
    }

    /// Case 4 of 4: a truncated (0-byte) file. Empty input is valid TOML and
    /// deserializes into the complete set of defaults without any warning, so
    /// it has to be rejected explicitly.
    #[test]
    fn empty_config_is_a_hard_error() {
        let dir = tempfile::tempdir().unwrap();
        for (name, body) in [("empty", ""), ("whitespace", "\n  \n\t\n")] {
            let path = dir.path().join(format!("{name}.toml"));
            fs::write(&path, body).unwrap();
            assert!(
                Config::load(&path).is_err(),
                "a {name} config must be rejected, not treated as all-defaults"
            );
        }
    }

    /// A config truncated part-way through is still valid TOML — it just loses
    /// its later sections. That is the most likely way one gets damaged, and it
    /// walks straight past an emptiness check, so `[domains]` being required is
    /// what catches it.
    #[test]
    fn truncated_config_is_a_hard_error() {
        let dir = tempfile::tempdir().unwrap();
        // Cut after a complete [general] section: parses fine, no [domains].
        let truncated = "[general]\nqueue_num = 200\nipv6 = true\nmode = 5\n";
        assert!(
            toml::from_str::<toml::Value>(truncated).is_ok(),
            "the fixture must be valid TOML, otherwise it proves nothing"
        );

        let path = dir.path().join("config.toml");
        fs::write(&path, truncated).unwrap();
        assert!(
            Config::load(&path).is_err(),
            "a config truncated before [domains] must not be silently completed"
        );
    }

    /// Whitespace-only and comment-only files are valid TOML with zero keys and
    /// would otherwise deserialize into a full set of defaults.
    #[test]
    fn whitespace_and_comment_only_configs_are_hard_errors() {
        let dir = tempfile::tempdir().unwrap();
        for (name, body) in [
            ("whitespace", "   \n\t\n   \n"),
            ("comments", "# CachyDPI config\n# nothing else survived\n"),
            ("comments-and-blanks", "\n# just a note\n\n   \n"),
        ] {
            let path = dir.path().join(format!("{name}.toml"));
            fs::write(&path, body).unwrap();
            assert!(
                Config::load(&path).is_err(),
                "a {name}-only config must be rejected, not treated as all-defaults"
            );
        }
    }

    /// A `[domains]` section that exists but does not state a mode is just as
    /// under-specified as a missing one.
    #[test]
    fn domains_section_without_mode_is_a_hard_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(
            &path,
            "[domains]\nblacklist_file = \"/etc/cachydpi/blacklist.txt\"\n",
        )
        .unwrap();
        assert!(
            Config::load(&path).is_err(),
            "[domains] without a mode must be rejected"
        );
    }

    /// A dangling symlink reports NotFound like a missing file, but the path is
    /// there and the install is broken — that must not silently use defaults.
    #[test]
    fn dangling_config_symlink_is_a_hard_error() {
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("config.toml");
        std::os::unix::fs::symlink(dir.path().join("gone.toml"), &link).unwrap();

        assert!(
            Config::load(&link).is_err(),
            "a dangling config symlink must not be treated as a fresh install"
        );
    }

    /// The property behind all four cases: no way of loading a config can end
    /// in DomainMode::None (bypass every site) unless the file actually asks
    /// for it. Every input either fails outright or yields a restrictive mode.
    #[test]
    fn no_config_failure_mode_can_reach_god_mode() {
        let dir = tempfile::tempdir().unwrap();

        let mut cases: Vec<(&str, std::path::PathBuf)> = Vec::new();

        let missing = dir.path().join("missing.toml");
        cases.push(("missing file", missing));

        for (name, body) in [
            ("empty file", ""),
            ("whitespace only", "   \n\t\n"),
            ("truncated mid-value", "[domains]\nmode = \"blackl"),
            ("truncated mid-section", "[gene"),
            ("only an unrelated section", "[general]\nmode = 5\n"),
            ("nul bytes", "\0\0\0\0"),
            ("html error page", "<!DOCTYPE html><h1>404</h1>"),
            (
                "domains section without mode",
                "[domains]\nblacklist = []\n",
            ),
        ] {
            let path = dir.path().join(format!("{}.toml", name.replace(' ', "-")));
            fs::write(&path, body).unwrap();
            cases.push((name, path));
        }

        // A file that exists but cannot be read (skipped as root).
        if !nix::unistd::geteuid().is_root() {
            let path = dir.path().join("unreadable.toml");
            let mut f = fs::File::create(&path).unwrap();
            f.write_all(b"[domains]\nmode = \"blacklist\"\n").unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o000)).unwrap();
            cases.push(("unreadable file", path));
        }

        for (name, path) in cases {
            match Config::load(&path) {
                // Hard failure is always an acceptable outcome.
                Err(_) => {}
                // Succeeding is only acceptable with a restrictive filter.
                Ok(config) => assert_ne!(
                    config.domains.mode,
                    DomainMode::None,
                    "loading a config with {name} silently produced god mode"
                ),
            }
        }
    }

    /// Both list modes treat "you chose this mode and did not configure it" the
    /// same way: refuse. One would bypass everything, the other nothing, and
    /// both leave a service that reports itself healthy while not doing the job
    /// it was installed for.
    #[test]
    fn an_unconfigured_list_is_refused_in_both_modes() {
        let dir = tempfile::tempdir().unwrap();

        for mode in ["blacklist", "exempt"] {
            let path = dir.path().join(format!("{mode}.toml"));
            fs::write(&path, format!("[domains]\nmode = \"{mode}\"\n")).unwrap();
            let mut config = Config::load(&path).unwrap();
            assert!(
                config.load_domain_lists().is_err(),
                "an empty {mode} list must be refused rather than started with"
            );
        }
    }

    /// …except in passive-only mode, where the list is never consulted: the
    /// outbound side accepts regardless and the inbound side that drops forged
    /// RSTs does not look at it. Refusing there would stop a working defence.
    #[test]
    fn passive_only_mode_accepts_an_empty_list() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("passive.toml");
        fs::write(
            &path,
            "[general]\nmode = 1\n\n[domains]\nmode = \"blacklist\"\n",
        )
        .unwrap();

        let mut config = Config::load(&path).unwrap();
        config
            .load_domain_lists()
            .expect("passive-only mode does not need a domain list");
    }

    /// The predicate above hard-codes mode 1, so pin the assumption it rests
    /// on: passive is the only mode that applies no active technique.
    #[test]
    fn passive_is_the_only_mode_without_the_domain_filter() {
        use crate::strategies::BypassMode;

        for mode in 1..=7u8 {
            let mut config = Config::default();
            config.general.mode = mode;
            let passive = matches!(BypassMode::from_mode_number(mode), BypassMode::Passive);
            assert_eq!(
                config.domain_filter_is_used(),
                !passive,
                "mode {mode} disagrees with BypassMode about needing the domain filter"
            );
        }
    }

    /// A populated exemption list behaves as its name says: listed domains are
    /// left alone, everything else is processed.
    #[test]
    fn a_populated_exempt_list_leaves_listed_domains_alone() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(
            &path,
            "[domains]\nmode = \"exempt\"\nexempt = [\"safe.com\"]\n",
        )
        .unwrap();

        let mut config = Config::load(&path).unwrap();
        config.load_domain_lists().unwrap();
        assert!(!config.should_process_domain("safe.com"));
        assert!(config.should_process_domain("other.com"));
    }

    /// The pre-1.1.0 spelling is refused with a message that says what it
    /// became, rather than serde's bare "unknown variant".
    #[test]
    fn the_removed_whitelist_spelling_is_refused_with_its_new_name() {
        let dir = tempfile::tempdir().unwrap();
        for old in [
            "[domains]\nmode = \"whitelist\"\nwhitelist = [\"safe.com\"]\n",
            "[domains]\nmode = \"exempt\"\nwhitelist_file = \"/etc/cachydpi/x.txt\"\n",
        ] {
            let path = dir.path().join("config.toml");
            fs::write(&path, old).unwrap();
            let err = format!("{:#}", Config::load(&path).unwrap_err());
            assert!(
                err.contains("exempt") && err.contains(WHITELIST_REMOVED_IN),
                "refusal must name the replacement and the release: {err}"
            );
        }
    }

    /// A comment that mentions the old name is not a use of it.
    #[test]
    fn a_comment_mentioning_whitelist_is_not_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(
            &path,
            "[domains]\n# formerly \"whitelist\"\nmode = \"exempt\"\nexempt = [\"safe.com\"]\n",
        )
        .unwrap();
        let config = Config::load(&path).expect("comments must not trip the check");
        assert_eq!(config.domains.mode, DomainMode::Exempt);
    }

    /// A mode that consults no list must report "no list", not "a list with
    /// nothing in it" — a watcher cannot tell the second from a failed load.
    #[test]
    fn no_list_in_use_is_distinguishable_from_an_empty_list() {
        let dir = tempfile::tempdir().unwrap();

        // mode = "none": no list is consulted at all.
        let none = dir.path().join("none.toml");
        fs::write(&none, "[domains]\nmode = \"none\"\n").unwrap();
        let mut config = Config::load(&none).unwrap();
        config.load_domain_lists().unwrap();
        assert_eq!(config.active_domain_list_size(), None);

        // Passive-only mode never reaches the filter either.
        let passive = dir.path().join("passive.toml");
        fs::write(
            &passive,
            "[general]\nmode = 1\n\n[domains]\nmode = \"blacklist\"\n",
        )
        .unwrap();
        let mut config = Config::load(&passive).unwrap();
        config.load_domain_lists().unwrap();
        assert_eq!(config.active_domain_list_size(), None);

        // A list that is actually in effect reports its size.
        let listed = dir.path().join("listed.toml");
        fs::write(
            &listed,
            "[domains]\nmode = \"blacklist\"\nblacklist = [\"a.com\", \"b.com\"]\n",
        )
        .unwrap();
        let mut config = Config::load(&listed).unwrap();
        config.load_domain_lists().unwrap();
        assert_eq!(config.active_domain_list_size(), Some(2));
    }

    /// The escape hatch still works: god mode remains reachable, but only when
    /// the config explicitly asks for it.
    #[test]
    fn explicit_none_mode_is_still_honoured() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "[domains]\nmode = \"none\"\n").unwrap();

        let config = Config::load(&path).expect("an explicit config must load");
        assert_eq!(config.domains.mode, DomainMode::None);
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

    /// The CLI bounds queue_num to 0..=65534, but a value read from config.toml
    /// bypasses that parser. validate() must enforce the same bound, since the
    /// inbound queue uses queue_num + 1 and 65535 would wrap to queue 0.
    #[test]
    fn validate_rejects_queue_num_whose_inbound_would_overflow() {
        let mut config = Config::default();

        config.general.queue_num = 65535;
        assert!(
            config.validate().is_err(),
            "queue_num 65535 overflows the inbound queue and must be rejected",
        );

        config.general.queue_num = 65534; // inbound = 65535, the highest valid
        assert!(
            config.validate().is_ok(),
            "queue_num 65534 must be accepted"
        );

        config.general.queue_num = 200; // shipped default
        assert!(config.validate().is_ok());
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
