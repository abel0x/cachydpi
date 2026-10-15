// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/dns.rs — encrypted DNS through systemd-resolved
//
// Splitting the SNI does nothing for a site whose name the ISP's resolver
// answers with the address of a block page: the connection goes to the wrong
// place before any packet reaches the engine. DNS-over-TLS through
// systemd-resolved closes that gap. This module checks whether it is on, and
// turns it on in a way that cannot leave the machine without DNS.
//
// The bundled drop-in sets DNSOverTLS=yes, the strict mode: opportunistic
// mode falls back to plaintext, which is exactly the poisoned path. Strict
// mode with port 853 blocked would mean no DNS at all, so enabling probes the
// servers first and checks resolution afterwards, rolling back if it fails.

use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

/// The drop-in this tool installs, and the only file it ever removes.
pub const DROPIN_PATH: &str = "/etc/systemd/resolved.conf.d/cachydpi-dns-over-tls.conf";

/// Bundled resolved configuration: Cloudflare and Google, Quad9 fallback.
pub const DROPIN_CONTENT: &str = include_str!("../dns-over-tls.conf");

/// Where resolved reads its configuration, lowest precedence first. Drop-ins
/// in later directories override same-named ones in earlier directories, and
/// all drop-ins are applied after the main file in lexical filename order.
const RESOLVED_MAIN: &str = "/etc/systemd/resolved.conf";
const RESOLVED_DROPIN_DIRS: [&str; 3] = [
    "/usr/lib/systemd/resolved.conf.d",
    "/run/systemd/resolved.conf.d",
    "/etc/systemd/resolved.conf.d",
];

/// The stub listener resolv.conf points at when resolved is in charge.
const RESOLVED_STUB: &str = "127.0.0.53";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DotMode {
    Off,
    /// Encrypts when it can and falls back to plaintext — the poisoned path.
    Opportunistic,
    Strict,
}

/// The DNSOverTLS= value resolved ends up with, from file contents given in
/// the order resolved applies them. Unset means off.
pub fn effective_dot_mode<'a>(files: impl IntoIterator<Item = &'a str>) -> DotMode {
    let mut mode = DotMode::Off;
    for content in files {
        let mut in_resolve = false;
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with('[') {
                in_resolve = line == "[Resolve]";
                continue;
            }
            if !in_resolve || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=')
                && key.trim() == "DNSOverTLS"
            {
                mode = match value.trim().to_ascii_lowercase().as_str() {
                    "yes" | "true" | "1" | "on" => DotMode::Strict,
                    "opportunistic" => DotMode::Opportunistic,
                    _ => DotMode::Off,
                };
            }
        }
    }
    mode
}

/// The resolved configuration files in the order resolved applies them.
fn resolved_config_files(root: &Path) -> Vec<PathBuf> {
    let under = |p: &str| root.join(p.trim_start_matches('/'));
    let mut files = vec![under(RESOLVED_MAIN)];
    // Same-named drop-ins in later directories replace earlier ones.
    let mut dropins = std::collections::BTreeMap::new();
    for dir in RESOLVED_DROPIN_DIRS {
        if let Ok(entries) = std::fs::read_dir(under(dir)) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                if name.to_string_lossy().ends_with(".conf") {
                    dropins.insert(name, entry.path());
                }
            }
        }
    }
    files.extend(dropins.into_values());
    files
}

/// What the machine's DNS looks like.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsStatus {
    /// resolv.conf sends queries to resolved's stub listener.
    pub via_resolved: bool,
    pub dot: DotMode,
    /// This tool's drop-in is installed.
    pub ours: bool,
}

impl DnsStatus {
    /// Whether lookups are protected from an ISP rewriting the answers.
    pub fn encrypted(&self) -> bool {
        self.via_resolved && self.dot == DotMode::Strict
    }
}

/// Read the DNS setup from the filesystem under `root` (`/` in production).
pub fn status_at(root: &Path) -> DnsStatus {
    let resolv = std::fs::read_to_string(root.join("etc/resolv.conf")).unwrap_or_default();
    let via_resolved = resolv.lines().any(|l| {
        let mut words = l.split_whitespace();
        words.next() == Some("nameserver") && words.next() == Some(RESOLVED_STUB)
    });
    let contents: Vec<String> = resolved_config_files(root)
        .iter()
        .filter_map(|p| std::fs::read_to_string(p).ok())
        .collect();
    DnsStatus {
        via_resolved,
        dot: effective_dot_mode(contents.iter().map(String::as_str)),
        ours: root.join(DROPIN_PATH.trim_start_matches('/')).exists(),
    }
}

pub fn status() -> DnsStatus {
    status_at(Path::new("/"))
}

/// The DoT servers the bundled drop-in names, primary and fallback.
pub fn bundled_servers() -> Vec<IpAddr> {
    DROPIN_CONTENT
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            l.strip_prefix("DNS=")
                .or_else(|| l.strip_prefix("FallbackDNS="))
        })
        .flat_map(|v| v.split_whitespace())
        .filter_map(|entry| entry.split('#').next()?.parse().ok())
        .collect()
}

/// What enabling needs from the machine, behind a trait so the decision
/// logic — refuse when 853 is blocked, roll back when resolution breaks —
/// can be tested without root or a live resolver.
pub trait Host {
    fn dot_port_reachable(&self, server: IpAddr) -> bool;
    fn install_dropin(&self) -> Result<()>;
    fn remove_dropin(&self) -> Result<()>;
    fn restart_resolved(&self) -> Result<()>;
    /// Whether names resolve through the system resolver right now.
    fn resolution_works(&self) -> bool;
}

/// Turn on strict DNS-over-TLS, or leave things as they were.
pub fn enable_with(host: &dyn Host, servers: &[IpAddr]) -> Result<()> {
    let reachable: Vec<IpAddr> = servers
        .iter()
        .copied()
        .filter(|s| host.dot_port_reachable(*s))
        .collect();
    if reachable.is_empty() {
        bail!(
            "none of the DNS-over-TLS servers answered on port 853 — the network appears \
             to block it. Strict DNS-over-TLS would leave this machine without DNS, so \
             nothing was changed"
        );
    }

    host.install_dropin()?;
    host.restart_resolved()?;
    if host.resolution_works() {
        return Ok(());
    }

    // Leave the machine as it was rather than without DNS.
    let undo = host.remove_dropin().and_then(|_| host.restart_resolved());
    match undo {
        Ok(()) => {
            bail!("names did not resolve with DNS-over-TLS on, so the change was rolled back")
        }
        Err(e) => bail!(
            "names did not resolve with DNS-over-TLS on, and rolling back failed: {e:#} — \
             remove {DROPIN_PATH} and run: systemctl restart systemd-resolved"
        ),
    }
}

/// Remove this tool's drop-in. Other resolved settings are not touched.
pub fn disable_with(host: &dyn Host) -> Result<()> {
    host.remove_dropin()?;
    host.restart_resolved()
}

/// The real machine.
pub struct System;

impl Host for System {
    fn dot_port_reachable(&self, server: IpAddr) -> bool {
        TcpStream::connect_timeout(&SocketAddr::new(server, 853), Duration::from_secs(3)).is_ok()
    }

    fn install_dropin(&self) -> Result<()> {
        let path = Path::new(DROPIN_PATH);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)
                .with_context(|| format!("failed to create {}", dir.display()))?;
        }
        let content = format!(
            "# Installed by `cachydpi dns enable`; removed by `cachydpi dns disable`.\n{DROPIN_CONTENT}"
        );
        crate::settings::write_atomically(path, &content)
    }

    fn remove_dropin(&self) -> Result<()> {
        match std::fs::remove_file(DROPIN_PATH) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("failed to remove {DROPIN_PATH}")),
        }
    }

    fn restart_resolved(&self) -> Result<()> {
        let status = std::process::Command::new("systemctl")
            .args(["restart", "systemd-resolved"])
            .status()
            .context("failed to run systemctl — is systemd available?")?;
        if !status.success() {
            bail!(
                "systemctl restart systemd-resolved failed ({:?})",
                status.code()
            );
        }
        Ok(())
    }

    fn resolution_works(&self) -> bool {
        // resolved needs a moment after a restart to bring up its TLS
        // connections; give it a few seconds before concluding anything.
        let deadline = Instant::now() + Duration::from_secs(8);
        loop {
            if ("one.one.one.one", 443).to_socket_addrs().is_ok() {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[test]
    fn the_last_setting_wins_and_unset_is_off() {
        assert_eq!(
            effective_dot_mode(["[Resolve]\nDNS=1.1.1.1\n"]),
            DotMode::Off
        );
        assert_eq!(
            effective_dot_mode([
                "[Resolve]\nDNSOverTLS=yes\n",
                "[Resolve]\nDNSOverTLS=opportunistic\n"
            ]),
            DotMode::Opportunistic
        );
        assert_eq!(
            effective_dot_mode(["[Resolve]\n#DNSOverTLS=yes\n"]),
            DotMode::Off,
            "a commented-out line is not a setting"
        );
        assert_eq!(
            effective_dot_mode(["[Other]\nDNSOverTLS=yes\n"]),
            DotMode::Off,
            "only the [Resolve] section counts"
        );
        assert_eq!(effective_dot_mode([DROPIN_CONTENT]), DotMode::Strict);
    }

    #[test]
    fn status_reads_resolv_conf_and_dropins_in_order() {
        let root = tempfile::tempdir().unwrap();
        let p = |rel: &str| root.path().join(rel);
        std::fs::create_dir_all(p("etc/systemd/resolved.conf.d")).unwrap();
        std::fs::create_dir_all(p("usr/lib/systemd/resolved.conf.d")).unwrap();
        std::fs::write(
            p("etc/resolv.conf"),
            "nameserver 127.0.0.53\noptions edns0\n",
        )
        .unwrap();
        std::fs::write(p("etc/systemd/resolved.conf"), "[Resolve]\n").unwrap();
        // A vendor drop-in turns it on; a same-named one in /etc turns it off.
        std::fs::write(
            p("usr/lib/systemd/resolved.conf.d/10-x.conf"),
            "[Resolve]\nDNSOverTLS=yes\n",
        )
        .unwrap();
        std::fs::write(
            p("etc/systemd/resolved.conf.d/10-x.conf"),
            "[Resolve]\nDNSOverTLS=no\n",
        )
        .unwrap();
        let s = status_at(root.path());
        assert!(s.via_resolved);
        assert_eq!(s.dot, DotMode::Off);
        assert!(!s.encrypted() && !s.ours);

        std::fs::write(p(DROPIN_PATH.trim_start_matches('/')), DROPIN_CONTENT).unwrap();
        let s = status_at(root.path());
        assert!(s.ours && s.encrypted());

        std::fs::write(p("etc/resolv.conf"), "nameserver 192.168.1.1\n").unwrap();
        assert!(
            !status_at(root.path()).encrypted(),
            "resolv.conf not pointing at resolved bypasses it"
        );
    }

    #[test]
    fn bundled_servers_include_primary_and_fallback() {
        let servers = bundled_servers();
        assert!(servers.contains(&"1.1.1.1".parse().unwrap()));
        assert!(servers.contains(&"9.9.9.9".parse().unwrap()));
    }

    #[derive(Default)]
    struct Fake {
        reachable: bool,
        resolves: bool,
        log: RefCell<Vec<&'static str>>,
    }

    impl Host for Fake {
        fn dot_port_reachable(&self, _: IpAddr) -> bool {
            self.reachable
        }
        fn install_dropin(&self) -> Result<()> {
            self.log.borrow_mut().push("install");
            Ok(())
        }
        fn remove_dropin(&self) -> Result<()> {
            self.log.borrow_mut().push("remove");
            Ok(())
        }
        fn restart_resolved(&self) -> Result<()> {
            self.log.borrow_mut().push("restart");
            Ok(())
        }
        fn resolution_works(&self) -> bool {
            self.resolves
        }
    }

    #[test]
    fn a_blocked_port_853_changes_nothing() {
        let host = Fake::default();
        let err = enable_with(&host, &bundled_servers()).unwrap_err();
        assert!(format!("{err}").contains("853"));
        assert!(host.log.borrow().is_empty());
    }

    #[test]
    fn broken_resolution_is_rolled_back() {
        let host = Fake {
            reachable: true,
            ..Default::default()
        };
        assert!(enable_with(&host, &bundled_servers()).is_err());
        assert_eq!(
            *host.log.borrow(),
            ["install", "restart", "remove", "restart"]
        );
    }

    #[test]
    fn working_resolution_is_kept() {
        let host = Fake {
            reachable: true,
            resolves: true,
            ..Default::default()
        };
        enable_with(&host, &bundled_servers()).unwrap();
        assert_eq!(*host.log.borrow(), ["install", "restart"]);
    }
}
