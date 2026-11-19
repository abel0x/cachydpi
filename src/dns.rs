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

/// A file as it was before a change: what to put back on rollback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedFile {
    pub content: Vec<u8>,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

/// What enabling needs from the machine, behind a trait so the decision
/// logic — refuse when 853 is blocked, roll back when resolution breaks —
/// can be tested without root or a live resolver.
pub trait Host {
    fn dot_port_reachable(&self, server: IpAddr) -> bool;
    /// The drop-in as it is now, `None` if there is none.
    fn read_dropin(&self) -> Result<Option<SavedFile>>;
    fn install_dropin(&self) -> Result<()>;
    /// Put the drop-in back as `prior` describes: rewrite it with its old
    /// content, mode and owner, or remove it if there was none.
    fn restore_dropin(&self, prior: Option<&SavedFile>) -> Result<()>;
    fn remove_dropin(&self) -> Result<()>;
    fn restart_resolved(&self) -> Result<()>;
    /// Whether names resolve through the system resolver right now.
    fn resolution_works(&self) -> bool;
}

/// Earlier drop-in content short enough to print for manual recovery.
const PRINTABLE_PRIOR_MAX: usize = 4096;

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

    // Everything after the write is undone back to this, so a failed enable
    // neither leaves a new file to take effect later nor loses one an
    // administrator had put there.
    let prior = host
        .read_dropin()
        .context("cannot read the current drop-in, so nothing was changed")?;
    host.install_dropin()
        .context("writing the drop-in failed; the file is unchanged")?;

    let failure = match host.restart_resolved() {
        Err(e) => e.context("restarting systemd-resolved with DNS-over-TLS on failed"),
        Ok(()) if host.resolution_works() => return Ok(()),
        Ok(()) => anyhow::anyhow!("names did not resolve with DNS-over-TLS on"),
    };

    // Leave the machine as it was rather than without DNS.
    let what_was_restored = match &prior {
        Some(_) => format!("{DROPIN_PATH} was restored to its earlier content"),
        None => format!("{DROPIN_PATH} was removed"),
    };
    if let Err(undo) = host.restore_dropin(prior.as_ref()) {
        let by_hand = match &prior {
            None => format!("remove {DROPIN_PATH}"),
            Some(saved) => match std::str::from_utf8(&saved.content) {
                Ok(text) if text.len() <= PRINTABLE_PRIOR_MAX => format!(
                    "put this back in {DROPIN_PATH} (mode {:o}):\n{text}",
                    saved.mode & 0o7777
                ),
                _ => format!("restore {DROPIN_PATH} from a backup"),
            },
        };
        bail!(
            "DNS-over-TLS was not enabled: {failure:#}\n\
             Rolling back failed as well: {undo:#}\n\
             {DROPIN_PATH} still holds the strict configuration. To recover, \
             {by_hand}\nthen run: systemctl restart systemd-resolved"
        );
    }
    if let Err(restart) = host.restart_resolved() {
        bail!(
            "DNS-over-TLS was not enabled: {failure:#}\n\
             {what_was_restored}, but restarting systemd-resolved failed as well: \
             {restart:#}\nIt may still run with the strict configuration; run: \
             systemctl restart systemd-resolved"
        );
    }
    Err(failure.context(format!(
        "DNS-over-TLS was not enabled; {what_was_restored} and systemd-resolved restarted"
    )))
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

    fn read_dropin(&self) -> Result<Option<SavedFile>> {
        read_file(Path::new(DROPIN_PATH))
    }

    fn restore_dropin(&self, prior: Option<&SavedFile>) -> Result<()> {
        restore_file(Path::new(DROPIN_PATH), prior)
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

/// Take `path` as it is now. A missing file is `None`; a symlink is refused,
/// because restoring would replace the link with a regular file.
fn read_file(path: &Path) -> Result<Option<SavedFile>> {
    use std::os::unix::fs::MetadataExt;
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("cannot stat {}", path.display())),
    };
    if !meta.file_type().is_file() {
        bail!("{} is not a regular file; leaving it alone", path.display());
    }
    let content = std::fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
    Ok(Some(SavedFile {
        content,
        mode: meta.mode() & 0o7777,
        uid: meta.uid(),
        gid: meta.gid(),
    }))
}

/// Put `path` back as `prior` says, atomically.
fn restore_file(path: &Path, prior: Option<&SavedFile>) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    let Some(saved) = prior else {
        return match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).with_context(|| format!("failed to remove {}", path.display())),
        };
    };
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir)
        .with_context(|| format!("failed to create a temp file in {}", dir.display()))?;
    tmp.write_all(&saved.content)
        .and_then(|()| tmp.as_file().sync_all())
        .with_context(|| format!("failed to write the earlier {}", path.display()))?;
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(saved.mode))
        .with_context(|| format!("failed to set the mode of {}", path.display()))?;
    // Only root can give a file away; as anyone else the owner is already ours.
    if nix::unistd::geteuid().is_root() {
        std::os::unix::fs::fchown(tmp.as_file(), Some(saved.uid), Some(saved.gid))
            .with_context(|| format!("failed to set the owner of {}", path.display()))?;
    }
    tmp.persist(path)
        .map_err(|e| anyhow::anyhow!("failed to replace {}: {}", path.display(), e))?;
    Ok(())
}

/// Serialize `dns enable` and `dns disable`: one rolling back while another
/// writes would delete or overwrite the other's file.
pub fn lock_changes() -> Result<crate::lockfile::Held> {
    let dir = Path::new(crate::lockfile::LOCK_DIR);
    crate::lockfile::try_exclusive(dir, "dns.lock")?.ok_or_else(|| {
        anyhow::anyhow!("another `cachydpi dns` command is changing the configuration; try again")
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::{Cell, RefCell};

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

    /// A drop-in and a resolver that fail where a test says.
    #[derive(Default)]
    struct Fake {
        reachable: bool,
        resolves: bool,
        /// The drop-in: `None` is no file.
        file: RefCell<Option<SavedFile>>,
        fail_read: bool,
        fail_install: bool,
        fail_restore: bool,
        /// Restart calls that fail, counted from 1.
        failing_restarts: Vec<u32>,
        restarts: Cell<u32>,
        log: RefCell<Vec<&'static str>>,
    }

    fn ours() -> SavedFile {
        SavedFile {
            content: DROPIN_CONTENT.as_bytes().to_vec(),
            mode: 0o644,
            uid: 0,
            gid: 0,
        }
    }

    fn custom() -> SavedFile {
        SavedFile {
            content: b"[Resolve]\nDNS=192.0.2.53#dns.example\nDNSOverTLS=yes\n".to_vec(),
            mode: 0o640,
            uid: 0,
            gid: 42,
        }
    }

    impl Host for Fake {
        fn dot_port_reachable(&self, _: IpAddr) -> bool {
            self.reachable
        }
        fn read_dropin(&self) -> Result<Option<SavedFile>> {
            self.log.borrow_mut().push("read");
            if self.fail_read {
                bail!("read failed");
            }
            Ok(self.file.borrow().clone())
        }
        fn install_dropin(&self) -> Result<()> {
            self.log.borrow_mut().push("install");
            if self.fail_install {
                bail!("disk full");
            }
            *self.file.borrow_mut() = Some(ours());
            Ok(())
        }
        fn restore_dropin(&self, prior: Option<&SavedFile>) -> Result<()> {
            self.log.borrow_mut().push("restore");
            if self.fail_restore {
                bail!("read-only filesystem");
            }
            *self.file.borrow_mut() = prior.cloned();
            Ok(())
        }
        fn remove_dropin(&self) -> Result<()> {
            self.log.borrow_mut().push("remove");
            *self.file.borrow_mut() = None;
            Ok(())
        }
        fn restart_resolved(&self) -> Result<()> {
            self.log.borrow_mut().push("restart");
            let n = self.restarts.get() + 1;
            self.restarts.set(n);
            if self.failing_restarts.contains(&n) {
                bail!("systemctl restart systemd-resolved failed");
            }
            Ok(())
        }
        fn resolution_works(&self) -> bool {
            self.resolves
        }
    }

    fn reachable() -> Fake {
        Fake {
            reachable: true,
            ..Default::default()
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
    fn working_resolution_is_kept() {
        let host = Fake {
            resolves: true,
            ..reachable()
        };
        enable_with(&host, &bundled_servers()).unwrap();
        assert_eq!(*host.log.borrow(), ["read", "install", "restart"]);
        assert_eq!(*host.file.borrow(), Some(ours()));
    }

    #[test]
    fn broken_resolution_is_rolled_back() {
        let host = reachable();
        let err = enable_with(&host, &bundled_servers()).unwrap_err();
        assert_eq!(
            *host.log.borrow(),
            ["read", "install", "restart", "restore", "restart"]
        );
        assert_eq!(*host.file.borrow(), None, "no new file may be left behind");
        assert!(format!("{err:#}").contains("did not resolve"), "{err:#}");
    }

    /// The regression: a failed restart returned before any rollback, and
    /// the new file stayed to take effect at the next restart or boot.
    #[test]
    fn a_failed_restart_is_rolled_back_too() {
        let host = Fake {
            failing_restarts: vec![1],
            resolves: true,
            ..reachable()
        };
        let err = enable_with(&host, &bundled_servers()).unwrap_err();
        assert_eq!(
            *host.log.borrow(),
            ["read", "install", "restart", "restore", "restart"]
        );
        assert_eq!(*host.file.borrow(), None);
        assert!(
            format!("{err:#}").contains("restarting systemd-resolved"),
            "{err:#}"
        );
    }

    /// The regression: rollback removed the path, so a drop-in the
    /// administrator had written there was deleted.
    #[test]
    fn an_earlier_file_is_put_back_not_deleted() {
        for failing_restarts in [vec![], vec![1]] {
            let host = Fake {
                file: RefCell::new(Some(custom())),
                failing_restarts,
                ..reachable()
            };
            let err = enable_with(&host, &bundled_servers()).unwrap_err();
            assert_eq!(*host.file.borrow(), Some(custom()));
            assert!(
                format!("{err:#}").contains("restored to its earlier content"),
                "{err:#}"
            );
        }
    }

    #[test]
    fn nothing_is_written_when_the_current_file_cannot_be_read() {
        let host = Fake {
            fail_read: true,
            ..reachable()
        };
        assert!(enable_with(&host, &bundled_servers()).is_err());
        assert_eq!(*host.log.borrow(), ["read"]);
    }

    #[test]
    fn a_failed_write_needs_no_rollback() {
        let host = Fake {
            fail_install: true,
            file: RefCell::new(Some(custom())),
            ..reachable()
        };
        let err = enable_with(&host, &bundled_servers()).unwrap_err();
        assert_eq!(*host.log.borrow(), ["read", "install"]);
        assert!(format!("{err:#}").contains("unchanged"), "{err:#}");
    }

    /// A rollback that fails is reported as its own failure, with what to
    /// put back by hand, never as a clean rollback.
    #[test]
    fn a_failed_rollback_says_so_and_how_to_recover() {
        let restore_fails = Fake {
            fail_restore: true,
            file: RefCell::new(Some(custom())),
            ..reachable()
        };
        let err = format!(
            "{:#}",
            enable_with(&restore_fails, &bundled_servers()).unwrap_err()
        );
        assert!(err.contains("did not resolve"), "{err}");
        assert!(
            err.contains("Rolling back failed as well: read-only filesystem"),
            "{err}"
        );
        assert!(err.contains("DNS=192.0.2.53#dns.example"), "{err}");
        assert!(err.contains("mode 640"), "{err}");
        assert!(!err.contains("was restored"), "{err}");

        let second_restart_fails = Fake {
            failing_restarts: vec![2],
            ..reachable()
        };
        let err = format!(
            "{:#}",
            enable_with(&second_restart_fails, &bundled_servers()).unwrap_err()
        );
        assert!(err.contains("was removed, but restarting"), "{err}");
        assert_eq!(*second_restart_fails.file.borrow(), None);
    }

    #[test]
    fn a_file_is_restored_with_its_content_and_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.conf");
        std::fs::write(&path, "before\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();

        let saved = read_file(&path).unwrap().expect("exists");
        std::fs::write(&path, "after\n").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        restore_file(&path, Some(&saved)).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "before\n");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(mode, 0o640);

        restore_file(&path, None).unwrap();
        assert!(!path.exists());
        restore_file(&path, None).expect("removing what is gone is fine");
        assert_eq!(read_file(&path).unwrap(), None);
    }

    #[test]
    fn a_symlinked_dropin_is_not_taken() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("x.conf");
        std::os::unix::fs::symlink("/etc/hostname", &path).unwrap();
        assert!(read_file(&path).is_err());
    }
}
