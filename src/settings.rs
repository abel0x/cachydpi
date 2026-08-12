// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/settings.rs — Interactive domain filter settings

use std::fs;
use std::io::{self, BufRead, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::{Context, Result, bail};
use tempfile::NamedTempFile;

use crate::config::{Config, DomainMode};

/// Fallback blacklist path used only when `[domains].blacklist_file` is unset.
const DEFAULT_BLACKLIST: &str = "/etc/cachydpi/blacklist.txt";

/// Resolve the blacklist file path to operate on: the configured
/// `[domains].blacklist_file`, or DEFAULT_BLACKLIST when none is set.
fn resolve_blacklist_path(config: &Config) -> &str {
    config
        .domains
        .blacklist_file
        .as_deref()
        .unwrap_or(DEFAULT_BLACKLIST)
}

/// Run the interactive domain filter settings menu.
pub fn run_settings(config: &Config, config_path: &Path) -> Result<()> {
    let current = match config.domains.mode {
        DomainMode::None => "all  (god mode — every site)",
        DomainMode::Blacklist => "list (blacklist.txt only)",
        DomainMode::Exempt => "exempt",
    };

    let blacklist_file = resolve_blacklist_path(config);

    print_menu(current);

    let new_mode = prompt_choice()?;

    match new_mode {
        "blacklist" => {
            print_list_summary(blacklist_file);
            update_mode_in_file(config_path, "blacklist", blacklist_file)?;
            println!("  Config updated → mode = \"blacklist\"");
        }
        "none" => {
            println!();
            println!("  God mode enabled — DPI bypass will apply to every site.");
            update_mode_in_file(config_path, "none", blacklist_file)?;
            println!("  Config updated → mode = \"none\"");
        }
        _ => unreachable!(),
    }

    offer_restart()
}

fn print_menu(current: &str) {
    println!();
    println!("╔════════════════════════════════════════════════════════╗");
    println!("║          CachyDPI — Domain Filter Settings             ║");
    println!("╠════════════════════════════════════════════════════════╣");
    println!("║  Current mode: {:<39}║", current);
    println!("╠════════════════════════════════════════════════════════╣");
    println!("║                                                        ║");
    println!("║  [1] list  — bypass DPI only for domains listed in     ║");
    println!("║              /etc/cachydpi/blacklist.txt               ║");
    println!("║                                                        ║");
    println!("║  [2] all   — God Mode: bypass DPI for every site       ║");
    println!("║              (no domain filter at all)                 ║");
    println!("║                                                        ║");
    println!("╚════════════════════════════════════════════════════════╝");
    println!();
}

fn prompt_choice() -> Result<&'static str> {
    loop {
        print!("Select [1/2] (q = quit): ");
        io::stdout().flush()?;

        let mut line = String::new();
        io::stdin().lock().read_line(&mut line)?;

        match line.trim() {
            "1" | "list" => return Ok("blacklist"),
            "2" | "all" => return Ok("none"),
            "q" | "Q" | "quit" | "exit" => {
                println!("Cancelled — no changes made.");
                std::process::exit(0);
            }
            _ => println!("  Invalid choice, enter 1 or 2."),
        }
    }
}

/// Count the active (non-blank, non-comment) domain entries in a list file.
/// Returns None when the file cannot be read.
fn count_list_domains(path: &str) -> Option<usize> {
    fs::read_to_string(path).ok().map(|content| {
        content
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
            .count()
    })
}

fn print_list_summary(blacklist_file: &str) {
    print!("\n  List mode: ");
    match count_list_domains(blacklist_file) {
        Some(count) => println!("{} domains in {} will be bypassed.", count, blacklist_file),
        None => println!("{} not found — no domains will be filtered.", blacklist_file),
    }
}

/// Replace `path` with `content` atomically.
///
/// A truncating write (`fs::write`) leaves config.toml empty or half-written if
/// the process is interrupted — a Ctrl+C at the interactive prompt, or a full
/// disk — and a truncated config silently falls back to the built-in defaults
/// (which bypass *every* domain, not just the blacklist). Instead the content
/// goes to a temp file in the *same directory* (rename is only atomic within one
/// filesystem), is fsynced, and is then renamed over the destination: a reader
/// and an interrupted write both see either the old file or the new one.
fn write_atomically(path: &Path, content: &str) -> Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = NamedTempFile::new_in(dir)
        .with_context(|| format!("failed to create temp file in {}", dir.display()))?;

    tmp.write_all(content.as_bytes())
        .with_context(|| format!("failed to write {}", path.display()))?;
    tmp.as_file()
        .sync_all()
        .with_context(|| format!("failed to flush {} to disk", path.display()))?;

    // NamedTempFile is created 0600. Carry over the destination's mode (or 0644
    // for a new file) before the rename, otherwise the daemon's unprivileged
    // user loses read access to its own config.
    let perms = fs::metadata(path)
        .map(|m| m.permissions())
        .unwrap_or_else(|_| fs::Permissions::from_mode(0o644));
    let _ = fs::set_permissions(tmp.path(), perms);

    tmp.persist(path)
        .map_err(|e| anyhow::anyhow!("failed to replace {}: {}", path.display(), e))?;

    // fsync the directory too: the rename is atomic against concurrent readers
    // either way, but without this the directory entry itself may not survive a
    // power cut. ext4 usually rescues this case through its rename heuristic;
    // that is filesystem-specific, not a guarantee. A failure here means the
    // update already applied but its durability is unconfirmed, so warn rather
    // than report the whole write as failed.
    // (this runs before logging is initialised, so report on stderr)
    match fs::File::open(dir) {
        Ok(dir_file) => {
            if let Err(e) = dir_file.sync_all() {
                eprintln!(
                    "  warning: {} written but its directory could not be synced: {e}",
                    path.display()
                );
            }
        }
        Err(e) => eprintln!(
            "  warning: {} written but {} could not be opened to sync: {e}",
            path.display(),
            dir.display()
        ),
    }

    Ok(())
}

/// Rewrite only the `mode = "..."` line inside the `[domains]` section.
/// All comments and other settings are preserved exactly.
fn update_mode_in_file(path: &Path, mode: &str, blacklist_file: &str) -> Result<()> {
    if !path.exists() {
        let content = format!(
            "[domains]\nmode = \"{}\"\nblacklist_file = \"{}\"\n",
            mode, blacklist_file
        );
        return write_atomically(path, &content);
    }

    let content =
        fs::read_to_string(path).with_context(|| format!("failed to read {}", path.display()))?;

    let mut out = String::with_capacity(content.len() + 4);
    let mut in_domains = false;
    let mut updated = false;

    for line in content.lines() {
        let t = line.trim();

        // Track section boundaries (ignore [[ array-of-tables]])
        if t.starts_with('[') && !t.starts_with("[[") {
            in_domains = t == "[domains]";
        }

        if in_domains && (t.starts_with("mode =") || t.starts_with("mode=")) {
            out.push_str(&format!("mode = \"{}\"\n", mode));
            updated = true;
            continue;
        }

        out.push_str(line);
        out.push('\n');
    }

    if !updated {
        bail!(
            "could not find 'mode = ...' under [domains] in {}\n\
             Add it manually: mode = \"none\"  or  mode = \"blacklist\"",
            path.display()
        );
    }

    write_atomically(path, &out)
}

fn offer_restart() -> Result<()> {
    println!();
    print!("Restart CachyDPI service now to apply? [y/N]: ");
    io::stdout().flush()?;

    let mut line = String::new();
    io::stdin().lock().read_line(&mut line)?;

    if matches!(line.trim().to_lowercase().as_str(), "y" | "yes") {
        println!("  Restarting cachydpi...");
        let status = std::process::Command::new("systemctl")
            .args(["restart", "cachydpi"])
            .status()
            .context("failed to run systemctl — is systemd available?")?;

        if status.success() {
            println!("  CachyDPI restarted successfully.");
        } else {
            bail!("systemctl restart failed (exit code: {:?})", status.code());
        }
    } else {
        println!("  Run `sudo systemctl restart cachydpi` to apply changes.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The interactive menu must resolve the blacklist path from
    /// `config.domains.blacklist_file`, falling back to DEFAULT_BLACKLIST only
    /// when the option is unset.
    #[test]
    fn resolve_blacklist_path_prefers_config_value() {
        let mut config = Config::default();
        config.domains.blacklist_file = Some("/etc/cachydpi/custom.txt".to_string());
        assert_eq!(resolve_blacklist_path(&config), "/etc/cachydpi/custom.txt");

        config.domains.blacklist_file = None;
        assert_eq!(resolve_blacklist_path(&config), DEFAULT_BLACKLIST);
    }

    /// print_list_summary's counting logic skips blank lines and comments.
    #[test]
    fn count_list_domains_skips_blanks_and_comments() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bl.txt");
        fs::write(&path, "# comment\nexample.com\n\n   \nfoo.com\n").unwrap();
        assert_eq!(count_list_domains(path.to_str().unwrap()), Some(2));
    }

    /// A missing list file yields None (the "not found" branch).
    #[test]
    fn count_list_domains_missing_file_is_none() {
        assert_eq!(count_list_domains("/nonexistent/cachydpi/none.txt"), None);
    }

    /// End-to-end proof that settings reads the *configured* blacklist file:
    /// a Config carrying a custom blacklist_file resolves to that path, and
    /// reading it returns the count of that file (not the hardcoded default).
    #[test]
    fn reads_configured_blacklist_path_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let custom = dir.path().join("custom-blacklist.txt");
        fs::write(&custom, "# header comment\na.com\nb.com\nc.com\n").unwrap();
        let custom_str = custom.to_str().unwrap().to_string();

        let mut config = Config::default();
        config.domains.blacklist_file = Some(custom_str.clone());

        // Resolution picks the configured path…
        let resolved = resolve_blacklist_path(&config);
        assert_eq!(resolved, custom_str);
        // …and that path is the one actually read, yielding its 3 domains.
        assert_eq!(count_list_domains(resolved), Some(3));
    }

    /// Creating a fresh config writes the *configured* blacklist path, not the
    /// hardcoded default.
    #[test]
    fn new_file_uses_configured_blacklist_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        update_mode_in_file(&path, "blacklist", "/etc/cachydpi/custom.txt").unwrap();
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("blacklist_file = \"/etc/cachydpi/custom.txt\""));
        assert!(content.contains("mode = \"blacklist\""));
    }

    /// Rewriting an existing config touches only the mode line and leaves a
    /// custom blacklist_file untouched.
    #[test]
    fn existing_file_preserves_custom_blacklist_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(
            &path,
            "[domains]\nmode = \"none\"\nblacklist_file = \"/etc/cachydpi/custom.txt\"\n",
        )
        .unwrap();
        update_mode_in_file(&path, "blacklist", "/etc/cachydpi/ignored.txt").unwrap();
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("mode = \"blacklist\""));
        assert!(content.contains("blacklist_file = \"/etc/cachydpi/custom.txt\""));
    }

    /// Only the [domains] mode is rewritten — the integer `mode` under
    /// [general] (and all comments/other keys) must survive untouched.
    #[test]
    fn update_mode_only_touches_domains_section() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let original = "# CachyDPI config\n\
                        [general]\n\
                        mode = 5          # bypass strategy, NOT the domain mode\n\
                        queue_num = 200\n\
                        \n\
                        [domains]\n\
                        # domain filter mode\n\
                        mode = \"none\"\n\
                        blacklist_file = \"/etc/cachydpi/blacklist.txt\"\n";
        fs::write(&path, original).unwrap();

        update_mode_in_file(&path, "blacklist", "/etc/cachydpi/blacklist.txt").unwrap();
        let content = fs::read_to_string(&path).unwrap();

        // The [domains] mode flipped…
        assert!(content.contains("mode = \"blacklist\""));
        assert!(!content.contains("mode = \"none\""));
        // …while [general]'s integer mode and other content are preserved.
        assert!(content.contains("mode = 5          # bypass strategy, NOT the domain mode"));
        assert!(content.contains("queue_num = 200"));
        assert!(content.contains("# CachyDPI config"));
        assert!(content.contains("# domain filter mode"));
    }

    /// An existing file whose [domains] section lacks a `mode` line is an error,
    /// and the file must be left unchanged (no partial write).
    #[test]
    fn update_mode_bails_when_domains_mode_absent() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let original = "[domains]\nblacklist_file = \"/etc/cachydpi/blacklist.txt\"\n";
        fs::write(&path, original).unwrap();

        let result = update_mode_in_file(&path, "blacklist", "/etc/cachydpi/blacklist.txt");
        assert!(result.is_err(), "missing [domains].mode must be an error");
        // File untouched on failure.
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
    }

    /// The update must land via rename(2), not by truncating the destination in
    /// place. A rename swaps in a different inode; an O_TRUNC write keeps the
    /// same one. This is the mechanism that makes the update atomic.
    #[test]
    fn update_mode_replaces_via_rename_not_truncate() {
        use std::os::unix::fs::MetadataExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "[domains]\nmode = \"none\"\n").unwrap();
        let ino_before = fs::metadata(&path).unwrap().ino();

        update_mode_in_file(&path, "blacklist", "/etc/cachydpi/blacklist.txt").unwrap();

        let ino_after = fs::metadata(&path).unwrap().ino();
        assert_ne!(
            ino_before, ino_after,
            "config must be replaced by rename (new inode), not truncated in place",
        );
        assert!(
            fs::read_to_string(&path)
                .unwrap()
                .contains("mode = \"blacklist\"")
        );
    }

    /// Acceptance criterion: config.toml is only ever observable as the old or
    /// the new complete file — never truncated or half-written. A reader thread
    /// samples the file while it is rewritten repeatedly; with a truncating
    /// write it catches short/empty states, with rename it cannot.
    #[test]
    fn concurrent_reader_never_observes_partial_config() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        // Pad the file so a truncating write leaves a wide, easily-sampled
        // window in which the content is incomplete.
        let padding = format!("# {}\n", "x".repeat(200_000));
        let write_config = |mode: &str| format!("{padding}[domains]\nmode = \"{mode}\"\n");
        let min_len = padding.len();
        fs::write(&path, write_config("none")).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let reader_path = path.clone();
        let reader_stop = Arc::clone(&stop);
        let reader = std::thread::spawn(move || {
            let mut bad: Vec<String> = Vec::new();
            while !reader_stop.load(Ordering::Relaxed) {
                match fs::read_to_string(&reader_path) {
                    // A complete config always carries the padding, the section
                    // header, and a trailing newline.
                    Ok(c) => {
                        if c.len() < min_len || !c.contains("[domains]") || !c.ends_with('\n') {
                            bad.push(format!("partial read of {} bytes", c.len()));
                        }
                    }
                    Err(e) => bad.push(format!("config unreadable mid-update: {e}")),
                }
            }
            bad
        });

        for i in 0..40 {
            let mode = if i % 2 == 0 { "blacklist" } else { "none" };
            update_mode_in_file(&path, mode, "/etc/cachydpi/blacklist.txt").unwrap();
        }
        stop.store(true, Ordering::Relaxed);

        let bad = reader.join().unwrap();
        assert!(
            bad.is_empty(),
            "reader observed {} non-atomic state(s): {:?}",
            bad.len(),
            &bad[..bad.len().min(3)],
        );
    }
}
