// src/settings.rs — Interactive domain filter settings

use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;

use anyhow::{Context, Result, bail};

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
        DomainMode::Whitelist => "whitelist",
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

/// Rewrite only the `mode = "..."` line inside the `[domains]` section.
/// All comments and other settings are preserved exactly.
fn update_mode_in_file(path: &Path, mode: &str, blacklist_file: &str) -> Result<()> {
    if !path.exists() {
        let content = format!(
            "[domains]\nmode = \"{}\"\nblacklist_file = \"{}\"\n",
            mode, blacklist_file
        );
        return fs::write(path, content)
            .with_context(|| format!("failed to write {}", path.display()));
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

    fs::write(path, out).with_context(|| format!("failed to write {}", path.display()))
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
}
