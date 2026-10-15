// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/shelby.rs — intentionally absent from the README, --help, and
// mode_description. Reached only through a hidden subcommand; found by
// reading the source, not by being told.

/// The notice, as log lines: level and message.
const NOTICE: [(&str, &str); 3] = [
    ("INFO", "This network is under new management."),
    ("WARN", "Deep packet inspection is hereby forbidden."),
    ("INFO", "By order of the Peaky Blinders."),
];

/// Render the notice. With `color`, the levels take the colours the daemon's
/// own log uses: green for INFO, yellow for WARN.
pub fn render(color: bool) -> String {
    let mut out = String::new();
    for (level, message) in NOTICE {
        let tag = if color {
            let code = if level == "WARN" { 33 } else { 32 };
            format!("\x1b[{code}m[{level}]\x1b[0m")
        } else {
            format!("[{level}]")
        };
        out.push_str(&format!("{tag} {message}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_as_three_log_lines_ending_with_the_order() {
        let plain = render(false);
        let lines: Vec<&str> = plain.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("[INFO] This network is under new management"));
        assert!(lines[1].starts_with("[WARN] Deep packet inspection"));
        assert_eq!(lines[2], "[INFO] By order of the Peaky Blinders.");
    }

    #[test]
    fn plain_output_carries_no_escape_codes() {
        assert!(!render(false).contains('\x1b'));
        assert!(render(true).contains("\x1b[33m[WARN]"));
    }
}
