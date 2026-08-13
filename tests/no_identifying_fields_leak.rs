// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// tests/no_identifying_fields_leak.rs — identifying log fields stay behind the switch
//
// Redacting the fields once is not the hard part; keeping them redacted is.
// These fields are added while chasing a bug, when the last thing on anyone's
// mind is that the value says which site the user is visiting. This walks the
// source and fails if a field whose name marks it as identifying is logged
// without going through logging::peer().

use std::fs;
use std::path::{Path, PathBuf};

/// Field names classified as revealing where the user connects.
const IDENTIFYING_FIELDS: &[&str] = &["domain", "sni", "src", "dst", "host", "peer_addr"];

fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn identifying_fields_are_logged_only_through_the_redaction_helper() {
    let src = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_sources(&src, &mut files);
    assert!(!files.is_empty(), "no sources found under {}", src.display());

    let mut offenders = Vec::new();

    for file in &files {
        // The helper itself and its tests name these fields legitimately.
        if file.ends_with("logging.rs") {
            continue;
        }
        for (i, line) in fs::read_to_string(file).unwrap().lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") || trimmed.starts_with("///") {
                continue;
            }
            for field in IDENTIFYING_FIELDS {
                // A tracing field is written `name = value` or `name = %value`
                // and, being a macro argument, ends in a comma. An ordinary
                // assignment of the same name ends in a semicolon — those are
                // parser internals, not log output.
                let assignment = format!("{field} = ");
                if !trimmed.starts_with(&assignment) || !trimmed.ends_with(',') {
                    continue;
                }
                if trimmed.contains("logging::peer(") {
                    continue;
                }
                offenders.push(format!(
                    "{}:{}: {}",
                    file.strip_prefix(&src).unwrap_or(file).display(),
                    i + 1,
                    trimmed
                ));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "these log fields reveal where the user connects and must be wrapped in \
         logging::peer(), so they stay redacted unless [logging] \
         log_identifying_fields is on:\n  {}",
        offenders.join("\n  ")
    );
}

/// The switch must default to off wherever it is declared, so an operator has
/// to ask for browsing data rather than inherit it.
#[test]
fn the_privacy_switches_default_to_off() {
    let config = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src/config.rs"),
    )
    .unwrap();

    for field in ["log_identifying_fields", "log_packet_bytes"] {
        assert!(
            config.contains(&format!("{field}: false")),
            "{field} must default to false in the built-in LogConfig"
        );
    }

    // …and the shipped config must not turn them on either.
    let shipped = fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config/config.toml"),
    )
    .unwrap();
    for line in shipped.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        for field in ["log_identifying_fields", "log_packet_bytes"] {
            assert!(
                !(line.starts_with(field) && line.contains("true")),
                "the shipped config must not enable {field}: {line}"
            );
        }
    }
}
