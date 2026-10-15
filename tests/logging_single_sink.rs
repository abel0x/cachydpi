// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// tests/logging_single_sink.rs — one message must reach the journal once
//
// With both a journald layer and a stderr layer registered, everything the
// daemon logs lands in the journal twice under systemd: once structured with
// its fields, once as flat text carrying none of them. The two are buffered
// separately, so they can arrive out of order, and a multi-line message is
// split differently in each stream. systemd sets JOURNAL_STREAM when it has
// connected stdout or stderr to the journal, which is the signal that the fmt
// layer would be a duplicate.

use std::path::PathBuf;
use std::process::Command;

/// Run the daemon far enough to emit its startup line and return its log output.
///
/// `--dry-run` still reaches the capability check and fails there as an
/// ordinary user, but "CachyDPI starting" is logged before that, which is all
/// this needs — so no privileges and no namespace are required.
fn startup_log(journal_stream: Option<&str>) -> String {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let config = repo.join("target/logging-test-config.toml");
    std::fs::write(
        &config,
        "[general]\nmode = 5\n\n[domains]\nmode = \"none\"\n",
    )
    .unwrap();

    let mut cmd = Command::new(repo.join("target/debug/cachydpi"));
    cmd.arg("--config").arg(&config).arg("--dry-run");
    match journal_stream {
        Some(value) => cmd.env("JOURNAL_STREAM", value),
        None => cmd.env_remove("JOURNAL_STREAM"),
    };

    let out = cmd.output().expect("failed to run cachydpi");
    // tracing-subscriber's fmt layer writes to stdout, not stderr. The unit
    // routes both to the journal, so either one duplicates the journald layer.
    String::from_utf8_lossy(&out.stdout).into_owned()
}

fn starting_lines(output: &str) -> usize {
    output
        .lines()
        .filter(|l| l.contains("CachyDPI starting"))
        .count()
}

/// Under systemd the fmt layer's stream is itself the journal, so it must be
/// left out — otherwise every message is recorded twice.
#[test]
fn no_second_copy_when_the_stream_is_already_the_journal() {
    if !PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/debug/cachydpi")
        .exists()
    {
        eprintln!("skipping: target/debug/cachydpi not built");
        return;
    }

    let output = startup_log(Some("8:123456"));
    assert_eq!(
        starting_lines(&output),
        0,
        "with JOURNAL_STREAM set the journald layer already records the event; \
         a second copy would duplicate it. output was:\n{output}"
    );
}

/// A config still using the "whitelist" spelling removed in 1.2.0 must stop
/// the daemon with a message naming what replaced it, not start with a
/// different domain filter or fail with serde's bare "unknown variant".
#[test]
fn the_removed_whitelist_spelling_stops_startup_and_names_its_replacement() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let binary = repo.join("target/debug/cachydpi");
    if !binary.exists() {
        eprintln!("skipping: target/debug/cachydpi not built");
        return;
    }

    let config = repo.join("target/logging-test-removed-whitelist.toml");
    std::fs::write(
        &config,
        "[general]\nmode = 5\n\n[domains]\nmode = \"whitelist\"\nwhitelist = [\"safe.com\"]\n",
    )
    .unwrap();

    let out = Command::new(&binary)
        .arg("--config")
        .arg(&config)
        .arg("--dry-run")
        .env_remove("JOURNAL_STREAM")
        .output()
        .expect("failed to run cachydpi");
    let stderr = String::from_utf8_lossy(&out.stderr);

    assert!(!out.status.success(), "the daemon must not start");
    assert!(
        stderr.contains("\"exempt\"") && stderr.contains("removed in 1.2.0"),
        "the refusal must name the replacement and the release: {stderr}"
    );
}

/// Run by hand from a terminal there is no journald stream, and the fmt layer
/// is the only thing the operator can read — it must stay.
#[test]
fn foreground_runs_still_print_their_log() {
    if !PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/debug/cachydpi")
        .exists()
    {
        eprintln!("skipping: target/debug/cachydpi not built");
        return;
    }

    let output = startup_log(None);
    assert_eq!(
        starting_lines(&output),
        1,
        "a foreground run must print exactly once. output was:\n{output}"
    );
}
