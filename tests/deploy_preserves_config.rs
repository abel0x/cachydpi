// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// tests/deploy_preserves_config.rs — deploy.sh must not clobber an existing config
//
// A deploy that replaces /etc/cachydpi/config.toml does not fail loudly the
// way a corrupt config does: the daemon starts happily with a domain filter
// nobody asked for. These tests run the real script against a sandbox, with
// the system commands it calls stubbed out.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Directory of stub executables, so the script's systemctl/curl/tcpdump/ip
/// calls succeed without touching the machine.
fn stub_bin(dir: &Path) -> PathBuf {
    let bin = dir.join("stubbin");
    fs::create_dir_all(&bin).unwrap();
    for name in ["systemctl", "curl", "tcpdump", "ip", "sleep", "timeout"] {
        let path = bin.join(name);
        // `systemctl is-active` must report a healthy service or the script
        // treats the deploy as failed and exits non-zero.
        fs::write(&path, "#!/bin/sh\nif [ \"$1\" = \"is-active\" ]; then echo active; fi\nexit 0\n")
            .unwrap();
        let mut perms = fs::metadata(&path).unwrap().permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        fs::set_permissions(&path, perms).unwrap();
    }
    bin
}

struct Sandbox {
    _dir: tempfile::TempDir,
    config: PathBuf,
    bin_dest: PathBuf,
    stub: PathBuf,
    repo: PathBuf,
}

fn sandbox() -> Option<Sandbox> {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    // The script copies the release binary; without one there is nothing to
    // deploy and the test would be measuring the wrong failure.
    if !repo.join("target/release/cachydpi").exists() {
        eprintln!("skipping: target/release/cachydpi not built (cargo build --release)");
        return None;
    }
    let dir = tempfile::tempdir().unwrap();
    let stub = stub_bin(dir.path());
    Some(Sandbox {
        config: dir.path().join("etc/config.toml"),
        bin_dest: dir.path().join("usr/cachydpi"),
        stub,
        repo,
        _dir: dir,
    })
}

fn run_deploy(sb: &Sandbox) -> std::process::Output {
    Command::new("bash")
        .arg(sb.repo.join("deploy.sh"))
        .env("CACHYDPI_CONFIG_DEST", &sb.config)
        .env("CACHYDPI_BIN_DEST", &sb.bin_dest)
        .env(
            "PATH",
            format!(
                "{}:{}",
                sb.stub.display(),
                std::env::var("PATH").unwrap_or_default()
            ),
        )
        .current_dir(&sb.repo)
        .output()
        .expect("failed to run deploy.sh")
}

/// The regression: an existing config must survive a deploy byte for byte.
#[test]
fn deploy_does_not_overwrite_an_existing_config() {
    let Some(sb) = sandbox() else { return };

    // A config with a deliberate, non-default operator choice.
    let operator_config = "[domains]\nmode = \"none\"\n# hand-tuned, do not lose\n";
    fs::create_dir_all(sb.config.parent().unwrap()).unwrap();
    fs::write(&sb.config, operator_config).unwrap();

    let out = run_deploy(&sb);
    assert!(
        out.status.success(),
        "deploy.sh failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    assert_eq!(
        fs::read_to_string(&sb.config).unwrap(),
        operator_config,
        "deploy.sh overwrote an existing config"
    );
    // The shipped version is still made available, just not in place.
    let shipped = sb.config.with_extension("toml.new");
    assert!(
        shipped.exists(),
        "the shipped config should be left alongside as .new"
    );
}

/// First install still has to work: with no config in place the shipped one
/// is installed normally.
#[test]
fn deploy_installs_the_config_when_none_exists() {
    let Some(sb) = sandbox() else { return };
    fs::create_dir_all(sb.config.parent().unwrap()).unwrap();
    assert!(!sb.config.exists());

    let out = run_deploy(&sb);
    assert!(
        out.status.success(),
        "deploy.sh failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let installed = fs::read_to_string(&sb.config).expect("config should have been installed");
    let shipped = fs::read_to_string(sb.repo.join("config/config.toml")).unwrap();
    assert_eq!(installed, shipped);
}

/// The packaged upgrade path relies on pacman's backup= handling to produce a
/// .pacnew instead of replacing the file, and on .SRCINFO agreeing with it.
#[test]
fn packaging_marks_the_config_as_a_backup_file() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let pkgbuild = fs::read_to_string(repo.join("PKGBUILD")).unwrap();
    let srcinfo = fs::read_to_string(repo.join(".SRCINFO")).unwrap();

    for file in ["etc/cachydpi/config.toml", "etc/cachydpi/blacklist.txt"] {
        assert!(
            pkgbuild.contains(&format!("'{file}'")),
            "PKGBUILD backup= must list {file}, or pacman replaces it on upgrade"
        );
        assert!(
            srcinfo.contains(&format!("backup = {file}")),
            ".SRCINFO must stay in sync with PKGBUILD backup= for {file}"
        );
    }
}
