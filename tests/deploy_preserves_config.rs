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
        fs::write(
            &path,
            "#!/bin/sh\nif [ \"$1\" = \"is-active\" ]; then echo active; fi\nexit 0\n",
        )
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

    // The hooks only run if pacman is told about the .install file. Declaring
    // them inside the PKGBUILD, as they were, means they never execute.
    assert!(
        pkgbuild.contains("install=\"$pkgname.install\""),
        "PKGBUILD must declare install=, or the package hooks never run"
    );
    assert!(
        srcinfo.contains("install = cachydpi.install"),
        ".SRCINFO must record the install file"
    );
    assert!(
        repo.join("cachydpi.install").exists(),
        "the declared .install file must exist"
    );
}

/// `make install` is the third way a config reaches /etc and must preserve an
/// existing one just like deploy.sh and pacman do.
#[test]
fn make_install_does_not_overwrite_an_existing_config() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if !repo.join("target/release/cachydpi").exists() {
        eprintln!("skipping: target/release/cachydpi not built");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let etc = dir.path().join("etc/cachydpi");
    fs::create_dir_all(&etc).unwrap();
    let config = etc.join("config.toml");
    let operator_config = "[domains]\nmode = \"none\"\n# hand-tuned\n";
    fs::write(&config, operator_config).unwrap();

    let out = Command::new("make")
        .args(["install", "PREFIX=/usr", "SYSCONFDIR=/etc"])
        .arg(format!("DESTDIR={}", dir.path().display()))
        .current_dir(&repo)
        .output()
        .expect("failed to run make install");
    assert!(
        out.status.success(),
        "make install failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    assert_eq!(
        fs::read_to_string(&config).unwrap(),
        operator_config,
        "make install overwrote an existing config"
    );
    // …and the pristine copy the recovery docs point at is installed.
    assert!(
        dir.path()
            .join("usr/share/doc/cachydpi/config.toml")
            .exists(),
        "a reference config must be installed for recovery"
    );
}

/// An upgrade from 1.0.x has to announce the config break, because
/// /etc/cachydpi/config.toml is never replaced and an old one can stop the
/// daemon from starting.
#[test]
fn post_upgrade_announces_the_breaking_config_change() {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    if Command::new("vercmp").arg("1").arg("1").output().is_err() {
        eprintln!("skipping: vercmp (pacman) not available");
        return;
    }

    let run = |from: &str| -> String {
        let script = format!(
            "source ./cachydpi.install; systemd-sysusers() {{ :; }}; \
             systemd-tmpfiles() {{ :; }}; post_upgrade 1.2.0 {from}"
        );
        let out = Command::new("bash")
            .arg("-c")
            .arg(script)
            .current_dir(&repo)
            .output()
            .expect("failed to run post_upgrade");
        String::from_utf8_lossy(&out.stdout).into_owned()
    };

    let from_old = run("1.0.0");
    assert!(
        from_old.contains("BREAKING CHANGE"),
        "upgrading from 1.0.0 must announce the config break, got:\n{from_old}"
    );
    assert!(
        from_old.contains("[domains]") && from_old.contains("exempt"),
        "the announcement must name what changed, got:\n{from_old}"
    );

    let from_1_1 = run("1.1.1");
    assert!(
        from_1_1.contains("BREAKING CHANGE in 1.2.0") && from_1_1.contains("exempt"),
        "upgrading from 1.1.x must announce that \"whitelist\" is refused, got:\n{from_1_1}"
    );
    assert!(
        !from_1_1.contains("BREAKING CHANGE in 1.1.0"),
        "the 1.1.0 notice must not repeat for 1.1.x, got:\n{from_1_1}"
    );

    let from_new = run("1.2.0");
    assert!(
        !from_new.contains("BREAKING CHANGE"),
        "the announcement must not repeat on later upgrades, got:\n{from_new}"
    );
}
