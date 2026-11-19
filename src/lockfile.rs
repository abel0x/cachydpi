// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/lockfile.rs — exclusive locks that only root and the service user can hold
//
// The kernel releases an flock when its holder exits, however it exits, so a
// lock taken here never needs recovering after a crash. What needs care is who
// can take it: flock works on a read-only descriptor, so any account that can
// open the file can hold the lock and keep the daemon or a command from
// running. The file is therefore 0600 and owned by its directory's owner.

use std::fs::File;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg};

/// Where the locks live. Under systemd this is the unit's `RuntimeDirectory`,
/// the one place `ProtectSystem=strict` leaves writable; only root and the
/// service user can write to it.
pub const LOCK_DIR: &str = "/run/cachydpi";

/// A held lock. Dropping it releases the lock; the file stays, because
/// unlinking a lock file others may be waiting on lets two holders exist.
pub struct Held {
    _lock: Flock<File>,
    pub path: PathBuf,
}

/// Take an exclusive lock on `dir/name` without waiting.
///
/// `Ok(None)` means another process holds it. `dir` is created if missing.
pub fn try_exclusive(dir: &Path, name: &str) -> Result<Option<Held>> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};

    match std::fs::DirBuilder::new().mode(0o755).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e).with_context(|| format!("cannot create {}", dir.display())),
    }
    let path = dir.join(name);
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
        .with_context(|| format!("cannot open the lock {}", path.display()))?;

    // A root run may create the file; hand it to the directory's owner so the
    // service user can still open it afterwards. Only root can change the
    // owner, and nobody else needs to.
    if let (Ok(d), Ok(f)) = (std::fs::metadata(dir), file.metadata())
        && (f.uid(), f.gid()) != (d.uid(), d.gid())
    {
        let _ = std::os::unix::fs::fchown(&file, Some(d.uid()), Some(d.gid()));
    }

    match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
        Ok(lock) => Ok(Some(Held { _lock: lock, path })),
        Err((_, Errno::EWOULDBLOCK)) => Ok(None),
        Err((_, e)) => Err(e).with_context(|| format!("cannot lock {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_held_lock_excludes_others_until_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let first = try_exclusive(dir.path(), "x.lock").unwrap().expect("free");
        assert!(try_exclusive(dir.path(), "x.lock").unwrap().is_none());
        assert!(
            try_exclusive(dir.path(), "y.lock").unwrap().is_some(),
            "names are independent"
        );
        drop(first);
        assert!(try_exclusive(dir.path(), "x.lock").unwrap().is_some());
    }

    #[test]
    fn the_lock_file_is_closed_to_other_accounts() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let held = try_exclusive(dir.path(), "x.lock").unwrap().unwrap();
        let mode = std::fs::metadata(&held.path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn a_symlink_is_not_followed() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("elsewhere");
        std::fs::write(&target, "keep").unwrap();
        std::os::unix::fs::symlink(&target, dir.path().join("x.lock")).unwrap();
        assert!(try_exclusive(dir.path(), "x.lock").is_err());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "keep");
    }
}
