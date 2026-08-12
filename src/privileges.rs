// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/privileges.rs — Linux privilege and capability management
//
// CachyDPI needs CAP_NET_ADMIN + CAP_NET_RAW to operate.
// This module handles:
// - Checking required capabilities
// - Dropping unnecessary privileges after initialization
// - Switching to a dedicated non-root user
// - Running with minimal capabilities

use anyhow::{Context, Result, bail};
use tracing::{debug, info, warn};

/// Capabilities needed during startup, before any privileges are dropped:
/// installing nftables rules, opening the nfqueue handles and the raw sockets.
const REQUIRED_CAPS: &[caps::Capability] = &[
    caps::Capability::CAP_NET_ADMIN, // For nfqueue and nftables
    caps::Capability::CAP_NET_RAW,   // For raw sockets
];

/// Capabilities kept *after* the drop.
///
/// Deliberately smaller than [`REQUIRED_CAPS`]: the raw sockets and the nfqueue
/// handles are opened during startup and keep working through their file
/// descriptors, so CAP_NET_RAW is never needed again and is given up for good.
/// CAP_NET_ADMIN has to stay because teardown shells out to `nft`, which needs
/// it in the child process.
const RETAINED_CAPS: &[caps::Capability] = &[caps::Capability::CAP_NET_ADMIN];

/// `SECBIT_NO_CAP_AMBIENT_RAISE` from linux/securebits.h — when set, no process
/// may add capabilities to its ambient set, which would leave the child `nft`
/// without CAP_NET_ADMIN after a setuid.
const SECBIT_NO_CAP_AMBIENT_RAISE: libc::c_int = 1 << 6;

/// Whether `NoNewPrivileges` is in effect (systemd hardening sets it).
fn no_new_privs() -> bool {
    unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1 }
}

/// Whether the kernel currently forbids raising ambient capabilities.
fn ambient_raise_forbidden() -> Result<bool> {
    let bits = unsafe { libc::prctl(libc::PR_GET_SECUREBITS, 0, 0, 0, 0) };
    if bits < 0 {
        bail!("prctl(PR_GET_SECUREBITS) failed");
    }
    Ok(bits & SECBIT_NO_CAP_AMBIENT_RAISE != 0)
}

/// Validate that the privilege drop we are about to perform can actually
/// succeed — *before* any external state such as nftables rules exists.
///
/// Running this first matters: if the drop failed afterwards the daemon would
/// exit having already installed rules, leaving exactly the stale ruleset that
/// teardown is supposed to prevent.
pub fn preflight_drop_root() -> Result<()> {
    if !nix::unistd::getuid().is_root() || no_new_privs() {
        // These paths only trim capabilities; nothing else to verify.
        return Ok(());
    }
    if nix::unistd::User::from_name("cachydpi")
        .context("failed to lookup cachydpi user")?
        .is_none()
    {
        // Falls back to trimming capabilities while staying root.
        return Ok(());
    }

    // The setuid path will be taken — check what it depends on.
    if ambient_raise_forbidden()? {
        bail!(
            "SECBIT_NO_CAP_AMBIENT_RAISE is set, so CAP_NET_ADMIN cannot be made \
             ambient and nftables teardown would fail after switching user"
        );
    }
    let permitted =
        caps::read(None, caps::CapSet::Permitted).context("failed to read permitted capabilities")?;
    for &cap in RETAINED_CAPS {
        if !permitted.contains(&cap) {
            bail!("{cap:?} is not in the permitted set; cannot retain it across setuid");
        }
    }

    // Checking the preconditions is not the same as checking the operation.
    // A uid that is not mapped into the current user namespace passes every
    // test above and still fails at setuid — after the rules are installed,
    // which is precisely the point of no return this gate exists to stay ahead
    // of. So rehearse the whole transition in a child process.
    let user = nix::unistd::User::from_name("cachydpi")
        .context("failed to lookup cachydpi user")?
        .expect("presence checked above");
    match rehearse_privilege_drop(&user)? {
        Rehearsal::Succeeded => {}
        Rehearsal::Failed => bail!(
            "switching to the cachydpi user (uid {}) is not possible here — the uid is \
             most likely not mapped into this user namespace",
            user.uid.as_raw()
        ),
        // Not evidence of anything, so do not block on it. If the real drop
        // does fail later, startup aborts and the nftables rules are removed
        // again on the way out.
        Rehearsal::Inconclusive(why) => warn!(
            "could not verify the privilege drop before installing rules ({why}) — \
             continuing"
        ),
    }

    debug!("privilege drop preflight passed (setuid to cachydpi is viable)");
    Ok(())
}

/// Perform the privilege drop in a throwaway child and report whether it worked.
///
/// The drop is irreversible, so it cannot be tried in the daemon itself, and
/// reading uid_map or securebits only tells us about the preconditions. Forking
/// exercises the real syscalls — setgid, setuid and the ambient raise — while
/// the parent is still able to abort cleanly.
///
/// Safe to fork here: preflight runs before any thread is spawned.
fn rehearse_privilege_drop(user: &nix::unistd::User) -> Result<Rehearsal> {
    match unsafe { nix::unistd::fork() } {
        Ok(nix::unistd::ForkResult::Child) => {
            let ok = unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) } == 0
                && nix::unistd::setgroups(&[]).is_ok()
                && nix::unistd::setgid(user.gid).is_ok()
                && nix::unistd::setuid(user.uid).is_ok()
                && raise_retained_caps().is_ok();
            // _exit, not exit: this child must not run atexit handlers or
            // flush the parent's buffers.
            unsafe { libc::_exit(i32::from(!ok)) }
        }
        Ok(nix::unistd::ForkResult::Parent { child }) => {
            Ok(classify_rehearsal(nix::sys::wait::waitpid(child, None)))
        }
        Err(e) => bail!("could not fork to rehearse the privilege drop: {e}"),
    }
}

/// Turn the child's wait status into a verdict.
///
/// Split out from the fork so the classification can be tested directly: the
/// distinction that matters is invisible in an exit code alone.
fn classify_rehearsal(status: nix::Result<nix::sys::wait::WaitStatus>) -> Rehearsal {
    use nix::sys::wait::WaitStatus;
    match status {
        Ok(WaitStatus::Exited(_, 0)) => Rehearsal::Succeeded,
        // A non-zero exit is the child reporting that a syscall refused.
        Ok(WaitStatus::Exited(_, _)) => Rehearsal::Failed,
        // Killed by a signal — the OOM killer, or a SIGTERM aimed at the
        // process group during startup. That says nothing about whether the
        // uid switch works, so it must not be reported as a failure and stop a
        // daemon that would have run fine.
        Ok(WaitStatus::Signaled(_, signal, _)) => {
            Rehearsal::Inconclusive(format!("the rehearsal was killed by {signal:?}"))
        }
        Ok(other) => Rehearsal::Inconclusive(format!("the rehearsal ended unexpectedly: {other:?}")),
        Err(e) => Rehearsal::Inconclusive(format!("could not wait for the rehearsal: {e}")),
    }
}

/// Outcome of [`rehearse_privilege_drop`].
///
/// Deliberately three-valued: "the child did not exit 0" covers both a real
/// setuid failure and the rehearsal being killed for unrelated reasons, and
/// treating the second as the first would abort startup over an OOM kill.
enum Rehearsal {
    Succeeded,
    Failed,
    Inconclusive(String),
}

/// Restore the retained capabilities after a uid change and make them ambient.
///
/// Shared by the real drop and its rehearsal so the two cannot drift: a
/// rehearsal that tested a different sequence would be worth very little.
fn raise_retained_caps() -> Result<()> {
    let retained: std::collections::HashSet<caps::Capability> =
        RETAINED_CAPS.iter().copied().collect();

    // KEEPCAPS carried the *permitted* set across the uid change, but the
    // kernel clears the *effective* set whenever the euid changes, so it has to
    // be raised again by hand. That order is not optional: ambient raise
    // requires the capability to be present in both permitted and inheritable
    // at the time of the call.
    caps::set(None, caps::CapSet::Effective, &retained)
        .context("failed to restore effective capabilities after setuid")?;
    caps::set(None, caps::CapSet::Permitted, &retained)
        .context("failed to restore permitted capabilities after setuid")?;
    caps::set(None, caps::CapSet::Inheritable, &retained)
        .context("failed to set inheritable capabilities")?;

    // Only the ambient set survives execve for a non-root process. The
    // inheritable set alone would leave the `nft` child with nothing, which is
    // how teardown used to fail silently.
    for &cap in RETAINED_CAPS {
        caps::raise(None, caps::CapSet::Ambient, cap)
            .with_context(|| format!("failed to raise {cap:?} into the ambient set"))?;
    }
    Ok(())
}

/// Confirm the process really ended up in the intended state.
///
/// Without this the daemon could report a successful privilege drop while
/// holding no usable capability — the ambiguous state that made the previous
/// implementation look correct while `nft` silently lost CAP_NET_ADMIN.
fn verify_dropped_state() -> Result<()> {
    if nix::unistd::geteuid().is_root() {
        bail!("privilege drop reported success but the process is still root");
    }
    for &cap in RETAINED_CAPS {
        if !caps::has_cap(None, caps::CapSet::Effective, cap).unwrap_or(false) {
            bail!("{cap:?} missing from the effective set after setuid");
        }
        // Ambient is what actually survives execve into the `nft` child;
        // inheritable alone grants a non-root child nothing.
        if !caps::has_cap(None, caps::CapSet::Ambient, cap).unwrap_or(false) {
            bail!("{cap:?} missing from the ambient set — child processes such as nft would run without it");
        }
    }
    // What we deliberately gave up must really be gone.
    if caps::has_cap(None, caps::CapSet::Permitted, caps::Capability::CAP_NET_RAW).unwrap_or(false) {
        bail!("CAP_NET_RAW is still permitted after the drop");
    }
    Ok(())
}

/// Check that the process has the required capabilities.
/// Returns an error with a helpful message if not.
pub fn check_capabilities() -> Result<()> {
    let effective =
        caps::read(None, caps::CapSet::Effective).context("failed to read process capabilities")?;

    let mut missing = Vec::new();
    for &cap in REQUIRED_CAPS {
        if !effective.contains(&cap) {
            missing.push(format!("{:?}", cap));
        }
    }

    if !missing.is_empty() {
        bail!(
            "missing required capabilities: {}. \
             Run as root or use: setcap cap_net_admin,cap_net_raw=eip cachydpi",
            missing.join(", ")
        );
    }

    debug!("all required capabilities present");
    Ok(())
}

/// Drop all capabilities except those required for ongoing operation.
///
/// After nftables rules are installed and nfqueue is opened, we only need
/// CAP_NET_ADMIN and CAP_NET_RAW. Everything else is dropped.
pub fn drop_unnecessary_caps() -> Result<()> {
    // Runs after the sockets and queues are open, so the startup-only
    // capabilities (CAP_NET_RAW) go too — see RETAINED_CAPS.
    let required: std::collections::HashSet<caps::Capability> =
        RETAINED_CAPS.iter().copied().collect();

    // Clear the permitted set of all non-required caps
    let permitted = caps::read(None, caps::CapSet::Permitted)
        .context("failed to read permitted capabilities")?;

    for cap in &permitted {
        if !required.contains(cap) {
            let _ = caps::drop(None, caps::CapSet::Effective, *cap);
            let _ = caps::drop(None, caps::CapSet::Permitted, *cap);
        }
    }

    // Clear inheritable set of non-retained caps. Inheritable alone grants a
    // non-root child nothing — it is a precondition for raising the ambient
    // set, which is what actually survives execve (see drop_root).
    let inheritable = caps::read(None, caps::CapSet::Inheritable).unwrap_or_default();
    for cap in &inheritable {
        if !required.contains(cap) {
            let _ = caps::drop(None, caps::CapSet::Inheritable, *cap);
        }
    }

    debug!("dropped unnecessary capabilities, keeping {RETAINED_CAPS:?}");
    Ok(())
}

/// Switch to a non-root user if currently running as root.
///
/// When systemd sets NoNewPrivileges=yes, setuid/setgroups are blocked.
/// In that case (or if the cachydpi user doesn't exist), we fall back
/// to simply dropping unnecessary capabilities while staying as root.
pub fn drop_root() -> Result<()> {
    let uid = nix::unistd::getuid();
    if !uid.is_root() {
        debug!(
            "not running as root (uid={}), dropping unnecessary capabilities",
            uid
        );
        drop_unnecessary_caps()?;
        return Ok(());
    }

    // Check if NoNewPrivileges is set (prevents setuid/setgroups)
    let nnp = unsafe { libc::prctl(libc::PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) };
    if nnp == 1 {
        info!(
            "NoNewPrivileges is set (systemd hardening) — skipping setuid, dropping capabilities only"
        );
        drop_unnecessary_caps()?;
        return Ok(());
    }

    // Try to switch to the dedicated 'cachydpi' user
    match nix::unistd::User::from_name("cachydpi").context("failed to lookup cachydpi user")? {
        Some(user) => {
            // Tell the kernel to preserve capabilities across setuid
            unsafe {
                if libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) != 0 {
                    bail!("prctl(PR_SET_KEEPCAPS) failed");
                }
            }

            // Switch supplementary groups, GID, then UID (order matters)
            nix::unistd::setgroups(&[]).context("failed to clear supplementary groups")?;
            nix::unistd::setgid(user.gid).context("failed to setgid to cachydpi")?;
            nix::unistd::setuid(user.uid).context("failed to setuid to cachydpi")?;

            // Same sequence the preflight rehearsed, deliberately shared.
            raise_retained_caps()?;

            // Disable keepcaps now that we're done
            unsafe {
                libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0);
            }

            // Refuse to run on in an ambiguous state.
            verify_dropped_state()?;

            info!(
                uid = nix::unistd::getuid().as_raw(),
                gid = user.gid.as_raw(),
                retained = ?RETAINED_CAPS,
                "dropped root privileges to cachydpi user"
            );
        }
        None => {
            warn!("cachydpi user not found — continuing as root with reduced capabilities");
            drop_unnecessary_caps()?;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use nix::unistd::{ForkResult, fork};

    /// The setuid path needs root, a resolvable cachydpi uid that is mapped in
    /// the current user namespace, and no NoNewPrivileges. A plain `cargo test`
    /// has none of that, so these tests skip unless run as:
    ///   unshare -Urn --map-auto --map-root-user cargo test --lib privileges::
    fn setuid_path_available() -> Option<nix::unistd::User> {
        if !nix::unistd::getuid().is_root() {
            crate::testing::skip_unless_required(
                "not root (try `unshare -Urn --map-auto --map-root-user`)",
            );
            return None;
        }
        if no_new_privs() {
            crate::testing::skip_unless_required("NoNewPrivileges is set, the setuid path cannot run");
            return None;
        }
        match nix::unistd::User::from_name("cachydpi") {
            Ok(Some(user)) => Some(user),
            _ => {
                crate::testing::skip_unless_required("no cachydpi user on this system");
                None
            }
        }
    }

    /// Run `body` in a forked child and return its exit code. The privilege
    /// drop is irreversible, so it must not happen in the test process itself.
    fn in_forked_child(body: impl FnOnce() -> i32) -> Option<i32> {
        match unsafe { fork() } {
            Ok(ForkResult::Child) => {
                let code = body();
                unsafe { libc::_exit(code) };
            }
            Ok(ForkResult::Parent { child }) => match nix::sys::wait::waitpid(child, None) {
                Ok(nix::sys::wait::WaitStatus::Exited(_, code)) => Some(code),
                other => {
                    crate::testing::skip_unless_required(&format!("child did not exit normally: {other:?}"));
                    None
                }
            },
            Err(e) => {
                crate::testing::skip_unless_required(&format!("fork failed ({e})"));
                None
            }
        }
    }

    /// A rehearsal killed by a signal says nothing about whether the uid switch
    /// works. Folding it in with a non-zero exit would abort startup over an
    /// OOM kill or a SIGTERM aimed at the process group.
    #[test]
    fn a_signalled_rehearsal_is_inconclusive_not_a_failure() {
        use nix::sys::signal::Signal;
        use nix::sys::wait::WaitStatus;
        let pid = nix::unistd::Pid::from_raw(1234);

        assert!(matches!(
            classify_rehearsal(Ok(WaitStatus::Exited(pid, 0))),
            Rehearsal::Succeeded
        ));
        assert!(
            matches!(
                classify_rehearsal(Ok(WaitStatus::Exited(pid, 1))),
                Rehearsal::Failed
            ),
            "a non-zero exit is the child reporting a refused syscall"
        );
        assert!(
            matches!(
                classify_rehearsal(Ok(WaitStatus::Signaled(pid, Signal::SIGKILL, false))),
                Rehearsal::Inconclusive(_)
            ),
            "a signalled rehearsal must not be reported as a failed uid switch"
        );
        assert!(
            matches!(
                classify_rehearsal(Err(nix::errno::Errno::ECHILD)),
                Rehearsal::Inconclusive(_)
            ),
            "not being able to wait is not evidence that setuid is impossible"
        );
    }

    /// The ordering trap that ambient raising depends on: PR_SET_KEEPCAPS
    /// carries the *permitted* set across the uid change, but the kernel clears
    /// the *effective* set when the euid changes, so effective has to be raised
    /// again by hand before anything else works.
    #[test]
    fn keepcaps_preserves_permitted_but_effective_is_cleared_by_setuid() {
        let Some(user) = setuid_path_available() else {
            return;
        };
        const OK: i32 = 0;
        const KEEPCAPS_FAILED: i32 = 1;
        const SETUID_FAILED: i32 = 2;
        const PERMITTED_LOST: i32 = 3;
        const EFFECTIVE_SURVIVED: i32 = 4;
        const RERAISE_FAILED: i32 = 5;

        let code = in_forked_child(move || {
            let cap = caps::Capability::CAP_NET_ADMIN;
            if unsafe { libc::prctl(libc::PR_SET_KEEPCAPS, 1, 0, 0, 0) } != 0 {
                return KEEPCAPS_FAILED;
            }
            if nix::unistd::setgid(user.gid).is_err() || nix::unistd::setuid(user.uid).is_err() {
                return SETUID_FAILED;
            }

            // KEEPCAPS did its job…
            if !caps::has_cap(None, caps::CapSet::Permitted, cap).unwrap_or(false) {
                return PERMITTED_LOST;
            }
            // …but effective was wiped by the euid change.
            if caps::has_cap(None, caps::CapSet::Effective, cap).unwrap_or(false) {
                return EFFECTIVE_SURVIVED;
            }
            // Which is why it must be raised manually before ambient raise can
            // work (ambient requires permitted *and* inheritable).
            let want: std::collections::HashSet<_> = [cap].into_iter().collect();
            if caps::set(None, caps::CapSet::Effective, &want).is_err()
                || caps::set(None, caps::CapSet::Inheritable, &want).is_err()
                || caps::raise(None, caps::CapSet::Ambient, cap).is_err()
            {
                return RERAISE_FAILED;
            }
            OK
        });

        match code {
            None => {}
            Some(OK) => {}
            Some(PERMITTED_LOST) => panic!("PR_SET_KEEPCAPS did not preserve the permitted set"),
            Some(EFFECTIVE_SURVIVED) => {
                panic!("effective set survived the uid change — the manual re-raise assumption is wrong")
            }
            Some(RERAISE_FAILED) => panic!("re-raising effective/inheritable/ambient failed"),
            Some(other) => panic!("child could not reach the assertions (code {other})"),
        }
    }

    /// End to end: after drop_root the process is unprivileged, keeps
    /// CAP_NET_ADMIN in the ambient set, has genuinely given up CAP_NET_RAW,
    /// and — the part that actually matters — a child `nft` still gets
    /// CAP_NET_ADMIN, which is what teardown depends on.
    #[test]
    fn drop_root_leaves_a_child_nft_able_to_use_net_admin() {
        if setuid_path_available().is_none() {
            return;
        }
        if crate::rules::check_nft_available().is_err() {
            crate::testing::skip_unless_required("nft not available");
            return;
        }
        const OK: i32 = 0;
        const DROP_FAILED: i32 = 1;
        const STILL_ROOT: i32 = 2;
        const AMBIENT_MISSING: i32 = 3;
        const NET_RAW_RETAINED: i32 = 4;
        const CHILD_NFT_FAILED: i32 = 5;

        let code = in_forked_child(|| {
            if drop_root().is_err() {
                return DROP_FAILED;
            }
            if nix::unistd::geteuid().is_root() {
                return STILL_ROOT;
            }
            if !caps::has_cap(
                None,
                caps::CapSet::Ambient,
                caps::Capability::CAP_NET_ADMIN,
            )
            .unwrap_or(false)
            {
                return AMBIENT_MISSING;
            }
            // CAP_NET_RAW was only needed to open the sockets; it must be gone.
            if caps::has_cap(
                None,
                caps::CapSet::Permitted,
                caps::Capability::CAP_NET_RAW,
            )
            .unwrap_or(false)
            {
                return NET_RAW_RETAINED;
            }

            // A populated ambient set is not the claim being tested — that the
            // execve'd child really receives the capability is. Ambient is
            // cleared when execve'ing a setuid binary or one carrying file
            // capabilities, so this exercises the real `nft` on this system.
            let mut rules = crate::rules::NftRules::new(200, true);
            if rules.install().is_err() || rules.remove().is_err() {
                return CHILD_NFT_FAILED;
            }
            OK
        });

        match code {
            None => {}
            Some(OK) => {}
            Some(AMBIENT_MISSING) => panic!("CAP_NET_ADMIN is not in the ambient set after the drop"),
            Some(NET_RAW_RETAINED) => panic!("CAP_NET_RAW was retained even though it is not needed"),
            Some(CHILD_NFT_FAILED) => {
                panic!("child nft could not manage rules — ambient capability did not reach it")
            }
            Some(STILL_ROOT) => panic!("drop_root reported success but the process is still root"),
            Some(other) => panic!("privilege drop failed (code {other})"),
        }
    }
}

/// Set the process name for ps/htop visibility
pub fn set_process_name() {
    // Set comm name via prctl
    unsafe {
        let name = b"cachydpi\0";
        libc::prctl(libc::PR_SET_NAME, name.as_ptr() as libc::c_ulong, 0, 0, 0);
    }
}
