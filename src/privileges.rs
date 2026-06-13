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

/// Required Linux capabilities for CachyDPI operation
const REQUIRED_CAPS: &[caps::Capability] = &[
    caps::Capability::CAP_NET_ADMIN, // For nfqueue and nftables
    caps::Capability::CAP_NET_RAW,   // For raw sockets
];

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
    let required: std::collections::HashSet<caps::Capability> =
        REQUIRED_CAPS.iter().copied().collect();

    // Clear the permitted set of all non-required caps
    let permitted = caps::read(None, caps::CapSet::Permitted)
        .context("failed to read permitted capabilities")?;

    for cap in &permitted {
        if !required.contains(cap) {
            let _ = caps::drop(None, caps::CapSet::Effective, *cap);
            let _ = caps::drop(None, caps::CapSet::Permitted, *cap);
        }
    }

    // Clear inheritable set of non-required caps (keep NET_ADMIN + NET_RAW
    // so that child processes like nft can inherit them via ambient caps)
    let inheritable = caps::read(None, caps::CapSet::Inheritable).unwrap_or_default();
    for cap in &inheritable {
        if !required.contains(cap) {
            let _ = caps::drop(None, caps::CapSet::Inheritable, *cap);
        }
    }

    debug!("dropped unnecessary capabilities, keeping NET_ADMIN + NET_RAW");
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

            // Re-acquire only required capabilities after setuid
            let required: std::collections::HashSet<caps::Capability> =
                REQUIRED_CAPS.iter().copied().collect();
            caps::set(None, caps::CapSet::Effective, &required)
                .context("failed to restore effective capabilities after setuid")?;
            caps::set(None, caps::CapSet::Permitted, &required)
                .context("failed to restore permitted capabilities after setuid")?;

            // Set inheritable to only required caps (for child processes like nft)
            caps::set(None, caps::CapSet::Inheritable, &required)
                .context("failed to set inheritable capabilities")?;

            // Disable keepcaps now that we're done
            unsafe {
                libc::prctl(libc::PR_SET_KEEPCAPS, 0, 0, 0, 0);
            }

            // Verify we are no longer root
            let new_uid = nix::unistd::getuid();
            if new_uid.is_root() {
                bail!("setuid succeeded but still running as root");
            }

            info!(
                uid = new_uid.as_raw(),
                gid = user.gid.as_raw(),
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

/// Set the process name for ps/htop visibility
pub fn set_process_name() {
    // Set comm name via prctl
    unsafe {
        let name = b"cachydpi\0";
        libc::prctl(libc::PR_SET_NAME, name.as_ptr() as libc::c_ulong, 0, 0, 0);
    }
}
