// src/rules.rs — nftables rule management
//
// Automatically creates and removes nftables rules to queue packets
// to NFQUEUE for processing by the CachyDPI daemon.
//
// Rules are placed in a dedicated nftables table "cachydpi" to avoid
// conflicts with existing firewall rules.

use anyhow::{Context, Result, bail};
use tracing::{debug, info, warn};

use crate::rawsocket::CACHYDPI_MARK;

/// Name of the nftables table used by CachyDPI
const NFT_TABLE: &str = "cachydpi";

/// Default NFQUEUE number
pub const DEFAULT_QUEUE_NUM: u16 = 200;

/// Manages nftables rules for packet queueing
pub struct NftRules {
    queue_num: u16,
    ipv6: bool,
    installed: bool,
}

impl NftRules {
    pub fn new(queue_num: u16, ipv6: bool) -> Self {
        NftRules {
            queue_num,
            ipv6,
            installed: false,
        }
    }

    /// Install nftables rules to queue HTTP/HTTPS/QUIC packets.
    ///
    /// Creates a table "cachydpi" with chains for OUTPUT (outbound)
    /// and INPUT (inbound, for passive DPI detection).
    pub fn install(&mut self) -> Result<()> {
        info!(
            "installing nftables rules (table={}, queue={})",
            NFT_TABLE, self.queue_num
        );

        // Remove any stale rules from a previous run
        let _ = self.remove();

        let mut nft_script = String::new();

        // ── IPv4 rules ──
        nft_script.push_str(&format!(
            r#"
table ip {table} {{
    chain output {{
        type filter hook output priority 0; policy accept;

        # Skip packets already processed by CachyDPI (marked)
        meta mark {mark:#x} accept

        # Queue outgoing HTTP requests (port 80)
        tcp dport {{ 80, 8080 }} tcp flags & (syn|psh|ack) == psh|ack queue num {queue} bypass

        # Queue outgoing HTTPS (port 443) — for TLS ClientHello
        # Use ACK flag only (not PSH+ACK) because the OS may split
        # ClientHello across segments where non-final segments lack PSH.
        # meta length > 80 filters out empty ACKs.
        tcp dport 443 tcp flags & ack == ack meta length > 80 queue num {queue} bypass

        # Queue outgoing TCP SYN (for window size manipulation)
        tcp dport {{ 80, 443, 8080 }} tcp flags & (syn|ack) == syn queue num {queue} bypass

        # Queue outgoing QUIC/UDP (port 443)
        udp dport 443 queue num {queue} bypass
    }}

    chain input {{
        type filter hook input priority 0; policy accept;

        # Queue incoming TCP RST (for passive DPI detection)
        tcp sport {{ 80, 443, 8080 }} tcp flags & rst == rst queue num {queue_in} bypass

        # Queue incoming SYN-ACK (for auto-TTL detection from server response)
        tcp sport {{ 80, 443, 8080 }} tcp flags & (syn|ack) == syn|ack queue num {queue_in} bypass

        # Queue incoming HTTP responses from port 80 (for redirect detection)
        tcp sport 80 tcp flags & (psh|ack) == psh|ack queue num {queue_in} bypass

        # Queue incoming small TLS packets from port 443 (for forged TLS alert detection)
        # TLS alerts are tiny (< 120 bytes total); only queue small packets to avoid overhead
        tcp sport 443 tcp flags & (psh|ack) == psh|ack meta length < 120 queue num {queue_in} bypass
    }}
}}
"#,
            table = NFT_TABLE,
            mark = CACHYDPI_MARK,
            queue = self.queue_num,
            queue_in = self.queue_num + 1,
        ));

        // ── IPv6 rules ──
        if self.ipv6 {
            nft_script.push_str(&format!(
                r#"
table ip6 {table} {{
    chain output {{
        type filter hook output priority 0; policy accept;
        meta mark {mark:#x} accept
        tcp dport {{ 80, 8080 }} tcp flags & (syn|psh|ack) == psh|ack queue num {queue} bypass
        tcp dport 443 tcp flags & ack == ack meta length > 80 queue num {queue} bypass
        tcp dport {{ 80, 443, 8080 }} tcp flags & (syn|ack) == syn queue num {queue} bypass
        udp dport 443 queue num {queue} bypass
    }}

    chain input {{
        type filter hook input priority 0; policy accept;
        tcp sport {{ 80, 443, 8080 }} tcp flags & rst == rst queue num {queue_in} bypass
        tcp sport {{ 80, 443, 8080 }} tcp flags & (syn|ack) == syn|ack queue num {queue_in} bypass
        tcp sport 80 tcp flags & (psh|ack) == psh|ack queue num {queue_in} bypass
        tcp sport 443 tcp flags & (psh|ack) == psh|ack meta length < 120 queue num {queue_in} bypass
    }}
}}
"#,
                table = NFT_TABLE,
                mark = CACHYDPI_MARK,
                queue = self.queue_num,
                queue_in = self.queue_num + 1,
            ));
        }

        // Apply rules via nft
        self.run_nft(&nft_script)?;
        self.installed = true;

        info!("nftables rules installed successfully");
        Ok(())
    }

    /// Remove all CachyDPI nftables rules.
    ///
    /// Both families are cleaned regardless of the `ipv6` setting: an ip6 table
    /// installed by an earlier `ipv6 = true` run must not survive a later
    /// `ipv6 = false` teardown, or the machine does not return to its
    /// pre-start state and the stale rules keep steering IPv6 traffic into a
    /// queue whose daemon may no longer have an IPv6 raw socket.
    ///
    /// Each family is deleted with the `table <family> <name>` /
    /// `delete table <family> <name>` idiom: a bodyless `table` line creates
    /// the table when it is missing, so the following `delete` succeeds whether
    /// or not anything was installed — no spurious error on a clean system.
    /// The two families run as separate `nft` invocations on purpose, because
    /// `nft -f` applies a script as one transaction: a kernel without nf_tables
    /// IPv6 support would otherwise roll back the IPv4 deletion too.
    pub fn remove(&mut self) -> Result<()> {
        debug!("removing nftables rules (table={})", NFT_TABLE);

        let mut first_err: Option<anyhow::Error> = None;
        for family in ["ip", "ip6"] {
            let script = format!(
                "table {family} {table}\ndelete table {family} {table}\n",
                family = family,
                table = NFT_TABLE
            );
            // Keep going after a failure so one family cannot block the other.
            if let Err(e) = self.run_nft(&script)
                && first_err.is_none()
            {
                first_err = Some(e);
            }
        }

        self.installed = false;
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Check if rules are currently installed
    pub fn is_installed(&self) -> bool {
        self.installed
    }

    /// Mark rules as persistent so they won't be removed on drop
    pub fn set_persistent(&mut self) {
        self.installed = false;
    }

    /// Run an nft command
    fn run_nft(&self, script: &str) -> Result<()> {
        let output = std::process::Command::new("nft")
            .arg("-f")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                if let Some(ref mut stdin) = child.stdin {
                    stdin.write_all(script.as_bytes())?;
                }
                child.wait_with_output()
            })
            .context("failed to execute nft — is nftables installed?")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            warn!("nft command failed: {}", stderr.trim());
            bail!("nft failed: {}", stderr.trim());
        }

        Ok(())
    }

    /// Get the inbound queue number (outbound + 1)
    pub fn inbound_queue_num(&self) -> u16 {
        self.queue_num + 1
    }
}

impl Drop for NftRules {
    fn drop(&mut self) {
        if self.installed {
            info!("cleaning up nftables rules");
            if let Err(e) = self.remove() {
                warn!("failed to remove nftables rules on exit: {}", e);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The table name is a fixed global, so these tests must not run
    /// concurrently against the same netns.
    static NFT_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn ruleset_dump() -> String {
        std::process::Command::new("nft")
            .args(["list", "ruleset"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
            .unwrap_or_default()
    }

    /// These tests need nft plus CAP_NET_ADMIN, so a plain `cargo test` skips
    /// them. To actually exercise them in an isolated network namespace:
    ///   unshare -Urn cargo test --lib rules::
    fn nft_writable() -> bool {
        if check_nft_available().is_err() {
            eprintln!("skipping: nft not available");
            return false;
        }
        let mut probe = NftRules::new(200, true);
        if probe.install().is_err() {
            eprintln!("skipping: cannot install nftables rules (need CAP_NET_ADMIN — try `unshare -Urn`)");
            return false;
        }
        let _ = probe.remove();
        true
    }

    /// The regression: an ip6 table installed while ipv6 was enabled must be
    /// removed by a later teardown that runs with ipv6 disabled.
    #[test]
    fn teardown_removes_ip6_table_left_by_an_earlier_ipv6_run() {
        let _guard = NFT_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if !nft_writable() {
            return;
        }

        let mut with_v6 = NftRules::new(200, true);
        with_v6.install().expect("install with ipv6 should succeed");
        with_v6.set_persistent(); // leave the tables behind deliberately
        let installed = ruleset_dump();
        assert!(
            installed.contains(&format!("table ip6 {NFT_TABLE}")),
            "ipv6 install should create an ip6 table, got:\n{installed}"
        );

        // A later run configured without IPv6 still has to clean it up.
        let mut without_v6 = NftRules::new(200, false);
        without_v6.remove().expect("teardown must succeed");

        let after = ruleset_dump();
        assert!(
            !after.contains(NFT_TABLE),
            "no cachydpi trace may survive teardown, got:\n{after}"
        );
    }

    /// Acceptance criterion end to end: start(ipv6) → stop → start(no ipv6) →
    /// stop leaves nothing behind, and teardown on an already-clean system
    /// still succeeds (so start does not log a spurious nft error).
    #[test]
    fn start_stop_cycle_with_changing_ipv6_leaves_no_trace() {
        let _guard = NFT_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if !nft_writable() {
            return;
        }

        for ipv6 in [true, false] {
            let mut rules = NftRules::new(200, ipv6);
            rules.install().expect("install should succeed");
            assert!(
                ruleset_dump().contains(NFT_TABLE),
                "rules should be present while running (ipv6={ipv6})"
            );

            rules.remove().expect("teardown must succeed");
            let after = ruleset_dump();
            assert!(
                !after.contains(NFT_TABLE),
                "teardown left a trace (ipv6={ipv6}):\n{after}"
            );
        }

        // Idempotent and quiet: nothing installed, teardown still succeeds.
        let mut again = NftRules::new(200, false);
        again
            .remove()
            .expect("teardown on a clean system must not error");
    }
}

/// Check if nftables is available on the system
pub fn check_nft_available() -> Result<()> {
    let output = std::process::Command::new("nft")
        .arg("--version")
        .output()
        .context("nft command not found — install nftables: pacman -S nftables")?;

    if !output.status.success() {
        bail!("nft --version failed");
    }

    let version = String::from_utf8_lossy(&output.stdout);
    debug!("nftables version: {}", version.trim());
    Ok(())
}
