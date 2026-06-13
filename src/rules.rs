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

    /// Remove all CachyDPI nftables rules
    pub fn remove(&mut self) -> Result<()> {
        debug!("removing nftables rules (table={})", NFT_TABLE);

        // Delete IPv4 table
        let _ = self.run_nft(&format!("delete table ip {}", NFT_TABLE));

        // Delete IPv6 table
        if self.ipv6 {
            let _ = self.run_nft(&format!("delete table ip6 {}", NFT_TABLE));
        }

        self.installed = false;
        Ok(())
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
