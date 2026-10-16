// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
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
    quic: bool,
    adaptive: bool,
    installed: bool,
}

/// How many packets of a connection, counted in one direction, can still
/// matter to the engine. The ClientHello follows the SYN and the handshake ACK
/// and spans at most three segments; the margin covers retransmissions.
/// Everything after this goes straight through the kernel.
const OUTBOUND_PACKETS: u32 = 10;
/// Reply packets in which an injected TLS alert can arrive. A DPI box answers
/// the ClientHello at once, ahead of the server's own first flight.
const INBOUND_PACKETS: u32 = 16;
/// An injected HTTP redirect is a short response; a download is full-size
/// segments, and none of those need to leave the kernel.
const HTTP_RESPONSE_MAX_LEN: u32 = 1000;
/// Reply packets in which mode 7 looks for the server's first data. The
/// server ACKs each segment of a split or reordered ClientHello on its own,
/// so after the SYN-ACK up to three empty ACKs, plus duplicates for
/// out-of-order segments, can come before its first flight. At 4 the first
/// flight often fell outside the window, and the teardown RST of a healthy
/// connection then read as a reset before any answer.
const ANSWER_PACKETS: u32 = 8;

impl NftRules {
    pub fn new(queue_num: u16, ipv6: bool) -> Self {
        NftRules {
            queue_num,
            ipv6,
            quic: false,
            adaptive: false,
            installed: false,
        }
    }

    /// Queue the first packets of QUIC connections. Only worth doing when
    /// QUIC desync is going to act on them: otherwise every QUIC packet would
    /// make a round trip through the daemon to be accepted unchanged.
    pub fn with_quic(mut self, quic: bool) -> Self {
        self.quic = quic;
        self
    }

    /// Queue the server's first large reply packets, for mode 7: an answer
    /// tells it the handshake got through, and an RST before any answer that
    /// it did not.
    pub fn with_adaptive(mut self, adaptive: bool) -> Self {
        self.adaptive = adaptive;
        self
    }

    /// The nft script `install` applies.
    ///
    /// `ct original packets` / `ct reply packets` cap queueing to the start of
    /// each connection. Using them makes the kernel turn on conntrack
    /// accounting for the namespace, so they work whatever
    /// net.netfilter.nf_conntrack_acct was.
    pub fn ruleset_script(&self) -> String {
        let quic = if self.quic {
            format!(
                "        udp dport 443 ct original packets <= 4 queue num {} bypass\n",
                self.queue_num
            )
        } else {
            String::new()
        };
        let answers = if self.adaptive {
            format!(
                "        tcp sport 443 tcp flags & ack == ack meta length >= 120 ct reply packets <= {ANSWER_PACKETS} queue num {} bypass\n",
                self.queue_num + 1
            )
        } else {
            String::new()
        };
        let mut families = vec!["ip"];
        if self.ipv6 {
            families.push("ip6");
        }
        families
            .into_iter()
            .map(|family| {
                format!(
                    r#"
table {family} {table} {{
    chain output {{
        type filter hook output priority 0; policy accept;

        # Skip packets already processed by CachyDPI (marked)
        meta mark {mark:#x} accept

        # Outgoing HTTP requests
        tcp dport {{ 80, 8080 }} tcp flags & (syn|psh|ack) == psh|ack queue num {queue} bypass

        # Outgoing HTTPS data at the start of a connection, for the ClientHello.
        # ACK rather than PSH|ACK: the non-final segments of a ClientHello
        # spanning several carry no PSH. meta length > 80 skips empty ACKs.
        tcp dport 443 tcp flags & ack == ack meta length > 80 ct original packets <= {out_pkts} queue num {queue} bypass

        # Outgoing SYN: window size, and the start of the per-connection record
        tcp dport {{ 80, 443, 8080 }} tcp flags & (syn|ack) == syn queue num {queue} bypass
{quic}    }}

    chain input {{
        type filter hook input priority 0; policy accept;

        # RSTs, judged against the server's hop count
        tcp sport {{ 80, 443, 8080 }} tcp flags & rst == rst queue num {queue_in} bypass

        # SYN-ACKs: the server's hop count, and auto-TTL
        tcp sport {{ 80, 443, 8080 }} tcp flags & (syn|ack) == syn|ack queue num {queue_in} bypass

        # Short HTTP responses, for injected redirects
        tcp sport 80 tcp flags & (psh|ack) == psh|ack meta length <= {http_len} queue num {queue_in} bypass

        # Small TLS records early in a connection, for injected alerts
        tcp sport 443 tcp flags & (psh|ack) == psh|ack meta length < 120 ct reply packets <= {in_pkts} queue num {queue_in} bypass
{answers}    }}
}}
"#,
                    table = NFT_TABLE,
                    mark = CACHYDPI_MARK,
                    queue = self.queue_num,
                    queue_in = self.queue_num + 1,
                    out_pkts = OUTBOUND_PACKETS,
                    in_pkts = INBOUND_PACKETS,
                    http_len = HTTP_RESPONSE_MAX_LEN,
                )
            })
            .collect()
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

        let nft_script = self.ruleset_script();

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

        let mut failed: Vec<String> = Vec::new();
        let mut first_err: Option<anyhow::Error> = None;
        for family in ["ip", "ip6"] {
            let script = format!(
                "table {family} {table}\ndelete table {family} {table}\n",
                family = family,
                table = NFT_TABLE
            );
            // Keep going after a failure so one family cannot block the other.
            if let Err(e) = self.run_nft(&script) {
                failed.push(family.to_string());
                if first_err.is_none() {
                    first_err = Some(e);
                }
            }
        }

        self.installed = false;

        // Splitting the families means teardown is no longer atomic across
        // them, so a partial result is possible. Name what is still in place
        // instead of letting the caller report a clean removal.
        match first_err {
            Some(e) => Err(e.context(format!(
                "nftables teardown incomplete — table {} still present for: {}",
                NFT_TABLE,
                failed.join(", ")
            ))),
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
            crate::testing::skip_unless_required("nft not available");
            return false;
        }
        let mut probe = NftRules::new(200, true);
        if probe.install().is_err() {
            crate::testing::skip_unless_required(
                "cannot install nftables rules (needs CAP_NET_ADMIN - try `unshare -Urn`)",
            );
            return false;
        }
        let _ = probe.remove();
        true
    }

    fn line_with<'a>(script: &'a str, needle: &str) -> &'a str {
        script
            .lines()
            .find(|l| l.contains(needle))
            .unwrap_or_else(|| panic!("no rule containing {needle:?} in:\n{script}"))
    }

    /// Once the ClientHello is past, a connection's traffic has nothing left
    /// to give the engine; queueing it anyway sent every upload through a
    /// daemon held to a quarter of a CPU.
    #[test]
    fn only_the_start_of_a_connection_is_queued() {
        let script = NftRules::new(200, false).ruleset_script();
        assert!(line_with(&script, "tcp dport 443").contains("ct original packets <= 10"));
        assert!(
            line_with(&script, "tcp sport 443 tcp flags & (psh|ack)")
                .contains("ct reply packets <= 16")
        );
        assert!(
            line_with(&script, "tcp sport 80 tcp flags & (psh|ack)")
                .contains("meta length <= 1000")
        );
    }

    #[test]
    fn server_answers_are_queued_only_for_mode_7() {
        let plain = NftRules::new(200, false).ruleset_script();
        assert!(!plain.contains("meta length >= 120"));
        let adaptive = NftRules::new(200, false)
            .with_adaptive(true)
            .ruleset_script();
        assert!(
            line_with(&adaptive, "meta length >= 120")
                .contains("ct reply packets <= 8 queue num 201")
        );
    }

    /// The regression: against a reordered three-way split, a server sent
    /// the SYN-ACK, three empty ACKs, and only then its first data, the fifth
    /// reply packet, which a window of 4 never queued.
    #[test]
    fn the_answer_window_reaches_past_the_acks_of_a_split_client_hello() {
        let syn_ack = 1;
        let acks_for_three_segments = 3;
        assert!(ANSWER_PACKETS > syn_ack + acks_for_three_segments);
    }

    /// QUIC used to be queued whole whether or not anything would act on it.
    #[test]
    fn quic_is_queued_only_when_desync_will_use_it() {
        let off = NftRules::new(200, true).ruleset_script();
        assert!(!off.contains("udp dport 443"), "{off}");
        let on = NftRules::new(200, true).with_quic(true).ruleset_script();
        assert_eq!(
            on.matches("udp dport 443 ct original packets <= 4").count(),
            2
        );
    }

    #[test]
    fn ip6_table_mirrors_ip_and_appears_only_with_ipv6() {
        let v4 = NftRules::new(200, false).ruleset_script();
        assert!(v4.contains("table ip cachydpi") && !v4.contains("table ip6"));
        let both = NftRules::new(200, true).ruleset_script();
        let (ip, ip6) = both.split_at(both.find("table ip6").unwrap());
        assert_eq!(
            ip.trim().replace("table ip ", ""),
            ip6.trim().replace("table ip6 ", "")
        );
    }

    /// The optional rules are only text until nft accepts them.
    #[test]
    fn every_optional_rule_installs() {
        let _guard = NFT_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if !nft_writable() {
            return;
        }
        let mut rules = NftRules::new(200, true).with_quic(true).with_adaptive(true);
        rules
            .install()
            .expect("nft must accept the QUIC and mode 7 rules");
        let dump = ruleset_dump();
        assert!(dump.contains("udp dport 443"), "{dump}");
        assert!(
            dump.contains(&format!("ct reply packets <= {ANSWER_PACKETS}")),
            "{dump}"
        );
        rules.remove().unwrap();
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

    /// The Drop path is what cleans up when startup fails after the rules are
    /// installed — main returning Err drops the NftRules value. It therefore
    /// only ever runs on the error path and would otherwise never be exercised,
    /// which is how a broken cleanup would stay invisible until the day it
    /// matters and leaves a live ruleset behind.
    #[test]
    fn dropping_installed_rules_cleans_them_up() {
        let _guard = NFT_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        if !nft_writable() {
            return;
        }

        {
            let mut rules = NftRules::new(200, true);
            rules.install().expect("install should succeed");
            assert!(
                ruleset_dump().contains(NFT_TABLE),
                "rules should be present before the value is dropped"
            );
            // Falling out of scope here stands in for main returning Err.
        }

        let after = ruleset_dump();
        assert!(
            !after.contains(NFT_TABLE),
            "dropping installed rules must remove them, got:\n{after}"
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
