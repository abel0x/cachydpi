# CachyDPI — Real-World Validation Test Plan

**Evaluator Role:** Senior Network Test Engineer & Adversarial Systems Evaluator  
**Target:** CachyDPI v1.0.0  
**Date:** 2026-04-09  
**Scope:** Complete behavioral validation under real and hostile conditions

---

## TEST PLAN

---

### TC-001: Basic HTTPS Bypass — Known Blocked Domain

**Purpose:** Validate that TLS ClientHello SNI fragmentation actually defeats real DPI on a known blocked HTTPS site.

**Setup:**
- CachyDPI running, mode 5, auto_ttl=true
- Domain in blacklist (e.g., youtube.com)
- Direct ISP connection (no VPN)

**Steps:**
1. `sudo systemctl start cachydpi`
2. `curl -v --max-time 15 https://www.youtube.com 2>&1`
3. Record TLS handshake completion (Server Hello received)
4. `sudo cachydpi -m 5 --foreground -vvv &` — capture logs
5. Repeat curl, check logs for "TLS ClientHello detected, applying strategy"

**Expected Result:**
- TLS handshake completes (Server Hello, Certificate, Finished)
- HTTP 200 or 301/302 from real server (not block page)
- Logs show SNI fragmentation applied

**Failure Indicators:**
- `SSL_connect: Connection reset` → DPI still blocking
- Logs show "domain not in filter list, skipping" → blacklist not loaded
- No log output at all → nftables rules not matching

---

### TC-002: HTTP Bypass — Blocked HTTP Site

**Purpose:** Verify HTTP Host header fragmentation works against DPI redirect injection.

**Setup:**
- Mode 5, domain in blacklist
- Target: any domain blocked on port 80

**Steps:**
1. `curl -v --max-time 10 http://<blocked-domain> 2>&1`
2. Check for forged 302 redirect vs real response
3. Compare response with CachyDPI off vs on

**Expected Result:**
- With CachyDPI: Real server response received
- Without CachyDPI: DPI-injected 302 redirect to block page

**Failure Indicators:**
- Still receiving 302 redirect to block page
- Logs show "HTTP request detected" but fragmentation produces same result
- Connection timeout (DPI drops rather than redirects)

---

### TC-003: Mode 1 (Passive Only) — Forged RST Drop

**Purpose:** Validate that passive mode correctly identifies and drops DPI-injected RST packets without modifying outbound traffic.

**Setup:**
- Mode 1, passive_dpi=true
- Target: HTTPS blocked domain

**Steps:**
1. Start with `-m 1 --foreground -vvv`
2. `curl -v https://<blocked-domain>`
3. Monitor logs for "dropping forged RST packet from DPI"
4. Monitor with `tcpdump -i <iface> host <target-ip> and tcp[tcpflags] & tcp-rst != 0`

**Expected Result:**
- tcpdump shows inbound RST packets arriving
- Logs show them scored and dropped (score ≥ 4)
- Connection still may fail (passive only drops RST, doesn't fragment)

**Failure Indicators:**
- RST packets not reaching queue 201 → nftables INPUT rules missing
- RST scored < 4 (false negative) → DPI crafting RSTs with TCP options/non-zero window
- Connection succeeds → DPI was only using RST (passive mode was sufficient)

---

### TC-004: Forged RST Scoring — False Positive Test

**Purpose:** Ensure legitimate server RST packets are NOT dropped.

**Setup:**
- Mode 5, passive_dpi=true
- Target: a site that legitimately sends RST on connection close

**Steps:**
1. Connect to a service that normally RSTs (e.g., port scan a closed port)
2. `curl http://<non-blocked-site>:<closed-port>` 
3. Check logs — no "dropping forged RST" should appear
4. Test against a server deliberately configured to RST with non-zero window + options

**Expected Result:**
- Legitimate RSTs pass through (score < 4)
- Only DPI-signature RSTs (window=0, no options, TTL 64/128, RST|ACK) are dropped

**Failure Indicators:**
- Legitimate RSTs dropped → scoring threshold too low
- Legitimate connections to non-blocked sites break randomly
- Gaming/streaming connections drop mid-session

---

### TC-005: QUIC Desynchronization — UDP 443

**Purpose:** Validate QUIC Initial packet IP fragmentation in mode 6.

**Setup:**
- Mode 6 (Aggressive), quic_desync=true
- IPv4 connection only (IPv6 QUIC desync is unsupported)
- Target: YouTube or Google services that use QUIC

**Steps:**
1. `curl --http3 https://www.youtube.com` (if curl supports HTTP/3)
2. Alternatively, open Chrome with QUIC enabled
3. Monitor `tcpdump -i <iface> udp port 443`
4. Check for IP fragmented UDP datagrams (MF flag set)

**Expected Result:**
- QUIC Initial packets fragmented at IP layer
- Service loads successfully via QUIC
- tcpdump shows fragmented UDP 443 packets outbound

**Failure Indicators:**
- No fragmentation seen → nftables UDP 443 rule not matching
- Service falls back to TCP → QUIC desync broke the handshake
- IPv6-only connection → QUIC desync returns None (expected)

---

### TC-006: QUIC Desync IPv6 Limitation

**Purpose:** Confirm that QUIC desync silently fails on IPv6 (known limitation).

**Setup:**
- Mode 6, IPv6 enabled, target with IPv6 AAAA record
- Force IPv6: `curl -6 --http3 https://www.google.com`

**Steps:**
1. Check logs for QUIC evaluation
2. Verify connection still works (accept, no intervention)

**Expected Result:**
- QUIC packets accepted unmodified on IPv6
- No crash, no error, connection succeeds via IPv6 TCP fallback or unmodified QUIC

**Failure Indicators:**
- Crash or panic on IPv6 QUIC packet
- Incorrect fragmentation attempt on IPv6

---

### TC-007: Auto-TTL Detection Accuracy

**Purpose:** Validate that SYN-ACK based TTL auto-detection calculates a usable fake TTL.

**Setup:**
- Mode 5, auto_ttl=true, fake_packet_ttl=0
- Multiple target servers with different hop distances

**Steps:**
1. `sudo cachydpi -m 5 --auto-ttl --foreground -vvv`
2. Connect to blocked domain
3. Check log for "auto-TTL detected from SYN-ACK" — note recv_ttl, initial_ttl, hops, fake_ttl
4. Verify: `traceroute <target>` — compare real hop count with detected
5. Verify fake_ttl > 0 and fake_ttl < hops

**Expected Result:**
- recv_ttl matches expected (e.g., server with initial TTL 64 at 12 hops → recv_ttl≈52)
- hops = initial_ttl - recv_ttl (e.g., 12)
- fake_ttl = hops - 2 (e.g., 10 — reaches DPI but expires before server)
- Bypass succeeds

**Failure Indicators:**
- fake_ttl = 0 → detection never triggered (SYN-ACK not reaching queue 201)
- fake_ttl too low (1-2) → fakes expire before DPI
- fake_ttl too high → fakes reach server, potentially confusing TCP state
- Detection stores first value only → problem if first connection goes to nearby CDN

---

### TC-008: Auto-TTL with CDN Edge Nodes

**Purpose:** Test TTL detection robustness when initial SYN-ACK comes from a nearby CDN (1-3 hops) and DPI is at the same distance.

**Setup:**
- auto_ttl=true
- Target: Cloudflare-fronted domain (CDN edge typically 1-5 hops)

**Steps:**
1. `traceroute <cloudflare-ip>` — note real hops
2. Start CachyDPI, connect
3. Check detected fake_ttl
4. If hops ≤ 3, auto-TTL formula falls back to `hops.max(1)` — test this scenario

**Expected Result:**
- For nearby CDN: fake_ttl = max(1, hops) — minimum viable TTL
- Bypass may fail if DPI and CDN are at same hop count

**Failure Indicators:**
- fake_ttl = 1 but DPI is at hop 2 → fakes don't reach DPI
- fake_ttl = hops (no subtraction) → fakes reach server
- One CDN edge detection locks TTL for all subsequent connections to different servers

---

### TC-009: Manual TTL Override

**Purpose:** Verify --set-ttl overrides auto-detection and uses fixed value.

**Setup:**
- `--set-ttl 8 --foreground -vvv`
- auto_ttl should be disabled when set-ttl > 0

**Steps:**
1. Start with `--set-ttl 8`
2. Connect to blocked domain
3. Verify logs show NO "auto-TTL detected" message
4. Verify fake packets use TTL=8

**Expected Result:**
- auto_ttl disabled by CLI override
- All fake packets use TTL=8 regardless of SYN-ACK TTL

**Failure Indicators:**
- "auto-TTL detected" appears → override not applied
- Fake packets visible in tcpdump with wrong TTL value

---

### TC-010: Domain Blacklist Loading & Matching

**Purpose:** Verify blacklist file is correctly loaded, case-insensitive, with subdomain matching.

**Setup:**
- blacklist.txt with entries: `youtube.com`, `twitter.com`
- Mode 5, mode=blacklist

**Steps:**
1. Start CachyDPI, check "loaded blacklist file" log (domain count)
2. `curl https://www.youtube.com` → should apply strategies (subdomain match)
3. `curl https://youtube.com` → should apply (exact match)
4. `curl https://studio.youtube.com` → should apply (subdomain match)
5. `curl https://www.example.com` → should NOT apply (not in blacklist)
6. Verify log: "domain not in filter list, skipping" for example.com

**Expected Result:**
- youtube.com and all subdomains processed
- Unrelated domains pass through unmodified

**Failure Indicators:**
- "domain not in filter list" for youtube.com → blacklist not loaded from /etc/cachydpi/
- www.youtube.com not matching → subdomain matching broken
- example.com being processed → filter logic inverted

---

### TC-011: Empty Blacklist File

**Purpose:** Test behavior when blacklist file exists but contains zero domains.

**Setup:**
- /etc/cachydpi/blacklist.txt contains only comments
- domains.mode = "blacklist"

**Steps:**
1. Start CachyDPI
2. Connect to any blocked domain
3. Check if strategies are applied

**Expected Result:**
- domain_set is empty
- No domain matches → ALL connections pass through unmodified
- Effective bypass: zero (nothing processed)

**Failure Indicators:**
- Crash on empty set
- All domains processed (inverted logic)
- Panic in domain_in_set

---

### TC-012: Missing Blacklist File

**Purpose:** Test behavior when blacklist_file path doesn't exist.

**Setup:**
- config.toml: blacklist_file = "/etc/cachydpi/nonexistent.txt"
- domains.mode = "blacklist"

**Steps:**
1. Start CachyDPI
2. Check logs for "blacklist file not found"
3. Connect to any domain

**Expected Result:**
- Warning logged but service starts successfully
- No domains in set → zero bypass applied
- Non-fatal degradation

**Failure Indicators:**
- Service refuses to start
- Panic/crash on missing file
- Silent failure (no warning logged)

---

### TC-013: Whitelist (Exception) Mode

**Purpose:** Validate whitelist mode applies the bypass to every domain
EXCEPT the listed (trusted) ones — the genuine opposite of blacklist mode.

**Setup:**
- domains.mode = "whitelist"
- whitelist.txt: trusted.example, intranet.local

**Steps:**
1. `curl https://trusted.example` → should pass through untouched (in whitelist → excepted)
2. `curl https://www.reddit.com` → should apply strategies (NOT in whitelist → processed)

**Expected Result:**
- Whitelist mode: domains IN the list are skipped (passed through unmodified)
- Domains NOT in the list get the bypass applied

**Failure Indicators:**
- Whitelist behaves identically to blacklist (listed domains processed) — the bug this mode was fixed for
- Listed (trusted) domains still get the bypass

---

### TC-014: High Traffic Burst — Queue Saturation

**Purpose:** Test NFQUEUE behavior under heavy traffic load (packet burst).

**Setup:**
- Mode 5, default queue length 8192
- Load generator: `ab -n 10000 -c 100 https://www.youtube.com/` or `wrk`

**Steps:**
1. Start CachyDPI
2. Launch traffic flood with 100+ concurrent connections
3. Monitor `journalctl -u cachydpi -f` for ENOBUFS errors
4. Monitor `cat /proc/net/netfilter/nfnetlink_queue` for queue fill level
5. Check CPU with `top -p $(pgrep cachydpi)`

**Expected Result:**
- Queue processes packets, some may drop with ENOBUFS under extreme load
- Bypass flag on nftables rules ensures dropped packets still reach destination
- CPU usage proportional to traffic
- No crash, no deadlock

**Failure Indicators:**
- System-wide network hang (queue full, no bypass flag)
- Memory growth unbounded
- CPU 100% sustained after burst ends
- Deadlock between outbound and inbound threads

---

### TC-015: Long-Running Stability — 24-Hour Soak Test

**Purpose:** Detect memory leaks, file descriptor leaks, or resource exhaustion over extended operation.

**Setup:**
- Mode 5, auto_ttl=true, normal browsing workload
- Process monitoring: `pidstat -r -p $(pgrep cachydpi) 60` (every 60s)

**Steps:**
1. Start CachyDPI
2. Normal internet usage for 24 hours (browsing, streaming, downloads)
3. Record RSS memory, open FDs, and CPU every minute
4. `ls -la /proc/$(pgrep cachydpi)/fd | wc -l` — FD count
5. Compare start vs end metrics

**Expected Result:**
- RSS memory stable (within 5% of initial after warmup)
- FD count stable (2 raw sockets + 2 nfqueue FDs + stdio)
- CPU near-zero when idle
- No OOM kills, no queue stalls

**Failure Indicators:**
- RSS grows monotonically → memory leak in Vec allocations
- FD count increases → nfqueue or socket leak
- Queue stalls after N hours → buffer managment issue
- Periodic latency spikes → rate limiter Mutex contention

---

### TC-016: Packet Loss / Unstable Network

**Purpose:** Validate behavior on lossy connections (mobile, WiFi congestion).

**Setup:**
- Simulate 5% packet loss: `sudo tc qdisc add dev <iface> root netem loss 5%`
- Mode 5

**Steps:**
1. Apply packet loss
2. Browse blocked sites
3. Compare experience with CachyDPI off vs on
4. Remove packet loss: `sudo tc qdisc del dev <iface> root`

**Expected Result:**
- Bypass still works (TCP retransmit handles lost fragments)
- Slightly increased latency due to fragment retransmissions
- No worse than normal browsing under 5% loss

**Failure Indicators:**
- Complete connection failure (fragments not retransmitted properly)
- Infinite retry loop
- Forged RST detection false positives from retransmit-induced RSTs

---

### TC-017: Network Interface Change — WiFi to Ethernet

**Purpose:** Test behavior when network interface changes mid-session.

**Setup:**
- CachyDPI running on WiFi interface
- Ethernet cable available

**Steps:**
1. Start CachyDPI on WiFi
2. Connect Ethernet cable (new default route)
3. Disconnect WiFi
4. Try browsing blocked sites via Ethernet

**Expected Result:**
- nftables rules apply to OUTPUT chain (not interface-specific) → should adapt
- Raw socket sends via new route
- Bypass continues working

**Failure Indicators:**
- Old nftables rules reference wrong interface
- Raw socket fails with ENETUNREACH
- Auto-TTL value from old interface unusable on new path

---

### TC-018: Multiple DPI Techniques Active Simultaneously

**Purpose:** Verify all strategies compose correctly when processing the same packet.

**Setup:**
- Mode 5: HTTP frag + TLS frag + fake packets all enabled

**Steps:**
1. Browse a blocked HTTPS site
2. Check logs: should see "TLS ClientHello detected" + fragmentation + fake injection
3. tcpdump: verify packet order (fakes first, then fragments)

**Expected Result:**
- InjectAndFragment action: raw socket sends fake(s), then fragments
- Fragment SEQ numbers correct (original seq for frag1, seq+frag1_len for frag2)
- Fake packet has wrong TTL/checksum/seq as configured

**Failure Indicators:**
- Only fakes sent (fragments not generated) → fragmentation returned None
- Fragment SEQ numbers wrong → TCP retransmit storm
- Fake packets accepted by server → TTL too high or checksum valid

---

### TC-019: Fake Packet Detection by DPI

**Purpose:** Test if DPI detects and ignores CachyDPI's fake packets.

**Setup:**
- Mode 4 (fake only), wrong_checksum=true

**Steps:**
1. `curl https://<blocked-domain>` with only fake packet strategy
2. If blocked: DPI verifies checksums (our fakes detected)
3. Switch to wrong_seq=true, retry
4. Switch to wrong TTL, retry
5. Record which fake strategies succeed

**Expected Result:**
- At least one fake strategy should work (DPI can't verify all three simultaneously)
- wrong_checksum: fails if DPI validates TCP checksums
- wrong_seq: usually works (DPI doesn't track per-flow windows)
- wrong TTL: most reliable (DPI processes, server never receives)

**Failure Indicators:**
- All three fail → DPI is extremely sophisticated (state-tracking + checksum verification)
- wrong TTL fails → fake_ttl too high (reaching server) or too low (not reaching DPI)

---

### TC-020: TLS 1.3 with 0-RTT (Encrypted ClientHello)

**Purpose:** Test behavior with TLS 1.3 Encrypted ClientHello (ECH) where SNI is encrypted.

**Setup:**
- Browser/curl with ECH support
- Target: Cloudflare domain with ECH enabled

**Steps:**
1. `curl --ech true https://crypto.cloudflare.com/cdn-cgi/trace`
2. Check CachyDPI logs — does it detect ClientHello? Can it find SNI?

**Expected Result:**
- With ECH: ClientHello is parsed but SNI not found (encrypted)
- Parser returns `has_sni() = false`, logs "TLS ClientHello has no SNI, skipping"
- Packet accepted unmodified

**Failure Indicators:**
- Parser crash on ECH-formatted ClientHello
- False SNI extraction (parsing garbage)
- Bypass applied to wrong offset

---

### TC-021: Concurrent Connections — Thread Safety

**Purpose:** Stress test the two-thread architecture with many simultaneous connections.

**Setup:**
- Mode 5, 200 concurrent connections
- Target: multiple different blocked domains

**Steps:**
1. `for i in (seq 1 200); curl -s -o /dev/null --max-time 5 https://www.youtube.com &; end`
2. Monitor queue 200 and 201 simultaneously
3. Check for race conditions in auto_ttl AtomicU8

**Expected Result:**
- All connections processed without deadlock
- auto_ttl set once by first SYN-ACK, reused by all subsequent
- No verdict leaks (every packet gets ACCEPT or DROP)

**Failure Indicators:**
- Packets stuck in queue (no verdict issued)
- Network-wide stall
- Inconsistent auto_ttl values seen across log entries

---

### TC-022: Raw Socket Rate Limiter Under Load

**Purpose:** Test the 5000 pkt/s rate limiter behavior under heavy fake packet generation.

**Setup:**
- Mode 5, many simultaneous HTTPS connections generating fakes
- Monitor: `sudo cachydpi --foreground -vvv` + filter "rate limit"

**Steps:**
1. Generate 1000+ concurrent connections to blocked sites
2. Monitor for "rate limit exceeded" warnings
3. Measure actual sent packet rate via `iptables -L -v -n` or nftables counters

**Expected Result:**
- Rate limiter kicks in at ~5000 pkt/s
- Warning logged
- Excess fake packets silently dropped (not sent)
- Bypass still works for most connections (fragments still sent via nfqueue verdict)

**Failure Indicators:**
- Rate limiter never triggers (counter bug)
- Mutex contention causes all sends to block → latency spike
- Fake packets sent but fragments not → bypass fails

---

### TC-023: Graceful Shutdown — Rule Cleanup

**Purpose:** Verify nftables rules are removed on normal shutdown and on crash.

**Setup:**
- Running CachyDPI

**Steps:**
1. `sudo nft list table ip cachydpi` — rules present
2. `sudo systemctl stop cachydpi`
3. `sudo nft list table ip cachydpi` — should fail (table removed)
4. Start again, then `kill -9 $(pgrep cachydpi)` (SIGKILL — no cleanup)
5. `sudo nft list table ip cachydpi` — check if rules remain

**Expected Result:**
- Normal stop (SIGTERM): rules cleaned up by Drop handler
- SIGKILL: panic hook may not run → rules may persist
- NFQUEUE bypass flag prevents traffic blackhole even if rules persist

**Failure Indicators:**
- Rules remain after SIGTERM → Drop handler not called
- Traffic blocked after SIGKILL → bypass flag not set on nftables rules
- System requires manual `nft delete table ip cachydpi` after crashes

---

### TC-024: Service Crash Recovery — Systemd Restart

**Purpose:** Test systemd Restart=on-failure behavior after unexpected crash.

**Setup:**
- systemd unit with Restart=on-failure

**Steps:**
1. Trigger crash (e.g., corrupt config that causes panic)
2. Check `systemctl status cachydpi` — should show restart attempt
3. Verify rules cleaned (old rules) and reinstalled (new instance)

**Expected Result:**
- Systemd restarts service within RestartSec
- Old nftables table deleted, new one created
- Service resumes DPI bypass

**Failure Indicators:**
- nftables "table already exists" error on restart → old rules not cleaned
- Restart loop (crash → restart → crash)
- Rules conflicting with stale state

---

### TC-025: Invalid Mode Number

**Purpose:** Test behavior with invalid CLI mode values.

**Setup:**
- CLI: `--mode 0`, `--mode 8`, `--mode 255`, `--mode -1`

**Steps:**
1. `sudo cachydpi -m 0`
2. `sudo cachydpi -m 8`
3. `sudo cachydpi -m 99`

**Expected Result:**
- Invalid modes default to Mode 5 (AllActive) via `from_mode_number()` match arm `_ => BypassMode::AllActive`
- No crash, graceful fallback

**Failure Indicators:**
- Crash on invalid mode
- Silent mode 0 (no bypass at all, not obvious to user)
- Clap rejects before reaching from_mode_number (mode range validation)

---

### TC-026: Missing Root Permissions

**Purpose:** Test startup without root/capabilities.

**Setup:**
- Run as normal user: `cachydpi -m 5` (no sudo)

**Steps:**
1. Run without sudo
2. Check error message

**Expected Result:**
- Clear error: "requires CAP_NET_ADMIN and CAP_NET_RAW capabilities"
- Non-zero exit code
- No partial state left behind

**Failure Indicators:**
- Confusing error message
- Partial rule installation before failure
- Segfault from libnetfilter_queue without capabilities

---

### TC-027: Blacklist Path Traversal Attempt

**Purpose:** Verify security of domain list file path validation.

**Setup:**
- config.toml: `blacklist_file = "/etc/cachydpi/../../etc/passwd"`
- config.toml: `blacklist_file = "/etc/cachydpi/legit" → symlink to /etc/shadow`

**Steps:**
1. Set traversal path, start CachyDPI
2. Check logs for "blacklist path rejected"
3. Create symlink, retry

**Expected Result:**
- `../../etc/passwd`: First check fails (doesn't start with /etc/cachydpi after normalization)
- Symlink: `canonicalize()` resolves symlink → target outside allowed dirs → rejected

**Failure Indicators:**
- /etc/passwd content loaded as domain list
- Symlink resolution bypassed
- Error not logged (silent acceptance)

---

### TC-028: Fiber vs Mobile vs Hotspot — ISP Variability

**Purpose:** Compare bypass effectiveness across different connection types.

**Setup:**
- Same device, same config (mode 5, auto_ttl=true)
- Test on: fiber, 4G mobile data, phone hotspot

**Steps:**
1. For each connection type:
   - Record auto-TTL detected values
   - Test 5 blocked domains
   - Record success/failure per domain
2. Compare results across connection types

**Expected Result:**
- Auto-TTL adapts per connection type (different hop counts)
- Fiber: most reliable (stable path)
- Mobile: may vary (CGNAT adds hops, path changes)
- Hotspot: double NAT complicates routing

**Failure Indicators:**
- Same auto_ttl for wildly different hop counts
- Mobile consistently fails (DPI at different position)
- Hotspot fails (carrier-grade NAT + hotspot NAT)

---

### TC-029: Partially Blocked Services — CDN Endpoints

**Purpose:** Test domains where main site is blocked but API/CDN subdomains are not.

**Setup:**
- Blacklist: twitter.com
- Test: twitter.com (blocked), pbs.twimg.com (CDN, may not be blocked), api.twitter.com

**Steps:**
1. `curl https://twitter.com` (blocked, bypass applied)
2. `curl https://pbs.twimg.com/some-image` (not same domain, may bypass)
3. Check if CDN connections are unnecessarily modified

**Expected Result:**
- twitter.com: bypass applied (in blacklist, subdomain match)
- pbs.twimg.com: NOT matched (different TLD) → passes through unmodified
- If twimg.com is not in blacklist, no intervention

**Failure Indicators:**
- CDN connections broken by unnecessary intervention
- Subdomain matching incorrectly matches across different base domains
- Performance degradation from processing all CDN traffic

---

### TC-030: DPI Detect Subcommand Accuracy

**Purpose:** Validate the `detect` subcommand produces useful fingerprinting results.

**Setup:**
- Known ISP with known DPI behavior

**Steps:**
1. `sudo cachydpi detect www.youtube.com`
2. `sudo cachydpi detect www.google.com` (likely not blocked)
3. Compare results

**Expected Result:**
- youtube.com: DPI detected (RST and/or redirect injection), recommended mode ≥ 3
- google.com: No DPI detected, recommended mode 1

**Failure Indicators:**
- False positive on google.com (DPI detected where none exists)
- False negative on youtube.com (DPI not detected but site is blocked)
- Timeout (connect_timeout 5s) on every attempt → firewall rules blocking test traffic
- ISP blocking port 80 entirely → HTTP redirect test fails

---

### TC-031: TCP Segmentation — Split ClientHello

**Purpose:** Test handling when a TLS ClientHello is split across TCP segments by the OS.

**Setup:**
- Low MSS or small window size forcing OS-level TCP segmentation
- Mode 5

**Steps:**
1. Set TCP window size very small: `--window-size 100`
2. Connect to HTTPS blocked domain
3. Check if ClientHello parser handles partial records

**Expected Result:**
- First segment may contain partial ClientHello → parser handles gracefully
- Second segment with remaining data → nftables only queues first ACK with payload
- Bypass may partially fail if SNI in second segment

**Failure Indicators:**
- Parser panic on truncated ClientHello
- Double processing (both segments matched)
- SNI not found because it's in second segment (known limitation)

---

### TC-032: Oversized TLS ClientHello

**Purpose:** Test handling of ClientHellos with many extensions (common in modern browsers).

**Setup:**
- Modern browser (Chrome/Firefox) with many TLS extensions
- ClientHello often 500-700 bytes

**Steps:**
1. Browse blocked HTTPS site via Firefox
2. Check if ClientHello fits in single queued packet
3. Verify SNI found despite many extensions before it

**Expected Result:**
- Parser skips extensions until SNI found
- Fragmentation applied at correct SNI offset

**Failure Indicators:**
- SNI not found (parser stops too early)
- Split position wrong (offset calculation error with many extensions)
- Packet > MTU after fragmentation → dropped

---

### TC-033: Non-Standard HTTP Ports (8080, 8888, 3128)

**Purpose:** Verify DPI bypass works on non-standard HTTP ports.

**Setup:**
- Proxy or service on port 8080
- nftables rules include port 8080

**Steps:**
1. `curl -v http://<target>:8080/`
2. Check nftables match: `sudo nft list chain ip cachydpi output | grep 8080`
3. Check logs for HTTP request detection

**Expected Result:**
- Packet queued and HTTP request detected on port 8080
- Fragmentation applied

**Failure Indicators:**
- nftables rules don't match 8080 → rules.rs missing port
- HTTP parser doesn't recognize port as HTTP → is_http_port() check fails

---

### TC-034: DNS Poisoning Interaction

**Purpose:** Test behavior when DNS itself is poisoned (returns wrong IP).

**Setup:**
- ISP DNS returning poisoned IP for blocked domain
- CachyDPI has no DNS bypass capability

**Steps:**
1. `dig youtube.com @<isp-dns>` — check if IP looks legitimate
2. `dig youtube.com @8.8.8.8` — compare with known-good DNS
3. If DNS is poisoned, CachyDPI connects to wrong IP → bypass is irrelevant

**Expected Result:**
- CachyDPI does NOT handle DNS poisoning
- If DNS returns wrong IP, bypass strategies are applied but to wrong server
- User must use DoH/DoT/alternative DNS separately

**Failure Indicators:**
- This is a known limitation, not a bug
- Documentation should clearly state DNS must be clean

---

### TC-035: VPN + CachyDPI Interaction

**Purpose:** Test behavior when user already has VPN active.

**Setup:**
- WireGuard/OpenVPN active (all traffic through VPN)
- CachyDPI running

**Steps:**
1. Start VPN
2. Start CachyDPI
3. Browse any site
4. Check if nftables rules affect VPN tunnel traffic

**Expected Result:**
- nftables OUTPUT chain applies to pre-VPN packets (depends on routing)
- If VPN encrypts everything before nftables: CachyDPI sees encrypted VPN traffic, not HTTP/TLS → no bypass applied
- CachyDPI is redundant with VPN

**Failure Indicators:**
- CachyDPI breaks VPN tunnel
- Double manipulation of already-encrypted traffic
- Performance degradation from unnecessary queueing

---

### TC-036: nftables Conflict with Existing Rules

**Purpose:** Test what happens when user has existing nftables rules (firewall).

**Setup:**
- Pre-existing nftables rules (e.g., firewalld, ufw converted to nft)
- CachyDPI creates its own table "cachydpi"

**Steps:**
1. `sudo nft list tables` — note existing tables
2. Start CachyDPI
3. `sudo nft list tables` — verify "cachydpi" added, others untouched
4. Stop CachyDPI
5. Verify other tables still intact

**Expected Result:**
- CachyDPI uses dedicated table, does not modify other tables
- No rule conflicts
- Cleanup only removes "cachydpi" table

**Failure Indicators:**
- Existing firewall rules deleted or modified
- CachyDPI rules conflict (packets matched by wrong chain)
- Multiple "cachydpi" tables after restart

---

### TC-037: Rapid Service Restart

**Purpose:** Test repeated start/stop cycles for rule leaks.

**Setup:**
- CachyDPI service

**Steps:**
1. Loop 20 times: `sudo systemctl restart cachydpi`
2. `sudo nft list tables | grep cachydpi | wc -l` — should be exactly 1
3. Stop service, verify 0

**Expected Result:**
- Each restart cleanly removes old rules and installs new
- No orphaned rules after stop

**Failure Indicators:**
- Multiple "cachydpi" tables accumulated
- "table already exists" error
- Rules missing after restart (not reinstalled)

---

### TC-038: Config File Syntax Error

**Purpose:** Test behavior with malformed TOML configuration.

**Setup:**
- /etc/cachydpi/config.toml with syntax error (e.g., missing quotes, invalid type)

**Steps:**
1. Edit config: `mode = "not_a_number"`
2. Start CachyDPI
3. Check error message

**Expected Result:**
- Clear parse error logged
- Service fails to start with descriptive error (not generic panic)

**Failure Indicators:**
- Panic with raw TOML error
- Falls back to defaults silently (user doesn't know config is broken)
- Partial config loaded (some sections parsed, others not)

---

### TC-039: SO_MARK Packet Loop Prevention

**Purpose:** Verify that raw socket packets with mark 0xCACD don't re-enter the queue.

**Setup:**
- Mode 5, foreground verbose

**Steps:**
1. Send fake packet via raw socket
2. tcpdump with nflog to check if marked packets bypass nftables queue
3. Check nftables rule: `meta mark 0xCACD accept`

**Expected Result:**
- Fake/fragment packets sent via raw socket have SO_MARK=0xCACD
- nftables skips these packets → no re-queueing loop

**Failure Indicators:**
- Packet loop detected (exponential packet growth)
- CPU spike from re-processing own packets
- mark not set on raw socket → SO_MARK setsockopt failed

---

### TC-040: Connection to Non-Blocked Site Performance

**Purpose:** Measure latency overhead for traffic that matches nftables but isn't in the domain filter.

**Setup:**
- Mode 5, blacklist with 5000 domains
- Target: domain NOT in blacklist (e.g., google.com if not listed)

**Steps:**
1. Measure baseline: `curl -w "%{time_connect} %{time_starttls}" -o /dev/null https://www.google.com` without CachyDPI
2. Start CachyDPI, repeat measurement 10 times
3. Compare average latency

**Expected Result:**
- Added latency < 2ms (queue processing + domain lookup + accept verdict)
- HashSet lookup is O(1), impact minimal

**Failure Indicators:**
- > 10ms added latency → queue processing slow
- Periodically high latency → Mutex contention in rate limiter
- Latency increases over time → memory/resource leak

---

## FAILURE MATRIX

| # | Failure Condition | Component Affected | Impact | Severity |
|---|---|---|---|---|
| F-01 | DPI verifies TCP checksums | fake_packet (wrong_checksum) | Fake packets ignored by DPI | Medium — use wrong_ttl/wrong_seq instead |
| F-02 | DPI at same hop as CDN edge | auto_ttl | Fake TTL can't target gap between DPI and server | High — manual TTL needed |
| F-03 | DNS poisoned by ISP | All bypass strategies | Bypass applied to wrong IP, useless | Critical — requires external DoH/DoT |
| F-04 | TLS ClientHello split across TCP segments | tls_split | SNI in second segment, missed by parser | Medium — rare with normal MSS |
| F-05 | IPv6 QUIC traffic | quic desync | No IP fragmentation possible on IPv6 | Medium — QUIC falls back to TCP |
| F-06 | ENOBUFS under extreme load | nfqueue | Kernel drops packets | Low — bypass flag prevents blackhole |
| F-07 | SIGKILL (kill -9) | rule cleanup | nftables rules remain | Low — bypass flag prevents blackhole, manual cleanup needed |
| F-08 | ECH (Encrypted ClientHello) | tls_split | SNI not visible → no bypass possible | High — growing adoption |
| F-09 | ISP changes DPI strategy | passive detection | Scoring thresholds may not match new patterns | Medium — requires threshold tuning |
| F-10 | Auto-TTL locked to first SYN-ACK | auto_ttl | All connections use TTL from first server (CDN) | Medium — hot path to different server may differ |
| F-11 | Mobile data CGNAT multi-hop | auto_ttl | Extra hops from CGNAT affect TTL calculation | Medium — fake_ttl may be wrong |
| F-12 | Rate limiter Mutex contention | rawsocket | High-load fake packet sending delayed | Low — affects only fake timing |
| F-13 | Hardcoded fake payload (www.google.com) | fake_packet | DPI could detect and ignore pattern | Low — unlikely DPI checks this |
| F-14 | Stale nftables rules after upgrade | rules.rs | New version's rule format conflicts | Medium — requires manual cleanup |
| F-15 | Multiple CachyDPI instances | nfqueue/rules | Queue conflict, double processing | High — systemd prevents, but manual runs possible |
| F-16 | Metrics socket permission denied | metrics_server.rs | Monitor can't read counters | Low — socket created 0666, RuntimeDirectory 0755 |
| F-17 | Stale metrics socket | metrics_server.rs | Monitor connects to dead socket | Low — connect() fails immediately, retry loop handles |
| F-18 | Per-dest TTL cache grows unbounded | strategies/mod.rs | Memory growth with many destinations | Low — entries are small (IpAddr + u8), thousands fit in KB |

---

## RELIABILITY SCORE

### Success Rate Estimates (Based on Architecture Analysis)

| Scenario | Estimated Success Rate | Confidence |
|---|---|---|
| HTTPS bypass (TLS frag, mode 5) | 85–95% | High |
| HTTP bypass (fragmentation) | 80–90% | High |
| QUIC bypass (IPv4) | 70–80% | Medium |
| QUIC bypass (IPv6) | 0% | Known limitation |
| Passive RST detection | 75–85% | Medium |
| Auto-TTL accuracy | 75–90% | Medium |
| Per-dest TTL cache | 90–95% | High |
| Long-term stability (24h+) | 90–95% | High |
| Monitor TUI connectivity | 95–99% | High |
| Cross-ISP compatibility | 60–80% | Low |

### Stability Assessment

| Area | Stability | Notes |
|---|---|---|
| Core packet processing | **Stable** | Pre-allocated buffers, careful error handling |
| nftables management | **Stable** | Isolated table, clean Drop handler |
| TLS/HTTP parsing | **Stable** | Bounds checks, partial record handling |
| Auto-TTL detection | **Improved** | Per-destination cache eliminates first-connection lock-in |
| QUIC desync | **Fragile** | IPv6 unsupported, IP fragmentation may be blocked |
| Passive RST detection | **Moderate** | Threshold-based, may need tuning per ISP |
| Fake packet strategy | **Moderate** | Depends on DPI sophistication |
| Domain filtering | **Stable** | O(1) lookup, subdomain matching |
| Resource management | **Stable** | No evident leaks, pre-allocated buffers |
| Metrics & monitoring | **Stable** | Atomic counters, Unix socket IPC, graceful disconnect handling |
| CLI subcommands | **Stable** | Handled before logging init, clean error messages |

### Most Fragile Components (Ranked)

1. **QUIC desync** — IPv6 unsupported, middlebox fragmentation drop
2. **Passive RST scoring** — Hardcoded thresholds, ISP-specific DPI behavior
3. **Fake packet effectiveness** — DPI sophistication varies widely
4. **Auto-TTL detection** — Improved with per-destination cache, but CGNAT still affects calculation

---

## WHAT THE SYSTEM CAN DO

1. **Fragment TLS ClientHello at SNI boundary** — Splits the SNI extension across two TCP segments, defeating DPI that inspects the first packet only. Works reliably for TLS 1.2 and 1.3 with plaintext SNI.

2. **Fragment HTTP Host header** — Splits HTTP requests at the Host header, defeating DPI that matches domain on first packet. Works for standard port 80 and alternate HTTP ports (8080, 8888, 3128).

3. **Inject fake packets** — Sends packets with wrong TTL (expires before server), wrong checksum (server drops), or wrong sequence number (out of window). DPI processes them; server ignores them.

4. **Drop DPI-forged RST packets** — Identifies and discards RST packets that score highly on DPI indicators (window=0, no options, suspicious TTL, RST|ACK flags).

5. **Drop DPI-forged HTTP redirects** — Identifies injected 302/301 redirects containing block page indicators from known DPI vendors (Sandvine, Forcepoint, Allot, Netsweeper, etc.).

6. **Auto-detect optimal fake packet TTL** — Uses SYN-ACK TTL to estimate server hop distance and calculates a TTL that passes the DPI but expires before reaching the server.

7. **QUIC desync via IP fragmentation** — Fragments QUIC Initial packets at the IP layer (IPv4 only), splitting the connection ID across fragments.

8. **Domain-level filtering** — Applies bypass only to specified domains (blacklist/whitelist), with subdomain matching. Unrelated traffic passes through with minimal overhead.

9. **Survive crashes without blocking traffic** — NFQUEUE bypass flag ensures packets flow even if CachyDPI crashes. Drop handler cleans nftables rules on normal exit.

10. **ISP-agnostic operation** — No hardcoded ISP detection. Auto-TTL and generic block page patterns work across any ISP with DPI.

11. **Monitor real-time performance** — Built-in TUI dashboard showing packet counters, strategy hits, health indicators, and recent events. Zero-overhead atomic counters with Unix socket IPC.

12. **Per-destination TTL management** — Separate auto-TTL values for each destination IP address, preventing CDN proximity issues from affecting other connections.

---

### TC-041: Monitor TUI — Socket Connection

**Purpose:** Validate that `cachydpi monitor` successfully connects to the metrics socket and displays live data.

**Setup:**
- CachyDPI daemon running (`sudo systemctl start cachydpi`)
- Metrics socket at `/run/cachydpi/metrics.sock`

**Steps:**
1. `sudo systemctl start cachydpi`
2. `ls -la /run/cachydpi/metrics.sock` — verify socket exists
3. `cachydpi monitor` (no sudo needed)
4. Observe TUI dashboard rendering
5. Generate traffic: `curl https://www.youtube.com`
6. Verify counters update in real-time

**Expected Result:**
- TUI connects within 1 second
- Dashboard shows: service state "running", mode, PID, uptime
- Packet counters increment when traffic flows
- Strategy hit counters update when bypass is applied
- Quit with 'q' key — clean exit

**Failure Indicators:**
- "Socket not found" error → daemon not running or RuntimeDirectory missing
- TUI connects but shows all zeros → metrics not instrumented in strategies
- TUI hangs → socket read timeout missing
- Terminal corruption after exit → crossterm cleanup not called

---

### TC-042: Monitor TUI — Daemon Not Running

**Purpose:** Verify graceful behavior when monitor is started without the daemon running.

**Setup:**
- CachyDPI daemon NOT running
- No socket at `/run/cachydpi/metrics.sock`

**Steps:**
1. `sudo systemctl stop cachydpi`
2. `cachydpi monitor`
3. Observe error handling

**Expected Result:**
- Clear error message: "Cannot connect to CachyDPI daemon" or similar
- TUI shows "disconnected" state
- Periodic reconnection attempts (every 1-2 seconds)
- When daemon starts, monitor auto-connects

**Failure Indicators:**
- Panic/crash on missing socket
- Infinite loop without user feedback
- No reconnection after daemon restarts

---

### TC-043: Restart Subcommand

**Purpose:** Validate `cachydpi restart` correctly restarts the systemd service.

**Setup:**
- CachyDPI daemon running

**Steps:**
1. `sudo systemctl start cachydpi`
2. Note PID: `pgrep cachydpi`
3. `sudo cachydpi restart`
4. Note new PID: `pgrep cachydpi`
5. `systemctl status cachydpi` — verify active

**Expected Result:**
- Old PID different from new PID (service restarted)
- nftables rules cleaned and recreated
- Service status "active (running)"
- No error messages

**Failure Indicators:**
- Same PID → restart command did nothing
- Service in "failed" state → restart triggered but daemon crashed on startup
- nftables rules missing → cleanup happened but new rules not installed

---

### TC-044: Monitor Custom Socket Path

**Purpose:** Verify `cachydpi monitor --socket <path>` connects to a custom socket.

**Setup:**
- CachyDPI running with default socket
- Alternative: start daemon with metrics at custom path

**Steps:**
1. `cachydpi monitor --socket /run/cachydpi/metrics.sock` (explicit default path)
2. `cachydpi monitor --socket /tmp/nonexistent.sock` (invalid path)
3. Verify error handling for invalid path

**Expected Result:**
- Explicit path: connects normally
- Invalid path: clear error message, no crash

**Failure Indicators:**
- `--socket` flag not recognized → CLI not updated
- Path accepted but silent failure → no connection error

---

### TC-045: Metrics Counter Accuracy

**Purpose:** Verify that atomic counters accurately track packet processing decisions.

**Setup:**
- CachyDPI running, mode 5, foreground verbose
- Monitor TUI in separate terminal

**Steps:**
1. Start daemon with `-vvv --foreground` in one terminal
2. Start `cachydpi monitor` in another terminal
3. `curl https://www.youtube.com` — single HTTPS connection
4. Count log entries: "TLS ClientHello detected", "applying strategy", "dropping forged"
5. Compare log counts with monitor TUI values

**Expected Result:**
- `tls_fragment_hits` in monitor matches "TLS ClientHello" log count
- `forged_rst_drops` matches "dropping forged RST" log count
- `packets_accepted` + `packets_dropped` + `packets_modified` ≈ total processed
- No counter overflow or reset during normal operation

**Failure Indicators:**
- Monitor shows 0 while logs show activity → counters not incremented
- Counters wildly off from log counts → race condition or double-counting
- Counter decreases → AtomicU64 underflow (should never happen with fetch_add)

---

### TC-046: Per-Destination TTL Cache Behavior

**Purpose:** Validate that auto-TTL is stored and used per destination IP, not globally.

**Setup:**
- Mode 5, auto_ttl=true, foreground verbose
- Two target servers at different hop distances

**Steps:**
1. Start with `-m 5 --auto-ttl --foreground -vvv`
2. `curl https://www.youtube.com` — note auto-TTL in logs (e.g., fake_ttl=10 for IP 142.250.X.X)
3. `curl https://discord.com` — note auto-TTL in logs (e.g., fake_ttl=7 for IP 162.159.X.X)
4. Repeat youtube.com — verify same TTL used (cache hit, not re-detected)
5. Verify both TTL values correct for their respective servers

**Expected Result:**
- Different destination IPs get different fake_ttl values
- Cache persists across connections to same IP
- Log shows "TTL cache hit" for repeated connections
- No interference between different destination TTLs

**Failure Indicators:**
- All destinations get same TTL → global cache still in use
- TTL changes on repeated connection → cache not persisting
- RwLock contention visible in logs → performance issue

---

## WHAT THE SYSTEM CANNOT DO

1. **Cannot bypass DNS poisoning** — If the ISP returns wrong IP addresses via DNS, CachyDPI connects to the wrong server. Users must separately configure DoH/DoT/alternative DNS.

2. **Cannot handle Encrypted ClientHello (ECH)** — When SNI is encrypted (TLS ECH extension), the parser finds no SNI to fragment. The packet passes through unmodified. ECH adoption is growing.

3. **Cannot fragment QUIC on IPv6** — IPv6 prohibits sender-side IP fragmentation. QUIC desync is IPv4-only. IPv6 QUIC traffic passes unmodified.

4. **Cannot adapt mid-session** — Auto-TTL is stored once from the first SYN-ACK and reused for all subsequent connections. It does not re-evaluate for different server paths.

5. **Cannot detect DPI strategy changes at runtime** — If the ISP changes DPI behavior (e.g., switches from passive to active), CachyDPI doesn't automatically adjust its mode.

6. **Cannot bypass stateful DPI that reassembles TCP** — If the DPI device buffers and reassembles full TCP streams before inspection, fragmentation is ineffective. This is uncommon due to performance cost but exists in advanced DPI (e.g., some Sandvine configurations).

7. **Cannot protect UDP traffic other than QUIC 443** — Only UDP port 443 is handled. Other UDP-based protocols are not affected.

8. **Cannot run without root/capabilities** — Requires CAP_NET_ADMIN (nftables) and CAP_NET_RAW (raw sockets). Cannot work in unprivileged containers without host capabilities.

9. **Cannot guarantee bypass on every ISP** — DPI technology varies widely. Mode 5 with auto_ttl works for most common DPI, but some ISPs may require different tuning or may be entirely resistant.

10. **Cannot recover auto-TTL for different network paths** — The first detected TTL is used globally. If connections go to servers at different distances, the fake TTL may be wrong for some of them.

---

## WHERE IT BREAKS

### Scenario 1: Cloudflare + Nearby CDN + Auto-TTL
- CDN edge at 2 hops, DPI at hop 1
- Auto-TTL calculates fake_ttl = max(1, 2) = 2
- DPI at hop 1 receives fake packet (correct)
- CDN at hop 2 also receives fake packet (incorrect — fake reaches real server)
- **Result:** TCP state corruption, connection failure

### Scenario 2: DNS Poisoning + DPI Bypass
- ISP returns poisoned IP for youtube.com
- CachyDPI fragments ClientHello to poisoned IP
- Poisoned server has valid TLS cert (wildcard ISP cert) → user sees block page
- **Result:** Bypass is technically successful but connects to wrong server

### Scenario 3: IPv6-Only ISP + QUIC
- User on IPv6-only connection (increasingly common with mobile)
- QUIC desync returns None → no bypass for UDP traffic
- TLS over TCP still works (fragmentation)
- **Result:** QUIC-only services may fail; TCP fallback adds latency

### Scenario 4: Extreme Traffic Burst
- 10,000+ concurrent connections
- NFQUEUE kernel buffer fills (default 8192)
- ENOBUFS: kernel drops excess packets
- **Result:** Brief connectivity disruption, bypass flag prevents blackhole, recovers

### Scenario 5: SIGKILL During Heavy Traffic
- `kill -9` sent to CachyDPI during active processing
- Panic hook doesn't run for SIGKILL
- nftables rules remain installed
- `bypass` flag on queue rules means traffic still flows through kernel
- **Result:** Rules persist but traffic not blocked; manual `nft delete table ip cachydpi` required

### Scenario 6: ISP Upgrades to Stateful TCP Reassembly DPI
- New DPI hardware buffers TCP segments before inspection
- Fragmented ClientHello reassembled → SNI visible
- Fake packets discarded (checksum/seq/TTL verification)
- **Result:** All bypass strategies fail; fundamental architectural limitation

### Scenario 7: Multiple CachyDPI Instances
- User runs `sudo cachydpi` manually while systemd service is active
- Both try to create "cachydpi" nftables table → second fails
- Both try to bind to queue 200 → undefined behavior
- **Result:** Unpredictable packet processing, possible queue stalls
