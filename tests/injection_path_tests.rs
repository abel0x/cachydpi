// tests/injection_path_tests.rs — process_packet verdict/injection sequencing
//
// Exercises the strategy engine's packet execution path through the
// VerdictSink + PacketInjector traits with mock implementations, proving:
//
// 1. Fragments carrying real user data are never silently lost: if
//    injection fails, the original packet must be ACCEPTED (connection
//    preserved), never dropped-and-forgotten.
// 2. All data fragments are handed to the raw socket BEFORE the original
//    packet's verdict is issued, so a send failure can still fall back.
// 3. A decoy (fake packet) failure must not abort the real bypass.

use std::net::Ipv4Addr;
use std::sync::{Arc, Mutex};

use anyhow::{Result, bail};

use cachydpi::config::Config;
use cachydpi::packet::{Direction, ip, tcp};
use cachydpi::strategies::{
    BypassMode, PacketInjector, StrategyEngine, VerdictSink, process_packet,
};

// ═══════════════════════════════════════════════════════════════════
//  Shared event log + mocks
// ═══════════════════════════════════════════════════════════════════

/// Everything the mocks observe, in call order.
#[derive(Debug, Clone, PartialEq)]
enum Event {
    DataSent(usize),  // fragment handed to the raw socket (payload length)
    DecoySent(usize), // fake packet handed to the raw socket
    Accept(u32),
    Drop(u32),
    AcceptModified(u32),
}

type Log = Arc<Mutex<Vec<Event>>>;

struct MockQueue {
    log: Log,
}

impl VerdictSink for MockQueue {
    fn verdict_accept(&self, packet_id: u32) -> Result<()> {
        self.log.lock().unwrap().push(Event::Accept(packet_id));
        Ok(())
    }
    fn verdict_drop(&self, packet_id: u32) -> Result<()> {
        self.log.lock().unwrap().push(Event::Drop(packet_id));
        Ok(())
    }
    fn verdict_accept_modified(&self, packet_id: u32, _data: &[u8]) -> Result<()> {
        self.log
            .lock()
            .unwrap()
            .push(Event::AcceptModified(packet_id));
        Ok(())
    }
}

struct MockInjector {
    log: Log,
    /// Simulate injection failure for real-data fragments (rate-limited
    /// socket, EPERM from nftables, ENOBUFS, ...). Per the PacketInjector
    /// contract such failures must be visible, so the mock returns Err.
    fail_data: bool,
    /// Simulate failure for decoy sends.
    fail_decoy: bool,
}

impl PacketInjector for MockInjector {
    fn send_data(&self, packet: &[u8]) -> Result<()> {
        if self.fail_data {
            bail!("simulated data injection failure");
        }
        self.log.lock().unwrap().push(Event::DataSent(packet.len()));
        Ok(())
    }
    fn send_decoy(&self, packet: &[u8]) -> Result<()> {
        if self.fail_decoy {
            bail!("simulated decoy injection failure");
        }
        self.log
            .lock()
            .unwrap()
            .push(Event::DecoySent(packet.len()));
        Ok(())
    }
}

fn harness(fail_data: bool, fail_decoy: bool) -> (Log, MockQueue, MockInjector) {
    let log: Log = Arc::new(Mutex::new(Vec::new()));
    let queue = MockQueue { log: log.clone() };
    let injector = MockInjector {
        log: log.clone(),
        fail_data,
        fail_decoy,
    };
    (log, queue, injector)
}

// ═══════════════════════════════════════════════════════════════════
//  Packet / engine builders (mirrors strategy_integration_tests.rs)
// ═══════════════════════════════════════════════════════════════════

/// Build a complete IPv4+TCP packet carrying a TLS ClientHello to port 443.
fn build_tls_client_hello_packet(domain: &str) -> Vec<u8> {
    let sni = domain.as_bytes();
    let sni_list_len = sni.len() + 3;
    let sni_ext_len = sni_list_len + 2;

    let mut extensions = Vec::new();
    extensions.extend_from_slice(&[0x00, 0x00]); // server_name extension
    extensions.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
    extensions.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
    extensions.push(0x00); // host_name
    extensions.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    extensions.extend_from_slice(sni);

    let mut client_hello = Vec::new();
    client_hello.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
    client_hello.extend_from_slice(&[0u8; 32]); // random
    client_hello.push(0x00); // session id len
    client_hello.extend_from_slice(&[0x00, 0x02, 0x00, 0x2F]); // one cipher suite
    client_hello.extend_from_slice(&[0x01, 0x00]); // null compression
    client_hello.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
    client_hello.extend_from_slice(&extensions);

    let mut handshake = Vec::new();
    handshake.push(0x01); // ClientHello
    handshake.push(0x00);
    handshake.extend_from_slice(&(client_hello.len() as u16).to_be_bytes());
    handshake.extend_from_slice(&client_hello);

    let mut payload = Vec::new();
    payload.push(0x16); // Handshake record
    payload.extend_from_slice(&[0x03, 0x01]);
    payload.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    payload.extend_from_slice(&handshake);

    let src = Ipv4Addr::new(192, 168, 1, 100);
    let dst = Ipv4Addr::new(93, 184, 216, 34);
    let tcp_seg = tcp::build_tcp_header(
        12345,
        443,
        1000,
        500,
        tcp::TCP_PSH | tcp::TCP_ACK,
        65535,
        &payload,
    );
    let mut packet = ip::build_ipv4_header(src, dst, ip::PROTO_TCP, 64, tcp_seg.len(), 0x1234);
    packet.extend_from_slice(&tcp_seg);
    packet
}

/// Build an empty TCP ACK (no payload) — should always be plainly accepted.
fn build_plain_ack_packet() -> Vec<u8> {
    let src = Ipv4Addr::new(192, 168, 1, 100);
    let dst = Ipv4Addr::new(93, 184, 216, 34);
    let tcp_seg = tcp::build_tcp_header(12345, 443, 1000, 500, tcp::TCP_ACK, 65535, &[]);
    let mut packet = ip::build_ipv4_header(src, dst, ip::PROTO_TCP, 64, tcp_seg.len(), 0x1234);
    packet.extend_from_slice(&tcp_seg);
    packet
}

/// Engine with default config (multi-fragment+disorder on, domain filter off).
/// `with_fakes` enables fake packet injection → InjectAndFragment path.
///
/// The domain filter is switched off explicitly: these tests are about the
/// injection path, and the default mode is now the restrictive one, which would
/// filter every packet out before the path under test is reached.
fn make_engine(with_fakes: bool) -> StrategyEngine {
    let mut config = Config::default();
    config.domains.mode = cachydpi::config::DomainMode::None;
    config.strategies.fake_packet_enabled = with_fakes;
    StrategyEngine::new(BypassMode::AllActive, config)
}

fn events(log: &Log) -> Vec<Event> {
    log.lock().unwrap().clone()
}

// ═══════════════════════════════════════════════════════════════════
//  Proof tests
// ═══════════════════════════════════════════════════════════════════

const PACKET_ID: u32 = 7;

/// If real-data fragments cannot be injected, the original packet must be
/// accepted so the connection survives — never dropped with nothing sent.
#[test]
fn data_send_failure_falls_back_to_accept() {
    let (log, queue, injector) = harness(true, false);
    let engine = make_engine(false);
    let pkt = build_tls_client_hello_packet("www.blockedsite.com");

    let result = process_packet(
        &engine,
        &queue,
        &injector,
        PACKET_ID,
        &pkt,
        Direction::Outbound,
    );

    let ev = events(&log);
    assert!(
        result.is_ok(),
        "injection failure must be handled internally, got {result:?}; events: {ev:?}"
    );
    assert!(
        !ev.contains(&Event::Drop(PACKET_ID)),
        "original packet must NOT be dropped when no fragment was delivered; events: {ev:?}"
    );
    assert!(
        ev.contains(&Event::Accept(PACKET_ID)),
        "original packet must fall back to ACCEPT when injection fails; events: {ev:?}"
    );
}

/// All data fragments must reach the raw socket BEFORE the original packet's
/// verdict is issued; otherwise a send failure can no longer be recovered.
#[test]
fn fragments_are_delivered_before_the_verdict() {
    let (log, queue, injector) = harness(false, false);
    let engine = make_engine(false);
    let pkt = build_tls_client_hello_packet("www.blockedsite.com");

    let result = process_packet(
        &engine,
        &queue,
        &injector,
        PACKET_ID,
        &pkt,
        Direction::Outbound,
    );
    assert!(result.is_ok(), "got {result:?}");

    let ev = events(&log);
    let verdict_pos = ev
        .iter()
        .position(|e| matches!(e, Event::Drop(_) | Event::Accept(_)))
        .unwrap_or_else(|| panic!("no verdict was issued; events: {ev:?}"));
    let data_positions: Vec<usize> = ev
        .iter()
        .enumerate()
        .filter(|(_, e)| matches!(e, Event::DataSent(_)))
        .map(|(i, _)| i)
        .collect();

    assert!(
        data_positions.len() >= 2,
        "expected the ClientHello to be split into multiple fragments; events: {ev:?}"
    );
    assert!(
        data_positions.iter().all(|&i| i < verdict_pos),
        "every data fragment must be sent before the verdict; events: {ev:?}"
    );
    assert!(
        ev.contains(&Event::Drop(PACKET_ID)),
        "successful fragmentation must drop the original packet; events: {ev:?}"
    );
}

/// A decoy failure is acceptable, but it must not abort the real bypass:
/// fragments still go out and the original is still dropped.
#[test]
fn decoy_failure_does_not_break_the_bypass() {
    let (log, queue, injector) = harness(false, true);
    let engine = make_engine(true); // fake packets on → InjectAndFragment
    let pkt = build_tls_client_hello_packet("www.blockedsite.com");

    let result = process_packet(
        &engine,
        &queue,
        &injector,
        PACKET_ID,
        &pkt,
        Direction::Outbound,
    );

    let ev = events(&log);
    assert!(
        result.is_ok(),
        "decoy failure must not become a packet processing error, got {result:?}; events: {ev:?}"
    );
    let data_sent = ev
        .iter()
        .filter(|e| matches!(e, Event::DataSent(_)))
        .count();
    assert!(
        data_sent >= 2,
        "real fragments must still be delivered when decoys fail; events: {ev:?}"
    );
    assert!(
        ev.contains(&Event::Drop(PACKET_ID)),
        "bypass must complete (original dropped) despite decoy failure; events: {ev:?}"
    );
}

/// Control: a packet no strategy cares about is simply accepted.
/// Must pass before AND after the fix.
#[test]
fn non_matching_packet_is_plainly_accepted() {
    let (log, queue, injector) = harness(true, true); // even with everything failing
    let engine = make_engine(true);
    let pkt = build_plain_ack_packet();

    let result = process_packet(
        &engine,
        &queue,
        &injector,
        PACKET_ID,
        &pkt,
        Direction::Outbound,
    );
    assert!(result.is_ok(), "got {result:?}");

    let ev = events(&log);
    assert_eq!(
        ev,
        vec![Event::Accept(PACKET_ID)],
        "plain ACK must produce exactly one ACCEPT verdict"
    );
}
