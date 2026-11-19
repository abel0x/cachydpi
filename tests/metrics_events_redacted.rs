// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// tests/metrics_events_redacted.rs — metrics events never name a peer
//
// The metrics snapshot is served on a 0666 socket, so any local account can
// read it. `[logging] log_identifying_fields` decides what the journal records;
// it must not decide what that socket hands out. This drives a real forged-RST
// detection through the strategy engine with the switch off and on, and checks
// the event that lands in the snapshot both times.
//
// Its own test binary because both METRICS and the logging switch are
// process-wide, and flipping the switch must not race other tests.

use std::net::Ipv4Addr;

use cachydpi::config::Config;
use cachydpi::metrics::METRICS;
use cachydpi::packet::{Direction, ParsedPacket, ip, tcp};
use cachydpi::strategies::{BypassMode, PacketAction, StrategyEngine};

const PEER: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 22);

fn inbound(flags: u8, ttl: u8) -> Vec<u8> {
    let header = tcp::build_tcp_header(443, 41000, 100, 200, flags, 65535, &[]);
    let mut packet = ip::build_ipv4_header(
        PEER,
        Ipv4Addr::new(192, 0, 2, 33),
        ip::PROTO_TCP,
        ttl,
        header.len(),
        1,
    );
    packet.extend(header);
    packet
}

#[test]
fn forged_rst_event_names_no_peer_in_either_logging_mode() {
    let engine = StrategyEngine::new(BypassMode::from_mode_number(1), Config::default());

    // A SYN-ACK at TTL 50 sets the flow's expected TTL; an RST at TTL 60 then
    // arrives from a different hop count, which is what marks it as forged.
    let syn_ack = inbound(0x12, 50);
    let rst = inbound(0x14, 60);
    engine.evaluate_inbound(&ParsedPacket::parse(&syn_ack, Direction::Inbound).unwrap());

    for identifying in [false, true] {
        cachydpi::logging::set_identifying_fields(identifying);
        let action =
            engine.evaluate_inbound(&ParsedPacket::parse(&rst, Direction::Inbound).unwrap());
        assert!(
            matches!(action, PacketAction::Drop),
            "the RST should be detected as forged (identifying = {identifying})"
        );

        let snapshot = METRICS.snapshot();
        let event = snapshot
            .recent_events
            .last()
            .expect("a forged-RST detection pushes an event");
        assert_eq!(event.message, "forged RST dropped");

        let json = serde_json::to_string(&snapshot).unwrap();
        assert!(
            !json.contains(&PEER.to_string()),
            "the public snapshot names the peer (identifying = {identifying}): {json}"
        );
    }
    cachydpi::logging::set_identifying_fields(false);
}
