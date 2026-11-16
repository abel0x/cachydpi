// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// fuzz/fuzz_targets/parse_packet.rs — arbitrary bytes through the packet path
//
// Everything the daemon takes off the queue is bytes from the network. This
// feeds arbitrary ones to ParsedPacket::parse in both directions and, when
// they parse, to the strategy engine in every mode with every technique on:
// the parsers, the splitters and the fake builders all see them. Any panic is
// a bug; a malformed packet must come back as "not for us", never take the
// bypass down.

#![no_main]

use std::sync::LazyLock;

use cachydpi::config::{Config, DomainMode};
use cachydpi::packet::{Direction, ParsedPacket};
use cachydpi::strategies::{BypassMode, StrategyEngine};
use libfuzzer_sys::fuzz_target;

/// One engine per mode, built once: each keeps flow state across inputs, so
/// a SYN-ACK in one input shapes how a later RST or ClientHello is judged.
static ENGINES: LazyLock<Vec<StrategyEngine>> = LazyLock::new(|| {
    let mut config = Config::default();
    config.domains.mode = DomainMode::None;
    let s = &mut config.strategies;
    s.fake_packet_enabled = true;
    s.fake_wrong_checksum = true;
    s.fake_wrong_seq = true;
    s.desync_first = true;
    s.quic_desync = true;
    s.auto_ttl = true;
    (1..=7)
        .map(|n| StrategyEngine::new(BypassMode::from_mode_number(n), config.clone()))
        .collect()
});

fuzz_target!(|data: &[u8]| {
    for direction in [Direction::Outbound, Direction::Inbound] {
        let Some(packet) = ParsedPacket::parse(data, direction) else {
            continue;
        };
        for engine in ENGINES.iter() {
            let _ = match direction {
                Direction::Outbound => engine.evaluate_outbound(&packet),
                Direction::Inbound => engine.evaluate_inbound(&packet),
            };
        }
    }
});
