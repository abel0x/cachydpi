// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/handshake_watch.rs — has the server answered this ClientHello yet?
//
// Mode 7 escalates on interference, and some interference leaves no forged
// packet to catch. A blackholed ClientHello is only visible as the kernel
// sending it again at the same sequence number. A reset that copies the
// server's TTL passes the hop-count check, but arriving before the server has
// sent a byte it still ends a handshake that was blocked. Both need to know,
// per connection, where the ClientHello started and whether the server has
// answered since.
//
// Fixed-size, seeded-hash tags, no addresses — as in flow_ttl.rs.

use std::hash::BuildHasher;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::flow_ttl::FlowKey;

const SLOTS: usize = 1 << 12;
const ANSWERED: u64 = 1 << 32;
const TAG_MASK: u64 = !0 << 33;

pub struct HandshakeWatch {
    /// Bits 63..33: tag, never zero for an occupied slot. 32: the server has
    /// answered. 31..0: sequence number the ClientHello started at.
    slots: Box<[AtomicU64]>,
    hasher: std::collections::hash_map::RandomState,
}

impl Default for HandshakeWatch {
    fn default() -> Self {
        Self::new()
    }
}

impl HandshakeWatch {
    pub fn new() -> Self {
        HandshakeWatch {
            slots: (0..SLOTS).map(|_| AtomicU64::new(0)).collect(),
            hasher: std::collections::hash_map::RandomState::new(),
        }
    }

    fn locate(&self, key: &FlowKey) -> (usize, u64) {
        let hash = self.hasher.hash_one(key);
        let index = (hash as usize) & (SLOTS - 1);
        (index, (hash | (1 << 63)) & TAG_MASK)
    }

    /// A ClientHello starting at `seq` went out. Returns whether it repeats
    /// one still unanswered — a retransmission.
    pub fn client_hello_sent(&self, key: &FlowKey, seq: u32) -> bool {
        let (index, tag) = self.locate(key);
        let previous = self.slots[index].swap(tag | u64::from(seq), Ordering::Relaxed);
        previous & TAG_MASK == tag && previous & ANSWERED == 0 && previous as u32 == seq
    }

    /// The server sent data on this connection.
    pub fn server_answered(&self, key: &FlowKey) {
        let (index, tag) = self.locate(key);
        let slot = &self.slots[index];
        let current = slot.load(Ordering::Relaxed);
        if current & TAG_MASK == tag {
            let _ = slot.compare_exchange(
                current,
                current | ANSWERED,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
        }
    }

    /// Whether a ClientHello went out on this connection and the server has
    /// not answered it.
    pub fn awaiting_answer(&self, key: &FlowKey) -> bool {
        let (index, tag) = self.locate(key);
        let current = self.slots[index].load(Ordering::Relaxed);
        current & TAG_MASK == tag && current & ANSWERED == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn key(port: u16) -> FlowKey {
        FlowKey {
            server: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)),
            client: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            server_port: 443,
            client_port: port,
        }
    }

    #[test]
    fn a_repeat_before_any_answer_is_a_retransmission() {
        let w = HandshakeWatch::new();
        assert!(!w.client_hello_sent(&key(1), 1000));
        assert!(w.awaiting_answer(&key(1)));
        assert!(w.client_hello_sent(&key(1), 1000));
        assert!(
            !w.client_hello_sent(&key(1), 2000),
            "a different start is a new hello"
        );
        assert!(!w.awaiting_answer(&key(2)));
    }

    #[test]
    fn an_answer_ends_the_wait() {
        let w = HandshakeWatch::new();
        w.client_hello_sent(&key(1), 1000);
        w.server_answered(&key(1));
        assert!(!w.awaiting_answer(&key(1)));
        assert!(!w.client_hello_sent(&key(1), 1000));
    }
}
