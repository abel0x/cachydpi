// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/flow_ttl.rs — the TTL a connection's server answered with, per flow
//
// An injected RST is told apart from the server's own by where it came from:
// the DPI sits closer than the server, so its packets arrive with more TTL
// left. The reference is the server's SYN-ACK on the same connection. Packet
// shape cannot do this — a Linux server's own RST has window 0 and no options,
// exactly the shape of a forged one.
//
// The table is fixed-size and holds no addresses. A flow is hashed with a
// per-process random seed into a slot that keeps a 24-bit tag and a TTL, the
// same reasoning as cardinality.rs: nothing in it can be turned back into a
// peer, and it cannot grow.

use std::hash::{BuildHasher, Hash};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, Ordering};

/// 8192 slots of four bytes. Entries are only needed between a SYN and the
/// first few round trips after it, so a slot reused by a later flow is the
/// normal way an entry ends.
const SLOTS: usize = 1 << 13;

/// What the table knows about a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowTtl {
    /// No record — never seen, or its slot has since been reused.
    Unknown,
    /// The client sent a SYN and no SYN-ACK has come back.
    AwaitingSynAck,
    /// The server's SYN-ACK arrived with this TTL.
    Server(u8),
}

/// A connection as seen from the server's side: (server, client) addresses and
/// ports, so both directions of one flow land in the same slot.
#[derive(Hash)]
pub struct FlowKey {
    pub server: IpAddr,
    pub client: IpAddr,
    pub server_port: u16,
    pub client_port: u16,
}

pub struct FlowTtlTable {
    /// High 24 bits: tag, never zero for an occupied slot. Low byte: TTL, with 0
    /// meaning "SYN seen, no SYN-ACK yet" — a SYN-ACK cannot arrive with TTL 0.
    slots: Box<[AtomicU32]>,
    hasher: std::collections::hash_map::RandomState,
}

impl Default for FlowTtlTable {
    fn default() -> Self {
        Self::new()
    }
}

impl FlowTtlTable {
    pub fn new() -> Self {
        FlowTtlTable {
            slots: (0..SLOTS).map(|_| AtomicU32::new(0)).collect(),
            hasher: std::collections::hash_map::RandomState::new(),
        }
    }

    fn locate(&self, key: &FlowKey) -> (usize, u32) {
        let hash = self.hasher.hash_one(key);
        let index = (hash as usize) & (SLOTS - 1);
        // Tag from bits the index did not use; forced non-zero so an empty
        // slot never matches. 24 bits make a reused slot answering for the
        // wrong flow a one-in-eight-million event.
        let tag = ((hash >> 40) as u32) | 1;
        (index, tag << 8)
    }

    /// The client sent a SYN for this flow.
    pub fn syn_sent(&self, key: &FlowKey) {
        let (index, tag) = self.locate(key);
        self.slots[index].store(tag, Ordering::Relaxed);
    }

    /// The server answered with a SYN-ACK carrying `ttl`.
    pub fn syn_ack_received(&self, key: &FlowKey, ttl: u8) {
        if ttl == 0 {
            return;
        }
        let (index, tag) = self.locate(key);
        self.slots[index].store(tag | ttl as u32, Ordering::Relaxed);
    }

    pub fn lookup(&self, key: &FlowKey) -> FlowTtl {
        let (index, tag) = self.locate(key);
        let slot = self.slots[index].load(Ordering::Relaxed);
        if slot & !0xFF != tag {
            return FlowTtl::Unknown;
        }
        match (slot & 0xFF) as u8 {
            0 => FlowTtl::AwaitingSynAck,
            ttl => FlowTtl::Server(ttl),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn key(client_port: u16) -> FlowKey {
        FlowKey {
            server: IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)),
            client: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
            server_port: 443,
            client_port,
        }
    }

    #[test]
    fn records_progress_through_the_handshake() {
        let table = FlowTtlTable::new();
        assert_eq!(table.lookup(&key(1)), FlowTtl::Unknown);
        table.syn_sent(&key(1));
        assert_eq!(table.lookup(&key(1)), FlowTtl::AwaitingSynAck);
        table.syn_ack_received(&key(1), 52);
        assert_eq!(table.lookup(&key(1)), FlowTtl::Server(52));
        assert_eq!(table.lookup(&key(2)), FlowTtl::Unknown);
    }

    #[test]
    fn a_reused_slot_reads_as_unknown_not_as_another_flows_ttl() {
        let table = FlowTtlTable::new();
        let ttl_for = |port: u16| (port % 200) as u8 + 1;
        for port in 0..u16::MAX {
            table.syn_ack_received(&key(port), ttl_for(port));
        }
        // Eight flows per slot: most have been overwritten. Whatever a lookup
        // returns must be the flow's own TTL or Unknown, never a neighbour's.
        let mut survived = 0;
        for port in 0..u16::MAX {
            match table.lookup(&key(port)) {
                FlowTtl::Unknown => {}
                FlowTtl::Server(t) if t == ttl_for(port) => survived += 1,
                other => panic!("port {port} read {other:?}"),
            }
        }
        assert!(survived > 0 && survived <= SLOTS);
    }
}
