// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/hello_resume.rs — where a ClientHello's extension walk continues
//
// When a ClientHello spans TCP segments and its SNI is not in the first one,
// the later segment can only be read by knowing where in it the next
// extension header falls. That position is a sequence number, and the number
// of extension bytes still to come; nothing else is needed and nothing else is
// kept. Like flow_ttl.rs, the table is fixed-size and keyed by a seeded hash,
// so it holds no address and cannot grow.

use std::hash::BuildHasher;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::flow_ttl::FlowKey;

/// Entries live from one segment of a ClientHello to the next, a fraction of a
/// round trip, so a small table is plenty.
const SLOTS: usize = 1 << 12;

pub struct HelloResumeTable {
    /// Bits 63..48: tag, never zero for an occupied slot. 47..16: sequence
    /// number of the next extension header. 15..0: extension bytes from there
    /// to the end of the block — at most 65535, the block's own length limit.
    slots: Box<[AtomicU64]>,
    hasher: std::collections::hash_map::RandomState,
}

impl Default for HelloResumeTable {
    fn default() -> Self {
        Self::new()
    }
}

impl HelloResumeTable {
    pub fn new() -> Self {
        HelloResumeTable {
            slots: (0..SLOTS).map(|_| AtomicU64::new(0)).collect(),
            hasher: std::collections::hash_map::RandomState::new(),
        }
    }

    fn locate(&self, key: &FlowKey) -> (usize, u64) {
        let hash = self.hasher.hash_one(key);
        let index = (hash as usize) & (SLOTS - 1);
        let tag = ((hash >> 48) | 1) << 48;
        (index, tag)
    }

    /// Remember that this flow's next extension header is at `next_seq`, with
    /// `remaining` extension bytes from there.
    pub fn store(&self, key: &FlowKey, next_seq: u32, remaining: u16) {
        let (index, tag) = self.locate(key);
        let value = tag | (u64::from(next_seq) << 16) | u64::from(remaining);
        self.slots[index].store(value, Ordering::Relaxed);
    }

    /// This flow's entry, if it has one. The entry stays: a retransmission of
    /// the segment it points into needs it again.
    pub fn get(&self, key: &FlowKey) -> Option<(u32, u16)> {
        let (index, tag) = self.locate(key);
        let value = self.slots[index].load(Ordering::Relaxed);
        if value & (0xFFFF << 48) != tag {
            return None;
        }
        Some(((value >> 16) as u32, value as u16))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn key(client_port: u16) -> FlowKey {
        FlowKey {
            server: IpAddr::V4(Ipv4Addr::new(162, 159, 128, 233)),
            client: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
            server_port: 443,
            client_port,
        }
    }

    #[test]
    fn an_entry_belongs_to_its_flow_and_survives_reading() {
        let table = HelloResumeTable::new();
        table.store(&key(1), 0xFFFF_FFF0, 1234);
        assert_eq!(table.get(&key(2)), None);
        assert_eq!(table.get(&key(1)), Some((0xFFFF_FFF0, 1234)));
        assert_eq!(table.get(&key(1)), Some((0xFFFF_FFF0, 1234)));
    }
}
