// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/escalation.rs — per-destination strategy level for mode 7
//
// Mode 7 starts every destination on the configured techniques and moves a
// destination up a level each time the DPI is seen interfering with one of its
// connections — a forged RST, TLS alert or redirect dropped by passive
// defence. Past the top level it starts again from the bottom: a level that
// does not work keeps producing interference, so cycling means no destination
// stays stuck on a technique that fails for it.
//
// Like flow_ttl.rs, the table is fixed-size and keyed by a per-process seeded
// hash: it holds no address and cannot grow.

use std::hash::{BuildHasher, Hash};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};

/// Number of levels; see `StrategyEngine::split_client_hello` for what each
/// adds.
pub const LEVELS: u8 = 4;

const SLOTS: usize = 1 << 12;

pub struct EscalationTable {
    /// Bits 63..40: destination tag, never zero for an occupied slot.
    /// 39..32: level. 31..0: hash of the connection that last raised it, so
    /// the several forged packets of one blocked connection count once.
    slots: Box<[AtomicU64]>,
    hasher: std::collections::hash_map::RandomState,
}

impl Default for EscalationTable {
    fn default() -> Self {
        Self::new()
    }
}

impl EscalationTable {
    pub fn new() -> Self {
        EscalationTable {
            slots: (0..SLOTS).map(|_| AtomicU64::new(0)).collect(),
            hasher: std::collections::hash_map::RandomState::new(),
        }
    }

    fn locate(&self, destination: IpAddr) -> (usize, u64) {
        let hash = self.hasher.hash_one(destination);
        let index = (hash as usize) & (SLOTS - 1);
        let tag = ((hash >> 40) | 1) << 40;
        (index, tag)
    }

    /// The level for a destination; 0 if it has never been raised.
    pub fn level(&self, destination: IpAddr) -> u8 {
        let (index, tag) = self.locate(destination);
        let slot = self.slots[index].load(Ordering::Relaxed);
        if slot & (0xFF_FFFF << 40) == tag {
            (slot >> 32) as u8
        } else {
            0
        }
    }

    /// Record interference on one connection to `destination`, identified by
    /// any value unique to the connection. Returns the new level if this
    /// connection had not already raised it.
    pub fn note_interference<C: Hash>(&self, destination: IpAddr, connection: &C) -> Option<u8> {
        let (index, tag) = self.locate(destination);
        // Never zero, so a fresh slot cannot look like this connection's.
        let conn = (self.hasher.hash_one(connection) as u32) | 1;
        let slot = &self.slots[index];
        let current = slot.load(Ordering::Relaxed);
        let (level, last) = if current & (0xFF_FFFF << 40) == tag {
            ((current >> 32) as u8, current as u32)
        } else {
            (0, 0)
        };
        if last == conn {
            return None;
        }
        let next = (level + 1) % LEVELS;
        let value = tag | (u64::from(next) << 32) | u64::from(conn);
        // A concurrent update for this slot wins; the next interference retries.
        slot.compare_exchange(current, value, Ordering::Relaxed, Ordering::Relaxed)
            .ok()?;
        Some(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([198, 51, 100, last])
    }

    #[test]
    fn one_connection_raises_a_destination_once() {
        let table = EscalationTable::new();
        assert_eq!(table.level(ip(1)), 0);
        assert_eq!(table.note_interference(ip(1), &1000u16), Some(1));
        assert_eq!(table.note_interference(ip(1), &1000u16), None);
        assert_eq!(table.level(ip(1)), 1);
        assert_eq!(table.note_interference(ip(1), &1001u16), Some(2));
        assert_eq!(table.level(ip(2)), 0, "other destinations are unaffected");
    }

    #[test]
    fn levels_wrap_around() {
        let table = EscalationTable::new();
        let mut seen = Vec::new();
        for port in 0..(LEVELS as u16 + 1) {
            seen.push(table.note_interference(ip(1), &port).unwrap());
        }
        assert_eq!(seen, [1, 2, 3, 0, 1]);
    }
}
