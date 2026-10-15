// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/cardinality.rs — counting distinct peers without keeping any
//
// Answering "how many different hosts did this happen to" does not require
// remembering which hosts. A set does, and a set of peer addresses is the same
// data this daemon works to keep out of logs: it can reach disk through swap, a
// core dump or /proc/pid/mem. HyperLogLog answers the question from fixed-size
// registers that hold nothing but small integers, so there is nothing to leak
// and no capacity to run out of.

use std::hash::{BuildHasher, Hash};

/// log2 of the register count. 2^11 registers, one byte each, is 2 KiB of
/// fixed state for a standard error around 2.3% — accurate enough to tell "one
/// peer" from "eighty", which is the distinction being measured.
const PRECISION: u32 = 11;
const REGISTERS: usize = 1 << PRECISION;

/// Distinct-count estimator with no memory of what it counted.
pub struct DistinctCounter {
    registers: Box<[u8; REGISTERS]>,
    /// Randomly seeded per process, so the register pattern cannot be related
    /// back to specific inputs even in principle.
    hasher: std::collections::hash_map::RandomState,
}

impl Default for DistinctCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl DistinctCounter {
    pub fn new() -> Self {
        DistinctCounter {
            registers: Box::new([0u8; REGISTERS]),
            hasher: std::collections::hash_map::RandomState::new(),
        }
    }

    /// Record an observation. The value is hashed and discarded.
    pub fn insert<T: Hash>(&mut self, value: &T) {
        let hash = self.hasher.hash_one(value);

        // Top PRECISION bits pick the register; the rest gives the rank, the
        // position of the first set bit.
        let index = (hash >> (64 - PRECISION)) as usize;
        let remainder = hash << PRECISION;
        let rank = (remainder.leading_zeros() + 1) as u8;

        let register = &mut self.registers[index];
        if rank > *register {
            *register = rank;
        }
    }

    /// Estimated number of distinct values seen.
    ///
    /// Non-decreasing: registers only ever grow, so a watcher never sees the
    /// count go backwards.
    pub fn estimate(&self) -> u64 {
        let m = REGISTERS as f64;
        let mut sum = 0.0f64;
        let mut zeros = 0usize;
        for &r in self.registers.iter() {
            sum += 1.0 / ((1u64 << r) as f64);
            if r == 0 {
                zeros += 1;
            }
        }

        let alpha = 0.7213 / (1.0 + 1.079 / m);
        let raw = alpha * m * m / sum;

        // Small cardinalities are badly served by the raw estimate; while empty
        // registers remain, linear counting is the accurate one.
        let estimate = if raw <= 2.5 * m && zeros > 0 {
            m * (m / zeros as f64).ln()
        } else {
            raw
        };

        estimate.round() as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn ipv4(n: u32) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(n))
    }

    /// The whole point: the numbers that matter here are small, and the
    /// estimator has to be right about them rather than merely close in the
    /// asymptotic sense.
    #[test]
    fn small_counts_are_exact_or_near_exact() {
        for n in [0u32, 1, 2, 5, 45, 79, 100] {
            let mut c = DistinctCounter::new();
            for i in 0..n {
                c.insert(&ipv4(0x0a00_0000 + i));
            }
            let got = c.estimate();
            let tolerance = ((n as f64) * 0.05).max(1.0);
            assert!(
                (got as f64 - n as f64).abs() <= tolerance,
                "estimated {got} distinct for {n} (tolerance {tolerance:.1})"
            );
        }
    }

    /// Repeats must not inflate the count — that is the difference between
    /// "one host resetting 45 times" and "45 hosts".
    #[test]
    fn repeats_do_not_count_twice() {
        let mut c = DistinctCounter::new();
        for _ in 0..1000 {
            c.insert(&ipv4(0x0a000001));
        }
        assert_eq!(c.estimate(), 1);

        for _ in 0..1000 {
            c.insert(&ipv4(0x0a000002));
        }
        assert_eq!(c.estimate(), 2);
    }

    /// Larger populations stay within the precision the register count implies.
    #[test]
    fn larger_counts_stay_within_the_error_bound() {
        let mut c = DistinctCounter::new();
        let n = 10_000u32;
        for i in 0..n {
            c.insert(&ipv4(0x0a00_0000 + i));
        }
        let got = c.estimate() as f64;
        let error = (got - n as f64).abs() / n as f64;
        assert!(
            error < 0.05,
            "error {:.3} estimating {n} (got {got})",
            error
        );
    }

    /// Fixed state, whatever it is fed: no capacity to exhaust, so no
    /// saturation to report and nothing that grows with a hostile network.
    #[test]
    fn state_is_fixed_size_and_holds_no_addresses() {
        let mut c = DistinctCounter::new();
        assert_eq!(std::mem::size_of_val(&*c.registers), 2048);

        let probe = Ipv6Addr::new(0x2600, 0x1901, 0, 0x5e8a, 0, 0, 0, 1);
        c.insert(&IpAddr::V6(probe));
        for i in 0..5000u32 {
            c.insert(&ipv4(i));
        }
        assert_eq!(std::mem::size_of_val(&*c.registers), 2048);

        // Registers are small ranks, not fragments of anything inserted.
        assert!(c.registers.iter().all(|&r| r <= 64));
    }

    /// IPv4 and IPv6 peers are counted in the same estimator.
    #[test]
    fn mixed_address_families_count_together() {
        let mut c = DistinctCounter::new();
        c.insert(&ipv4(0x0a000001));
        c.insert(&IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(c.estimate(), 2);
    }
}
