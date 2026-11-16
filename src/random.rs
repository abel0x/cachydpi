// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/random.rs — unpredictable bytes for the fields a DPI could match on
//
// Fake packets and probe handshakes carry values a real client never repeats:
// a ClientHello's random and key share, a corrupted checksum, a stray sequence
// offset. Any constant among them is a signature. These come from the kernel.

/// Fill `out` from the kernel's random source.
///
/// Callers draw once per fake or per probe, so a syscall costs nothing that
/// matters. Should `getrandom` fail, the bytes come from the standard
/// library's per-process random hash keys instead: still unpredictable from
/// outside and different for every call, which is what these values must be.
pub fn fill(out: &mut [u8]) {
    // SAFETY: `out` is a valid, writable buffer of exactly `out.len()` bytes.
    let filled = unsafe { libc::getrandom(out.as_mut_ptr().cast(), out.len(), 0) };
    if usize::try_from(filled).is_ok_and(|n| n == out.len()) {
        return;
    }

    use std::hash::{BuildHasher, Hasher};
    use std::sync::atomic::{AtomicU64, Ordering};
    static CALLS: AtomicU64 = AtomicU64::new(0);
    let call = CALLS.fetch_add(1, Ordering::Relaxed);
    let keys = std::collections::hash_map::RandomState::new();
    for (i, chunk) in out.chunks_mut(8).enumerate() {
        let mut h = keys.build_hasher();
        h.write_u64(call);
        h.write_usize(i);
        chunk.copy_from_slice(&h.finish().to_be_bytes()[..chunk.len()]);
    }
}

/// A random `N`-byte array.
pub fn bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    fill(&mut out);
    out
}

pub fn u32() -> u32 {
    u32::from_ne_bytes(bytes())
}

#[cfg(test)]
mod tests {
    #[test]
    fn draws_differ() {
        assert_ne!(super::bytes::<32>(), super::bytes::<32>());
    }

    #[test]
    fn odd_lengths_are_filled() {
        let mut out = [0u8; 13];
        // All-zero after a fill is a one-in-2^104 event.
        super::fill(&mut out);
        assert_ne!(out, [0u8; 13]);
    }
}
