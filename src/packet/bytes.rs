// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/packet/bytes.rs — checked reads and writes at byte offsets
//
// Every packet the daemon sees comes off the network, and a length field in
// it can say anything. An index past the end of a slice panics, and a panic
// on the packet path takes the bypass down for every connection. These
// helpers return None instead, so a short or lying packet is passed over the
// way any other unparseable one is. `packet` and `strategies` are linted to
// use nothing else.

/// The byte at `at`.
pub(crate) fn u8_at(data: &[u8], at: usize) -> Option<u8> {
    data.get(at).copied()
}

/// `N` bytes starting at `at`.
pub(crate) fn array_at<const N: usize>(data: &[u8], at: usize) -> Option<[u8; N]> {
    data.get(at..at.checked_add(N)?)?.try_into().ok()
}

/// A big-endian `u16` at `at`.
pub(crate) fn be16_at(data: &[u8], at: usize) -> Option<u16> {
    array_at(data, at).map(u16::from_be_bytes)
}

/// A big-endian `u32` at `at`.
pub(crate) fn be32_at(data: &[u8], at: usize) -> Option<u32> {
    array_at(data, at).map(u32::from_be_bytes)
}

/// `len` bytes starting at `at`.
pub(crate) fn slice_at(data: &[u8], at: usize, len: usize) -> Option<&[u8]> {
    data.get(at..at.checked_add(len)?)
}

/// Overwrite the bytes at `at` with `bytes`; None, and nothing written, if
/// they do not fit.
pub(crate) fn put(buf: &mut [u8], at: usize, bytes: &[u8]) -> Option<()> {
    buf.get_mut(at..at.checked_add(bytes.len())?)?
        .copy_from_slice(bytes);
    Some(())
}

pub(crate) fn put_u8(buf: &mut [u8], at: usize, value: u8) -> Option<()> {
    *buf.get_mut(at)? = value;
    Some(())
}

pub(crate) fn put_be16(buf: &mut [u8], at: usize, value: u16) -> Option<()> {
    put(buf, at, &value.to_be_bytes())
}

pub(crate) fn put_be32(buf: &mut [u8], at: usize, value: u32) -> Option<()> {
    put(buf, at, &value.to_be_bytes())
}

/// The sum of `data` as big-endian 16-bit words, an odd last byte padded
/// with zero, before folding: the body of every Internet checksum.
pub(crate) fn sum_words(data: &[u8]) -> u32 {
    let (words, rest) = data.as_chunks::<2>();
    let odd = rest.first().map_or(0, |&b| (b as u32) << 8);
    words
        .iter()
        .map(|&w| u16::from_be_bytes(w) as u32)
        .sum::<u32>()
        + odd
}

/// Fold a word sum into the ones' complement checksum.
pub(crate) fn fold(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !sum as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_inside_the_slice_succeed() {
        let data = [0x12, 0x34, 0x56, 0x78, 0x9a];
        assert_eq!(u8_at(&data, 4), Some(0x9a));
        assert_eq!(be16_at(&data, 0), Some(0x1234));
        assert_eq!(be32_at(&data, 1), Some(0x3456_789a));
        assert_eq!(array_at::<2>(&data, 3), Some([0x78, 0x9a]));
        assert_eq!(slice_at(&data, 1, 3), Some(&data[1..4]));
        assert_eq!(slice_at(&data, 5, 0), Some(&data[5..]));
    }

    #[test]
    fn reads_past_the_end_are_none() {
        let data = [0u8; 4];
        assert_eq!(u8_at(&data, 4), None);
        assert_eq!(be16_at(&data, 3), None);
        assert_eq!(be32_at(&data, 1), None);
        assert_eq!(slice_at(&data, 2, 3), None);
        // Offsets near usize::MAX must not wrap round to the start.
        assert_eq!(be16_at(&data, usize::MAX), None);
        assert_eq!(slice_at(&data, usize::MAX, 2), None);
    }

    #[test]
    fn writes_that_do_not_fit_change_nothing() {
        let mut buf = [0u8; 4];
        assert_eq!(put_be16(&mut buf, 2, 0xabcd), Some(()));
        assert_eq!(buf, [0, 0, 0xab, 0xcd]);
        assert_eq!(put_be32(&mut buf, 1, 0xffff_ffff), None);
        assert_eq!(put_u8(&mut buf, 4, 1), None);
        assert_eq!(put(&mut buf, usize::MAX, &[1]), None);
        assert_eq!(buf, [0, 0, 0xab, 0xcd]);
        assert_eq!(put_u8(&mut buf, 0, 7), Some(()));
        assert_eq!(buf[0], 7);
    }
}
