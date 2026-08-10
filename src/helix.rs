// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/helix.rs — intentionally absent from the README, --help, and
// mode_description. Reached only through a hidden subcommand; found by
// reading the source, not by being told.

use std::f64::consts::PI;

/// Render a DNA double helix as text.
///
/// Pure and deterministic so it can be exercised in a unit test without
/// touching the terminal. The two backbones weave on a sine, cross at the
/// `X` points, and the spread-apart rows carry labelled base pairs.
pub fn render() -> String {
    const ROWS: usize = 20;
    const WIDTH: usize = 18;
    const CENTER: f64 = 9.0;
    const AMPLITUDE: f64 = 7.0;
    const STEP: f64 = 0.5;

    // Base pairs cycle down the ladder: A-T, G-C, ...
    const PAIRS: [(u8, u8); 4] = [(b'A', b'T'), (b'G', b'C'), (b'T', b'A'), (b'C', b'G')];

    let mut out = String::with_capacity(ROWS * (WIDTH + 2) + 32);
    out.push('\n');

    for i in 0..ROWS {
        let phase = i as f64 * STEP;
        let x1 = (CENTER + AMPLITUDE * phase.sin()).round() as usize;
        let x2 = (CENTER + AMPLITUDE * (phase + PI).sin()).round() as usize;
        let (lo, hi) = if x1 <= x2 { (x1, x2) } else { (x2, x1) };

        let mut line = vec![b' '; WIDTH + 1];

        if x1 == x2 {
            // The strands cross over.
            line[x1] = b'X';
        } else if i % 2 == 0 && hi - lo >= 4 {
            // A base-pair rung: the two backbones become the paired bases.
            let (left, right) = PAIRS[(i / 2) % PAIRS.len()];
            for cell in line.iter_mut().take(hi).skip(lo + 1) {
                *cell = b'-';
            }
            line[lo] = left;
            line[hi] = right;
        } else {
            // Bare backbone beads.
            line[x1] = b'o';
            line[x2] = b'o';
        }

        // line holds only ASCII (space, 'o', 'X', '-', and base letters).
        out.push_str(std::str::from_utf8(&line).unwrap());
        out.push('\n');
    }

    // A quiet nod, tucked under the strands.
    out.push_str("         ~ Helix ~\n");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_without_panicking_and_carries_the_signature() {
        let art = render();
        assert!(!art.trim().is_empty(), "render produced no output");
        assert!(
            art.contains("Helix"),
            "expected signature missing from output"
        );
        // It is a drawing, not a one-liner.
        assert!(art.lines().count() > 5, "output is suspiciously short");
    }
}
