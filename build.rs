// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// build.rs — Link to libnetfilter_queue and libmnl at compile time
fn main() {
    // libnetfilter_queue: userspace library for nfqueue
    pkg_config::Config::new()
        .atleast_version("1.0")
        .probe("libnetfilter_queue")
        .expect("libnetfilter_queue >= 1.0 required. Install: pacman -S libnetfilter_queue");

    // libmnl: minimalistic netlink library (dependency of libnetfilter_queue)
    pkg_config::Config::new()
        .probe("libmnl")
        .expect("libmnl required. Install: pacman -S libmnl");

    // libnfnetlink: low-level netfilter netlink library
    pkg_config::Config::new()
        .probe("libnfnetlink")
        .expect("libnfnetlink required. Install: pacman -S libnfnetlink");
}
