// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/nfqueue/sys.rs — Raw FFI bindings to libnetfilter_queue
//
// These bindings provide direct access to the C library functions.
// All functions here are unsafe and should only be called through
// the safe wrapper in mod.rs.

#![allow(non_camel_case_types, dead_code)]

use libc::{c_char, c_int, c_uint, c_void, ssize_t};

// Opaque handles from libnetfilter_queue
pub enum nfq_handle {}
pub enum nfq_q_handle {}
pub enum nfq_data {}
pub enum nfgenmsg {}

/// Packet header from nfqueue
#[repr(C)]
pub struct nfqnl_msg_packet_hdr {
    /// Unique packet ID assigned by the kernel
    pub packet_id: u32,
    /// Hardware protocol (network byte order)
    pub hw_protocol: u16,
    /// Netfilter hook number
    pub hook: u8,
}

/// Callback function type for nfq_create_queue
pub type nfq_callback = unsafe extern "C" fn(
    qh: *mut nfq_q_handle,
    nfmsg: *mut nfgenmsg,
    nfad: *mut nfq_data,
    data: *mut c_void,
) -> c_int;

/// Copy modes for nfq_set_mode
pub const NFQNL_COPY_NONE: u8 = 0;
pub const NFQNL_COPY_META: u8 = 1;
pub const NFQNL_COPY_PACKET: u8 = 2;

/// Queue flag: when the queue is full, accept packets instead of dropping
/// them (Linux 3.6+).
pub const NFQA_CFG_F_FAIL_OPEN: u32 = 1 << 0;

/// Verdicts
pub const NF_DROP: u32 = 0;
pub const NF_ACCEPT: u32 = 1;
pub const NF_REPEAT: u32 = 4;

unsafe extern "C" {
    // ── Library handle management ──
    pub fn nfq_open() -> *mut nfq_handle;
    pub fn nfq_close(h: *mut nfq_handle) -> c_int;

    // ── Protocol family binding ──
    pub fn nfq_unbind_pf(h: *mut nfq_handle, pf: u16) -> c_int;
    pub fn nfq_bind_pf(h: *mut nfq_handle, pf: u16) -> c_int;

    // ── Queue management ──
    pub fn nfq_create_queue(
        h: *mut nfq_handle,
        num: u16,
        cb: nfq_callback,
        data: *mut c_void,
    ) -> *mut nfq_q_handle;
    pub fn nfq_destroy_queue(qh: *mut nfq_q_handle) -> c_int;

    // ── Queue configuration ──
    pub fn nfq_set_mode(qh: *mut nfq_q_handle, mode: u8, range: c_uint) -> c_int;
    pub fn nfq_set_queue_maxlen(qh: *mut nfq_q_handle, queuelen: u32) -> c_int;
    pub fn nfq_set_queue_flags(qh: *mut nfq_q_handle, mask: u32, flags: u32) -> c_int;

    // ── Verdict ──
    pub fn nfq_set_verdict(
        qh: *mut nfq_q_handle,
        id: u32,
        verdict: u32,
        data_len: u32,
        buf: *const u8,
    ) -> c_int;

    pub fn nfq_set_verdict2(
        qh: *mut nfq_q_handle,
        id: u32,
        verdict: u32,
        mark: u32,
        data_len: u32,
        buf: *const u8,
    ) -> c_int;

    // ── File descriptor for poll/select/epoll ──
    pub fn nfq_fd(h: *mut nfq_handle) -> c_int;

    // ── Packet processing ──
    pub fn nfq_handle_packet(h: *mut nfq_handle, buf: *mut c_char, len: c_int) -> c_int;

    // ── Packet data accessors ──
    pub fn nfq_get_msg_packet_hdr(nfad: *mut nfq_data) -> *mut nfqnl_msg_packet_hdr;
    pub fn nfq_get_payload(nfad: *mut nfq_data, data: *mut *mut u8) -> c_int;
    pub fn nfq_get_nfmark(nfad: *mut nfq_data) -> u32;
    pub fn nfq_get_indev(nfad: *mut nfq_data) -> u32;
    pub fn nfq_get_outdev(nfad: *mut nfq_data) -> u32;
}

// recv() is from libc, used to read from the nfqueue fd
unsafe extern "C" {
    pub fn recv(sockfd: c_int, buf: *mut c_void, len: usize, flags: c_int) -> ssize_t;
}
