// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 abel0x <https://github.com/abel0x>
// src/nfqueue/mod.rs — Safe Rust wrapper around libnetfilter_queue
//
// Provides a high-level, ergonomic API for interacting with Linux
// NFQUEUE. Packets are received from the kernel, processed in
// userspace, and a verdict (ACCEPT/DROP) is issued.

pub mod sys;

use std::io;
use std::ptr;

use anyhow::{Context, Result, bail};
use tracing::{debug, error, trace, warn};

/// Maximum packet buffer size (jumbo frame support)
const RECV_BUF_SIZE: usize = 65536;

/// Maximum queue length in kernel
const DEFAULT_QUEUE_MAXLEN: u32 = 8192;

/// Verdict to issue for a packet
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Accept the packet (let it through)
    Accept,
    /// Drop the packet silently
    Drop,
    /// Accept with modified payload
    AcceptModified(usize), // length stored externally
}

/// Information about a received packet
#[derive(Debug)]
pub struct PacketInfo {
    /// Kernel-assigned packet ID (used for verdict)
    pub id: u32,
    /// Raw packet payload (IP header + transport + data)
    pub payload: Vec<u8>,
    /// Netfilter hook number (0=PREROUTING, 1=INPUT, 3=FORWARD, 4=OUTPUT, 5=POSTROUTING)
    pub hook: u8,
    /// Packet mark (nfmark)
    pub mark: u32,
}

/// Callback data shared between the C callback and Rust
struct CallbackData {
    /// Queue of received packets waiting to be processed
    packets: Vec<PacketInfo>,
}

/// A handle to an nfqueue
pub struct NfQueue {
    handle: *mut sys::nfq_handle,
    queue_handle: *mut sys::nfq_q_handle,
    fd: i32,
    queue_num: u16,
    callback_data: *mut CallbackData,
    /// Pre-allocated receive buffer (reused across recv() calls)
    recv_buf: Vec<u8>,
    /// Swap buffer to avoid allocating a new Vec every recv() cycle
    swap_buf: Vec<PacketInfo>,
}

// SAFETY: NfQueue is used from a single thread (the packet processing loop)
unsafe impl Send for NfQueue {}

impl NfQueue {
    /// Open a new nfqueue connection and bind to the specified queue number.
    ///
    /// # Arguments
    /// * `queue_num` - The NFQUEUE number (must match nftables rules)
    /// * `ipv6` - Whether to also bind AF_INET6
    pub fn open(queue_num: u16, ipv6: bool) -> Result<Self> {
        unsafe {
            // Open library handle
            let handle = sys::nfq_open();
            if handle.is_null() {
                bail!("nfq_open() failed — is libnetfilter_queue installed?");
            }

            // Unbind existing handler (if any) and bind fresh
            sys::nfq_unbind_pf(handle, libc::AF_INET as u16);
            if sys::nfq_bind_pf(handle, libc::AF_INET as u16) < 0 {
                sys::nfq_close(handle);
                bail!(
                    "nfq_bind_pf(AF_INET) failed — are you running as root or with CAP_NET_ADMIN?"
                );
            }

            if ipv6 {
                sys::nfq_unbind_pf(handle, libc::AF_INET6 as u16);
                if sys::nfq_bind_pf(handle, libc::AF_INET6 as u16) < 0 {
                    warn!("nfq_bind_pf(AF_INET6) failed — IPv6 support disabled");
                }
            }

            // Allocate callback data on the heap
            let cb_data = Box::into_raw(Box::new(CallbackData {
                packets: Vec::with_capacity(64),
            }));

            // Create the queue with our callback
            let queue_handle = sys::nfq_create_queue(
                handle,
                queue_num,
                nfq_callback,
                cb_data as *mut libc::c_void,
            );
            if queue_handle.is_null() {
                drop(Box::from_raw(cb_data));
                sys::nfq_close(handle);
                bail!(
                    "nfq_create_queue({}) failed — is the queue number already in use?",
                    queue_num
                );
            }

            // Set copy mode: copy entire packet to userspace
            if sys::nfq_set_mode(queue_handle, sys::NFQNL_COPY_PACKET, RECV_BUF_SIZE as u32) < 0 {
                sys::nfq_destroy_queue(queue_handle);
                drop(Box::from_raw(cb_data));
                sys::nfq_close(handle);
                bail!("nfq_set_mode(COPY_PACKET) failed");
            }

            // Set queue max length
            sys::nfq_set_queue_maxlen(queue_handle, DEFAULT_QUEUE_MAXLEN);

            let fd = sys::nfq_fd(handle);
            if fd < 0 {
                sys::nfq_destroy_queue(queue_handle);
                drop(Box::from_raw(cb_data));
                sys::nfq_close(handle);
                bail!("nfq_fd() returned invalid fd");
            }

            debug!(
                queue_num = queue_num,
                fd = fd,
                "nfqueue opened successfully"
            );

            Ok(NfQueue {
                handle,
                queue_handle,
                fd,
                queue_num,
                callback_data: cb_data,
                recv_buf: vec![0u8; RECV_BUF_SIZE],
                swap_buf: Vec::with_capacity(64),
            })
        }
    }

    /// Receive packets from the queue with poll-based timeout.
    /// Returns a vector of received packets, or empty vec on timeout/interrupt.
    pub fn recv(&mut self) -> Result<Vec<PacketInfo>> {
        unsafe {
            // Poll with 500ms timeout so shutdown flag can be checked promptly
            let mut pollfd = libc::pollfd {
                fd: self.fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let poll_ret = libc::poll(&mut pollfd, 1, 500);
            if poll_ret == 0 {
                // Timeout — no data available, return empty for shutdown check
                return Ok(Vec::new());
            }
            if poll_ret < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    return Ok(Vec::new());
                }
                return Err(err).context("poll() on nfqueue fd failed");
            }

            let n = sys::recv(
                self.fd,
                self.recv_buf.as_mut_ptr() as *mut libc::c_void,
                self.recv_buf.len(),
                0,
            );

            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    return Ok(Vec::new());
                }
                return Err(err).context("recv() on nfqueue fd failed");
            }

            if n == 0 {
                return Ok(Vec::new());
            }

            // Process received data through libnetfilter_queue
            let ret = sys::nfq_handle_packet(
                self.handle,
                self.recv_buf.as_mut_ptr() as *mut libc::c_char,
                n as libc::c_int,
            );

            if ret < 0 {
                warn!("nfq_handle_packet() returned error");
                return Ok(Vec::new());
            }

            // Extract packets collected by the callback (swap buffers, zero allocation)
            let cb_data = &mut *self.callback_data;
            self.swap_buf.clear();
            std::mem::swap(&mut cb_data.packets, &mut self.swap_buf);
            let packets = std::mem::take(&mut self.swap_buf);

            trace!(count = packets.len(), "received packets from nfqueue");
            Ok(packets)
        }
    }

    /// Issue an ACCEPT verdict for a packet (let it through unmodified)
    pub fn verdict_accept(&self, packet_id: u32) -> Result<()> {
        unsafe {
            let ret =
                sys::nfq_set_verdict(self.queue_handle, packet_id, sys::NF_ACCEPT, 0, ptr::null());
            if ret < 0 {
                bail!("nfq_set_verdict(ACCEPT, {}) failed", packet_id);
            }
        }
        trace!(id = packet_id, "verdict: ACCEPT");
        Ok(())
    }

    /// Issue a DROP verdict for a packet (silently discard)
    pub fn verdict_drop(&self, packet_id: u32) -> Result<()> {
        unsafe {
            let ret =
                sys::nfq_set_verdict(self.queue_handle, packet_id, sys::NF_DROP, 0, ptr::null());
            if ret < 0 {
                bail!("nfq_set_verdict(DROP, {}) failed", packet_id);
            }
        }
        trace!(id = packet_id, "verdict: DROP");
        Ok(())
    }

    /// Issue an ACCEPT verdict with a modified packet payload
    pub fn verdict_accept_modified(&self, packet_id: u32, data: &[u8]) -> Result<()> {
        unsafe {
            let ret = sys::nfq_set_verdict(
                self.queue_handle,
                packet_id,
                sys::NF_ACCEPT,
                data.len() as u32,
                data.as_ptr(),
            );
            if ret < 0 {
                bail!("nfq_set_verdict(ACCEPT+modified, {}) failed", packet_id);
            }
        }
        trace!(
            id = packet_id,
            len = data.len(),
            "verdict: ACCEPT (modified)"
        );
        Ok(())
    }

    /// Issue an ACCEPT verdict with a mark set on the packet
    pub fn verdict_accept_mark(&self, packet_id: u32, mark: u32) -> Result<()> {
        unsafe {
            let ret = sys::nfq_set_verdict2(
                self.queue_handle,
                packet_id,
                sys::NF_ACCEPT,
                mark,
                0,
                ptr::null(),
            );
            if ret < 0 {
                bail!("nfq_set_verdict2(ACCEPT+mark, {}) failed", packet_id);
            }
        }
        trace!(id = packet_id, mark = mark, "verdict: ACCEPT (marked)");
        Ok(())
    }

    /// Get the raw file descriptor for use with epoll/poll
    pub fn fd(&self) -> i32 {
        self.fd
    }

    /// Get the queue number
    pub fn queue_num(&self) -> u16 {
        self.queue_num
    }
}

impl Drop for NfQueue {
    fn drop(&mut self) {
        unsafe {
            debug!(queue_num = self.queue_num, "closing nfqueue");
            sys::nfq_destroy_queue(self.queue_handle);
            sys::nfq_close(self.handle);
            // Reclaim the callback data
            drop(Box::from_raw(self.callback_data));
        }
    }
}

/// C callback invoked by libnetfilter_queue for each received packet.
///
/// SAFETY: This function is called from C code during nfq_handle_packet().
/// The `data` pointer must be a valid `*mut CallbackData`.
unsafe extern "C" fn nfq_callback(
    qh: *mut sys::nfq_q_handle,
    _nfmsg: *mut sys::nfgenmsg,
    nfad: *mut sys::nfq_data,
    data: *mut libc::c_void,
) -> libc::c_int {
    unsafe {
        let cb_data = &mut *(data as *mut CallbackData);

        // Get packet header (contains packet ID)
        let ph = sys::nfq_get_msg_packet_hdr(nfad);
        if ph.is_null() {
            error!("nfq_get_msg_packet_hdr() returned null");
            // Cannot get packet_id — kernel bypass flag handles stuck packets
            return 0;
        }

        let packet_id = u32::from_be((*ph).packet_id);
        let hook = (*ph).hook;

        // Get packet payload
        let mut payload_ptr: *mut u8 = ptr::null_mut();
        let payload_len = sys::nfq_get_payload(nfad, &mut payload_ptr);
        if payload_len <= 0 || payload_ptr.is_null() {
            error!(id = packet_id, "nfq_get_payload() failed");
            // Issue accept verdict to prevent queue leak
            let _ = sys::nfq_set_verdict(qh, packet_id, sys::NF_ACCEPT, 0, ptr::null());
            return 0;
        }

        // Copy payload into a Vec (we need ownership)
        let payload = std::slice::from_raw_parts(payload_ptr, payload_len as usize).to_vec();

        // Get nfmark
        let mark = sys::nfq_get_nfmark(nfad);

        cb_data.packets.push(PacketInfo {
            id: packet_id,
            payload,
            hook,
            mark,
        });

        0
    }
}
