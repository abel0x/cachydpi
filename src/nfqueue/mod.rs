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

/// How much of each packet the kernel copies to us: its maximum,
/// NFQNL_MAX_COPY_RANGE, 0xffff less the 4-byte attribute header, since the
/// payload attribute's 16-bit length has to cover both. A larger request is
/// clamped to this anyway. A packet longer than this arrives cut short; see
/// `process_packet`.
const COPY_RANGE: u32 = 0xffff - 4;

/// Netlink receive buffer.
///
/// Each queued packet arrives as one netlink message: a header, the
/// nfgenmsg and the attributes (packet header, mark, interfaces, hardware
/// address, timestamp) around up to `COPY_RANGE` bytes of packet. A buffer of
/// just 64 KiB cut a near-maximum packet's message short, and the library
/// then rejected it, so the packet never got a verdict and stayed queued in
/// the kernel. libnetfilter_queue sizes its own example buffer
/// `0xffff + MNL_SOCKET_BUFFER_SIZE / 2`, at most 0xffff + 4096; this leaves
/// twice that for the attributes. `recv` still detects a message that does
/// not fit, see `NfQueue::recv`.
const RECV_BUF_SIZE: usize = COPY_RANGE as usize + 8192;

/// Netlink message type of a queued packet: (NFNL_SUBSYS_QUEUE << 8) |
/// NFQNL_MSG_PACKET.
const NFQNL_MSG_PACKET_TYPE: u16 = 3 << 8;
/// Attribute carrying `nfqnl_msg_packet_hdr`, whose first field is the ID.
const NFQA_PACKET_HDR: u16 = 1;
/// `sizeof(struct nlmsghdr)` and `sizeof(struct nfgenmsg)`.
const NLMSG_HDRLEN: usize = 16;
const NFGENMSG_LEN: usize = 4;
/// Attribute type bits that are flags, not part of the type.
const NLA_TYPE_MASK: u16 = !((1 << 15) | (1 << 14));

/// The packet ID in a queued-packet netlink message, read without the
/// library.
///
/// Used when the library cannot handle a message, or it did not fit the
/// buffer, so the packet can still be given a verdict. Only the bytes
/// present are read: the packet header is the first attribute the kernel
/// writes, so it survives any cut that leaves the start of the message.
/// Returns `None` for anything that is not a queued-packet message or has no
/// complete packet header in `buf`.
pub fn packet_id_from_message(buf: &[u8]) -> Option<u32> {
    // Netlink headers are in host byte order.
    let ne16 = |at: usize| buf.get(at..at + 2)?.try_into().ok().map(u16::from_ne_bytes);
    let msg_len = buf.get(0..4)?.try_into().ok().map(u32::from_ne_bytes)? as usize;
    if ne16(4)? != NFQNL_MSG_PACKET_TYPE {
        return None;
    }
    // Attributes stop at the end of the message or of what was received.
    let end = msg_len.min(buf.len());

    let mut pos = NLMSG_HDRLEN + NFGENMSG_LEN;
    while pos + 4 <= end {
        let nla_len = usize::from(ne16(pos)?);
        let nla_type = ne16(pos + 2)? & NLA_TYPE_MASK;
        if nla_len < 4 {
            return None;
        }
        if nla_type == NFQA_PACKET_HDR {
            // packet_id (big-endian u32), hw_protocol (u16), hook (u8).
            if nla_len < 4 + 7 || pos + 8 > end {
                return None;
            }
            let id = buf.get(pos + 4..pos + 8)?.try_into().ok()?;
            return Some(u32::from_be_bytes(id));
        }
        // Attributes are padded to four bytes.
        pos = pos.checked_add((nla_len + 3) & !3)?;
    }
    None
}

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
            if sys::nfq_set_mode(queue_handle, sys::NFQNL_COPY_PACKET, COPY_RANGE) < 0 {
                sys::nfq_destroy_queue(queue_handle);
                drop(Box::from_raw(cb_data));
                sys::nfq_close(handle);
                bail!("nfq_set_mode(COPY_PACKET) failed");
            }

            // Set queue max length
            sys::nfq_set_queue_maxlen(queue_handle, DEFAULT_QUEUE_MAXLEN);

            // A full queue otherwise drops every packet that arrives until it
            // drains — the daemon falling behind would cut the user off. Fail
            // open: past the limit, packets go through unmodified, which is
            // what the rules' `bypass` already does when no one is listening.
            if sys::nfq_set_queue_flags(
                queue_handle,
                sys::NFQA_CFG_F_FAIL_OPEN,
                sys::NFQA_CFG_F_FAIL_OPEN,
            ) < 0
            {
                warn!(
                    queue_num = queue_num,
                    "could not set fail-open on the queue; if it fills, packets will be dropped"
                );
            }

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

            // MSG_TRUNC makes a netlink recv return the datagram's real
            // length even when it did not fit, which is how a cut message is
            // told apart from a complete one.
            let n = sys::recv(
                self.fd,
                self.recv_buf.as_mut_ptr() as *mut libc::c_void,
                self.recv_buf.len(),
                libc::MSG_TRUNC,
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

            let len = n as usize;
            if len > self.recv_buf.len() {
                // The library rejects a cut message outright, and the packet
                // would wait in the kernel queue for a verdict that never
                // comes. Its ID is at the start of the message, so let it
                // through unchanged.
                let received = &self.recv_buf[..];
                warn!(
                    queue_num = self.queue_num,
                    message = len,
                    buffer = received.len(),
                    "nfqueue message larger than the receive buffer"
                );
                self.accept_unhandled(received, &[]);
                return Ok(Vec::new());
            }

            // Process received data through libnetfilter_queue
            let ret = sys::nfq_handle_packet(
                self.handle,
                self.recv_buf.as_mut_ptr() as *mut libc::c_char,
                n as libc::c_int,
            );

            // Extract packets collected by the callback (swap buffers, zero
            // allocation). Done whatever `ret` says: anything the callback
            // collected is owed a verdict.
            let cb_data = &mut *self.callback_data;
            self.swap_buf.clear();
            std::mem::swap(&mut cb_data.packets, &mut self.swap_buf);
            let packets = std::mem::take(&mut self.swap_buf);

            if ret < 0 {
                warn!(
                    queue_num = self.queue_num,
                    message = len,
                    "nfq_handle_packet() could not handle a message"
                );
                self.accept_unhandled(&self.recv_buf[..len], &packets);
            }

            trace!(count = packets.len(), "received packets from nfqueue");
            Ok(packets)
        }
    }

    /// Accept the packet of a message the library did not hand to the
    /// callback, unless the callback did collect it (`collected`), so no
    /// packet gets two verdicts.
    fn accept_unhandled(&self, message: &[u8], collected: &[PacketInfo]) {
        match packet_id_from_message(message) {
            Some(id) if collected.iter().any(|p| p.id == id) => {}
            Some(id) => {
                if let Err(e) = self.verdict_accept(id) {
                    error!(id = id, "could not accept an unhandled packet: {e}");
                } else {
                    debug!(id = id, "accepted the packet of an unhandled message");
                }
            }
            None => error!(
                queue_num = self.queue_num,
                "no packet ID in an unhandled nfqueue message; that packet stays queued"
            ),
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
            // No packet ID, so no verdict can be given and the packet stays
            // queued. The rules' `bypass` does not release it: that applies
            // only while no program listens on the queue. The kernel puts the
            // packet header first in every message, so this does not happen
            // with a kernel-built message.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A netlink attribute as the kernel writes it: length and type in host
    /// order, the data, then padding to four bytes.
    fn attr(kind: u16, data: &[u8]) -> Vec<u8> {
        let mut a = Vec::new();
        a.extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
        a.extend_from_slice(&kind.to_ne_bytes());
        a.extend_from_slice(data);
        a.resize(a.len().next_multiple_of(4), 0);
        a
    }

    /// A queued-packet message laid out as the kernel builds it: the packet
    /// header first, then mark and output interface, then `payload_len`
    /// bytes of packet.
    fn queued_message(id: u32, payload_len: usize) -> Vec<u8> {
        const NFQA_MARK: u16 = 3;
        const NFQA_IFINDEX_OUTDEV: u16 = 5;
        const NFQA_PAYLOAD: u16 = 10;

        let mut packet_hdr = id.to_be_bytes().to_vec();
        packet_hdr.extend_from_slice(&0x0800u16.to_be_bytes()); // hw_protocol
        packet_hdr.push(3); // hook: LOCAL_OUT

        let mut body = vec![libc::AF_INET as u8, 0];
        body.extend_from_slice(&200u16.to_be_bytes()); // queue number
        body.extend(attr(NFQA_PACKET_HDR, &packet_hdr));
        body.extend(attr(NFQA_MARK, &0u32.to_be_bytes()));
        body.extend(attr(NFQA_IFINDEX_OUTDEV, &1u32.to_be_bytes()));
        // The payload attribute's length is a u16 like any other.
        let mut payload = attr(NFQA_PAYLOAD, &vec![0x45; payload_len]);
        payload[..2].copy_from_slice(&((4 + payload_len) as u16).to_ne_bytes());
        body.extend(payload);

        let mut msg = Vec::new();
        msg.extend_from_slice(&((NLMSG_HDRLEN + body.len()) as u32).to_ne_bytes());
        msg.extend_from_slice(&NFQNL_MSG_PACKET_TYPE.to_ne_bytes());
        msg.extend_from_slice(&[0; 10]); // flags, seq, pid
        msg.extend(body);
        msg
    }

    #[test]
    fn the_largest_queued_packet_fits_the_receive_buffer() {
        // The kernel copies at most COPY_RANGE bytes. The message around a
        // copy of that size must fit with room for the attributes the
        // kernel may add; at 64 KiB this message did not, and was dropped.
        let msg = queued_message(1, COPY_RANGE as usize);
        assert!(msg.len() > 65_536, "the old buffer could not hold it");
        assert!(
            msg.len() + 4096 <= RECV_BUF_SIZE,
            "{} bytes plus attribute room exceed the {RECV_BUF_SIZE}-byte buffer",
            msg.len()
        );
    }

    #[test]
    fn packet_id_is_read_from_a_whole_message() {
        assert_eq!(
            packet_id_from_message(&queued_message(0xdead_beef, 60)),
            Some(0xdead_beef)
        );
    }

    #[test]
    fn packet_id_survives_a_cut_message() {
        // What recv leaves when the message is longer than the buffer: the
        // start of it. The ID is still there to give the packet a verdict.
        let msg = queued_message(42, COPY_RANGE as usize);
        assert_eq!(packet_id_from_message(&msg[..65_536]), Some(42));
        assert_eq!(packet_id_from_message(&msg[..40]), Some(42));
    }

    #[test]
    fn packet_header_after_other_attributes_is_found() {
        let mut msg = queued_message(7, 20);
        // Move the packet header behind the mark attribute.
        let start = NLMSG_HDRLEN + NFGENMSG_LEN;
        let hdr: Vec<u8> = msg.drain(start..start + 12).collect();
        msg.splice(start + 8..start + 8, hdr);
        assert_eq!(packet_id_from_message(&msg), Some(7));
    }

    #[test]
    fn no_packet_id_without_a_whole_packet_header() {
        let msg = queued_message(9, 20);
        // Cut inside the packet header's ID.
        assert_eq!(
            packet_id_from_message(&msg[..NLMSG_HDRLEN + NFGENMSG_LEN + 6]),
            None
        );
        assert_eq!(packet_id_from_message(&msg[..3]), None);
        assert_eq!(packet_id_from_message(&[]), None);

        // Not a queued-packet message (here NLMSG_ERROR).
        let mut other = msg.clone();
        other[4..6].copy_from_slice(&2u16.to_ne_bytes());
        assert_eq!(packet_id_from_message(&other), None);
    }

    #[test]
    fn a_zero_length_attribute_ends_the_walk() {
        // A length below the attribute header would never advance; it must
        // stop the walk rather than loop.
        let mut msg = queued_message(5, 20);
        let start = NLMSG_HDRLEN + NFGENMSG_LEN;
        msg[start..start + 2].copy_from_slice(&0u16.to_ne_bytes());
        assert_eq!(packet_id_from_message(&msg), None);
    }

    #[test]
    fn the_walk_stops_at_the_declared_message_end() {
        // An ID past the message's own length belongs to whatever follows
        // it in the buffer, not to this message.
        let mut msg = queued_message(11, 20);
        let start = NLMSG_HDRLEN + NFGENMSG_LEN;
        msg[0..4].copy_from_slice(&(start as u32).to_ne_bytes());
        assert_eq!(packet_id_from_message(&msg), None);
    }
}
