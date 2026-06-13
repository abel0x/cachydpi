// src/strategies/window_size.rs — TCP Window Size manipulation
//
// Modifies the TCP window size in outgoing SYN packets to force
// the server to send smaller TCP segments. This causes the HTTP
// response headers to be fragmented, making DPI reassembly harder.
//
// This is a GoodbyeDPI classic technique (-w flag).

use crate::packet::ip::{self, IpHeader};
use crate::packet::tcp::{self, TcpHeader};

/// Default small window size that forces segmentation
pub const DEFAULT_SMALL_WINDOW: u16 = 4;

/// Modify the TCP window size in a SYN packet.
///
/// Returns a modified copy of the entire IP packet with the new window size
/// and recalculated checksums.
pub fn set_syn_window_size(
    raw_packet: &[u8],
    ip_hdr: &IpHeader,
    tcp_hdr: &TcpHeader<'_>,
    new_window: u16,
) -> Option<Vec<u8>> {
    if !tcp_hdr.is_syn() {
        return None;
    }

    let ip_hdr_len = ip_hdr.header_len();
    let mut packet = raw_packet.to_vec();

    // Set new window size
    let tcp_off = ip_hdr_len;
    packet[tcp_off + 14..tcp_off + 16].copy_from_slice(&new_window.to_be_bytes());

    // Recalculate checksums
    let version = (packet[0] >> 4) & 0x0F;
    packet[tcp_off + 16] = 0;
    packet[tcp_off + 17] = 0;
    if version == 4 {
        // IP checksum
        packet[10] = 0;
        packet[11] = 0;
        let ip_cksum = ip::ipv4_checksum(&packet[..ip_hdr_len]);
        packet[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

        // TCP checksum
        if packet.len() >= 20 {
            let src_ip: [u8; 4] = packet[12..16].try_into().unwrap_or([0; 4]);
            let dst_ip: [u8; 4] = packet[16..20].try_into().unwrap_or([0; 4]);
            let tcp_cksum = tcp::tcp_checksum_v4(&src_ip, &dst_ip, &packet[tcp_off..]);
            packet[tcp_off + 16..tcp_off + 18].copy_from_slice(&tcp_cksum.to_be_bytes());
        }
    } else if version == 6 {
        // TCP checksum (mandatory for IPv6)
        if packet.len() >= 40 {
            let src_ip: [u8; 16] = packet[8..24].try_into().unwrap_or([0; 16]);
            let dst_ip: [u8; 16] = packet[24..40].try_into().unwrap_or([0; 16]);
            let tcp_cksum = tcp::tcp_checksum_v6(&src_ip, &dst_ip, &packet[tcp_off..]);
            packet[tcp_off + 16..tcp_off + 18].copy_from_slice(&tcp_cksum.to_be_bytes());
        }
    }

    Some(packet)
}
