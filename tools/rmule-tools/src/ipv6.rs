//! The IPv6-dialect drivers (ADR-0087) the IPv6 harness flows run.
//!
//! Each command is one half of a flow in `tools/interop-harness`: the peer
//! hello over a chosen family ([`hello`]), the obfuscated client-UDP datagram
//! whose key layout follows that family ([`udp_key`]), the **Dial Chooser**
//! verdict a real `Core` publishes for a Low-ID peer that named an IPv6
//! ([`route`]), the eD2k server's own IPv6 capability surface
//! ([`server_probe`]), and the two requesters an ExtSX source answer needs
//! ([`source_exchange`]).
//!
//! Everything these write about rmule is **Stimulus** and is never evidence
//! (ADR-0045). What each one exists to *obtain* is the counterparty's bytes —
//! the hello answer, the reask reply, the login and `OP_SERVERIDENT` burst —
//! which are written out beside the row exactly as they arrived, so a flow can
//! judge them and a fixture can be promoted from them.
//!
//! The rows these write are [**Driver Rows**](crate::driver_row), rendered as
//! TOML by hand the way `nat portmap`'s already is.

pub(crate) mod hello;
pub(crate) mod route;
pub(crate) mod server_probe;
pub(crate) mod source_exchange;
pub(crate) mod udp_key;

pub(crate) use hello::{Ipv6HelloArgs, run_hello};
pub(crate) use route::{Ipv6RouteArgs, run_route};
pub(crate) use server_probe::{Ipv6ServerProbeArgs, run_server_probe};
pub(crate) use source_exchange::{Ipv6HoldSlotArgs, Ipv6SxAskArgs, run_hold_slot, run_sx_ask};
pub(crate) use udp_key::{Ipv6UdpKeyArgs, run_udp_key};

/// Walk a captured eD2k/peer byte stream into its `[proto][len u32 LE][body]`
/// frames, in arrival order.
///
/// A truncated trailing frame ends the walk rather than being returned partly:
/// a capture is read while the far end may still be writing, and half a frame
/// is not a frame a fixture may be cut from.
pub(crate) fn frames(stream: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut offset = 0usize;
    while let Some(header) = stream.get(offset..offset + 5) {
        let len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;
        let Some(frame) = stream.get(offset..offset + 5 + len) else {
            break;
        };
        out.push(frame);
        offset += 5 + len;
    }
    out
}

/// The first frame in `stream` carrying `opcode` under protocol byte `proto`,
/// whole and byte-exact — the fixture candidate a flow promotes.
pub(crate) fn first_frame(stream: &[u8], proto: u8, opcode: u8) -> Option<&[u8]> {
    frames(stream)
        .into_iter()
        .find(|frame| frame.first() == Some(&proto) && frame.get(5) == Some(&opcode))
}

#[cfg(test)]
mod tests {
    use super::{first_frame, frames};

    #[test]
    fn a_truncated_trailer_is_not_a_frame() {
        // Two whole frames, then a length prefix promising more than remains.
        let mut stream = vec![0xE3, 0x02, 0x00, 0x00, 0x00, 0x01, 0xAA];
        stream.extend_from_slice(&[0xE3, 0x01, 0x00, 0x00, 0x00, 0x4C]);
        stream.extend_from_slice(&[0xE3, 0x40, 0x00, 0x00, 0x00, 0x99]);
        let walked = frames(&stream);
        assert_eq!(walked.len(), 2);
        assert_eq!(first_frame(&stream, 0xE3, 0x4C), Some(&stream[7..13]));
        assert_eq!(first_frame(&stream, 0xE3, 0x99), None);
    }
}
