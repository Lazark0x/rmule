//! Reading a flow-L tap: what both reask verdicts judge with.
//!
//! A reask exchange is two datagrams whose obfuscation is decided at each
//! end by the policy and the hello in force at that moment, so judging one
//! needs the moment each obfuscation flip took effect on the tap's own clock,
//! the key each datagram opens under (the receiver's User Hash, read off a
//! plaintext link, with the sender's address mixed in), and the byte shape of
//! a `0x90` for the run's file.

use std::fs;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;

use rmule_primitives::{
    ClientDecryptKeys, DatagramSenderAddress, UserHash, decrypt_datagram_client,
    is_udp_plaintext_marker,
};

use crate::flow::evidence::flip_markers;
use crate::flow::pcap::Ed2kFrame;

/// `OP_EMULEPROT`, the protocol byte of every peer-UDP datagram here.
pub(crate) const EMULE_PROTOCOL: u8 = 0xC5;
/// `OP_REASKFILEPING`.
pub(crate) const OP_REASKFILEPING: u8 = 0x90;
/// `OP_REASKACK`.
pub(crate) const OP_REASKACK: u8 = 0x91;
/// aMule's `PARTSIZE`: the part-status count a ping carries is
/// `size / PARTSIZE + 1`.
const PART_SIZE: u64 = 9_728_000;
/// `OP_HELLO`, which opens with a one-byte hash size before the user hash.
/// A client's `OP_LOGINREQUEST` to a server shares the opcode and opens with
/// the hash itself.
pub(crate) const OP_HELLO: u8 = 0x01;
/// `OP_HELLOANSWER`, which opens with the user hash itself.
pub(crate) const OP_HELLOANSWER: u8 = 0x4C;

/// One `rmule-obfuscation-flip` marker: from its moment on, rmule's peer
/// obfuscation is armed or not.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Flip {
    /// Seconds after the rmule tool asked for its login.
    pub(crate) after_secs: u64,
    /// Whether the policy from then on is anything but `off`.
    pub(crate) crypt: bool,
    /// The wall clock the policy took effect at, in Unix seconds — the clock
    /// the tap stamps packets with. `None` on a marker printed before the
    /// tools carried it.
    pub(crate) at: Option<f64>,
}

impl Flip {
    /// The flips the marker lines in `log` name, in the order they fired.
    pub(crate) fn from_log(log: &str) -> Vec<Self> {
        flip_markers(log)
            .into_iter()
            .map(|marker| Self {
                after_secs: marker.after_secs,
                crypt: marker.policy != "off",
                at: marker.at_unix_ms.map(|ms| ms as f64 / 1000.0),
            })
            .collect()
    }

    /// The flips in the rmule tool's stdout under `root`, none if the run kept
    /// no such log.
    pub(crate) fn read_run_dir(root: &Path) -> Vec<Self> {
        fs::read_to_string(root.join("rmule/stdout.log"))
            .map_or_else(|_| Vec::new(), |log| Self::from_log(&log))
    }

    /// When this flip took effect on the tap's clock: its own wall clock, or —
    /// on a marker without one — `started` plus its offset, where `started`
    /// is the tap's first packet, a few seconds after the tool began and well
    /// inside the minutes flips are set apart by.
    fn moment(self, started: f64) -> f64 {
        self.at.unwrap_or(started + self.after_secs as f64)
    }
}

/// The obfuscation mode in force at capture time `at`: `start` until the
/// first flip, then each flip's mode from its own moment.
pub(crate) fn crypt_at(start: bool, flips: &[Flip], started: f64, at: f64) -> bool {
    flips
        .iter()
        .take_while(|flip| flip.moment(started) <= at)
        .last()
        .map_or(start, |flip| flip.crypt)
}

/// Whether a datagram left obfuscated: its first byte is no plaintext
/// protocol marker (an obfuscating sender draws its marker byte around them).
pub(crate) fn is_obfuscated(wire: &[u8]) -> bool {
    wire.first()
        .is_some_and(|byte| !is_udp_plaintext_marker(*byte))
}

/// A datagram's payload as plaintext: itself when `crypt` is false, else
/// opened under the receiver's user hash with the sender's address mixed in.
pub(crate) fn open(
    wire: &[u8],
    crypt: bool,
    receiver: Option<&UserHash>,
    sender: Ipv4Addr,
) -> Option<Vec<u8>> {
    if !crypt {
        return Some(wire.to_vec());
    }
    let keys = ClientDecryptKeys {
        kad_id: None,
        user_hash: Some(receiver?),
        sender: DatagramSenderAddress::from_ip(IpAddr::V4(sender)),
        receiver_verify_key: None,
    };
    decrypt_datagram_client(wire, &keys).map(|opened| opened.payload)
}

/// Whether `bytes` is an `OP_REASKFILEPING` for the run's file: the protocol
/// and opcode, the file hash, the part-status count its size implies with
/// that many status bits, and the two-byte complete-source count.
pub(crate) fn ping_shape(bytes: &[u8], file_hash: &[u8; 16], file_size: u64) -> bool {
    let count = file_size / PART_SIZE + 1;
    let status_bytes = usize::try_from(count.div_ceil(8)).unwrap_or(usize::MAX);
    bytes.len() == 2 + 16 + 2 + status_bytes + 2
        && bytes[0] == EMULE_PROTOCOL
        && bytes[1] == OP_REASKFILEPING
        && bytes[2..18] == *file_hash
        && u64::from(u16::from_le_bytes([bytes[18], bytes[19]])) == count
}

/// The user hash a peer's `OP_HELLO` or `OP_HELLOANSWER` announces.
pub(crate) fn hello_hash(frame: &Ed2kFrame) -> Option<UserHash> {
    let at = match frame.opcode {
        OP_HELLO => 1,
        OP_HELLOANSWER => 0,
        _ => return None,
    };
    let bytes: [u8; 16] = frame.payload().get(at..at + 16)?.try_into().ok()?;
    Some(UserHash::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::{Flip, crypt_at};

    /// A run that flips judges each datagram in the mode its own moment held:
    /// the start mode up to the marker, the marker's mode from it on, and the
    /// last of several markers wins once its time has passed.
    #[test]
    fn each_side_of_a_flip_is_judged_in_its_own_mode() {
        let flips = Flip::from_log(
            "rmule-obfuscation-flip after_secs=300 policy=supported\n\
             rmule-obfuscation-flip after_secs=600 policy=off\n",
        );
        assert!(!crypt_at(false, &flips, 1000.0, 1299.0));
        assert!(crypt_at(false, &flips, 1000.0, 1300.0));
        assert!(crypt_at(false, &flips, 1000.0, 1599.0));
        assert!(!crypt_at(false, &flips, 1000.0, 1600.0));
        assert!(crypt_at(true, &[], 0.0, 5.0));
    }

    /// A marker's own wall clock places it, whenever the tap began: a tap
    /// that started 7 s after the tool no longer shifts the flip by 7 s.
    #[test]
    fn a_flip_with_a_wall_clock_takes_effect_at_that_clock() {
        let flips = Flip::from_log(
            "rmule-obfuscation-flip after_secs=300 policy=supported at_unix_ms=1791428597250\n",
        );
        let tap_started = 1_791_428_297.0 + 7.0;
        assert!(!crypt_at(false, &flips, tap_started, 1_791_428_597.0));
        assert!(crypt_at(false, &flips, tap_started, 1_791_428_597.3));
    }
}
