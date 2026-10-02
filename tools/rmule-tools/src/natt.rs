//! The **NAT-T transport drivers** (ADR-0091) the NAT-T harness flows run.
//!
//! Three commands. [`caps_utp`] binds the one client-UDP socket a running
//! node binds, put the dialect's own frames on a counterparty's client-UDP
//! port, and records what came back — the CAPS probe, the KEY frame a uTP dial
//! arms, and the `ST_SYN` itself. [`server_punch`] runs a whole `Core` behind a
//! **NAT Gateway** and asks an eD2k server to introduce it to another Low-ID
//! rmule, which is ADR-0091's second Rendezvous coordinator. [`tunnel_transfer`]
//! takes that one rung further: a real download between two Low-ID nodes, whose
//! part bytes ride the Tunnel the punch raised.
//!
//! What rmule emits here is **Stimulus** and is never evidence (ADR-0045).
//! What the driver exists to obtain is the counterparty's own `0xB2` bytes:
//! every inbound NAT-T datagram is retained raw, in arrival order, beside a
//! [**Driver Row**](crate::driver_row) the flow parses back into claims.
//!
//! The driver deliberately assembles the *production* [`NattDemux`] over the
//! *production* [`ClientUdpSocket`] rather than hand-rolling a uTP handshake:
//! a bench leg that reimplemented the transport would prove the reimplementation
//! rather than the shipped one.
//!
//! [`NattDemux`]: rmule_net::natt::NattDemux
//! [`ClientUdpSocket`]: rmule_net::ed2k::ClientUdpSocket

pub(crate) mod buddy_rendezvous;
pub(crate) mod caps_utp;
pub(crate) mod server_punch;
pub(crate) mod tunnel_transfer;

pub(crate) use buddy_rendezvous::{NattBuddyRendezvousArgs, run_buddy_rendezvous};
pub(crate) use caps_utp::{NattCapsUtpArgs, run_caps_utp};
pub(crate) use server_punch::{NattServerPunchArgs, run_server_punch};
pub(crate) use tunnel_transfer::{NattTunnelTransferArgs, run_tunnel_transfer};

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use rmule_net::natt::{NattCrypt, NattOwnHash};
use rmule_primitives::{
    AddressFamily, DatagramNonce, DatagramSenderAddress, PeerEndpoint, UserHash,
};

/// rmule's own identity as a driver holds it: fixed for the run, because a
/// one-shot driver has exactly one identity and acquires it from its operands
/// rather than from a credentialed activity.
pub(crate) struct DriverIdentity {
    /// Our user hash — the KEY frame's whole body and the CAPS sender.
    pub(crate) user_hash: UserHash,
    /// Our own address as the counterparty observes it, which is what picks
    /// the 23- or 35-byte datagram key layout (ADR-0087). `None` leaves every
    /// NAT-T frame plaintext.
    pub(crate) observed_address: Option<IpAddr>,
}

impl NattOwnHash for DriverIdentity {
    fn user_hash(&self) -> Option<UserHash> {
        Some(self.user_hash)
    }
}

impl NattCrypt for DriverIdentity {
    fn own_user_hash(&self) -> UserHash {
        self.user_hash
    }

    fn sender_address(&self, family: AddressFamily) -> Option<DatagramSenderAddress> {
        let address = self.observed_address?;
        let matches = match (family, address) {
            (AddressFamily::V4, IpAddr::V4(_)) | (AddressFamily::V6, IpAddr::V6(_)) => true,
            (AddressFamily::V4 | AddressFamily::V6, _) => false,
        };
        matches.then(|| DatagramSenderAddress::from_ip(address))
    }

    fn nonce(&self) -> DatagramNonce {
        let mut raw = [0u8; 3];
        getrandom::fill(&mut raw).expect("OS entropy for the NAT-T crypt nonce");
        // aMule disables UDP padding outright, so a padded datagram would
        // decode and still not be byte-shaped like one of theirs.
        DatagramNonce {
            marker_byte: raw[0],
            random_key: u16::from_le_bytes([raw[1], raw[2]]),
            padding: Vec::new(),
        }
    }
}

/// One datagram the driver's socket received, exactly as it arrived.
#[derive(Clone, Debug)]
pub(crate) struct Seen {
    /// Where it came from.
    pub(crate) from: PeerEndpoint,
    /// The bytes, unmodified — the fixture candidate.
    pub(crate) bytes: Vec<u8>,
}

impl Seen {
    /// The NAT-T frame-type byte, for a datagram that is one.
    pub(crate) fn natt_frame_type(&self) -> Option<u8> {
        (self.bytes.first() == Some(&rmule_peer::natt::NATT_PROTOCOL))
            .then(|| self.bytes.get(1).copied())
            .flatten()
    }
}

/// The arrival log the receive pump fills and the row reads. Shared rather than
/// returned: the pump outlives every individual leg of a driver run, so the
/// legs read a growing record instead of each owning a socket.
#[derive(Clone, Default)]
pub(crate) struct Arrivals(Arc<Mutex<Vec<Seen>>>);

impl Arrivals {
    /// Record one datagram.
    pub(crate) fn push(&self, seen: Seen) {
        self.0
            .lock()
            .expect("the NAT-T arrival log is never poisoned")
            .push(seen);
    }

    /// Every datagram recorded so far, in arrival order.
    pub(crate) fn snapshot(&self) -> Vec<Seen> {
        self.0
            .lock()
            .expect("the NAT-T arrival log is never poisoned")
            .clone()
    }

    /// How many recorded datagrams carry NAT-T frame type `frame_type`.
    pub(crate) fn count_frames(&self, frame_type: u8) -> usize {
        self.snapshot()
            .iter()
            .filter(|seen| seen.natt_frame_type() == Some(frame_type))
            .count()
    }

    /// The first recorded datagram carrying `frame_type`.
    pub(crate) fn first_frame(&self, frame_type: u8) -> Option<Seen> {
        self.snapshot()
            .into_iter()
            .find(|seen| seen.natt_frame_type() == Some(frame_type))
    }
}
