//! Peer protocol-area commands, one module per command family: the live
//! welcome and transfer captures that compose `rmule-net`'s eD2k and peer
//! drivers through the application-level
//! [`PeerHandshakeContext`](rmule_peer::PeerHandshakeContext) bridge, the
//! source-exchange leg a transfer can follow with, the UDP reask capture, and
//! the offline packet inspector. Each observed
//! [`PeerEvent`](rmule_peer::PeerEvent) is printed via its co-located
//! `Display`; the command-specific status lines (`file_probed:`,
//! `slot_released:`, …) live with the command that emits them.

mod inspect;
mod reask;
mod source_exchange;
mod transfer;
mod welcome;

pub(crate) use inspect::inspect_packet;
pub(crate) use reask::{PeerReaskCaptureArgs, reask_capture};
pub(crate) use transfer::{PeerTransferCaptureArgs, transfer_capture};
pub(crate) use welcome::{PeerCaptureArgs, welcome_capture};
