//! **The large-file gate on the requester**: what a peer whose hello does not
//! claim large files is asked of one, which is nothing (`MiscOptions2` bit 4).
//! The serve half's gate is core's, on the identity the session read.

use rmule_primitives::{FileHash, is_large_file};

use super::download::ProbeState;
use super::{FileProbeStatus, PeerEvent, PeerSession, SlotReleaseReason};
use crate::RequesterEvent;
use crate::capability::MiscOptions2;
use crate::slot::CancelTransfer;

impl PeerSession {
    /// Whether `file_size` is a large file and this peer's hello does not
    /// claim them. Stock asks before it reads the claim and stops at the
    /// first block past 4 GiB (`DownloadClient.cpp:747`); a stock peer answers
    /// such an ask `OP_FILEREQANSNOFIL` (`ClientTCPSocket.cpp:1070`), which is
    /// what not asking stands in for.
    pub(super) fn large_file_refused(&self, file_size: u64) -> bool {
        is_large_file(file_size)
            && !self
                .peer_misc_options2
                .is_some_and(MiscOptions2::supports_large_files)
    }

    /// Read the refused file as one the peer lacks, as its answer would have
    /// it.
    pub(super) fn settle_refused_file(&mut self, file_hash: FileHash, file_size: u64) {
        let flow = self.per_file.entry(file_hash).or_default();
        flow.file_size = Some(file_size);
        flow.probe = ProbeState::NotAvailable;
        self.core
            .push_event(PeerEvent::Requester(RequesterEvent::FileProbed {
                file_hash,
                status: FileProbeStatus::NotAvailable,
            }));
    }

    /// A grant came for a large file this peer does not claim to take: stock
    /// cancels the transfer and leaves the source
    /// (`DownloadClient.cpp:748-757`).
    pub(super) fn end_large_file_transfer(&mut self, file_hash: FileHash, file_size: u64) {
        self.write_packet(CancelTransfer.encode_packet());
        self.settle_refused_file(file_hash, file_size);
        if self.active_slot == Some(file_hash) {
            self.release_slot(file_hash, SlotReleaseReason::FileNotFound);
        }
    }
}
