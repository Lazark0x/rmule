//! The **Requester** group of [`PeerCommand`](super::PeerCommand): our pull
//! from the peer (ADR-0025) — probes, file and part requests, source and AICH
//! asks, and the end of the slot we chase, including our `OP_CANCELTRANSFER`
//! (ADR-0056).

use rmule_primitives::{AichRootHash, FileHash};

use crate::file::PartBitmap;
use crate::parts::PartRanges;
use crate::slot::CancelTransfer;

use super::super::download::SlotState;
use super::super::{PeerEvent, PeerSession, RequesterEvent, SlotReleaseReason};

/// What we ask of the peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RequesterCommand {
    /// Probe whether the peer has a given file and learn its part bitmap.
    ProbeFile {
        /// The file to ask about.
        file_hash: FileHash,
        /// The file's size, recorded on the flow so a status answering this
        /// probe can expand aMule's part-count-0 "complete source" sentinel
        /// Every real caller knows it from the source row or
        /// ed2k link it is probing.
        file_size: u64,
        /// What rmule already holds of the file — rides the `0x58` whenever
        /// the session's extended-requests level asks for it.
        own_status: PartBitmap,
    },
    /// Open file negotiation with a source in one
    /// round (ADR-0054 emit): ask its name (`0x58`), and — folded per
    /// the same per-packet conditions rmule already applies — its part status
    /// (`0x4F`, when the file is multi-part), more sources (`0x81`/`0x83` per
    /// the ADR-0055 source-ask policy, when `want_sources`), and its AICH
    /// master root (`0x9E`, when
    /// `want_aich_root`, i.e. the download still lacks a trusted root). Against
    /// a peer that advertised MultiPacket these fold into a single
    /// `OP_MULTIPACKET` / `OP_MULTIPACKET_EXT` bundle; otherwise they go as the
    /// separate standalone packets — one decision core, two wire shapes,
    /// mirroring aMule's `CUpDownClient::SendFileRequest`. `file_size` sizes
    /// the multi-part decision and rides the `0xA4` form's `size8`.
    RequestFile {
        /// The file to negotiate.
        file_hash: FileHash,
        /// The file's size, which decides whether a part-status ask is worth folding in and rides the `0xA4` form's `size8`.
        file_size: u64,
        /// Fold in a source ask.
        want_sources: bool,
        /// Fold in an AICH master-root ask — set while the download still has no trusted root.
        want_aich_root: bool,
        /// What rmule already holds of the file
        /// ([`PartBitmap::downloader`]) — rides the `0x58` whenever the
        /// session's extended-requests level asks for it. aMule
        /// keeps it as the asker's part status, and refuses a complete file's
        /// source-exchange answer without one.
        own_status: PartBitmap,
    },
    /// Ask the peer for an upload slot for `file_hash` (`OP_STARTUPLOADREQ`,
    /// aMule `SendStartupLoadReq`): the flow takes the connection's slot
    /// context and is queued, and `SlotAsked` says the ask left. The caller
    /// sends it once the probe has answered, as aMule asks once a status names
    /// a part it needs; the part itself is asked for at the grant, with
    /// `RequestParts`. A flow already queued or granted is left alone, and a
    /// flow whose slot was given back or released asks again; another file
    /// holding the slot is `SlotBusy` (ADR-0025).
    AskSlot {
        /// The file the slot is for.
        file_hash: FileHash,
    },
    /// Ask the peer for `file_hash`'s part hash set (`OP_HASHSETREQUEST`), once
    /// per file on this connection; the answer arrives as `HashSetReceived`.
    /// Nothing waits on it here: which link asks, and when its slot ask
    /// follows, is the download's decision (ADR-0026).
    RequestHashSet {
        /// The file whose part hashes are wanted.
        file_hash: FileHash,
    },
    /// Request a specific set of part ranges. Without a slot ask yet, this
    /// asks the probe (when none was asked) and then the slot once the probe
    /// answers; before the grant the ranges wait for it. It asks no hash set
    /// ([`Self::RequestHashSet`] does).
    RequestParts {
        /// The file the ranges fall in.
        file_hash: FileHash,
        /// The file's size, which picks the 32- or 64-bit wire form.
        file_size: u64,
        /// Up to three ranges; the peer answers each as its own block.
        ranges: PartRanges,
    },
    /// Ask the peer for more sources of `file_hash` (`OP_REQUESTSOURCES`,
    /// receive-only — ADR-0055). The worker sends this once on connect.
    RequestSources {
        /// The file sources are wanted for.
        file_hash: FileHash,
    },
    /// Ask the peer for the AICH recovery data of `part`, quoting the master
    /// `root` we trust (`OP_AICHREQUEST`, ADR-0038). Core sends this after a
    /// part fails MD4 verification and a trusted AICH root is available.
    RequestAich {
        /// The file being recovered.
        file_hash: FileHash,
        /// The part that failed verification.
        part: u16,
        /// The master root we already trust, quoted so the peer can answer against it.
        root: AichRootHash,
    },
    /// Ask the peer for a file's AICH master hash (`OP_AICHFILEHASHREQ`,
    /// ADR-0038), to collect trusted-set root proposals when the link carried
    /// no `h=`. The worker sends this on connect for a rootless download.
    RequestAichFileHash {
        /// The file whose master hash is wanted.
        file_hash: FileHash,
    },
    /// Release the held upload slot for `file_hash`. The runtime worker
    /// sends this once it has assembled the whole part; the session keeps
    /// the slot across earlier block requests rather than releasing per
    /// `RequestParts` (ADR-0025, amended). A `ReleaseSlot` for a file that
    /// does not hold the active slot is a no-op.
    ReleaseSlot {
        /// The file whose slot to give up.
        file_hash: FileHash,
    },
    /// Local-reason teardown (ADR-0056): a worker
    /// torn down by `CancelDownload`, `PauseDownload`, or complete-overshoot
    /// while `file_hash` holds the connection's active slot context sends
    /// `OP_CANCELTRANSFER` before releasing it — the requester-side
    /// counterpart to `ReleaseSlot`'s silent local clear. With no slot
    /// active, it gives back a slot the peer offered unasked that no ask of
    /// ours answered since, as [`Self::DeclineSlot`] does: the rider that took
    /// the grant stops before asking. Anything else is a no-op (nothing to
    /// cancel); this also makes the emit idempotent within one ask-cycle.
    CancelTransfer {
        /// The file whose slot to cancel.
        file_hash: FileHash,
    },
    /// Give back a slot the peer offered unasked (`SlotOffered`) that no
    /// download takes: `OP_CANCELTRANSFER` once, as aMule's downloader
    /// cancels an accept it does not want (`ClientTCPSocket.cpp:646-659`,
    /// ADR-0056). A no-op once an ask of ours went out on the link, or with
    /// no offer pending.
    DeclineSlot,
}

impl PeerSession {
    pub(super) fn apply_requester(&mut self, command: RequesterCommand) {
        match command {
            RequesterCommand::ProbeFile {
                file_hash,
                file_size,
                own_status,
            } => self.handle_probe_file(file_hash, file_size, own_status),
            RequesterCommand::RequestFile {
                file_hash,
                file_size,
                want_sources,
                want_aich_root,
                own_status,
            } => self.handle_request_file(
                file_hash,
                file_size,
                want_sources,
                want_aich_root,
                own_status,
            ),
            RequesterCommand::AskSlot { file_hash } => self.handle_ask_slot(file_hash),
            RequesterCommand::RequestHashSet { file_hash } => {
                self.handle_request_hash_set(file_hash);
            }
            RequesterCommand::RequestParts {
                file_hash,
                file_size,
                ranges,
            } => self.handle_request_parts(file_hash, file_size, ranges),
            RequesterCommand::RequestSources { file_hash } => {
                self.handle_request_sources(file_hash)
            }
            RequesterCommand::RequestAich {
                file_hash,
                part,
                root,
            } => self.handle_request_aich(file_hash, part, root),
            RequesterCommand::RequestAichFileHash { file_hash } => {
                if self.require_identified() {
                    self.write_packet(crate::aich::AichFileHashReq { file_hash }.encode_packet());
                }
            }
            RequesterCommand::ReleaseSlot { file_hash } => {
                if self.active_slot == Some(file_hash) {
                    self.release_slot(file_hash, SlotReleaseReason::DownloadComplete);
                }
            }
            RequesterCommand::DeclineSlot => self.decline_offered_slot(),
            RequesterCommand::CancelTransfer { file_hash } => {
                if self.active_slot == Some(file_hash) {
                    self.write_packet(CancelTransfer.encode_packet());
                    self.forget_asked_ranges();
                    // The slot is given back and the connection held: a later
                    // slot ask runs the cycle again (ADR-0056).
                    if let Some(flow) = self.per_file.get_mut(&file_hash) {
                        flow.slot = SlotState::Standby;
                        flow.pending_request = None;
                    }
                    self.drop_compressed_blocks(file_hash);
                    self.active_slot = None;
                    self.core
                        .push_event(PeerEvent::Requester(RequesterEvent::SlotReleased {
                            file_hash,
                            reason: SlotReleaseReason::Cancelled,
                        }));
                } else {
                    // The rider took an unasked grant and stops before its
                    // own ask leaves: the grant is its to give back
                    // (ADR-0056 item 3).
                    self.decline_offered_slot();
                }
            }
        }
    }

    /// Give back a slot the peer offered unasked, once: `OP_CANCELTRANSFER`
    /// while the offer stands and no ask of ours went out since.
    fn decline_offered_slot(&mut self) {
        if std::mem::take(&mut self.slot_offered) && self.active_slot.is_none() {
            self.write_packet(CancelTransfer.encode_packet());
            self.forget_asked_ranges();
        }
    }
}
