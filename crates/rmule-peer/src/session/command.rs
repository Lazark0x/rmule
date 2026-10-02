//! What a driver asks of a peer session, and the fan-out that applies it.
//!
//! [`PeerCommand`] is the whole inbound vocabulary — both capabilities'
//! asks on one connection (ADR-0031). [`PeerSession::handle_command`] hands
//! every variant that touches session state to the leg that owns that state,
//! and frames here only the asks that are nothing but one packet on the wire.
//! Either path rejects what the current state forbids.

use rmule_primitives::{
    AichRootHash, Ed2kText, ExchangedSource, FileHash, PartHash, SessionOutput,
};

use super::download::SlotState;
use super::{PeerCloseReason, PeerEvent, PeerSession, SlotReleaseReason, State};
use crate::buddy::{Callback, ReaskCallbackTcp};
use crate::file::PartBitmap;
use crate::hash_set::HashSetAnswer;
use crate::ipv6::ChangeClientIpV6;
use crate::packet::PeerPacket;
use crate::parts::PartRanges;
use crate::slot::CancelTransfer;
use crate::source_exchange::ServedSourcesVersion;

/// One effect drained from a [`PeerSession`]: the shared [`SessionOutput`]
/// spine over the peer event and close-reason vocabularies (ADR-0044).
pub type PeerOutput = SessionOutput<PeerEvent, PeerCloseReason>;

#[derive(Clone, Debug, PartialEq, Eq)]
/// Everything a driver can ask of a session — both capabilities on one
/// connection (ADR-0031). A command the current state forbids is
/// answered with `CommandRejected`, never a panic and never silence.
pub enum PeerCommand {
    /// Close the link, sending nothing further.
    Disconnect,
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
    /// Requester Capability — open file negotiation with a source in one
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
    /// Request a specific set of part ranges. Auto-issues hash-set
    /// request and slot acquisition if not already done for `file_hash`.
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
    /// Requester Capability — local-reason teardown (ADR-0056): a worker
    /// torn down by `CancelDownload`, `PauseDownload`, or complete-overshoot
    /// while `file_hash` holds the connection's active slot context sends
    /// `OP_CANCELTRANSFER` before releasing it — the requester-side
    /// counterpart to `ReleaseSlot`'s silent local clear. A `CancelTransfer`
    /// for a file that does not hold the active slot is a no-op (nothing to
    /// cancel); this also makes the emit idempotent within one ask-cycle.
    CancelTransfer {
        /// The file whose slot to cancel.
        file_hash: FileHash,
    },
    /// Server Capability — answer an inbound `RequestFileName` (the peer
    /// asked the file's name). Core looks the file up in the Shared File
    /// Registry and supplies the name, or sends `AnswerFileNotFound`.
    AnswerFileName {
        /// The file that was asked about.
        file_hash: FileHash,
        /// The name to answer with.
        file_name: Ed2kText,
    },
    /// Server Capability — we do not share `file_hash`; frame
    /// `OP_FILEREQANSNOFIL`.
    AnswerFileNotFound {
        /// The file we do not have.
        file_hash: FileHash,
    },
    /// Server Capability — answer an inbound `SetReqFileId` with the file's
    /// part bitmap (`OP_FILESTATUS`).
    AnswerFileStatus {
        /// The file the bitmap describes.
        file_hash: FileHash,
        /// Which parts we hold.
        bitmap: PartBitmap,
    },
    /// Server Capability — answer an inbound `HashSetRequest` with the
    /// part-hash set (`OP_HASHSETANSWER`).
    AnswerHashSet {
        /// The file the set belongs to.
        file_hash: FileHash,
        /// One hash per part, in part order.
        part_hashes: Vec<PartHash>,
    },
    /// Server Capability — answer an inbound `OP_AICHREQUEST` with a part's AICH
    /// recovery data (`OP_AICHANSWER`, ADR-0038). Core builds the tree for the
    /// shared file and supplies `root` + `recovery_data`.
    AnswerAich {
        /// The file being recovered.
        file_hash: FileHash,
        /// The part the branch covers.
        part: u16,
        /// Our master root for the file.
        root: AichRootHash,
        /// The branch itself, built by core from the file's tree.
        recovery_data: Vec<u8>,
    },
    /// Server Capability — answer an inbound `OP_AICHFILEHASHREQ` with our AICH
    /// master `root` for the file (`OP_AICHFILEHASHANS`, ADR-0038).
    AnswerAichFileHash {
        /// Our master root for the connection's file — the wire carries no file hash here.
        root: AichRootHash,
    },
    /// Server Capability — grant the remote peer an upload slot for
    /// `file_hash` (`OP_ACCEPTUPLOADREQ`); records the per-connection
    /// `served_slot`.
    GrantSlot {
        /// The file the slot is granted for.
        file_hash: FileHash,
    },
    /// Server Capability — tell the queued peer its position
    /// (`OP_QUEUERANKING`). No `file_hash`: the wire packet is
    /// file-agnostic and the connection has at most one served context.
    SetQueueRank {
        /// Places ahead of the peer in our queue.
        rank: u16,
    },
    /// Server Capability — refuse / evict the slot (`OP_OUTOFPARTREQS`);
    /// clears `served_slot` when it matches `file_hash`.
    RefuseSlot {
        /// The file whose slot is refused.
        file_hash: FileHash,
    },
    /// Server Capability — push one block of part bytes to the granted
    /// peer (`OP_SENDINGPART`). Core reads `bytes` from the Content Store;
    /// the session frames it only when `served_slot` matches
    /// `file_hash`.
    SendBlock {
        /// The file the bytes come from.
        file_hash: FileHash,
        /// Absolute offset of the first byte.
        start: u64,
        /// Absolute offset one past the last.
        end: u64,
        /// The block, read by core from the content store.
        bytes: Vec<u8>,
    },
    /// Server Capability — answer a peer's source-exchange request (ADR-0055).
    /// Core supplies the filtered, capped `sources` (its pools /
    /// filters / throttle) and echoes back the `version` the session picked at
    /// request time; the session frames `OP_ANSWERSOURCES` (`0x82`) or
    /// `OP_ANSWERSOURCES2` (`0x84`) at that version and pack-attempts it above
    /// `PEER_PACK_THRESHOLD` (354 bytes, ADR-0053). An empty `sources` is
    /// still framed as an empty answer — core only issues this command when it
    /// decided to answer at all (a throttled or empty pool sends nothing).
    AnswerSources {
        /// The file the sources are for.
        file_hash: FileHash,
        /// The rows to answer with, already filtered and capped by core.
        sources: Vec<ExchangedSource>,
        /// The wire form the session picked when the request arrived, echoed back so both sides agree on the geometry.
        version: ServedSourcesVersion,
    },
    /// Kad firewall-check **dial-back** ack (ADR-0058 responder, v7+ path): frame
    /// the empty-body `OP_KAD_FWTCPCHECK_ACK` (`0xA8`) over this link. Core sends
    /// it once its Kad-brokered dial-back to a firewalled requester identifies —
    /// the connect-back that proves the requester's TCP port is open. The session
    /// stays Kad-ignorant: it only frames the null packet, guarded by the same
    /// `require_identified` precondition every emit uses (aMule sends the ack in
    /// `KS_CONNECTED_FWCHECK`, i.e. after the dial-back's hello completes).
    SendKadFirewallAck,
    /// Kad UDP firewall-check request (ADR-0058 requester): frame `request` as
    /// `OP_FWCHECKUDPREQ` (`0xA7`) over this link. Core sends it once its dial
    /// to an engaged UDP Firewall Helper identifies — aMule sends it on
    /// `KS_CONNECTING_FWCHECK_UDP` → `KS_FWCHECK_UDP`, i.e. once the hello
    /// completed (`BaseClient.cpp:2520-2522`). The body is the Kad node's,
    /// framed as given.
    SendKadUdpFirewallRequest {
        /// The `<intern port 2><extern port 2><sender key 4>` body.
        request: Vec<u8>,
    },
    /// Open-node buddy relay of a Kad `0x52`→`0x99` callback (ADR-0061):
    /// frame the `OP_CALLBACK` (`0x99`) over *this* buddy link. Core issues it once
    /// its single-slot buddy service verifies the relayed callback's buddy-ID
    /// against our registered buddy; the session only frames the pre-built packet,
    /// guarded by `require_identified` (the buddy link is a completed peer session).
    SendBuddyCallback(Callback),
    /// Open-node buddy relay of a peer-UDP `0x94`→`0x9A` reask (ADR-0061):
    /// frame the `OP_REASKCALLBACKTCP` (`0x9A`) over this buddy link. Emit-side twin
    /// of [`Self::SendBuddyCallback`].
    SendReaskCallbackTcp(ReaskCallbackTcp),
    /// Answer an `OP_BUDDYPING` with `OP_BUDDYPONG` (`0xA0`) over this buddy link
    /// (ADR-0061). Core issues it only when its buddy service confirms the
    /// ping came from our registered buddy (a stranger's ping is refused there);
    /// the session frames the null pong, guarded by `require_identified`.
    SendBuddyPong,
    /// Keep our own buddy link alive with `OP_BUDDYPING` (`0x9F`, ADR-0061
    /// firewalled-node operation): aMule's firewalled client dials its buddy
    /// and pings it for as long as it stays firewalled
    /// ([`BaseClient.cpp#L2544`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/BaseClient.cpp#L2544),
    /// driven from
    /// [`ClientList.cpp#L662`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/ClientList.cpp#L662)).
    /// The cadence is the firewalled front's; the session frames the null
    /// packet, guarded by `require_identified` like every other emit — the
    /// mirror of [`Self::SendBuddyPong`], which answers one.
    SendBuddyPing,
    /// Announce a changed Known IPv6 on this established session
    /// (`OP_CHANGE_CLIENT_IP` `0xAC`, ADR-0087). Core issues it when the
    /// Advertised Endpoints chooser settles on a different address than the
    /// one this session's hello named; without it a peer keeps dialing the
    /// address we no longer hold. Guarded by `require_identified` — a peer
    /// that has not yet heard our hello has nothing to correct.
    AnnounceIpv6Change(std::net::Ipv6Addr),
}

impl PeerSession {
    /// Apply one command, or reject it with the reason the state gives.
    /// Every variant lands on the leg that owns it; nothing is handled here.
    pub fn handle_command(&mut self, command: PeerCommand) {
        if matches!(self.state, State::Closed) {
            return;
        }
        match command {
            PeerCommand::Disconnect => self.close(PeerCloseReason::Local),
            PeerCommand::ProbeFile {
                file_hash,
                file_size,
                own_status,
            } => self.handle_probe_file(file_hash, file_size, own_status),
            PeerCommand::RequestFile {
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
            PeerCommand::RequestParts {
                file_hash,
                file_size,
                ranges,
            } => self.handle_request_parts(file_hash, file_size, ranges),
            PeerCommand::RequestSources { file_hash } => self.handle_request_sources(file_hash),
            PeerCommand::RequestAich {
                file_hash,
                part,
                root,
            } => self.handle_request_aich(file_hash, part, root),
            PeerCommand::RequestAichFileHash { file_hash } => {
                if self.require_identified() {
                    self.write_packet(crate::aich::AichFileHashReq { file_hash }.encode_packet());
                }
            }
            PeerCommand::ReleaseSlot { file_hash } => {
                if self.active_slot == Some(file_hash) {
                    self.release_slot(file_hash, SlotReleaseReason::DownloadComplete);
                }
            }
            PeerCommand::CancelTransfer { file_hash } => {
                if self.active_slot == Some(file_hash) {
                    self.write_packet(CancelTransfer.encode_packet());
                    // Transition to standby (slot dropped, connection held) for
                    // no-needed-parts emit, or teardown-emit path decides via
                    // later Disconnect (ADR-0056).
                    if let Some(flow) = self.per_file.get_mut(&file_hash) {
                        flow.slot = SlotState::Standby;
                        flow.pending_request = None;
                    }
                    self.active_slot = None;
                    self.core.push_event(PeerEvent::SlotReleased {
                        file_hash,
                        reason: SlotReleaseReason::Cancelled,
                    });
                }
            }
            PeerCommand::AnswerFileName {
                file_hash,
                file_name,
            } => {
                if self.require_identified() {
                    self.answer_file_name(file_hash, file_name);
                }
            }
            PeerCommand::AnswerFileNotFound { file_hash } => {
                if self.require_identified() {
                    self.answer_file_not_found(file_hash);
                }
            }
            PeerCommand::AnswerFileStatus { file_hash, bitmap } => {
                if self.require_identified() {
                    self.answer_file_status(file_hash, bitmap);
                }
            }
            PeerCommand::AnswerHashSet {
                file_hash,
                part_hashes,
            } => {
                if self.require_identified() {
                    self.write_packet(
                        HashSetAnswer {
                            file_hash,
                            part_hashes,
                        }
                        .encode_packet(),
                    );
                }
            }
            PeerCommand::AnswerAich {
                file_hash,
                part,
                root,
                recovery_data,
            } => {
                if self.require_identified() {
                    self.write_packet(
                        crate::aich::AichAnswer {
                            file_hash,
                            part,
                            root,
                            recovery_data,
                        }
                        .encode_packet(),
                    );
                }
            }
            PeerCommand::AnswerAichFileHash { root } => {
                if self.require_identified() {
                    self.answer_aich_file_hash(root);
                }
            }
            PeerCommand::GrantSlot { file_hash } => self.grant_slot(file_hash),
            PeerCommand::SetQueueRank { rank } => self.set_queue_rank(rank),
            PeerCommand::RefuseSlot { file_hash } => self.refuse_slot(file_hash),
            PeerCommand::SendBlock {
                file_hash,
                start,
                end,
                bytes,
            } => self.send_block(file_hash, start, end, bytes),
            PeerCommand::AnswerSources {
                file_hash,
                sources,
                version,
            } => {
                if self.require_identified() {
                    self.answer_sources(file_hash, sources, version);
                }
            }
            PeerCommand::SendKadUdpFirewallRequest { request } => {
                if self.require_identified() {
                    self.write_packet(PeerPacket::KadUdpFirewallRequest(request).encode());
                }
            }
            PeerCommand::SendKadFirewallAck => {
                // ADR-0058 responder dial-back ack: the null `OP_KAD_FWTCPCHECK_ACK`
                // over this link, sent only once the requester's hello completed
                // (aMule's `KS_CONNECTED_FWCHECK`). Nothing else — the ack's whole
                // meaning is its arrival on the connection we dialed back.
                if self.require_identified() {
                    self.write_packet(PeerPacket::KadFirewallAck.encode());
                }
            }
            // ADR-0061 open-node buddy relays: the two verified relay
            // outputs and the pong ride this buddy link, framed directly from the
            // `crate::buddy` codecs (never round-tripped through the umbrella, which
            // parks these opcodes as `Unknown`). Each is guarded by the same
            // `require_identified` precondition every emit uses — the buddy link is
            // a completed peer session. The verify decisions (buddy-ID match, the
            // pong's our-buddy gate) already happened core-side; the session only
            // frames what core told it to send.
            PeerCommand::SendBuddyCallback(callback) => {
                if self.require_identified() {
                    self.write_packet(callback.encode_packet());
                }
            }
            PeerCommand::SendReaskCallbackTcp(relay) => {
                if self.require_identified() {
                    self.write_packet(relay.encode_packet());
                }
            }
            PeerCommand::SendBuddyPong => {
                if self.require_identified() {
                    self.write_packet(PeerPacket::BuddyPong.encode());
                }
            }
            PeerCommand::SendBuddyPing => {
                if self.require_identified() {
                    self.write_packet(PeerPacket::BuddyPing.encode());
                }
            }
            PeerCommand::AnnounceIpv6Change(address) => {
                // An address no 16-byte tag can identify is refused at the
                // constructor, so a mis-wired caller sends nothing rather than
                // naming a peer two ways.
                if let Some(announcement) = ChangeClientIpV6::new(address)
                    && self.require_identified()
                {
                    self.write_packet(announcement.encode_packet());
                }
            }
        }
    }
}
