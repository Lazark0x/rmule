//! The **Server** group of [`PeerCommand`](super::PeerCommand): our answers
//! to the peer's pull (ADR-0031) — names, statuses, hash sets, AICH data,
//! sources, the slot grant, the queue rank and the blocks on a granted slot.
//! Who gets a slot is core's decision; these only carry it out.

use rmule_primitives::{AichRootHash, Ed2kText, FileHash, PartHash, SourceSighting};

use crate::file::PartBitmap;
use crate::hash_set::HashSetAnswer;

use super::super::PeerSession;

/// What we answer the peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServerCommand {
    /// Answer an inbound `RequestFileName` (the peer
    /// asked the file's name). Core looks the file up in the Shared File
    /// Registry and supplies the name, or sends `AnswerFileNotFound`.
    AnswerFileName {
        /// The file that was asked about.
        file_hash: FileHash,
        /// The name to answer with.
        file_name: Ed2kText,
    },
    /// We do not share `file_hash`; frame
    /// `OP_FILEREQANSNOFIL`.
    AnswerFileNotFound {
        /// The file we do not have.
        file_hash: FileHash,
    },
    /// Answer an inbound `SetReqFileId` with the file's
    /// part bitmap (`OP_FILESTATUS`).
    AnswerFileStatus {
        /// The file the bitmap describes.
        file_hash: FileHash,
        /// Which parts we hold.
        bitmap: PartBitmap,
    },
    /// Answer an inbound `HashSetRequest` with the
    /// part-hash set (`OP_HASHSETANSWER`).
    AnswerHashSet {
        /// The file the set belongs to.
        file_hash: FileHash,
        /// One hash per part, in part order.
        part_hashes: Vec<PartHash>,
    },
    /// Answer an inbound `OP_AICHREQUEST` with a part's AICH
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
    /// Answer an inbound `OP_AICHFILEHASHREQ` with our AICH
    /// master `root` for the file (`OP_AICHFILEHASHANS`, ADR-0038).
    AnswerAichFileHash {
        /// Our master root for the connection's file — the wire carries no file hash here.
        root: AichRootHash,
    },
    /// Grant the remote peer an upload slot for
    /// `file_hash` (`OP_ACCEPTUPLOADREQ`); records the per-connection
    /// `served_slot`.
    GrantSlot {
        /// The file the slot is granted for.
        file_hash: FileHash,
    },
    /// Tell the queued peer its position
    /// (`OP_QUEUERANKING`). No `file_hash`: the wire packet is
    /// file-agnostic and the connection has at most one served context.
    SetQueueRank {
        /// Places ahead of the peer in our queue.
        rank: u16,
    },
    /// Push one block of part bytes to the granted peer, cut into packets
    /// of about 10 KiB as aMule's uploader does (`OP_SENDINGPART`, or a run
    /// of `OP_COMPRESSEDPART`, ADR-0031). Core reads `bytes` from the Content
    /// Store; the session frames it only when `served_slot` matches
    /// `file_hash`.
    SendBlock {
        /// The file the bytes come from.
        file_hash: FileHash,
        /// Absolute offset of the first byte.
        start: u64,
        /// Absolute offset one past the last. Core reads exactly
        /// `start..end`; the frames name the range `bytes` spans from `start`.
        end: u64,
        /// The block, read by core from the content store.
        bytes: Vec<u8>,
    },
    /// Answer a peer's source-exchange request (ADR-0055) with the
    /// filtered, capped `sources` core picked from its pools. The session
    /// frames them in the wire form it chose when the ask arrived:
    /// `OP_ANSWERSOURCES` (`0x82`) or `OP_ANSWERSOURCES2` (`0x84`), classic
    /// entries or ExtSX records, pack-attempted above `PEER_PACK_THRESHOLD`
    /// (354 bytes, ADR-0053). A classic answer leaves out every source with
    /// no ed2k wire form (an IPv6-only one, ADR-0087), and an answer left
    /// empty sends nothing, aMule's `NULL` reply.
    AnswerSources {
        /// The file the sources are for.
        file_hash: FileHash,
        /// The rows to answer with, already filtered and capped by core.
        sources: Vec<SourceSighting>,
    },
}

impl PeerSession {
    pub(super) fn apply_server(&mut self, command: ServerCommand) {
        match command {
            ServerCommand::AnswerFileName {
                file_hash,
                file_name,
            } => {
                if self.require_identified() {
                    self.answer_file_name(file_hash, file_name);
                }
            }
            ServerCommand::AnswerFileNotFound { file_hash } => {
                if self.require_identified() {
                    self.answer_file_not_found(file_hash);
                }
            }
            ServerCommand::AnswerFileStatus { file_hash, bitmap } => {
                if self.require_identified() {
                    self.answer_file_status(file_hash, bitmap);
                }
            }
            ServerCommand::AnswerHashSet {
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
            ServerCommand::AnswerAich {
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
            ServerCommand::AnswerAichFileHash { root } => {
                if self.require_identified() {
                    self.answer_aich_file_hash(root);
                }
            }
            ServerCommand::GrantSlot { file_hash } => self.grant_slot(file_hash),
            ServerCommand::SetQueueRank { rank } => self.set_queue_rank(rank),
            ServerCommand::SendBlock {
                file_hash,
                start,
                end: _,
                bytes,
            } => self.send_block(file_hash, start, bytes),
            ServerCommand::AnswerSources { file_hash, sources } => {
                if self.require_identified() {
                    self.answer_sources(file_hash, sources);
                }
            }
        }
    }
}
