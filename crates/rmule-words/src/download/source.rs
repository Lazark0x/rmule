//! The words for a download's sources: how many ask, wait and transfer, what
//! a worker slot is doing, why one left, why a dial ended before its hello, why one was let go or a reask
//! answer changed nothing, what a download with no source to try waits on,
//! and the remembered peers a restart dials first (ADR-0109).

use rmule_core::LinkTurn;
use rmule_core::diagnostics::{SourceActivity, WorkerPhase};
use rmule_core::{
    DialEnd, IgnoredReaskReply, PartReleaseReason, PeerRetirementReason, PurgedSource,
    SourcePurgeReason, SourceWait,
};
use rmule_primitives::PeerEndpoint;

use super::super::Sentence;
use super::super::units::{address, count};

/// The Connection Ceiling a binary lowered at its start because the
/// process's open-file limit left no room for the configured one (ADR-0116):
/// the limit, and the Ceiling in force against the one configured.
#[must_use]
pub fn ceiling_lowered(lowered: rmule_core::CeilingLowered) -> Sentence {
    let rmule_core::CeilingLowered {
        descriptors,
        configured,
        ceiling,
    } = lowered;
    let held = count(ceiling as u64, "peer connection", "peer connections");
    Sentence::owned(format!(
        "this process may hold {} open at once, so downloads hold at most {held}, not {configured}",
        count(descriptors, "file", "files"),
    ))
}

/// A running download's sources as the operator reads them (ADR-0116): how
/// many it knows, and of those how many are asking for a queue place, waiting
/// in one with no connection, and transferring on a granted slot.
#[must_use]
pub fn source_activity_words(known: u32, activity: SourceActivity) -> String {
    let SourceActivity {
        asking,
        queued,
        transferring,
    } = activity;
    format!("{known} known: {asking} asking, {queued} queued, {transferring} transferring")
}

/// What a download waiting for a connection needs to move on (ADR-0097): no
/// server session and no Kad node exist to ask for sources on.
pub const NO_NETWORK_WAIT: &str =
    "waiting for a network to find sources on: connect to a server, or enable Kad";

/// [`NO_NETWORK_WAIT`] as the status bar's note.
pub const NO_NETWORK_WAIT_NOTE: Sentence = Sentence::fixed(NO_NETWORK_WAIT);

/// Why a source left a download.
#[must_use]
pub const fn retirement_words(reason: PeerRetirementReason) -> &'static str {
    match reason {
        PeerRetirementReason::PeerDisconnected => "it disconnected",
        PeerRetirementReason::SlotTimeout => "its queue took too long",
        PeerRetirementReason::PartVerificationFailed => "a part it sent failed its check",
        PeerRetirementReason::VerificationAuthorityMismatch => {
            "its part hashes contradicted the file's"
        }
        PeerRetirementReason::CryptIncompatible => "its encryption and yours cannot meet",
        PeerRetirementReason::Distrusted => "it sent this file bad data before",
        PeerRetirementReason::SameSource => "another connection already reaches this peer",
        PeerRetirementReason::NoNeededParts => "it holds no part we still need",
        PeerRetirementReason::NoFreePart => {
            "every part it has that we need is coming from another source"
        }
        PeerRetirementReason::FileNotFound => "it does not have this file",
        PeerRetirementReason::Queued => "it queued us; we hung up and keep our place",
        PeerRetirementReason::LinkEnded => {
            "the connection it was waiting on closed; we ask it again later"
        }
    }
}

/// Why a dial to a source ended before its hello.
#[must_use]
pub const fn dial_end_words(cause: DialEnd) -> &'static str {
    match cause {
        DialEnd::CryptStanceUnknown => {
            "refused: its crypt stance is unknown and obfuscation is required"
        }
        DialEnd::CryptUnsupported => "refused: it cannot obfuscate and obfuscation is required",
        DialEnd::CryptRequiredByPeer => "refused: it requires obfuscation and yours is off",
        DialEnd::CryptKeyUnknown => "refused: obfuscation is required and its user hash is unknown",
        DialEnd::IpFiltered => "not dialled: the IP filter blocks it",
        DialEnd::Banned => "not dialled: it is banned",
        DialEnd::ConnectionRefused => "connection refused",
        DialEnd::TimedOut => "no answer",
        DialEnd::Reset => "reset",
        DialEnd::Os { kind } => super::super::os::kind_words(kind),
        DialEnd::ClosedBeforeHello => "it hung up before its hello",
        DialEnd::NoHelloInTime => "no hello in time",
        DialEnd::ProtocolViolation => "it broke the protocol before its hello",
        DialEnd::ClosedLocally => "closed here before its hello",
    }
}

/// The source a download let go, as the operator reads it: its address, or
/// a Low ID with the server that assigned it.
pub(super) fn purged_source_words(source: PurgedSource) -> String {
    match source {
        PurgedSource::Endpoint(peer) => format!("peer {}", address(peer)),
        PurgedSource::LowId {
            low_id,
            server: None,
        } => format!("low-ID peer {} on our server", low_id.as_u32()),
        PurgedSource::LowId {
            low_id,
            server: Some(server),
        } => format!(
            "low-ID peer {} on server {}",
            low_id.as_u32(),
            address(PeerEndpoint::V4(server))
        ),
    }
}

/// Why a source was let go, as the verb phrase after its name.
#[must_use]
pub const fn source_purge_reason_words(reason: SourcePurgeReason) -> &'static str {
    match reason {
        SourcePurgeReason::LowToLow => "could not be reached by any road",
        SourcePurgeReason::NoNeededParts => "held no part we still need",
        SourcePurgeReason::QueueFull => "kept its queue full",
    }
}

/// Why a reask reply changed nothing.
#[must_use]
pub const fn ignored_reask_reply_words(reason: IgnoredReaskReply) -> &'static str {
    match reason {
        IgnoredReaskReply::Runt => "it was too short to read",
        IgnoredReaskReply::UnexpectedOpcode => "it was not a reask answer",
        IgnoredReaskReply::NoPooledSource => "no queued source holds that address",
        IgnoredReaskReply::Misframed => "its body did not read as the answer owed",
        IgnoredReaskReply::PartCountMismatch => {
            "its part list counted a different number of parts than the file has"
        }
    }
}

/// Why a part went back to the pool for another source.
#[must_use]
pub const fn release_words(reason: PartReleaseReason) -> &'static str {
    match reason {
        PartReleaseReason::PeerRetired(retired) => retirement_words(retired),
        PartReleaseReason::Paused => "the download was paused",
        PartReleaseReason::Cancelled => "the download was cancelled",
        PartReleaseReason::BackOnQueue => "it put us back on its queue",
    }
}

/// What a download with no source to try waits on (ADR-0051's amendment):
/// the global sweep asks only while a server session is up, so without one
/// the server's sources wait for it, and Kad — when it runs — asks alone.
#[must_use]
pub const fn source_wait_words(reason: SourceWait) -> &'static str {
    match reason {
        SourceWait::Asking => "waiting for sources",
        SourceWait::KadAlone => "asking Kad; no server session for more sources",
        SourceWait::NoSession => {
            "no source left to try; waiting for a server session or Kad: connect to a server, or enable Kad"
        }
    }
}

/// [`source_wait_words`] as the status bar's note.
#[must_use]
pub const fn waiting_for_sources(reason: SourceWait) -> Sentence {
    Sentence::fixed(source_wait_words(reason))
}

/// What a worker slot is doing, as the Sources pane's Phase cell says it:
/// the dial, the file asked, its place in the uploader's queue, the part it
/// fetches, and its end (ADR-0028).
#[must_use]
pub fn phase_words(phase: &WorkerPhase) -> String {
    match phase {
        WorkerPhase::Idle => "idle".to_string(),
        WorkerPhase::Connecting => "connecting".to_string(),
        WorkerPhase::AskingFile => "asking file".to_string(),
        WorkerPhase::WaitingForSlot { rank: None } => "queued".to_string(),
        WorkerPhase::WaitingForSlot { rank: Some(rank) } => format!("queued #{rank}"),
        WorkerPhase::RequestingPart { part_index } => format!("req p{part_index}"),
        WorkerPhase::ReceivingPart { part_index, .. } => format!("recv p{part_index}"),
        WorkerPhase::VerifyingPart { part_index } => format!("verify p{part_index}"),
        WorkerPhase::Retired { .. } => "retired".to_string(),
        WorkerPhase::ShutDown => "shutdown".to_string(),
    }
}

/// The mark a source dialed from the download's **Source Seeds** carries in
/// the Sources pane (ADR-0109): a peer the last run knew, dialed before
/// anyone was asked.
pub const REMEMBERED: &str = "remembered";

/// The mark a source reached over its peer's link, rather than a dial of its
/// own, carries in the Sources pane (ADR-0107).
#[must_use]
pub const fn link_turn_words(turn: LinkTurn) -> &'static str {
    match turn {
        LinkTurn::Waiting => "waits for the link",
        LinkTurn::Riding => "shared link",
    }
}

/// What a saved `Remember peers` keeps, for the Settings receipt.
#[must_use]
pub fn remember_peers_receipt(peers: rmule_core::RememberPeers) -> String {
    format!(
        "remember {} per download",
        count(u64::from(peers.get().get()), "peer", "peers")
    )
}

/// Why a typed `Remember peers` was refused.
pub const REMEMBER_PEERS_REFUSED: &str = "remember peers: a whole number from 1 to 255";

/// The `Remember peers` row's note: what the count is for.
pub const REMEMBER_PEERS_NOTE: &str = "per download, dialled first after a restart";

/// Attach's one line about the **Source Seeds** it loaded (ADR-0109): how
/// many remembered peers go first for how many downloads, and how many were
/// too old to dial.
#[must_use]
pub fn seeds_loaded(downloads: usize, seeds: usize, expired: usize) -> String {
    let peers = |n: usize| {
        count(
            u64::try_from(n).unwrap_or(u64::MAX),
            "remembered peer",
            "remembered peers",
        )
    };
    let dropped = format!("{} older than a day dropped", peers(expired));
    match (downloads, expired) {
        (0, _) => format!("{dropped}; none to dial"),
        (_, 0) => format!(
            "dialling {} for {} first",
            peers(seeds),
            count(
                u64::try_from(downloads).unwrap_or(u64::MAX),
                "download",
                "downloads"
            )
        ),
        _ => format!("{}; {dropped}", seeds_loaded(downloads, seeds, 0)),
    }
}
