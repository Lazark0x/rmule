//! The words for a download's sources: why one left, why a dial ended
//! before its hello, why one was let go or a reask answer changed nothing,
//! what a download with no source to try waits on, and the remembered peers
//! a restart dials first (ADR-0109).

use rmule_core::{
    DialEnd, IgnoredReaskReply, PartReleaseReason, PeerRetirementReason, PurgedSource,
    SourcePurgeReason, SourceWait,
};
use rmule_primitives::PeerEndpoint;

use super::super::Sentence;
use super::super::units::{address, count};

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
        PeerRetirementReason::SlotRejected => "it refused an upload slot",
        PeerRetirementReason::SlotTimeout => "its queue took too long",
        PeerRetirementReason::PartVerificationFailed => "a part it sent failed its check",
        PeerRetirementReason::VerificationAuthorityMismatch => {
            "its part hashes contradicted the file's"
        }
        PeerRetirementReason::CryptIncompatible => "its encryption and yours cannot meet",
        PeerRetirementReason::Distrusted => "it sent this file bad data before",
        PeerRetirementReason::SameSource => "another connection already reaches this peer",
        PeerRetirementReason::NoNeededParts => "it holds no part we still need",
        PeerRetirementReason::FileNotFound => "it does not have this file",
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

/// The mark a source dialed from the download's **Source Seeds** carries in
/// the Sources pane (ADR-0109): a peer the last run knew, dialed before
/// anyone was asked.
pub const REMEMBERED: &str = "remembered";

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
