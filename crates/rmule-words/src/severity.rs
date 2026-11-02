//! How much a line of the Networks log asks of the operator, read from the
//! event's code and never from its words: the log can be translated.
//!
//! One reading for every event, each listed by name, so a code core adds cannot
//! reach the log without a severity. What a stranger can cause at will (a
//! refused hello, a malformed ask, a peer's failed dial) stays [`Severity::Info`]
//! whatever it says: a peer must not be able to fill the ring that keeps the
//! operator's failures.

use rmule_core::{
    CoreEvent, DownloadEvent, KadStopReason, LoginStep, ReconnectEnd, ScanEvent, SearchEvent,
    ServeEvent, ServerConnectionEvent, ServerListEvent,
};

/// How much a line asks of the operator, least first.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// What happened; nothing is asked.
    Info,
    /// Something went wrong and rmule carries on.
    Warning,
    /// Something the operator wanted did not happen, or stopped.
    Failure,
}

impl Severity {
    /// The mark in the log's gutter, which never leans on colour alone.
    #[must_use]
    pub const fn glyph(self) -> &'static str {
        match self {
            Self::Info => "·",
            Self::Warning => "!",
            Self::Failure => "✗",
        }
    }

    /// The word that opens the line; the everyday line needs none.
    #[must_use]
    pub const fn word(self) -> Option<&'static str> {
        match self {
            Self::Info => None,
            Self::Warning => Some("warning"),
            Self::Failure => Some("failure"),
        }
    }
}

/// The severity of an event's log line.
#[must_use]
pub fn of(event: &CoreEvent) -> Severity {
    use Severity::{Failure, Info, Warning};
    match event {
        CoreEvent::Download(event) => download(event),
        CoreEvent::Serve(event) => serve(event),
        CoreEvent::Search(event) => search(event),
        CoreEvent::Scan(event) => scan(event),
        CoreEvent::ServerList(event) => server_list(event),
        CoreEvent::ServerConnection(event) => server_connection(event),
        CoreEvent::ServerLogin { step, .. } => login(step),
        CoreEvent::KadStopped { reason } => match reason {
            KadStopReason::Stopped => Info,
            KadStopReason::Ended => Warning,
            KadStopReason::TaskFailed => Failure,
        },
        CoreEvent::ClientUdpBindFailed { .. } | CoreEvent::TaskDied { .. } => Failure,
        CoreEvent::CommandRejected { .. }
        | CoreEvent::SocketBoundWithoutFamily { .. }
        | CoreEvent::MappingReleaseKept { .. }
        | CoreEvent::EventsShed { .. } => Warning,
        CoreEvent::SecuredIdentityMismatch { .. }
        | CoreEvent::PeerReachRouted { .. }
        | CoreEvent::NattTunnelRisen { .. }
        | CoreEvent::PeerHelloRefused { .. }
        | CoreEvent::PeerLinkBroken { .. }
        | CoreEvent::DiagnosticsSnapshot { .. }
        | CoreEvent::FileHistory { .. }
        | CoreEvent::Quitting { .. }
        | CoreEvent::BuddyDialFailed { .. }
        | CoreEvent::KadHelperTestLate { .. }
        | CoreEvent::ObfuscationPolicyAtStart { .. }
        | CoreEvent::ObfuscationPolicyChanged { .. } => Info,
    }
}

const fn download(event: &DownloadEvent) -> Severity {
    use DownloadEvent as D;
    match event {
        D::PartFileLost { .. }
        | D::FinishedFileRejected { .. }
        | D::DownloadFailed { .. }
        | D::FailureNotRecorded { .. }
        | D::StoreStopped
        | D::VolumeStopped { .. } => Severity::Failure,
        D::DamagedPartsDropped { .. }
        | D::PartsDisproved { .. }
        | D::KadAichRootContested { .. }
        | D::PartCorrupt { .. }
        | D::SourceSetAside { .. }
        | D::BadDataCounted { .. }
        | D::HoleLessDestination { .. }
        | D::CancelledFileLeft { .. }
        | D::RowsUnreadable { .. } => Severity::Warning,
        D::DownloadQueued { .. }
        | D::DownloadRecovered { .. }
        | D::DownloadProgressRestored { .. }
        | D::DownloadRestarted { .. }
        | D::ServerLoginAccepted { .. }
        | D::SourcesFound { .. }
        | D::SourcesExchanged { .. }
        | D::LinkSourcesAdded { .. }
        | D::SeedsLoaded { .. }
        | D::SeedsDialled { .. }
        | D::PeerSelected { .. }
        | D::PeerQueued { .. }
        | D::PeerSlotGranted { .. }
        | D::PeerSlotTimeout { .. }
        | D::SourceRemoteQueued { .. }
        | D::SourceSpared { .. }
        | D::SourceWaitsOnStanding { .. }
        | D::SourceRoadHeld { .. }
        | D::SourceHandedOver { .. }
        | D::SourceReaskAcked { .. }
        | D::SourceReaskQueueFull { .. }
        | D::SourceReaskedOverTcp { .. }
        | D::SlotOffered { .. }
        | D::SourcePurged { .. }
        | D::SourceReaskDropped { .. }
        | D::ReaskReplyIgnored { .. }
        | D::DialEnded { .. }
        | D::LinkShared { .. }
        | D::HashSetReceived { .. }
        | D::PartAssigned { .. }
        | D::EndGameBlocks { .. }
        | D::PartReleased { .. }
        | D::PeerRetired { .. }
        | D::PartVerified { .. }
        | D::DownloadCompleted { .. }
        | D::DownloadCancelled { .. }
        | D::DownloadCleared { .. }
        | D::DownloadPaused { .. }
        | D::DownloadResumed { .. }
        | D::WaitingForSources { .. }
        | D::WaitingForConnection { .. }
        | D::PartFilesAdopted { .. }
        | D::Completing { .. } => Severity::Info,
    }
}

const fn serve(event: &ServeEvent) -> Severity {
    use ServeEvent as S;
    match event {
        S::ServingFailed { .. } => Severity::Failure,
        S::SharesUnwatched | S::ShareRejected { .. } => Severity::Warning,
        S::FileShared { .. }
        | S::FileUnshared { .. }
        | S::FileWithheld { .. }
        | S::FileOffered { .. }
        | S::PartialOffered { .. }
        | S::PartialWithdrawn { .. }
        | S::OfferChecked { .. }
        | S::ServingStarted { .. }
        | S::FilesAnnounced { .. }
        | S::FilesWithheld { .. }
        | S::UploadSlotGranted { .. }
        | S::UploadDialBack { .. }
        | S::UploadDialBackFailed { .. }
        | S::PeerQueued { .. }
        | S::UploadQueueFull { .. }
        | S::UploadLowIdAbuseRefused { .. }
        | S::ReaskPingMalformed { .. }
        | S::NameAskMalformed { .. }
        | S::UploadAddressCapReached { .. }
        | S::BlockAskRefused { .. }
        | S::UploadSlotReleased { .. }
        | S::WaiterLeft { .. }
        | S::WaiterRelinked { .. }
        | S::CrossedHelloHeld { .. }
        | S::CrossedDialKept { .. }
        | S::CrossedDialRefused { .. }
        | S::DeadDialLetGo { .. }
        | S::SourcesServed { .. }
        | S::ServingStopped { .. } => Severity::Info,
    }
}

const fn search(event: &SearchEvent) -> Severity {
    use SearchEvent as S;
    match event {
        S::SearchFailed { .. } => Severity::Failure,
        S::SearchRefused { .. } | S::SearchMoreRefused { .. } => Severity::Warning,
        S::SearchStarted { .. }
        | S::SearchResultsReceived { .. }
        | S::SearchResultSkipped { .. }
        | S::SearchCompleted { .. }
        | S::SearchCancelled { .. }
        | S::SearchWaitingForTurn { .. }
        | S::SearchWaitingForConnection { .. }
        | S::SearchLegsChanged { .. }
        | S::SearchDeferredKadPublish { .. }
        | S::SearchSentToServer { .. }
        | S::SearchMoreRequested { .. } => Severity::Info,
    }
}

const fn scan(event: &ScanEvent) -> Severity {
    use ScanEvent as S;
    match event {
        S::DirectoryRefused { .. }
        | S::DownloadDirectoryRefused { .. }
        | S::DirectoryMissing { .. }
        | S::WatchUnavailable { .. }
        | S::WatchInterrupted { .. }
        | S::PathUnwatched { .. }
        | S::FileNotHashed { .. }
        | S::FileRefused { .. }
        | S::Unlistable { .. } => Severity::Warning,
        S::ConsentRequested { .. }
        | S::DirectoryAdded { .. }
        | S::DirectoryRemoved { .. }
        | S::DirectoryReturned { .. }
        | S::Finished { .. }
        | S::Declined { .. }
        | S::WatchRestored { .. }
        | S::LeftoverParts { .. } => Severity::Info,
    }
}

const fn server_list(event: &ServerListEvent) -> Severity {
    use ServerListEvent as S;
    match event {
        S::ServerListUpdateFailed { .. } => Severity::Warning,
        S::ServerAdded { .. }
        | S::ServerUpdated { .. }
        | S::ServerRemoved { .. }
        | S::ReservedServerDropped { .. }
        | S::ServerPriorityChanged { .. }
        | S::ServerStaticChanged { .. }
        | S::ServerListUpdateStarted { .. }
        | S::ServerListUpdated { .. }
        | S::ServerListAutoUpdateStarted { .. }
        | S::ServerListAutoUpdateFetched { .. } => Severity::Info,
    }
}

/// A session that ended is told by what follows it: an operator's switch says
/// nothing more, a lost one says [`ServerConnectionEvent::Reconnecting`].
const fn server_connection(event: &ServerConnectionEvent) -> Severity {
    use ServerConnectionEvent as S;
    match event {
        S::ConnectFailed { .. } => Severity::Failure,
        S::Reconnecting { .. } => Severity::Warning,
        S::ReconnectEnded { reason, .. } => match reason {
            ReconnectEnd::OperatorDisconnected | ReconnectEnd::Replaced => Severity::Info,
            ReconnectEnd::AttemptsSpent { .. } | ReconnectEnd::Unlisted => Severity::Failure,
        },
        S::Connecting { .. } | S::Connected { .. } | S::Disconnected { .. } => Severity::Info,
    }
}

const fn login(step: &LoginStep) -> Severity {
    match step {
        LoginStep::DialFailed { .. }
        | LoginStep::ClosedBeforeAnswer { .. }
        | LoginStep::MappingWait { settled: false, .. } => Severity::Warning,
        LoginStep::MappingWait { settled: true, .. }
        | LoginStep::LinkChosen { .. }
        | LoginStep::LoginSent { .. }
        | LoginStep::PortTestAwaited
        | LoginStep::PortTestArrived { .. }
        | LoginStep::PortTestEnded { .. }
        | LoginStep::PortTestLate { .. }
        | LoginStep::PortTestWindowClosed { .. }
        | LoginStep::Answered { .. }
        | LoginStep::Reassigned { .. }
        | LoginStep::Ipv6Probe { .. }
        | LoginStep::KadRecheck => Severity::Info,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rmule_core::{DownloadFailure, DownloadId, ServerConnectFailure};
    use rmule_primitives::ServerEndpoint;

    fn server() -> ServerEndpoint {
        ServerEndpoint::new("10.0.0.1", 4661).expect("endpoint")
    }

    /// A failed connect and a stranger's refused hello read apart, however the
    /// two sentences happen to be worded.
    #[test]
    fn the_operators_loss_is_a_failure_and_a_session_lost_is_a_warning() {
        let failed = CoreEvent::ServerConnection(ServerConnectionEvent::ConnectFailed {
            server: server(),
            reason: ServerConnectFailure::Unreachable,
        });
        assert_eq!(of(&failed), Severity::Failure);
        let ended = |reason| {
            of(&CoreEvent::ServerConnection(
                ServerConnectionEvent::ReconnectEnded {
                    server: server(),
                    reason,
                },
            ))
        };
        assert_eq!(ended(ReconnectEnd::OperatorDisconnected), Severity::Info);
        assert_eq!(ended(ReconnectEnd::Unlisted), Severity::Failure);
        let download = CoreEvent::Download(DownloadEvent::DownloadFailed {
            download_id: DownloadId::from_u64(1),
            reason: DownloadFailure::NoUsableSources,
        });
        assert_eq!(of(&download), Severity::Failure);
    }
}
