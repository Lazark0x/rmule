//! What the Outbox may do with each event (ADR-0069, "The Outbox"). Every
//! match here is exhaustive, so a new event does not compile until it is
//! placed: an Edge unless its front-end fold can stand losing it.

use rmule_primitives::{PeerEndpoint, ServerEndpoint};

use crate::service::{
    CoreEvent, DownloadEvent, DownloadId, ScanEvent, SearchEvent, SearchId, ServeEvent,
    ServerConnectionEvent, ServerListEvent,
};

/// What the queue may do with one event.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Weight {
    /// A change the front end's state cannot rebuild: never dropped.
    Edge,
    /// A value the next one of the same subject replaces.
    Level(LevelKey),
    /// A peer-driven fact with no successor: dropped only past the room.
    Note,
}

/// The subject of a [`Weight::Level`].
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) enum LevelKey {
    /// Where a source holds a download in its upload queue.
    RemoteRank(DownloadId, PeerEndpoint),
    /// What a parked download waits for.
    DownloadWait(DownloadId),
    /// Where a waiter stands in rmule's upload queue.
    QueueRank(PeerEndpoint),
    /// A search's whole leg picture.
    SearchLegs(SearchId),
    /// How long a search's server leg is held back.
    SearchTurn(SearchId),
    /// The next redial of a lost session.
    Reconnect(ServerEndpoint),
    /// The latest dump of the levels.
    Diagnostics,
}

/// `event`'s weight.
pub(super) fn of(event: &CoreEvent) -> Weight {
    match event {
        CoreEvent::Download(event) => of_download(event),
        CoreEvent::Serve(event) => of_serve(event),
        CoreEvent::Search(event) => of_search(event),
        CoreEvent::Scan(event) => of_scan(event),
        CoreEvent::ServerList(event) => of_server_list(event),
        CoreEvent::ServerConnection(event) => of_server_connection(event),
        CoreEvent::DiagnosticsSnapshot { .. } => Weight::Level(LevelKey::Diagnostics),
        CoreEvent::CommandRejected { .. }
        | CoreEvent::ClientUdpBindFailed { .. }
        | CoreEvent::SocketBoundWithoutFamily { .. }
        | CoreEvent::FileHistory { .. }
        | CoreEvent::KadStopped { .. }
        | CoreEvent::Quitting { .. }
        | CoreEvent::TaskDied { .. }
        | CoreEvent::ObfuscationPolicyAtStart { .. }
        | CoreEvent::ObfuscationPolicyChanged { .. }
        | CoreEvent::EventsShed { .. } => Weight::Edge,
        CoreEvent::SecuredIdentityMismatch { .. }
        | CoreEvent::PeerReachRouted { .. }
        | CoreEvent::NattTunnelRisen { .. }
        | CoreEvent::PeerHelloRefused { .. }
        | CoreEvent::PeerLinkBroken { .. }
        | CoreEvent::ServerLogin { .. }
        | CoreEvent::BuddyDialFailed { .. }
        | CoreEvent::KadHelperTestLate { .. }
        | CoreEvent::MappingReleaseKept { .. } => Weight::Note,
    }
}

fn of_download(event: &DownloadEvent) -> Weight {
    use DownloadEvent as E;
    match event {
        E::PeerQueued {
            download_id, peer, ..
        } => Weight::Level(LevelKey::RemoteRank(*download_id, *peer)),
        E::WaitingForSources { download_id, .. } | E::WaitingForConnection { download_id } => {
            Weight::Level(LevelKey::DownloadWait(*download_id))
        }
        E::DownloadQueued { .. }
        | E::DownloadRecovered { .. }
        | E::DownloadProgressRestored { .. }
        | E::DamagedPartsDropped { .. }
        | E::PartsDisproved { .. }
        | E::PartFileLost { .. }
        | E::FinishedFileRejected { .. }
        | E::DownloadRestarted { .. }
        | E::HashSetReceived { .. }
        | E::KadAichRootContested { .. }
        | E::PartVerified { .. }
        | E::DownloadCompleted { .. }
        | E::DownloadCancelled { .. }
        | E::DownloadCleared { .. }
        | E::DownloadPaused { .. }
        | E::DownloadResumed { .. }
        | E::DownloadFailed { .. }
        | E::FailureNotRecorded { .. }
        | E::HoleLessDestination { .. }
        | E::VolumeStopped { .. }
        | E::CancelledFileLeft { .. }
        | E::RowsUnreadable { .. }
        | E::PartFilesAdopted { .. }
        | E::StoreStopped
        | E::Completing { .. } => Weight::Edge,
        E::ServerLoginAccepted { .. }
        | E::SourcesFound { .. }
        | E::SourcesExchanged { .. }
        | E::LinkSourcesAdded { .. }
        | E::SeedsLoaded { .. }
        | E::SeedsDialled { .. }
        | E::PeerSelected { .. }
        | E::PeerSlotGranted { .. }
        | E::PeerSlotTimeout { .. }
        | E::SourceRemoteQueued { .. }
        | E::SourceSpared { .. }
        | E::SourceWaitsOnStanding { .. }
        | E::SourceRoadHeld { .. }
        | E::SourceHandedOver { .. }
        | E::SourceReaskAcked { .. }
        | E::SourceReaskQueueFull { .. }
        | E::SourceReaskedOverTcp { .. }
        | E::SlotOffered { .. }
        | E::SourcePurged { .. }
        | E::SourceReaskDropped { .. }
        | E::ReaskReplyIgnored { .. }
        | E::DialEnded { .. }
        | E::LinkShared { .. }
        | E::PartAssigned { .. }
        | E::EndGameBlocks { .. }
        | E::PartCorrupt { .. }
        | E::SourceSetAside { .. }
        | E::BadDataCounted { .. }
        | E::PartReleased { .. }
        | E::PeerRetired { .. } => Weight::Note,
    }
}

fn of_serve(event: &ServeEvent) -> Weight {
    use ServeEvent as E;
    match event {
        E::PeerQueued { peer, .. } => Weight::Level(LevelKey::QueueRank(*peer)),
        E::FileShared { .. }
        | E::FileUnshared { .. }
        | E::FileWithheld { .. }
        | E::FileOffered { .. }
        | E::PartialOffered { .. }
        | E::PartialWithdrawn { .. }
        | E::OfferChecked { .. }
        | E::SharesUnwatched
        | E::ShareRejected { .. }
        | E::ServingStarted { .. }
        | E::ServingFailed { .. }
        | E::FilesAnnounced { .. }
        | E::FilesWithheld { .. }
        | E::ServingStopped { .. } => Weight::Edge,
        E::UploadSlotGranted { .. }
        | E::UploadDialBack { .. }
        | E::UploadDialBackFailed { .. }
        | E::UploadQueueFull { .. }
        | E::UploadLowIdAbuseRefused { .. }
        | E::ReaskPingMalformed { .. }
        | E::NameAskMalformed { .. }
        | E::UploadAddressCapReached { .. }
        | E::BlockAskRefused { .. }
        | E::UploadSlotReleased { .. }
        | E::WaiterLeft { .. }
        | E::WaiterRelinked { .. }
        | E::CrossedHelloHeld { .. }
        | E::CrossedDialKept { .. }
        | E::CrossedDialRefused { .. }
        | E::DeadDialLetGo { .. }
        | E::SourcesServed { .. } => Weight::Note,
    }
}

fn of_search(event: &SearchEvent) -> Weight {
    use SearchEvent as E;
    match event {
        E::SearchLegsChanged { search_id, .. } => Weight::Level(LevelKey::SearchLegs(*search_id)),
        E::SearchWaitingForTurn { search_id, .. } => {
            Weight::Level(LevelKey::SearchTurn(*search_id))
        }
        E::SearchStarted { .. }
        | E::SearchResultsReceived { .. }
        | E::SearchCompleted { .. }
        | E::SearchCancelled { .. }
        | E::SearchRefused { .. }
        | E::SearchWaitingForConnection { .. }
        | E::SearchDeferredKadPublish { .. }
        | E::SearchSentToServer { .. }
        | E::SearchMoreRequested { .. }
        | E::SearchMoreRefused { .. }
        | E::SearchFailed { .. } => Weight::Edge,
        E::SearchResultSkipped { .. } => Weight::Note,
    }
}

/// A scan's facts follow the operator's directories, not peer traffic.
fn of_scan(event: &ScanEvent) -> Weight {
    use ScanEvent as E;
    match event {
        E::ConsentRequested { .. }
        | E::DirectoryAdded { .. }
        | E::DirectoryRefused { .. }
        | E::DownloadDirectoryRefused { .. }
        | E::DirectoryRemoved { .. }
        | E::DirectoryMissing { .. }
        | E::DirectoryReturned { .. }
        | E::Finished { .. }
        | E::Declined { .. }
        | E::WatchUnavailable { .. }
        | E::WatchInterrupted { .. }
        | E::WatchRestored { .. }
        | E::PathUnwatched { .. }
        | E::LeftoverParts { .. }
        | E::FileNotHashed { .. }
        | E::FileRefused { .. }
        | E::Unlistable { .. } => Weight::Edge,
    }
}

/// The server list moves with the operator and the list's own updates.
fn of_server_list(event: &ServerListEvent) -> Weight {
    use ServerListEvent as E;
    match event {
        E::ServerAdded { .. }
        | E::ServerUpdated { .. }
        | E::ServerRemoved { .. }
        | E::ReservedServerDropped { .. }
        | E::ServerPriorityChanged { .. }
        | E::ServerStaticChanged { .. }
        | E::ServerListUpdateStarted { .. }
        | E::ServerListUpdated { .. }
        | E::ServerListAutoUpdateStarted { .. }
        | E::ServerListAutoUpdateFetched { .. }
        | E::ServerListUpdateFailed { .. } => Weight::Edge,
    }
}

fn of_server_connection(event: &ServerConnectionEvent) -> Weight {
    use ServerConnectionEvent as E;
    match event {
        E::Reconnecting { server, .. } => Weight::Level(LevelKey::Reconnect(server.clone())),
        E::Connecting { .. }
        | E::Connected { .. }
        | E::ConnectFailed { .. }
        | E::Disconnected { .. }
        | E::ReconnectEnded { .. } => Weight::Edge,
    }
}
