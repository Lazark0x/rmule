//! The Run Log's code for each closed vocabulary core's events carry: one
//! exhaustive `match` per type, so a variant core adds fails to compile until
//! it has a code here, read by the events' own records and by the
//! reachability trail's.

use crate::port_mapping::{
    MappingError, MappingProtocol, MappingRefusal, MappingStatus, MappingTransportFault,
};
use crate::{
    ConfidenceTier, CoreCommandRejectReason, DialEnd, DialFailure, DownloadFailure,
    DownloadLifecycle, IgnoredReaskReply, KadStopReason, KadUnavailableReason, LegNotSent,
    NatTraversalUnavailableReason, PairRole, PartFileChange, PartReleaseReason, PartsLost,
    PeerReachDropReason, PeerRetirementReason, PeerStreamRole, QuitStep, ReconnectEnd,
    RelatedSearchRefusal, SearchFailure, SearchLegState, SearchResultSkipReason, ServeStartFailure,
    ServeStopReason, ServerConnectFailure, ServerListUpdateFailure, ShareRejectReason,
    SharesWithheld, SocketRole, SourcePurgeReason, SourceWait, TunnelTransport,
    VerificationAuthority, WaiterLeaveCause, WatchFault, WithheldReason,
};
use rmule_primitives::AddressFamily;

use super::record::Record;

/// An address family's code.
#[must_use]
pub(crate) const fn family(family: AddressFamily) -> &'static str {
    match family {
        AddressFamily::V4 => "ipv4",
        AddressFamily::V6 => "ipv6",
    }
}

/// A socket role's code.
#[must_use]
pub(crate) const fn role(role: SocketRole) -> &'static str {
    match role {
        SocketRole::Tcp => "tcp",
        SocketRole::Udp => "udp",
    }
}

pub(super) const fn pair_role(role: PairRole) -> &'static str {
    match role {
        PairRole::ClientUdp => "client_udp",
        PairRole::Ed2kListener => "ed2k_listener",
        PairRole::ServerUdp => "server_udp",
    }
}

pub(super) const fn source_wait(reason: SourceWait) -> &'static str {
    match reason {
        SourceWait::Asking => "asking",
        SourceWait::KadAlone => "kad_alone",
        SourceWait::NoSession => "no_session",
    }
}

pub(super) const fn lifecycle(state: DownloadLifecycle) -> &'static str {
    match state {
        DownloadLifecycle::Queued => "queued",
        DownloadLifecycle::Active => "active",
        DownloadLifecycle::Paused => "paused",
        DownloadLifecycle::Failed => "failed",
        DownloadLifecycle::Completed => "completed",
        DownloadLifecycle::Cancelled => "cancelled",
    }
}

/// A download's failure as a `failure` code, with the fault behind a storage
/// integrity failure as its own fields.
pub(super) fn failure(record: Record, failure: &DownloadFailure) -> Record {
    let code = match failure {
        DownloadFailure::NoUsableSources => "no_usable_sources",
        DownloadFailure::HashSetMismatch => "hash_set_mismatch",
        DownloadFailure::Cancelled => "cancelled",
        DownloadFailure::Paused => "paused",
        DownloadFailure::ServerDisconnected => "server_disconnected",
        DownloadFailure::ServerFiltered => "server_filtered",
        DownloadFailure::SourceLookupTimedOut => "source_lookup_timed_out",
        DownloadFailure::PeerDisconnected => "peer_disconnected",
        DownloadFailure::PartVerificationFailed => "part_verification_failed",
        DownloadFailure::FinalPathTaken => "final_path_taken",
        DownloadFailure::StoreFailed => "store_failed",
        DownloadFailure::CompletedFileNotMoved { os_code } => {
            let record = record.code("failure", "completed_file_not_moved");
            return match os_code {
                Some(number) => record.count("os_code", *number),
                None => record.code("os_code", "none"),
            };
        }
        DownloadFailure::StorageIntegrityFailed(fault) => {
            return storage_fault(record.code("failure", "storage_integrity_failed"), fault);
        }
    };
    record.code("failure", code)
}

/// A storage integrity fault as a `fault` code and what it names.
pub(super) fn storage_fault(record: Record, fault: &crate::StorageIntegrityFault) -> Record {
    use crate::StorageIntegrityFault as Fault;
    match fault {
        Fault::PartFileMissing => record.code("fault", "part_file_missing"),
        Fault::PartFileUnreadable { os_code } => {
            let record = record.code("fault", "part_file_unreadable");
            match os_code {
                Some(number) => record.count("os_code", *number),
                None => record.code("os_code", "none"),
            }
        }
        Fault::NoPartHolds { recorded, first } => {
            let record = record
                .code("fault", "no_part_holds")
                .count("recorded_parts", *recorded);
            part_fault(record, first)
        }
    }
}

/// A part's fault as a `part_fault` code, the part's index and its numbers.
pub(super) fn part_fault(record: Record, fault: &crate::PartFault) -> Record {
    use crate::PartFault as Fault;
    match fault {
        Fault::Short {
            part_index,
            expected_end,
            found_len,
        } => record
            .code("part_fault", "short")
            .count("part_index", *part_index)
            .count("expected_end", *expected_end)
            .count("found_len", *found_len),
        Fault::HashMismatch {
            part_index,
            expected,
            found,
        } => record
            .code("part_fault", "hash_mismatch")
            .count("part_index", *part_index)
            .part_hash("expected", expected)
            .part_hash("found", found),
    }
}

pub(super) fn part_file_change(record: Record, change: PartFileChange) -> Record {
    match change {
        PartFileChange::Gone => record.code("found", "gone"),
        PartFileChange::Replaced => record.code("found", "replaced"),
        PartFileChange::Truncated { len } => {
            record.code("found", "truncated").count("found_len", len)
        }
    }
}

/// What a changed part file cost: the parts and bytes the store dropped, or
/// that it could not say.
pub(super) fn parts_lost(record: Record, lost: PartsLost) -> Record {
    match lost {
        PartsLost::Counted { parts, bytes } => record
            .code("lost", "counted")
            .count("parts_lost", parts)
            .count("bytes_lost", bytes),
        PartsLost::NotCounted => record.code("lost", "not_counted"),
    }
}

pub(super) const fn authority(authority: VerificationAuthority) -> &'static str {
    match authority {
        VerificationAuthority::LinkPartHashSet => "link_part_hash_set",
        VerificationAuthority::PeerHashSet => "peer_hash_set",
        VerificationAuthority::FileHashOnly => "file_hash_only",
    }
}

pub(super) const fn retirement(reason: PeerRetirementReason) -> &'static str {
    match reason {
        PeerRetirementReason::PeerDisconnected => "peer_disconnected",
        PeerRetirementReason::SlotRejected => "slot_rejected",
        PeerRetirementReason::SlotTimeout => "slot_timeout",
        PeerRetirementReason::PartVerificationFailed => "part_verification_failed",
        PeerRetirementReason::VerificationAuthorityMismatch => "verification_authority_mismatch",
        PeerRetirementReason::CryptIncompatible => "crypt_incompatible",
        PeerRetirementReason::Distrusted => "distrusted",
        PeerRetirementReason::SameSource => "same_source",
        PeerRetirementReason::NoNeededParts => "no_needed_parts",
    }
}

pub(super) fn part_release(record: Record, reason: PartReleaseReason) -> Record {
    match reason {
        PartReleaseReason::PeerRetired(why) => record
            .code("reason", "peer_retired")
            .code("retired", retirement(why)),
        PartReleaseReason::Paused => record.code("reason", "paused"),
        PartReleaseReason::Cancelled => record.code("reason", "cancelled"),
    }
}

pub(super) fn withheld(record: Record, reason: WithheldReason) -> Record {
    match reason {
        WithheldReason::Missing => record.code("reason", "missing"),
        WithheldReason::Changed => record.code("reason", "changed"),
        WithheldReason::FolderMissing => record.code("reason", "folder_missing"),
        WithheldReason::Unreadable(kind) => {
            record.code("reason", "unreadable").os_error(kind, None)
        }
        WithheldReason::Refused => record.code("reason", "refused"),
    }
}

pub(super) const fn share_rejected(reason: ShareRejectReason) -> &'static str {
    match reason {
        ShareRejectReason::NotShared => "not_shared",
        ShareRejectReason::RegistryError => "registry_error",
    }
}

pub(super) const fn shares_withheld(reason: SharesWithheld) -> &'static str {
    match reason {
        SharesWithheld::RelatedSearchGranted => "related_search_granted",
        SharesWithheld::RelatedSearchGrantedAfterAnnounce => {
            "related_search_granted_after_announce"
        }
    }
}

pub(super) fn serve_start_failure(record: Record, reason: ServeStartFailure) -> Record {
    match reason {
        ServeStartFailure::Bind(kind) => record.code("reason", "bind").os_error(kind, None),
        ServeStartFailure::Adapter => record.code("reason", "adapter"),
    }
}

pub(super) const fn serve_stop(reason: ServeStopReason) -> &'static str {
    match reason {
        ServeStopReason::Requested => "requested",
        ServeStopReason::ListenerClosed => "listener_closed",
        ServeStopReason::TaskFailed => "task_failed",
    }
}

pub(super) const fn partial_end(cause: crate::PartialEnd) -> &'static str {
    match cause {
        crate::PartialEnd::Completed => "completed",
        crate::PartialEnd::Ended => "ended",
        crate::PartialEnd::HeldBack => "held_back",
        crate::PartialEnd::Changed => "changed",
        crate::PartialEnd::Unreadable => "unreadable",
    }
}

pub(super) const fn waiter_left(cause: WaiterLeaveCause) -> &'static str {
    match cause {
        WaiterLeaveCause::Purged => "purged",
        WaiterLeaveCause::Cancelled => "cancelled",
    }
}

pub(super) fn watch_fault(record: Record, fault: WatchFault) -> Record {
    match fault {
        WatchFault::Limit => record.code("reason", "limit"),
        WatchFault::PathNotFound => record.code("reason", "path_not_found"),
        WatchFault::Io { kind, os_code } => record.code("reason", "io").os_error(kind, os_code),
        WatchFault::Stopped => record.code("reason", "stopped"),
        WatchFault::Backend => record.code("reason", "backend"),
        WatchFault::RegistryUnreadable => record.code("reason", "registry_unreadable"),
    }
}

pub(super) fn directory_refusal(record: Record, reason: &crate::DirectoryRefusal) -> Record {
    directory_refusal_as(record, "reason", reason)
}

/// A directory refusal's code under the field `name`.
fn directory_refusal_as(
    record: Record,
    name: &'static str,
    reason: &crate::DirectoryRefusal,
) -> Record {
    use crate::DirectoryRefusal as R;
    match reason {
        R::NotADirectory => record.code(name, "not_a_directory"),
        R::Unreachable(kind) => record.code(name, "unreachable").os_error(*kind, None),
        R::NotUtf8 => record.code(name, "not_utf8"),
        R::NotAbsolute => record.code(name, "not_absolute"),
        R::HomeDirectory => record.code(name, "home_directory"),
        R::FilesystemRoot => record.code(name, "filesystem_root"),
        R::DataDirectory => record.code(name, "data_directory"),
        R::HoldsDataDirectory => record.code(name, "holds_data_directory"),
        R::AlreadyShared => record.code(name, "already_shared"),
        R::InsideShared { parent } => record.code(name, "inside_shared").path("parent", parent),
        R::HoldsShared { child } => record.code(name, "holds_shared").path("child", child),
        R::HoldsTempDirectory => record.code(name, "holds_temp_directory"),
        R::DownloadDirectory => record.code(name, "download_directory"),
        R::NotShared => record.code(name, "not_shared"),
        R::StoreFailed => record.code(name, "store_failed"),
    }
}

/// Why Core Settings refused a value; a refused download directory adds the
/// guard it failed.
pub(super) fn setting_refusal(record: Record, refusal: &crate::SettingRefusal) -> Record {
    use crate::SettingRefusal as R;
    match refusal {
        R::PortZero => record.code("reason", "port_zero"),
        R::DeadServerRetriesZero => record.code("reason", "dead_server_retries_zero"),
        R::DownloadDirNotAbsolute => record.code("reason", "download_dir_not_absolute"),
        R::DownloadDirNotUtf8 => record.code("reason", "download_dir_not_utf8"),
        R::DownloadDirNotADirectory => record.code("reason", "download_dir_not_a_directory"),
        R::DownloadDirRefused(guard) => directory_refusal_as(
            record.code("reason", "download_dir_refused"),
            "guard",
            guard,
        ),
        R::TempDirRefused(guard) => {
            directory_refusal_as(record.code("reason", "temp_dir_refused"), "guard", guard)
        }
        R::NicknameUnfit => record.code("reason", "nickname_unfit"),
        R::UrlBlank => record.code("reason", "url_blank"),
        R::CoreKey => record.code("reason", "core_key"),
    }
}

pub(super) fn list_update_failure(record: Record, reason: ServerListUpdateFailure) -> Record {
    match reason {
        ServerListUpdateFailure::Unreachable => record.code("reason", "unreachable"),
        ServerListUpdateFailure::TimedOut => record.code("reason", "timed_out"),
        ServerListUpdateFailure::HttpStatus(status) => {
            record.code("reason", "http_status").count("status", status)
        }
        ServerListUpdateFailure::TooLarge { cap } => {
            record.code("reason", "too_large").count("cap", cap)
        }
        ServerListUpdateFailure::NotServerMet => record.code("reason", "not_server_met"),
        ServerListUpdateFailure::StoreFailed => record.code("reason", "store_failed"),
    }
}

pub(super) const fn connect_failure(reason: ServerConnectFailure) -> &'static str {
    match reason {
        ServerConnectFailure::Filtered => "filtered",
        ServerConnectFailure::Unreachable => "unreachable",
        ServerConnectFailure::LoginRefused => "login_refused",
        ServerConnectFailure::ClosedBeforeAnswer => "closed_before_answer",
        ServerConnectFailure::LoginTimedOut => "login_timed_out",
    }
}

pub(super) fn reconnect_end(record: Record, reason: &ReconnectEnd) -> Record {
    match reason {
        ReconnectEnd::OperatorDisconnected => record.code("reason", "operator_disconnected"),
        ReconnectEnd::Replaced => record.code("reason", "replaced"),
        ReconnectEnd::AttemptsSpent { attempts } => record
            .code("reason", "attempts_spent")
            .count("attempts", *attempts),
        ReconnectEnd::Unlisted => record.code("reason", "unlisted"),
    }
}

/// An OS error's kind as a code of rmule's own: the standard library's text
/// holds spaces and may change with the toolchain, so it never reaches the
/// log. A kind rmule names no code for is `other`.
pub(super) const fn io_error(kind: std::io::ErrorKind) -> &'static str {
    use std::io::ErrorKind as K;
    match kind {
        K::NotFound => "not_found",
        K::PermissionDenied => "permission_denied",
        K::ConnectionRefused => "connection_refused",
        K::ConnectionReset => "connection_reset",
        K::HostUnreachable => "host_unreachable",
        K::NetworkUnreachable => "network_unreachable",
        K::ConnectionAborted => "connection_aborted",
        K::NotConnected => "not_connected",
        K::AddrInUse => "address_in_use",
        K::AddrNotAvailable => "address_not_available",
        K::NetworkDown => "network_down",
        K::BrokenPipe => "broken_pipe",
        K::AlreadyExists => "already_exists",
        K::WouldBlock => "would_block",
        K::NotADirectory => "not_a_directory",
        K::IsADirectory => "is_a_directory",
        K::DirectoryNotEmpty => "directory_not_empty",
        K::ReadOnlyFilesystem => "read_only_filesystem",
        K::InvalidInput => "invalid_input",
        K::InvalidData => "invalid_data",
        K::TimedOut => "timed_out",
        K::WriteZero => "write_zero",
        K::StorageFull => "storage_full",
        K::ResourceBusy => "resource_busy",
        K::Interrupted => "interrupted",
        K::Unsupported => "unsupported",
        K::UnexpectedEof => "unexpected_eof",
        K::OutOfMemory => "out_of_memory",
        _ => "other",
    }
}

/// A client family's code: the family the hello's software word names, or
/// the code itself for a family no table names.
pub(super) fn client_family(family: crate::diagnostics::ClientFamily) -> String {
    use crate::diagnostics::ClientFamily as F;
    match family {
        F::Emule => "emule",
        F::EmuleOld => "emule_old",
        F::Cdonkey => "cdonkey",
        F::Xmule => "xmule",
        F::Amule => "amule",
        F::Rmule => "rmule",
        F::Shareaza => "shareaza",
        F::EmulePlus => "emule_plus",
        F::HydraNode => "hydranode",
        F::MlDonkey => "mldonkey",
        F::MlDonkeyOld => "mldonkey_old",
        F::Lphant => "lphant",
        F::EdonkeyHybrid => "edonkey_hybrid",
        F::Edonkey => "edonkey",
        F::Compatible(code) => return format!("compatible_{code:#04x}"),
        F::Unknown => "unknown",
    }
    .to_owned()
}

pub(super) fn command_rejected(record: Record, reason: &CoreCommandRejectReason) -> Record {
    let code = match reason {
        CoreCommandRejectReason::DownloadAlreadyActive => "download_already_active",
        CoreCommandRejectReason::DuplicateDownload => "duplicate_download",
        CoreCommandRejectReason::DownloadPathConflict => "download_path_conflict",
        CoreCommandRejectReason::NoDownloadDir => "no_download_dir",
        CoreCommandRejectReason::DownloadDirRefused(guard) => {
            return directory_refusal_as(
                record.code("reason", "download_dir_refused"),
                "guard",
                guard,
            );
        }
        CoreCommandRejectReason::DownloadStoreFailed => "download_store_failed",
        CoreCommandRejectReason::UnknownDownload => "unknown_download",
        CoreCommandRejectReason::DownloadNotCompleted => "download_not_completed",
        CoreCommandRejectReason::UnknownSearch => "unknown_search",
        CoreCommandRejectReason::SearchIdInUse => "search_id_in_use",
        CoreCommandRejectReason::KadUnavailable(why) => {
            return kad_unavailable(record.code("reason", "kad_unavailable"), why);
        }
        CoreCommandRejectReason::UnknownServer => "unknown_server",
        CoreCommandRejectReason::ServerListStoreFailed => "server_list_store_failed",
        CoreCommandRejectReason::ServerListFetchUnavailable => "server_list_fetch_unavailable",
        CoreCommandRejectReason::ServerListUpdateInFlight => "server_list_update_in_flight",
        CoreCommandRejectReason::ServerConnectInFlight => "server_connect_in_flight",
    };
    record.code("reason", code)
}

fn kad_unavailable(record: Record, reason: &KadUnavailableReason) -> Record {
    match reason {
        KadUnavailableReason::UdpUnbound { port, kind } => record
            .code("kad", "udp_unbound")
            .port("port", *port)
            .os_error(*kind, None),
        KadUnavailableReason::UdpFamilyMissing {
            family: missing,
            kind,
        } => record
            .code("kad", "udp_family_missing")
            .code("family", family(*missing))
            .os_error(*kind, None),
        KadUnavailableReason::StartFailed => record.code("kad", "start_failed"),
        KadUnavailableReason::TcpPortUnbound => record.code("kad", "tcp_port_unbound"),
    }
}

pub(super) const fn nat_unavailable(reason: NatTraversalUnavailableReason) -> &'static str {
    match reason {
        NatTraversalUnavailableReason::BuddyEndpointUnknown => "buddy_endpoint_unknown",
        NatTraversalUnavailableReason::NotEnactable => "not_enactable",
        NatTraversalUnavailableReason::TargetIdentityUnknown => "target_identity_unknown",
    }
}

pub(super) const fn reach_drop(reason: PeerReachDropReason) -> &'static str {
    match reason {
        PeerReachDropReason::LowToLow => "low_to_low",
        PeerReachDropReason::NoBuddy => "no_buddy",
        PeerReachDropReason::NoKadUdpEndpoint => "no_kad_udp_endpoint",
        PeerReachDropReason::NoCoordinator => "no_coordinator",
    }
}

pub(super) const fn transport(transport: TunnelTransport) -> &'static str {
    match transport {
        TunnelTransport::Utp => "utp",
        TunnelTransport::Quic => "quic",
    }
}

pub(super) const fn stream_role(role: PeerStreamRole) -> &'static str {
    match role {
        PeerStreamRole::Dialer => "dialer",
        PeerStreamRole::Responder => "responder",
    }
}

pub(super) const fn kad_stop(reason: KadStopReason) -> &'static str {
    match reason {
        KadStopReason::Ended => "ended",
        KadStopReason::Stopped => "stopped",
        KadStopReason::TaskFailed => "task_failed",
    }
}

pub(super) const fn quit_step(step: QuitStep) -> &'static str {
    match step {
        QuitStep::DirectoryScan => "directory_scan",
        QuitStep::Search => "search",
        QuitStep::Download => "download",
        QuitStep::Serve => "serve",
        QuitStep::Kad => "kad",
        QuitStep::PortMapping => "port_mapping",
        QuitStep::CreditCheckpoint => "credit_checkpoint",
    }
}

pub(super) const fn search_failure(reason: SearchFailure) -> &'static str {
    match reason {
        SearchFailure::ServerDisconnected => "server_disconnected",
        SearchFailure::RelatedSearchNotOffered => "related_search_not_offered",
        SearchFailure::RelatedAnswerUnattributable => "related_answer_unattributable",
        SearchFailure::TaskPanicked => "task_panicked",
    }
}

pub(super) const fn search_leg(state: SearchLegState) -> &'static str {
    match state {
        SearchLegState::WaitingForSession => "waiting_for_session",
        SearchLegState::WaitingForKad => "waiting_for_kad",
        SearchLegState::Sent => "sent",
        SearchLegState::Settled => "settled",
        SearchLegState::NotRun => "not_run",
        SearchLegState::Unanswered => "unanswered",
        SearchLegState::WalkStopped => "walk_stopped",
        SearchLegState::NotSent(LegNotSent::NoServer) => "not_sent_no_server",
        SearchLegState::NotSent(LegNotSent::NoKadContact) => "not_sent_no_kad_contact",
        SearchLegState::NotSent(LegNotSent::KadKeywordHeld) => "not_sent_kad_keyword_held",
        SearchLegState::NotSent(LegNotSent::NoKadKeyword) => "not_sent_no_kad_keyword",
        SearchLegState::NotSent(LegNotSent::KadStopped) => "not_sent_kad_stopped",
    }
}

pub(super) const fn search_skip(reason: SearchResultSkipReason) -> &'static str {
    match reason {
        SearchResultSkipReason::MalformedPayload => "malformed_payload",
        SearchResultSkipReason::MissingFileName => "missing_file_name",
        SearchResultSkipReason::MissingFileSize => "missing_file_size",
        SearchResultSkipReason::TagDecodeFailed => "tag_decode_failed",
        SearchResultSkipReason::FileSizeAboveLimit => "file_size_above_limit",
        SearchResultSkipReason::FileSizeZero => "file_size_zero",
    }
}

pub(super) const fn related_refusal(reason: RelatedSearchRefusal) -> &'static str {
    match reason {
        RelatedSearchRefusal::NotConnected => "not_connected",
        RelatedSearchRefusal::NotOffered => "not_offered",
    }
}

/// A port mapping's status code.
#[must_use]
pub(crate) const fn mapping_status(status: MappingStatus) -> &'static str {
    match status {
        MappingStatus::NotMapped => "not_mapped",
        MappingStatus::Probing => "probing",
        MappingStatus::Mapped => "mapped",
        MappingStatus::Degraded => "degraded",
        MappingStatus::Failed => "failed",
    }
}

/// A port mapping protocol's code.
#[must_use]
pub(crate) const fn protocol(protocol: MappingProtocol) -> &'static str {
    match protocol {
        MappingProtocol::Pcp => "pcp",
        MappingProtocol::NatPmp => "nat_pmp",
        MappingProtocol::Upnp => "upnp",
    }
}

/// A port mapping's error: its protocol, an `error` code, and the codes
/// and numbers that came with it.
#[must_use]
pub(crate) fn mapping_error(record: Record, error: &MappingError) -> Record {
    let record = record.code("protocol", protocol(error.protocol()));
    match error {
        MappingError::Unsupported(_) => record.code("error", "unsupported"),
        MappingError::Timeout(_) => record.code("error", "timeout"),
        MappingError::Refused { refusal, .. } => {
            let record = record.code("error", "refused");
            match refusal {
                MappingRefusal::UnknownCode(number) => record
                    .code("refusal", "unknown_code")
                    .count("refusal_code", *number),
                MappingRefusal::NotAuthorized => record.code("refusal", "not_authorized"),
                MappingRefusal::Malformed => record.code("refusal", "malformed"),
                MappingRefusal::Unsupported => record.code("refusal", "unsupported"),
                MappingRefusal::NetworkFailure => record.code("refusal", "network_failure"),
                MappingRefusal::NoResources => record.code("refusal", "no_resources"),
                MappingRefusal::QuotaExceeded => record.code("refusal", "quota_exceeded"),
                MappingRefusal::CannotProvideExternal => {
                    record.code("refusal", "cannot_provide_external")
                }
                MappingRefusal::AddressMismatch => record.code("refusal", "address_mismatch"),
                MappingRefusal::ExcessiveRemotePeers => {
                    record.code("refusal", "excessive_remote_peers")
                }
                MappingRefusal::BadAnswer => record.code("refusal", "bad_answer"),
                MappingRefusal::DeviceRefused => record.code("refusal", "device_refused"),
            }
        }
        MappingError::Transport { fault, .. } => {
            let record = record.code("error", "transport");
            match fault {
                MappingTransportFault::Io { kind, os_code } => record
                    .code("fault", "io")
                    .os_error_named("io_error", *kind, *os_code),
                MappingTransportFault::PortZero => record.code("fault", "port_zero"),
                MappingTransportFault::NoExternalAddress => {
                    record.code("fault", "no_external_address")
                }
                MappingTransportFault::NoIpv6Local => record.code("fault", "no_ipv6_local"),
                MappingTransportFault::Device => record.code("fault", "device"),
            }
        }
    }
}

/// A confidence tier's code.
#[must_use]
pub(crate) const fn tier(tier: ConfidenceTier) -> &'static str {
    match tier {
        ConfidenceTier::Override => "override",
        ConfidenceTier::Server => "server",
        ConfidenceTier::KadCheck => "kad_check",
        ConfidenceTier::PeerVote => "peer_vote",
        ConfidenceTier::MappingGrant => "mapping_grant",
        ConfidenceTier::LowIdReport => "low_id_report",
        ConfidenceTier::Interface => "interface",
    }
}

pub(super) const fn server_priority(priority: crate::ServerPriority) -> &'static str {
    use crate::ServerPriority;
    match priority {
        ServerPriority::Normal => "normal",
        ServerPriority::High => "high",
        ServerPriority::Low => "low",
    }
}

/// Why a TCP dial did not come up: a server's or a buddy's.
pub(super) fn dial_failure(record: Record, cause: DialFailure) -> Record {
    match cause {
        DialFailure::TimedOut => record.code("cause", "timed_out"),
        DialFailure::Os { kind, os_code } => record.code("cause", "os").os_error(kind, os_code),
        DialFailure::DriverEnded => record.code("cause", "driver_ended"),
        DialFailure::CryptHandshake { kind } => {
            record.code("cause", "crypt_handshake").os_error(kind, None)
        }
    }
}

/// Why a source was let go to make room.
pub(super) const fn source_purge_reason(reason: SourcePurgeReason) -> &'static str {
    match reason {
        SourcePurgeReason::LowToLow => "low_to_low",
        SourcePurgeReason::NoNeededParts => "no_needed_parts",
        SourcePurgeReason::QueueFull => "queue_full",
    }
}

/// Why a reask reply changed nothing.
pub(super) const fn ignored_reask_reply(reason: IgnoredReaskReply) -> &'static str {
    match reason {
        IgnoredReaskReply::Runt => "runt",
        IgnoredReaskReply::UnexpectedOpcode => "unexpected_opcode",
        IgnoredReaskReply::NoPooledSource => "no_pooled_source",
        IgnoredReaskReply::Misframed => "misframed",
        IgnoredReaskReply::PartCountMismatch => "part_count_mismatch",
    }
}

/// Why a dial ended before the peer's hello; an OS error carries its kind.
pub(super) fn dial_end(record: Record, cause: DialEnd) -> Record {
    let code = match cause {
        DialEnd::CryptStanceUnknown => "crypt_stance_unknown",
        DialEnd::CryptUnsupported => "crypt_unsupported",
        DialEnd::CryptRequiredByPeer => "crypt_required_by_peer",
        DialEnd::CryptKeyUnknown => "crypt_key_unknown",
        DialEnd::IpFiltered => "ip_filtered",
        DialEnd::Banned => "banned",
        DialEnd::ConnectionRefused => "connection_refused",
        DialEnd::TimedOut => "timed_out",
        DialEnd::Reset => "reset",
        DialEnd::Os { kind } => return record.code("cause", "os").os_error(kind, None),
        DialEnd::ClosedBeforeHello => "closed_before_hello",
        DialEnd::NoHelloInTime => "no_hello_in_time",
        DialEnd::ProtocolViolation => "protocol_violation",
        DialEnd::ClosedLocally => "closed_locally",
    };
    record.code("cause", code)
}
