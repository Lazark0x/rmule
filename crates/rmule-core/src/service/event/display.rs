//! How an event renders in a log line — the one place the core's line format
//! lives, so every front end's log agrees. The line is diagnostic: it names
//! codes by their `Debug` form, and no surface an operator reads prints it (a
//! front end words an event itself, from its codes).
//! Each per-activity `Display` owns its `download` / `search` / `serve`
//! prefix; [`CoreEvent`] delegates to them and renders the
//! cross-activity facts itself. Exhaustive by design: a new variant fails to
//! compile until its projection lands here.

use std::fmt;

use rmule_primitives::ServerEndpoint;

use crate::service::{
    CoreEvent, DownloadEvent, PartsLost, RestartOutcome, SearchEvent, ServeEvent,
    ServeStartFailure, ServerConnectionEvent, ServerListEvent, SourceWait,
};

impl fmt::Display for DownloadEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DownloadEvent::DownloadQueued {
                download_id,
                file_hash,
                metadata,
            } => write!(
                f,
                "download queued id={} file_hash={} name={} size={}",
                download_id.as_u64(),
                file_hash.to_hex_upper(),
                metadata.name,
                metadata.size
            ),
            DownloadEvent::DownloadRecovered {
                download_id,
                state,
                failure,
                file_hash,
                metadata,
            } => {
                write!(
                    f,
                    "download recovered id={} state={state:?} file_hash={} name={} size={}",
                    download_id.as_u64(),
                    file_hash.to_hex_upper(),
                    metadata.name,
                    metadata.size
                )?;
                match failure {
                    Some(reason) => write!(f, " failure={reason:?}"),
                    None => Ok(()),
                }
            }
            DownloadEvent::DownloadProgressRestored {
                download_id,
                verified_parts,
                verified_bytes,
            } => write!(
                f,
                "download progress_restored id={} verified_parts={verified_parts} verified_bytes={verified_bytes}",
                download_id.as_u64()
            ),
            DownloadEvent::PartFileLost {
                download_id,
                found,
                lost,
            } => {
                write!(
                    f,
                    "download part_file_lost id={} found={found:?} ",
                    download_id.as_u64()
                )?;
                match lost {
                    PartsLost::Counted { parts, bytes } => {
                        write!(f, "parts_lost={parts} bytes_lost={bytes}")
                    }
                    PartsLost::NotCounted => f.write_str("parts_lost=uncounted"),
                }
            }
            DownloadEvent::FinishedFileRejected {
                download_id,
                parts_dropped,
                bytes_dropped,
            } => write!(
                f,
                "download finished_file_rejected id={} parts_dropped={parts_dropped} bytes_dropped={bytes_dropped}",
                download_id.as_u64()
            ),
            DownloadEvent::DownloadRestarted {
                download_id,
                outcome,
            } => match outcome {
                RestartOutcome::Continued {
                    kept_parts,
                    kept_bytes,
                    dropped_parts,
                    dropped_bytes,
                } => write!(
                    f,
                    "download restarted id={} outcome=continued kept_parts={kept_parts} kept_bytes={kept_bytes} dropped_parts={dropped_parts} dropped_bytes={dropped_bytes}",
                    download_id.as_u64()
                ),
                RestartOutcome::StartedOver {
                    fault,
                    dropped_parts,
                    dropped_bytes,
                } => write!(
                    f,
                    "download restarted id={} outcome=started_over fault={fault:?} dropped_parts={dropped_parts} dropped_bytes={dropped_bytes}",
                    download_id.as_u64()
                ),
            },
            DownloadEvent::DamagedPartsDropped {
                download_id,
                damaged,
            } => {
                write!(
                    f,
                    "download damaged_parts_dropped id={} parts={}",
                    download_id.as_u64(),
                    damaged.len()
                )?;
                for fault in damaged {
                    write!(f, "; {fault}")?;
                }
                Ok(())
            }
            DownloadEvent::ServerLoginAccepted {
                download_id,
                client_id,
            } => write!(
                f,
                "download server_login_accepted id={} client_id={}",
                download_id.as_u64(),
                client_id.as_u32()
            ),
            DownloadEvent::SourcesFound {
                download_id,
                total,
                usable_high_id,
            } => write!(
                f,
                "download sources_found id={} total={total} usable_high_id={usable_high_id}",
                download_id.as_u64()
            ),
            DownloadEvent::LinkSourcesAdded {
                download_id,
                named,
                admitted,
                new,
            } => write!(
                f,
                "download link_sources_added id={} named={named} admitted={admitted} new={new}",
                download_id.as_u64()
            ),
            DownloadEvent::SeedsLoaded {
                downloads,
                seeds,
                expired,
            } => write!(
                f,
                "download seeds_loaded downloads={downloads} seeds={seeds} expired={expired}"
            ),
            DownloadEvent::SeedsDialled {
                download_id,
                written,
                dialled,
                answered,
            } => write!(
                f,
                "download seeds_dialled id={} written={written} dialled={dialled} answered={answered}",
                download_id.as_u64()
            ),
            DownloadEvent::SourcesExchanged {
                download_id,
                peer,
                received,
                admitted,
            } => write!(
                f,
                "download sources_exchanged id={} peer={peer} received={received} \
                 admitted={admitted}",
                download_id.as_u64()
            ),
            DownloadEvent::PeerSelected { download_id, peer } => {
                write!(
                    f,
                    "download peer_selected id={} peer={peer}",
                    download_id.as_u64(),
                )
            }
            DownloadEvent::PeerQueued {
                download_id,
                peer,
                rank,
            } => {
                write!(
                    f,
                    "download peer_queued id={} peer={peer} rank={rank}",
                    download_id.as_u64(),
                )
            }
            DownloadEvent::PeerSlotGranted { download_id, peer } => {
                write!(
                    f,
                    "download peer_slot_granted id={} peer={peer}",
                    download_id.as_u64(),
                )
            }
            DownloadEvent::PeerSlotTimeout { download_id, peer } => {
                write!(
                    f,
                    "download peer_slot_timeout id={} peer={peer}",
                    download_id.as_u64(),
                )
            }
            DownloadEvent::SourceRemoteQueued {
                download_id,
                peer,
                rank,
            } => {
                write!(
                    f,
                    "download source_remote_queued id={} peer={peer} rank={rank}",
                    download_id.as_u64(),
                )
            }
            DownloadEvent::SourceReaskAcked {
                download_id,
                peer,
                rank,
            } => {
                write!(
                    f,
                    "download source_reask_acked id={} peer={peer} rank={rank}",
                    download_id.as_u64(),
                )
            }
            DownloadEvent::SourceReaskQueueFull { download_id, peer } => {
                write!(
                    f,
                    "download source_reask_queue_full id={} peer={peer}",
                    download_id.as_u64(),
                )
            }
            DownloadEvent::SourceReaskDropped { download_id, peer } => {
                write!(
                    f,
                    "download source_reask_dropped id={} peer={peer}",
                    download_id.as_u64(),
                )
            }
            DownloadEvent::ReaskReplyIgnored {
                download_id,
                peer,
                reason,
            } => write!(
                f,
                "download reask_reply_ignored id={} peer={peer} reason={reason:?}",
                download_id.as_u64()
            ),
            DownloadEvent::DialEnded {
                download_id,
                peer,
                cause,
            } => write!(
                f,
                "download dial_ended id={} peer={peer} cause={cause:?}",
                download_id.as_u64()
            ),
            DownloadEvent::HashSetReceived {
                download_id,
                part_count,
                authority,
            } => write!(
                f,
                "download hash_set_received id={} part_count={part_count} authority={authority:?}",
                download_id.as_u64()
            ),
            DownloadEvent::PartAssigned {
                download_id,
                peer,
                part_index,
            } => {
                write!(
                    f,
                    "download part_assigned id={} peer={peer} part_index={part_index}",
                    download_id.as_u64(),
                )
            }
            DownloadEvent::PartReleased {
                download_id,
                peer,
                part_index,
                reason,
            } => {
                write!(
                    f,
                    "download part_released id={} peer={peer} part_index={part_index} reason={reason:?}",
                    download_id.as_u64(),
                )
            }
            DownloadEvent::PeerRetired {
                download_id,
                peer,
                reason,
            } => {
                write!(
                    f,
                    "download peer_retired id={} peer={peer} reason={reason:?}",
                    download_id.as_u64(),
                )
            }
            DownloadEvent::PartVerified {
                download_id,
                part_index,
            } => write!(
                f,
                "download part_verified id={} part_index={part_index}",
                download_id.as_u64()
            ),
            DownloadEvent::DownloadCompleted { download_id } => {
                write!(f, "download completed id={}", download_id.as_u64())
            }
            DownloadEvent::DownloadCancelled { download_id } => {
                write!(f, "download cancelled id={}", download_id.as_u64())
            }
            DownloadEvent::DownloadCleared { download_id } => {
                write!(f, "download cleared id={}", download_id.as_u64())
            }
            DownloadEvent::DownloadPaused { download_id } => {
                write!(f, "download paused id={}", download_id.as_u64())
            }
            DownloadEvent::DownloadResumed { download_id } => {
                write!(f, "download resumed id={}", download_id.as_u64())
            }
            DownloadEvent::DownloadFailed {
                download_id,
                reason,
            } => write!(
                f,
                "download failed id={} reason={reason}",
                download_id.as_u64()
            ),
            DownloadEvent::WaitingForConnection { download_id } => {
                write!(
                    f,
                    "download waiting_for_connection id={}",
                    download_id.as_u64()
                )
            }
            DownloadEvent::FailureNotRecorded { download_id } => write!(
                f,
                "download failure_not_recorded id={}",
                download_id.as_u64()
            ),
            DownloadEvent::WaitingForSources {
                download_id,
                reason,
            } => {
                let reason = match reason {
                    SourceWait::Asking => "asking",
                    SourceWait::KadAlone => "kad_alone",
                    SourceWait::NoSession => "no_session",
                };
                write!(
                    f,
                    "download waiting_for_sources id={} reason={reason}",
                    download_id.as_u64()
                )
            }
        }
    }
}

impl fmt::Display for SearchEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SearchEvent::SearchStarted { search_id } => {
                write!(f, "search started id={}", search_id.as_u64())
            }
            SearchEvent::SearchResultsReceived { search_id, results } => write!(
                f,
                "search results_received id={} total={}",
                search_id.as_u64(),
                results.len()
            ),
            SearchEvent::SearchResultSkipped { search_id, reason } => write!(
                f,
                "search result_skipped id={} reason={reason:?}",
                search_id.as_u64()
            ),
            SearchEvent::SearchCompleted {
                search_id,
                total_results,
            } => write!(
                f,
                "search completed id={} total_results={total_results}",
                search_id.as_u64()
            ),
            SearchEvent::SearchCancelled { search_id } => {
                write!(f, "search cancelled id={}", search_id.as_u64())
            }
            SearchEvent::SearchRefused { search_id, reason } => write!(
                f,
                "search refused id={} reason={reason:?}",
                search_id.as_u64()
            ),
            SearchEvent::SearchWaitingForTurn { search_id, send_in } => write!(
                f,
                "search waiting_for_turn id={} send_in_ms={}",
                search_id.as_u64(),
                send_in.as_millis()
            ),
            SearchEvent::SearchWaitingForConnection { search_id } => {
                write!(f, "search waiting_for_connection id={}", search_id.as_u64())
            }
            SearchEvent::SearchLegsChanged { search_id, legs } => write!(
                f,
                "search legs id={} server={:?} sweep={:?} kad={:?} sweep_asked={} sweep_answered={}",
                search_id.as_u64(),
                legs.server,
                legs.sweep,
                legs.kad,
                legs.sweep_servers.asked,
                legs.sweep_servers.answered
            ),
            SearchEvent::SearchDeferredKadPublish { search_id } => {
                write!(f, "search deferred_kad_publish id={}", search_id.as_u64())
            }
            SearchEvent::SearchSentToServer { search_id } => {
                write!(f, "search sent_to_server id={}", search_id.as_u64())
            }
            SearchEvent::SearchMoreRequested { search_id } => {
                write!(f, "search more_requested id={}", search_id.as_u64())
            }
            SearchEvent::SearchMoreRefused { search_id } => {
                write!(f, "search more_refused id={}", search_id.as_u64())
            }
            SearchEvent::SearchFailed { search_id, reason } => write!(
                f,
                "search failed id={} reason={reason:?}",
                search_id.as_u64()
            ),
        }
    }
}

impl fmt::Display for ServeEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServeEvent::FileShared { file_hash } => {
                write!(
                    f,
                    "serve file_shared file_hash={}",
                    file_hash.to_hex_upper()
                )
            }
            ServeEvent::FileUnshared { file_hash } => write!(
                f,
                "serve file_unshared file_hash={}",
                file_hash.to_hex_upper()
            ),
            ServeEvent::FileWithheld {
                file_hash, reason, ..
            } => write!(
                f,
                "serve file_withheld file_hash={} reason={reason:?}",
                file_hash.to_hex_upper()
            ),
            ServeEvent::FileOffered { file_hash } => write!(
                f,
                "serve file_offered file_hash={}",
                file_hash.to_hex_upper()
            ),
            ServeEvent::SharesUnwatched => write!(f, "serve shares_unwatched"),
            ServeEvent::ShareRejected { reason } => {
                write!(f, "serve share_rejected reason={reason:?}")
            }
            ServeEvent::ServingStarted { listen_addr } => {
                write!(f, "serve serving_started listen_addr={listen_addr}")
            }
            ServeEvent::ServingFailed { reason } => {
                write!(f, "serve serving_failed reason={reason:?} ({reason})")
            }
            ServeEvent::FilesAnnounced { file_count } => {
                write!(f, "serve files_announced file_count={file_count}")
            }
            ServeEvent::FilesWithheld { file_count, reason } => {
                write!(
                    f,
                    "serve files_withheld file_count={file_count} reason={reason:?}"
                )
            }
            ServeEvent::UploadSlotGranted {
                peer,
                file_hash,
                software,
            } => {
                write!(
                    f,
                    "serve upload_slot_granted peer={peer} file_hash={} software={software:?}",
                    file_hash.to_hex_upper()
                )
            }
            ServeEvent::PeerQueued {
                peer,
                rank,
                file_hash,
                software,
            } => write!(
                f,
                "serve peer_queued peer={peer} rank={rank} file_hash={} software={software:?}",
                file_hash.to_hex_upper()
            ),
            ServeEvent::UploadQueueFull { peer } => {
                write!(f, "serve upload_queue_full peer={peer}",)
            }
            ServeEvent::UploadLowIdAbuseRefused { peer } => {
                write!(f, "serve upload_low_id_abuse_refused peer={peer}",)
            }
            ServeEvent::ReaskPingMalformed { peer } => {
                write!(f, "serve reask_ping_malformed peer={peer}",)
            }
            ServeEvent::NameAskMalformed { peer } => {
                write!(f, "serve name_ask_malformed peer={peer}",)
            }
            ServeEvent::UploadAddressCapReached { peer } => {
                write!(f, "serve upload_address_cap_reached peer={peer}",)
            }
            ServeEvent::UploadSlotReleased { peer } => {
                write!(f, "serve upload_slot_released peer={peer}",)
            }
            ServeEvent::WaiterLeft { peer, cause } => {
                write!(f, "serve waiter_left peer={peer} cause={cause:?}",)
            }
            ServeEvent::SourcesServed {
                peer,
                file_hash,
                count,
            } => {
                write!(
                    f,
                    "serve sources_served peer={peer} file_hash={} count={count}",
                    file_hash.to_hex_upper()
                )
            }
            ServeEvent::ServingStopped { reason } => {
                write!(f, "serve serving_stopped reason={reason:?}")
            }
        }
    }
}

/// The words an operator reads in the status bar when serving did not start.
/// A held port names who can hold it: since the listener sets
/// `SO_REUSEADDR` on Unix, and a Windows bind is refused only by a live
/// socket, a previous run's closed connections never do — only a live
/// socket, a second rmule or another program, listening on the same port.
impl fmt::Display for ServeStartFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bind(std::io::ErrorKind::AddrInUse) => f.write_str(
                "the eD2k listen port is in use by another program or a second rmule — \
                 serving is off until that port is free or another is chosen",
            ),
            Self::Bind(kind) => write!(
                f,
                "the eD2k listen port could not be bound ({kind}) — serving is off"
            ),
            Self::Adapter => f.write_str("the serve adapter refused the start — serving is off"),
        }
    }
}

impl fmt::Display for ServerListEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn endpoint(server: &ServerEndpoint) -> String {
            format!("{}:{}", server.host(), server.port())
        }
        match self {
            ServerListEvent::ServerAdded { server } => {
                write!(f, "server_list added server={}", endpoint(server))
            }
            ServerListEvent::ServerUpdated { server } => {
                write!(f, "server_list updated server={}", endpoint(server))
            }
            ServerListEvent::ServerRemoved { server } => {
                write!(f, "server_list removed server={}", endpoint(server))
            }
            ServerListEvent::ServerPriorityChanged { server, priority } => write!(
                f,
                "server_list priority_changed server={} priority={priority:?}",
                endpoint(server)
            ),
            ServerListEvent::ServerStaticChanged { server, is_static } => write!(
                f,
                "server_list static_changed server={} static={is_static}",
                endpoint(server)
            ),
            ServerListEvent::ServerListUpdateStarted { url } => {
                write!(f, "server_list update_started url={url}")
            }
            ServerListEvent::ServerListUpdated {
                added,
                updated,
                total,
            } => write!(
                f,
                "server_list updated_from_url added={added} updated={updated} total={total}"
            ),
            ServerListEvent::ServerListUpdateFailed { reason } => {
                write!(f, "server_list update_failed reason={reason:?}")
            }
        }
    }
}

impl fmt::Display for ServerConnectionEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn endpoint(server: &ServerEndpoint) -> String {
            format!("{}:{}", server.host(), server.port())
        }
        match self {
            ServerConnectionEvent::Connecting { server, leaving } => {
                write!(f, "server connecting server={}", endpoint(server))?;
                if let Some(left) = leaving {
                    write!(f, " leaving={}", endpoint(left))?;
                }
                Ok(())
            }
            ServerConnectionEvent::Connected { server, client_id } => write!(
                f,
                "server connected server={} client_id={}",
                endpoint(server),
                client_id.as_u32()
            ),
            ServerConnectionEvent::ConnectFailed { server, reason } => write!(
                f,
                "server connect_failed server={} reason={reason:?}",
                endpoint(server)
            ),
            ServerConnectionEvent::Disconnected { server } => {
                write!(f, "server disconnected server={}", endpoint(server))
            }
            ServerConnectionEvent::Reconnecting {
                server,
                attempt,
                next_in,
                ..
            } => write!(
                f,
                "server reconnecting server={} attempt={attempt} next_in_s={}",
                endpoint(server),
                next_in.as_secs()
            ),
            ServerConnectionEvent::ReconnectEnded { server, reason } => write!(
                f,
                "server reconnect_ended server={} reason={reason:?}",
                endpoint(server)
            ),
        }
    }
}

impl fmt::Display for CoreEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoreEvent::Download(event) => write!(f, "{event}"),
            CoreEvent::Serve(event) => write!(f, "{event}"),
            CoreEvent::Search(event) => write!(f, "{event}"),
            CoreEvent::ServerList(event) => write!(f, "{event}"),
            CoreEvent::ServerConnection(event) => write!(f, "{event}"),
            CoreEvent::SecuredIdentityMismatch { user_hash } => {
                write!(f, "secured_identity_mismatch {user_hash:?}")
            }
            CoreEvent::CommandRejected { reason } => write!(f, "command_rejected {reason:?}"),
            CoreEvent::PeerReachRouted { peer, route } => {
                write!(f, "peer_reach_routed peer={peer:?} route={route:?}")
            }
            CoreEvent::NattTunnelRisen {
                peer,
                transport,
                role,
            } => write!(
                f,
                "natt_tunnel_risen peer={peer:?} transport={transport:?} role={role:?}"
            ),
            CoreEvent::ClientUdpBindFailed { port, kind } => {
                write!(f, "client_udp_bind_failed port={port} kind={kind:?}")
            }
            CoreEvent::PeerHelloRefused { refusal } => match refusal.code {
                rmule_peer::HelloRefusalCode::TagCountShort { declared, written } => write!(
                    f,
                    "peer_hello_refused code=tag_count_short declared={declared} written={written}"
                ),
                _ => write!(f, "peer_hello_refused"),
            },
            CoreEvent::SocketBoundWithoutFamily { half_bound } => write!(
                f,
                "socket_bound_without_family role={:?} missing={} kind={:?}",
                half_bound.role, half_bound.missing, half_bound.kind
            ),
            CoreEvent::FileHistory { history } => write!(
                f,
                "file history shared={} had={} cancelled={} unread={:?}",
                history.shared.len(),
                history.had.len(),
                history.cancelled.len(),
                history.unread,
            ),
            CoreEvent::DiagnosticsSnapshot { snapshot } => {
                write!(
                    f,
                    "diagnostics snapshot downloads={} uploads={} down_bytes={} up_bytes={} undialable_family_sources={} unanswerable_family_datagrams={} peer_hellos_refused={}",
                    snapshot.downloads.len(),
                    snapshot.uploads.len(),
                    snapshot.session.down_bytes_total,
                    snapshot.session.up_bytes_total,
                    snapshot.session.undialable_family_sources_total,
                    snapshot.session.unanswerable_family_datagrams_total,
                    snapshot.session.peer_hellos_refused_total,
                )?;
                match &snapshot.kad {
                    None => Ok(()),
                    Some(kad) => {
                        write!(f, " kad_contact_responded={}", kad.contact_responded)
                    }
                }
            }
            CoreEvent::KadStopped { reason } => write!(f, "kad_stopped reason={reason:?}"),
            CoreEvent::Quitting { step } => write!(f, "quitting step={step:?}"),
            CoreEvent::ServerLogin { server, step } => write!(
                f,
                "server login server={}:{} step={step:?}",
                server.host(),
                server.port()
            ),
            CoreEvent::BuddyDialFailed { buddy, cause } => {
                write!(f, "buddy dial failed buddy={buddy} cause={cause:?}")
            }
            CoreEvent::KadHelperTestLate {
                helper,
                late_by,
                admission,
            } => write!(
                f,
                "kad helper test late helper={helper} late_by_ms={} admission={admission:?}",
                late_by.as_millis()
            ),
            CoreEvent::Scan(event) => write!(f, "{event}"),
        }
    }
}
