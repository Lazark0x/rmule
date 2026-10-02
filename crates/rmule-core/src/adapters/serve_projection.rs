//! Projection between core's serve vocabulary and the peer protocol: a
//! `ServeConnCommand` down to a `PeerCommand`, a `PeerEvent` up to a
//! `ServeConnEvent`, and the Server Capability split that decides which half
//! of a dialed connection owns an event.

use rmule_peer::{PeerCommand, PeerEvent};

use super::serve_runtime::{ServeConnCommand, ServeConnEvent};

/// Translate one serve-vocabulary command into the `PeerCommand` that enacts
/// it. Re-exported at the crate root under the `test-support` feature so
/// rmule-testkit's loopback bridge translates exactly as production does.
pub fn serve_command_to_peer(command: ServeConnCommand) -> PeerCommand {
    match command {
        ServeConnCommand::AnswerFileName {
            file_hash,
            file_name,
        } => PeerCommand::AnswerFileName {
            file_hash,
            file_name,
        },
        ServeConnCommand::AnswerFileNotFound { file_hash } => {
            PeerCommand::AnswerFileNotFound { file_hash }
        }
        ServeConnCommand::AnswerFileStatus { file_hash, bitmap } => {
            PeerCommand::AnswerFileStatus { file_hash, bitmap }
        }
        ServeConnCommand::AnswerHashSet {
            file_hash,
            part_hashes,
        } => PeerCommand::AnswerHashSet {
            file_hash,
            part_hashes,
        },
        ServeConnCommand::GrantSlot { file_hash } => PeerCommand::GrantSlot { file_hash },
        ServeConnCommand::SetQueueRank { rank } => PeerCommand::SetQueueRank { rank },
        ServeConnCommand::SendBlock {
            file_hash,
            start,
            end,
            bytes,
        } => PeerCommand::SendBlock {
            file_hash,
            start,
            end,
            bytes,
        },
        ServeConnCommand::AnswerAich {
            file_hash,
            part,
            root,
            recovery_data,
        } => PeerCommand::AnswerAich {
            file_hash,
            part,
            root,
            recovery_data,
        },
        ServeConnCommand::AnswerAichFileHash { root } => PeerCommand::AnswerAichFileHash { root },
        ServeConnCommand::AnswerSources {
            file_hash,
            sources,
            version,
        } => PeerCommand::AnswerSources {
            file_hash,
            sources,
            version,
        },
        ServeConnCommand::Disconnect => PeerCommand::Disconnect,
    }
}

/// Project a `PeerEvent` onto the serve vocabulary; `None` for events outside
/// the serve contract. Re-exported at the crate root under the `test-support`
/// feature so rmule-testkit's loopback bridge translates exactly as
/// production does.
pub fn serve_event_from_peer(event: PeerEvent) -> Option<ServeConnEvent> {
    match event {
        PeerEvent::FileRequested { file_hash, status } => {
            Some(ServeConnEvent::FileRequested { file_hash, status })
        }
        PeerEvent::FileBundleRequested {
            file_hash,
            file_size,
            asks,
            cut,
        } => Some(ServeConnEvent::FileBundleRequested {
            file_hash,
            file_size,
            asks,
            cut,
        }),
        PeerEvent::FileIdSet { file_hash } => Some(ServeConnEvent::FileIdSet { file_hash }),
        PeerEvent::HashSetRequested { file_hash } => {
            Some(ServeConnEvent::HashSetRequested { file_hash })
        }
        PeerEvent::SlotRequested { file_hash } => Some(ServeConnEvent::SlotRequested { file_hash }),
        PeerEvent::PartsRequested { file_hash, ranges } => {
            Some(ServeConnEvent::PartsRequested { file_hash, ranges })
        }
        PeerEvent::SourcesRequested { file_hash, version } => {
            Some(ServeConnEvent::SourcesRequested { file_hash, version })
        }
        PeerEvent::AichRequested {
            file_hash,
            part,
            root,
        } => Some(ServeConnEvent::AichRequested {
            file_hash,
            part,
            root,
        }),
        PeerEvent::AichFileHashRequested { file_hash } => {
            Some(ServeConnEvent::AichFileHashRequested { file_hash })
        }
        PeerEvent::TransferCancelled { file_hash } => {
            Some(ServeConnEvent::TransferCancelled { file_hash })
        }
        PeerEvent::Disconnected { .. } => Some(ServeConnEvent::Disconnected),
        PeerEvent::PeerIdentityVerified {
            user_hash,
            public_key,
        } => Some(ServeConnEvent::IdentityVerified {
            user_hash,
            public_key,
        }),
        PeerEvent::PeerReaskContactRevised {
            udp_port,
            udp_version,
        } => Some(ServeConnEvent::ReaskContactRevised {
            udp_port,
            udp_version,
        }),
        PeerEvent::PeerSoftwareRevised { software } => {
            Some(ServeConnEvent::SoftwareRevised { software })
        }
        PeerEvent::PeerIdentified { identity } => {
            // The peer's advertised client-UDP reask contact (`CT_EMULE_UDPPORTS`
            // low half + `MiscOptions1` UDP version): threaded now that the live
            // front serves peer-UDP (ADR-0057), so a queued waiter's inbound
            // `OP_REASKFILEPING` matches by IP + port and its `OP_REASKACK`
            // carries our part status. `(0, 0)` when the peer advertised none.
            let (udp_port, udp_version) = identity.client_udp_reask().unwrap_or((0, 0));
            Some(ServeConnEvent::Identified {
                user_hash: identity.user_hash(),
                client_id: identity.client_id(),
                connected_server: identity.connected_server(),
                // The peer's advertised eD2k listen port — its own source
                // coordinate for source-exchange serving (ADR-0055 §Serving).
                tcp_port: identity.tcp_port(),
                udp_port,
                udp_version,
                extended_requests_version: identity.extended_requests_version(),
                crypt: identity.crypt_stance(),
                ipv6: identity.peer_ipv6(),
                software: identity.software().clone(),
            })
        }
        // Requester-side and informational events are not part of the serve
        // contract; the loopback peer never drives them on this path.
        _ => None,
    }
}

/// Whether `event` is a Server Capability request — the peer pulling a file
/// *from us* — as opposed to a Requester Capability event (our pull) or a
/// neutral one. The router (`route_dialed_connection`) uses this to fan a
/// dialed connection's single `PeerEvent` stream to the serve half versus the
/// download half. `Disconnected` is neutral (both halves must free their
/// state) and is handled separately, so it is deliberately **not** a server
/// event here.
#[must_use]
pub(crate) fn is_server_capability_event(event: &PeerEvent) -> bool {
    matches!(
        event,
        PeerEvent::FileRequested { .. }
            | PeerEvent::FileBundleRequested { .. }
            | PeerEvent::FileIdSet { .. }
            | PeerEvent::HashSetRequested { .. }
            | PeerEvent::SlotRequested { .. }
            | PeerEvent::PartsRequested { .. }
            | PeerEvent::SourcesRequested { .. }
            | PeerEvent::AichRequested { .. }
            | PeerEvent::AichFileHashRequested { .. }
            | PeerEvent::TransferCancelled { .. }
    )
}

#[cfg(test)]
mod tests;
