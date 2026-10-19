//! The bytes a fixed session leaves in `rmule.log` at each level, pinned
//! line for line: they change only when a record's code, a field's name, its
//! kind or its rendering does.

use super::*;

/// Events whose records come from the reason code tables, each carrying what
/// the lean level withholds where its record has any.
fn reason_events() -> Vec<CoreEvent> {
    let peer = peer_at(198, 51, 100, 9, 4662);
    let server = rmule_primitives::ServerEndpoint::new("203.0.113.7", 4661).expect("endpoint");
    let download_id = crate::DownloadId::from_u64(4);
    let part_hash = |byte| rmule_primitives::PartHash::from_bytes([byte; 16]);
    vec![
        CoreEvent::Download(DownloadEvent::DownloadFailed {
            download_id,
            reason: crate::DownloadFailure::StorageIntegrityFailed(
                crate::StorageIntegrityFault::NoPartHolds {
                    recorded: 7,
                    first: crate::PartFault::HashMismatch {
                        part_index: 2,
                        expected: part_hash(0x11),
                        found: part_hash(0x22),
                    },
                },
            ),
        }),
        CoreEvent::Download(DownloadEvent::PartReleased {
            download_id,
            peer,
            part_index: 5,
            reason: crate::PartReleaseReason::PeerRetired(crate::PeerRetirementReason::SlotTimeout),
        }),
        CoreEvent::Serve(ServeEvent::FileWithheld {
            file_hash: file_hash(0xAB),
            reason: crate::WithheldReason::Unreadable(std::io::ErrorKind::PermissionDenied),
            since: std::time::SystemTime::UNIX_EPOCH,
        }),
        CoreEvent::Serve(ServeEvent::ServingFailed {
            reason: crate::ServeStartFailure::Bind(std::io::ErrorKind::AddrInUse),
        }),
        CoreEvent::Scan(ScanEvent::DirectoryRefused {
            dir: "/home/ann/films/new".into(),
            reason: crate::DirectoryRefusal::InsideShared {
                parent: "/home/ann/films".into(),
            },
        }),
        CoreEvent::ServerList(crate::ServerListEvent::ServerListUpdateStarted {
            url: "http://mirror.example/server.met".into(),
        }),
        CoreEvent::ServerList(crate::ServerListEvent::ServerListUpdateFailed {
            reason: crate::ServerListUpdateFailure::HttpStatus(404),
        }),
        CoreEvent::ServerConnection(ServerConnectionEvent::ReconnectEnded {
            server,
            reason: crate::ReconnectEnd::AttemptsSpent { attempts: 9 },
        }),
        CoreEvent::CommandRejected {
            reason: crate::CoreCommandRejectReason::KadUnavailable(
                crate::KadUnavailableReason::UdpUnbound {
                    port: 4672,
                    kind: std::io::ErrorKind::AddrInUse,
                },
            ),
        },
        CoreEvent::PeerReachRouted {
            peer,
            route: crate::PeerReachRoute::Buddy {
                buddy_id: crate::KadId::from_bytes([0x5A; 16]),
                emitted_to: Some(rmule_primitives::Ipv4Endpoint::new(
                    std::net::Ipv4Addr::new(198, 51, 100, 40),
                    4672,
                )),
            },
        },
        CoreEvent::NattTunnelRisen {
            peer,
            transport: crate::TunnelTransport::Utp,
            role: crate::PeerStreamRole::Dialer,
        },
        CoreEvent::ClientUdpBindFailed {
            port: 4672,
            kind: std::io::ErrorKind::AddrInUse,
        },
        CoreEvent::KadStopped {
            reason: crate::KadStopReason::TaskFailed,
        },
        CoreEvent::Quitting {
            step: crate::QuitStep::CreditCheckpoint,
        },
        CoreEvent::ObfuscationPolicyAtStart {
            policy: Some(crate::ObfuscationPolicy::Required),
        },
        CoreEvent::ObfuscationPolicyChanged { policy: None },
        CoreEvent::MappingReleaseKept {
            mapping: listener_row(),
            protocol: crate::port_mapping::MappingProtocol::Upnp,
            external_port: 4662,
            kept: crate::port_mapping::ReleaseKept::ForwardsElsewhere(peer_at(10, 77, 0, 5, 4662)),
        },
        CoreEvent::MappingReleaseKept {
            mapping: listener_row(),
            protocol: crate::port_mapping::MappingProtocol::Upnp,
            external_port: 53906,
            kept: crate::port_mapping::ReleaseKept::Unchecked(
                crate::port_mapping::MappingError::Refused {
                    protocol: crate::port_mapping::MappingProtocol::Upnp,
                    refusal: crate::port_mapping::MappingRefusal::UnknownCode(501),
                    hold_off: None,
                },
            ),
        },
    ]
}

/// The eD2k listener's IPv4 mapping row.
const fn listener_row() -> crate::port_mapping::DesiredMapping {
    crate::port_mapping::DesiredMapping {
        role: crate::SocketRole::Tcp,
        family: rmule_primitives::AddressFamily::V4,
        internal_port: 4662,
        pinhole: None,
    }
}

/// The bytes a fixed session's records leave in the file at `level`, each
/// line without its timestamp.
fn pinned_lines(level: Level) -> String {
    let events = session_events()
        .into_iter()
        .chain(login_events())
        .chain(reason_events());
    // A refused setting is no event; its record is written beside them.
    let refused = crate::SettingRefusal::DownloadDirRefused(crate::DirectoryRefusal::HomeDirectory);
    written(level, |handle| {
        write_each(events, handle);
        write(&refused.record(), handle.get());
    })
    .lines()
    .map(|line| line.split_once(' ').map_or(line, |(_, rest)| rest))
    .collect::<Vec<_>>()
    .join("\n")
}

/// What `pinned_lines` returns at the lean level.
const PINNED_LEAN: &str = r#" INFO run_log: server.connected server=203.0.113.7:4661 client_id=167772167
 INFO run_log: serve.serving_started listen_addr=203.0.113.5:4662
 INFO run_log: download.queued id=3
 INFO run_log: download.peer_selected id=3
 INFO run_log: serve.upload_slot_granted road=linked
 INFO run_log: scan.declined
 INFO run_log: identity.secured_mismatch
 INFO run_log: peer_reach.routed route=direct
 INFO run_log: search.results_received id=4611686018427387905 results=1
 INFO run_log: server.login server=203.0.113.7:4661 step=mapping_wait port=4662 settled=no
 INFO run_log: server.login server=203.0.113.7:4661 step=link_chosen link=obfuscated port=4673
 INFO run_log: server.login server=203.0.113.7:4661 step=login_sent family=ipv4 tcp_port=4662 client_udp_port=4665 kad_udp_port=4673 advertised_ipv6=2001:db8::5
 INFO run_log: server.login server=203.0.113.7:4661 step=port_test_awaited
 INFO run_log: server.login server=203.0.113.7:4661 step=port_test_arrived admission=test_connection
 INFO run_log: server.login server=203.0.113.7:4661 step=port_test_ended end=tester_closed
 INFO run_log: server.login server=203.0.113.7:4661 step=port_test_ended end=peer_connection_ended closed_by=peer
 INFO run_log: server.login server=203.0.113.7:4661 step=answered client_id=83915211 public_ip=203.0.113.5 compression=yes new_tags=no unicode=no related_search=no type_tag_integer=no large_files=yes tcp_obfuscation=no ipv6=no
 INFO run_log: server.login server=203.0.113.7:4661 step=port_test_window_closed arrived=yes
 INFO run_log: server.login server=203.0.113.7:4661 step=port_test_late late_by_ms=1250 admission=refused
 INFO run_log: server.login server=203.0.113.7:4661 step=reassigned client_id=10775 public_ip=refused_server_own reported=203.0.113.7 compression=no new_tags=no unicode=no related_search=no type_tag_integer=no large_files=no tcp_obfuscation=no ipv6=no
 INFO run_log: server.login server=192.0.2.44:4242 step=link_chosen link=obfuscated port=4254
 INFO run_log: server.login server=192.0.2.44:4242 step=dial_failed cause=crypt_handshake error=unexpected_eof os_code=none
 INFO run_log: server.login server=192.0.2.44:4242 step=link_chosen link=plain why=obfuscated_attempt_failed
 INFO run_log: server.login server=192.0.2.44:4242 step=dial_failed cause=os error=connection_refused os_code=61
 INFO run_log: peer_reach.routed route=direct
 INFO run_log: buddy.dial_failed cause=timed_out
 INFO run_log: kad.helper_test_late late_by_ms=3400 admission=refused
 INFO run_log: download.failed id=4 failure=storage_integrity_failed fault=no_part_holds recorded_parts=7 part_fault=hash_mismatch part_index=2
 INFO run_log: download.part_released id=4 part_index=5 reason=peer_retired retired=slot_timeout
 INFO run_log: serve.file_withheld reason=unreadable error=permission_denied os_code=none
 INFO run_log: serve.serving_failed reason=bind error=address_in_use os_code=none
 INFO run_log: shared_directory.refused reason=inside_shared
 INFO run_log: server_list.update_started
 INFO run_log: server_list.update_failed reason=http_status status=404
 INFO run_log: server.reconnect_ended server=203.0.113.7:4661 reason=attempts_spent attempts=9
 INFO run_log: command.rejected reason=kad_unavailable kad=udp_unbound port=4672 error=address_in_use os_code=none
 INFO run_log: peer_reach.routed route=buddy
 INFO run_log: natt.tunnel_risen transport=utp role=dialer
 INFO run_log: client_udp.bind_failed port=4672 error=address_in_use os_code=none
 INFO run_log: kad.stopped reason=task_failed
 INFO run_log: quit.step step=credit_checkpoint
 INFO run_log: obfuscation.policy policy=required
 INFO run_log: obfuscation.policy_changed policy=off
 INFO run_log: port_mapping.release_kept role=tcp family=ipv4 internal_port=4662 external_port=4662 kept=forwards_elsewhere protocol=upnp
 INFO run_log: port_mapping.release_kept role=tcp family=ipv4 internal_port=4662 external_port=53906 kept=unchecked protocol=upnp error=refused refusal=unknown_code refusal_code=501
 INFO run_log: setting.refused reason=download_dir_refused guard=home_directory"#;

/// What `pinned_lines` returns at the full level.
const PINNED_FULL: &str = r#" INFO run_log: server.connected server=203.0.113.7:4661 client_id=167772167
 INFO run_log: serve.serving_started listen_addr=203.0.113.5:4662
 INFO run_log: download.queued id=3 file_hash=ABABABABABABABABABABABABABABABAB name="secret holiday film.avi" size=734003200 file_path="/home/ann/films/secret holiday film.avi.part"
 INFO run_log: download.peer_selected id=3 peer=198.51.100.9:4662
 INFO run_log: serve.upload_slot_granted peer=198.51.100.9:4662 file_hash=ABABABABABABABABABABABABABABABAB road=linked software="amule" software_version="2.3.3"
 INFO run_log: scan.declined dir="/home/ann/private-share"
 INFO run_log: identity.secured_mismatch user_hash=CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD
 INFO run_log: peer_reach.routed peer=198.51.100.9:4662 route=direct dial=198.51.100.9:4662
 INFO run_log: search.results_received id=4611686018427387905 results=1
 INFO run_log: server.login server=203.0.113.7:4661 step=mapping_wait port=4662 settled=no
 INFO run_log: server.login server=203.0.113.7:4661 step=link_chosen link=obfuscated port=4673
 INFO run_log: server.login server=203.0.113.7:4661 step=login_sent family=ipv4 tcp_port=4662 client_udp_port=4665 kad_udp_port=4673 advertised_ipv6=2001:db8::5
 INFO run_log: server.login server=203.0.113.7:4661 step=port_test_awaited
 INFO run_log: server.login server=203.0.113.7:4661 step=port_test_arrived admission=test_connection
 INFO run_log: server.login server=203.0.113.7:4661 step=port_test_ended end=tester_closed
 INFO run_log: server.login server=203.0.113.7:4661 step=port_test_ended end=peer_connection_ended closed_by=peer
 INFO run_log: server.login server=203.0.113.7:4661 step=answered client_id=83915211 public_ip=203.0.113.5 compression=yes new_tags=no unicode=no related_search=no type_tag_integer=no large_files=yes tcp_obfuscation=no ipv6=no
 INFO run_log: server.login server=203.0.113.7:4661 step=port_test_window_closed arrived=yes
 INFO run_log: server.login server=203.0.113.7:4661 step=port_test_late late_by_ms=1250 admission=refused
 INFO run_log: server.login server=203.0.113.7:4661 step=reassigned client_id=10775 public_ip=refused_server_own reported=203.0.113.7 compression=no new_tags=no unicode=no related_search=no type_tag_integer=no large_files=no tcp_obfuscation=no ipv6=no
 INFO run_log: server.login server=192.0.2.44:4242 step=link_chosen link=obfuscated port=4254
 INFO run_log: server.login server=192.0.2.44:4242 step=dial_failed cause=crypt_handshake error=unexpected_eof os_code=none
 INFO run_log: server.login server=192.0.2.44:4242 step=link_chosen link=plain why=obfuscated_attempt_failed
 INFO run_log: server.login server=192.0.2.44:4242 step=dial_failed cause=os error=connection_refused os_code=61
 INFO run_log: peer_reach.routed peer=198.51.100.9:4662 route=direct dial=198.51.100.9:4662
 INFO run_log: buddy.dial_failed buddy=198.51.100.23:5731 cause=timed_out
 INFO run_log: kad.helper_test_late helper=198.51.100.31 late_by_ms=3400 admission=refused
 INFO run_log: download.failed id=4 failure=storage_integrity_failed fault=no_part_holds recorded_parts=7 part_fault=hash_mismatch part_index=2 expected=11111111111111111111111111111111 found=22222222222222222222222222222222
 INFO run_log: download.part_released id=4 peer=198.51.100.9:4662 part_index=5 reason=peer_retired retired=slot_timeout
 INFO run_log: serve.file_withheld file_hash=ABABABABABABABABABABABABABABABAB reason=unreadable error=permission_denied os_code=none
 INFO run_log: serve.serving_failed reason=bind error=address_in_use os_code=none
 INFO run_log: shared_directory.refused dir="/home/ann/films/new" reason=inside_shared parent="/home/ann/films"
 INFO run_log: server_list.update_started url="http://mirror.example/server.met"
 INFO run_log: server_list.update_failed reason=http_status status=404
 INFO run_log: server.reconnect_ended server=203.0.113.7:4661 reason=attempts_spent attempts=9
 INFO run_log: command.rejected reason=kad_unavailable kad=udp_unbound port=4672 error=address_in_use os_code=none
 INFO run_log: peer_reach.routed peer=198.51.100.9:4662 route=buddy buddy_id=5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A5A emitted_to=198.51.100.40:4672
 INFO run_log: natt.tunnel_risen peer=198.51.100.9:4662 transport=utp role=dialer
 INFO run_log: client_udp.bind_failed port=4672 error=address_in_use os_code=none
 INFO run_log: kad.stopped reason=task_failed
 INFO run_log: quit.step step=credit_checkpoint
 INFO run_log: obfuscation.policy policy=required
 INFO run_log: obfuscation.policy_changed policy=off
 INFO run_log: port_mapping.release_kept role=tcp family=ipv4 internal_port=4662 external_port=4662 kept=forwards_elsewhere protocol=upnp holder=10.77.0.5:4662
 INFO run_log: port_mapping.release_kept role=tcp family=ipv4 internal_port=4662 external_port=53906 kept=unchecked protocol=upnp error=refused refusal=unknown_code refusal_code=501
 INFO run_log: setting.refused reason=download_dir_refused guard=home_directory"#;

#[test]
fn a_fixed_session_writes_the_same_bytes_at_each_level() {
    assert_eq!(pinned_lines(Level::Lean), PINNED_LEAN);
    assert_eq!(pinned_lines(Level::Full), PINNED_FULL);
}
