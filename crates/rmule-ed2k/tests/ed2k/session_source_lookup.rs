//! Asking the server for sources: rejected before login, and after it the
//! opcode chosen by the obfuscation ladder both sides advertised.

use rmule_ed2k::{
    CommandRejectReason, Ed2kCommand, Ed2kCommandKind, Ed2kEvent, Ed2kSession, FoundSources,
    GetSourcesRequest, Output, ServerCapability, ServerTcpFlags,
};
use rmule_primitives::{
    Capabilities, ClientId, CryptStance, Packet, PeerSource, SourceClaim, SourceLookupTarget,
};

fn target(size: u64) -> SourceLookupTarget {
    SourceLookupTarget::new(crate::fixture::hash(0xAA), size)
}

#[test]
fn request_sources_before_login_emits_command_rejection() {
    let mut session = crate::fixture::started_session(0x42);

    session.handle_command(Ed2kCommand::RequestSources { target: target(42) });

    assert!(matches!(
        session.poll_output(),
        Some(Output::Event(Ed2kEvent::CommandRejected {
            command: Ed2kCommandKind::RequestSources,
            reason: CommandRejectReason::NotLoggedIn,
        }))
    ));
}

#[test]
fn request_server_list_before_login_emits_command_rejection() {
    let mut session = crate::fixture::started_session(0x42);

    session.handle_command(Ed2kCommand::RequestServerList);

    assert!(matches!(
        session.poll_output(),
        Some(Output::Event(Ed2kEvent::CommandRejected {
            command: Ed2kCommandKind::RequestServerList,
            reason: CommandRejectReason::NotLoggedIn,
        }))
    ));
}

fn crypt_supporting_session() -> Ed2kSession {
    crate::fixture::session(0x42)
        .with_capabilities(Capabilities::shipped(CryptStance::new(true, true, false)))
}

/// Emit the opcode of the source request `session` writes for `target`.
fn request_sources_opcode(session: &mut Ed2kSession, target: SourceLookupTarget) -> u8 {
    session.handle_command(Ed2kCommand::RequestSources { target });
    let Some(Output::Write(bytes)) = session.poll_output() else {
        panic!("expected source request write");
    };
    Packet::decode_exact(&bytes).unwrap().opcode()
}

#[test]
fn normal_request_sources_after_login_writes_get_sources() {
    let mut session = crate::fixture::started_session(0x42);
    crate::fixture::login_with_flags(&mut session, None);
    let expected = target(42);

    session.handle_command(Ed2kCommand::RequestSources { target: expected });

    let Some(Output::Write(bytes)) = session.poll_output() else {
        panic!("expected source request write");
    };
    let packet = Packet::decode_exact(&bytes).unwrap();
    assert_eq!(
        packet.opcode(),
        0x19,
        "no crypt stance → plain OP_GETSOURCES"
    );
    assert!(matches!(
        GetSourcesRequest::decode_packet(&packet).unwrap(),
        GetSourcesRequest::Normal { target } if target == expected
    ));
}

#[test]
fn obfu_request_only_when_server_and_client_are_both_crypt_capable() {
    // Server grants TCP obfuscation and rmule's stance supports crypt: request
    // the obfuscation-aware sources (`0x23`) so the server answers `0x44`.
    let mut both = crypt_supporting_session();
    crate::fixture::start(&mut both);
    crate::fixture::login_with_flags(
        &mut both,
        Some(ServerTcpFlags::from_bits(ServerTcpFlags::TCPOBFUSCATION)),
    );
    assert_eq!(request_sources_opcode(&mut both, target(42)), 0x23);

    // Server grants obfuscation but rmule's crypt is disabled: no point asking
    // for keys it will not use — plaintext `0x19` (matches aMule's
    // `IsClientCryptLayerSupported()` half of the gate).
    let mut client_off = crate::fixture::started_session(0x42);
    crate::fixture::login_with_flags(
        &mut client_off,
        Some(ServerTcpFlags::from_bits(ServerTcpFlags::TCPOBFUSCATION)),
    );
    assert_eq!(request_sources_opcode(&mut client_off, target(42)), 0x19);

    // rmule supports crypt but the server does not advertise it: plaintext
    // `0x19` (a `0x23` to such a server risks an unhandled opcode).
    let mut server_off = crypt_supporting_session();
    crate::fixture::start(&mut server_off);
    crate::fixture::login_with_flags(&mut server_off, None);
    assert_eq!(request_sources_opcode(&mut server_off, target(42)), 0x19);
}

#[test]
fn large_request_without_capability_is_rejected() {
    let mut session = crate::fixture::started_session(0x42);
    crate::fixture::login_with_flags(&mut session, None);

    session.handle_command(Ed2kCommand::RequestSources {
        target: target(u64::from(u32::MAX) + 1),
    });

    assert!(matches!(
        session.poll_output(),
        Some(Output::Event(Ed2kEvent::CommandRejected {
            command: Ed2kCommandKind::RequestSources,
            reason: CommandRejectReason::UnsupportedServerCapability {
                capability: ServerCapability::LargeFiles,
            },
        }))
    ));
}

#[test]
fn large_request_with_capability_writes_large_get_sources() {
    let mut session = crate::fixture::started_session(0x42);
    crate::fixture::login_with_flags(
        &mut session,
        Some(ServerTcpFlags::from_bits(ServerTcpFlags::LARGE_FILES)),
    );

    let large_target = target(u64::from(u32::MAX) + 1);
    session.handle_command(Ed2kCommand::RequestSources {
        target: large_target,
    });

    let Some(Output::Write(bytes)) = session.poll_output() else {
        panic!("expected source request write");
    };
    let packet = Packet::decode_exact(&bytes).unwrap();
    assert!(matches!(
        GetSourcesRequest::decode_packet(&packet).unwrap(),
        GetSourcesRequest::Large { target } if target == large_target
    ));
}

#[test]
fn inbound_found_sources_before_id_change_emits_event() {
    let mut session = crate::fixture::started_session(0x42);
    let source = PeerSource::new(ClientId::from_u32(ClientId::LOW_ID_THRESHOLD), 4662);
    let packet = FoundSources::new(crate::fixture::hash(0xBB), vec![source])
        .unwrap()
        .encode_packet();

    session.handle_bytes(&packet.encode());

    assert!(matches!(
        session.poll_output(),
        Some(Output::Event(Ed2kEvent::SourcesFound { file_hash, sources, .. }))
            if file_hash == crate::fixture::hash(0xBB) && sources == vec![SourceClaim::plain(source)]
    ));
}

/// The large form keys on aMule's `IsLargeFile`, strictly past
/// `OLD_MAX_FILE_SIZE`, which a `u32` still holds: the file one byte past it
/// is asked as large and only of a large-file server
/// (`DownloadQueue.cpp:1083-1098`).
#[test]
fn a_file_one_byte_past_old_max_file_size_is_asked_in_the_large_form() {
    let old_max = rmule_primitives::OLD_MAX_FILE_SIZE;
    let mut session = crate::fixture::started_session(0x42);
    crate::fixture::login_with_flags(
        &mut session,
        Some(ServerTcpFlags::from_bits(ServerTcpFlags::LARGE_FILES)),
    );
    let mut asked = |size| {
        session.handle_command(Ed2kCommand::RequestSources {
            target: target(size),
        });
        let Some(Output::Write(bytes)) = session.poll_output() else {
            panic!("expected source request write");
        };
        GetSourcesRequest::decode_packet(&Packet::decode_exact(&bytes).unwrap()).unwrap()
    };
    assert!(matches!(asked(old_max), GetSourcesRequest::Normal { .. }));
    assert!(matches!(
        asked(old_max + 1),
        GetSourcesRequest::Large { .. }
    ));

    let mut plain = crate::fixture::started_session(0x42);
    crate::fixture::login_with_flags(&mut plain, None);
    plain.handle_command(Ed2kCommand::RequestSources {
        target: target(old_max + 1),
    });
    assert!(matches!(
        plain.poll_output(),
        Some(Output::Event(Ed2kEvent::CommandRejected {
            command: Ed2kCommandKind::RequestSources,
            reason: CommandRejectReason::UnsupportedServerCapability {
                capability: ServerCapability::LargeFiles,
            },
        }))
    ));
}
