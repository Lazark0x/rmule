//! End-to-end Secure User Identification through the whole Core stack
//! (ADR-0041): the Core loads its keypair once at build from the
//! store it is given (ADR-0048 "Identity ownership"), the real
//! `RuntimePeerTransferService` dials with SUI, and by the
//! time the download completes each side has proven itself to the other —
//! rmule binds the peer as a **Secured Identity** in its credit store, and the
//! peer observed rmule's proof. Asymmetric keys and user hashes per side keep
//! a flipped signing direction detectable.

use crate::fixture::serving_started;
use rmule_core::DurableCreditStore;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;

use rmule_core::{
    AppConfigStore, Core, CoreCommand, CoreConfig, CoreEvent, CreditStore,
    DEFAULT_SLOT_WAIT_TIMEOUT, DownloadCommand, DownloadEvent, DownloadFailure, DurableAppConfig,
    RuntimePeerTransferService, ServeCommand, SourceLookupOutcome, SourceLookupService,
};
use rmule_net::peer::{ConnectOptions, Connection, PeerListener};
use rmule_peer::{
    ConnectionEvent, PartBitmap, PeerCommand, PeerEvent, PeerHandshakeContext, SecureIdentConfig,
    ServerCommand, ServerEvent,
};
use rmule_primitives::{
    ClientId, ClientIdentity, Ed2kFileLink, Ed2kText, FileHashSummary, PeerEndpoint, PeerSource,
    SecureIdentKey, ServerEndpoint, SourceLookupTarget, SourceSighting, UserHash, part_count,
};
use rmule_testkit::{PendingSourceLookup, RefusingPeerTransfer};

const FILE_BYTES: usize = 4096; // sub-part file: one block

#[derive(Clone)]
struct OneSourceLookup {
    peer: PeerSource,
}
impl SourceLookupService for OneSourceLookup {
    async fn lookup_sources(
        &mut self,
        _target: SourceLookupTarget,
    ) -> Result<SourceLookupOutcome, DownloadFailure> {
        Ok(SourceLookupOutcome {
            client_id: ClientId::from_u32(0x0100_007F),
            sources: vec![SourceSighting::plain(self.peer)],
        })
    }
}

/// Serve `bytes` once over an accepted SUI-enabled connection, answering the
/// requester probe steps, and report whether the dialer's Secure User
/// Identification proof was observed (with the dialer's hash + key DER).
async fn serve_once_with_sui(
    listener: PeerListener,
    key: Arc<SecureIdentKey>,
    bytes: Vec<u8>,
) -> Option<(UserHash, Vec<u8>)> {
    let ctx = PeerHandshakeContext {
        identity: rmule_testkit::test_identity(0x0B, "sui-loopback-peer", 4662),
        client_id: ClientId::from_u32(0x0100_007F),
        ed2k_client_id: ClientId::from_u32(0x0100_007F),
        public_ip: None,
        connected_server: None,
    };
    let options = ConnectOptions {
        secure_ident: Some(SecureIdentConfig {
            key,
            challenge: 0xB00B_0003,
        }),
        ..ConnectOptions::default()
    };
    let mut conn = listener.accept(ctx, options).await.ok()?;
    let mut verified = None;
    while let Some(event) = conn.next_event().await {
        match event {
            PeerEvent::Connection(ConnectionEvent::IdentityVerified {
                user_hash,
                public_key,
            }) => verified = Some((user_hash, public_key)),
            PeerEvent::Server(ServerEvent::FileRequested { file_hash, .. }) => {
                let _ = conn
                    .send(PeerCommand::Server(ServerCommand::AnswerFileName {
                        file_hash,
                        file_name: Ed2kText::from_utf8("loopback.bin"),
                    }))
                    .await;
            }
            PeerEvent::Server(ServerEvent::FileBundleRequested {
                file_hash, asks, ..
            }) => {
                for ask in asks {
                    let command = match ask {
                        rmule_peer::BundledAsk::Name { .. } => {
                            PeerCommand::Server(ServerCommand::AnswerFileName {
                                file_hash,
                                file_name: Ed2kText::from_utf8("loopback.bin"),
                            })
                        }
                        rmule_peer::BundledAsk::SetReqId => {
                            PeerCommand::Server(ServerCommand::AnswerFileStatus {
                                file_hash,
                                bitmap: PartBitmap::decode(part_count(bytes.len() as u64), &[0xFF])
                                    .unwrap(),
                            })
                        }
                        _ => continue,
                    };
                    let _ = conn.send(command).await;
                }
            }
            PeerEvent::Server(ServerEvent::FileIdSet { file_hash }) => {
                let bitmap = PartBitmap::decode(part_count(bytes.len() as u64), &[0xFF]).unwrap();
                let _ = conn
                    .send(PeerCommand::Server(ServerCommand::AnswerFileStatus {
                        file_hash,
                        bitmap,
                    }))
                    .await;
            }
            PeerEvent::Server(ServerEvent::HashSetRequested { file_hash }) => {
                let _ = conn
                    .send(PeerCommand::Server(ServerCommand::AnswerHashSet {
                        file_hash,
                        part_hashes: Vec::new(),
                    }))
                    .await;
            }
            PeerEvent::Server(ServerEvent::SlotRequested { file_hash }) => {
                let _ = conn
                    .send(PeerCommand::Server(ServerCommand::GrantSlot { file_hash }))
                    .await;
            }
            PeerEvent::Server(ServerEvent::PartsRequested { file_hash, ranges }) => {
                for &(start, end) in ranges.as_array().iter().filter(|(s, e)| e > s) {
                    let _ = conn
                        .send(PeerCommand::Server(ServerCommand::SendBlock {
                            file_hash,
                            start,
                            end,
                            bytes: bytes[start as usize..end as usize].to_vec(),
                        }))
                        .await;
                }
            }
            PeerEvent::Connection(ConnectionEvent::Disconnected { .. }) => break,
            _ => {}
        }
    }
    verified
}

/// The SUI acceptance loopback: a real download over real sockets with
/// SUI on both ends. rmule's side ends with the peer bound as a **Secured
/// Identity** in the credit store; the peer's side observed rmule's proof,
/// made with the Core's key.
#[tokio::test]
async fn a_sui_download_binds_both_identities_end_to_end() {
    sui_download(DialAdapter::Woven).await;
}

/// A dial adapter handed to `CoreBuilder::peer_transfer(..)` states
/// the builder's Hello Adverts — before, it kept an empty set of its own and
/// this download dialed without SUI, so the peer saw no proof at all.
#[tokio::test]
async fn a_builder_injected_dial_adapter_proves_with_the_core_s_key() {
    sui_download(DialAdapter::Injected).await;
}

/// Which dial adapter [`sui_download`]'s core runs.
enum DialAdapter {
    /// `Core::builder`'s own.
    Woven,
    /// A fresh `RuntimePeerTransferService` handed to `.peer_transfer(..)`.
    Injected,
}

async fn sui_download(dial: DialAdapter) {
    let output_dir = tempfile::tempdir().expect("temp dir");
    let store = rmule_testkit::memory_store();
    let key_rmule = the_core_s_key(&store);
    let key_peer = Arc::new(SecureIdentKey::generate().unwrap());
    let rmule_public = key_rmule.public_key_der();
    let peer_public = key_peer.public_key_der();
    let peer_hash = UserHash::from_bytes([0x0B; UserHash::BYTE_LEN]);

    let bytes = vec![0x5A_u8; FILE_BYTES];
    let summary = FileHashSummary::digest_bytes(&bytes);

    let listener = PeerListener::bind(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let bound = SocketAddrV4::new(Ipv4Addr::LOCALHOST, listener.local_port());
    let peer_task = tokio::spawn(serve_once_with_sui(
        listener,
        Arc::clone(&key_peer),
        bytes.clone(),
    ));

    // The listener's High-ID source: its IPv4 as an LE u32 client id + port.
    let source = PeerSource::new(
        ClientId::from_u32(u32::from_le_bytes(bound.ip().octets())),
        bound.port(),
    );
    let credit = DurableCreditStore::new(store.clone());
    let config = CoreConfig::default();
    let builder = Core::builder(config, store)
        .settings(rmule_testkit::in_download_dir(
            rmule_core::CoreSettings::default(),
            output_dir.path(),
        ))
        .user_hash(UserHash::from_bytes([0x01; UserHash::BYTE_LEN]))
        .source_lookup(OneSourceLookup { peer: source });
    let mut core = match dial {
        DialAdapter::Woven => builder.build(),
        DialAdapter::Injected => builder
            .peer_transfer(RuntimePeerTransferService::new(DEFAULT_SLOT_WAIT_TIMEOUT))
            .build(),
    };

    core.send(CoreCommand::Download(DownloadCommand::StartDownload {
        file: Ed2kFileLink {
            name: Ed2kText::from_utf8("loopback.bin"),
            size: FILE_BYTES as u64,
            file_hash: summary.file_hash(),
            part_hash_set: None,
            aich_root: None,
            ipv6_sources: Vec::new(),
            sources: Default::default(),
        },
        source_hint: Some(ServerEndpoint::new("127.0.0.1", 4661).unwrap()),
        name: rmule_testkit::file_name("loopback.bin"),
        if_taken: rmule_core::NameTaken::Refuse,
    }))
    .await
    .unwrap();

    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        while let Some(event) = core.next_event().await {
            match event {
                CoreEvent::Download(DownloadEvent::DownloadCompleted { .. }) => return,
                CoreEvent::Download(DownloadEvent::DownloadFailed { reason, .. }) => {
                    panic!("download failed: {reason}")
                }
                _ => {}
            }
        }
    })
    .await
    .expect("download completed within 10s");

    // rmule bound the peer's proven key as its Secured Identity.
    assert_eq!(
        credit.public_key(peer_hash).unwrap(),
        Some(peer_public),
        "the peer must be a Secured Identity in rmule's credit store"
    );

    // The peer observed rmule's proof — rmule's hash under rmule's key.
    let peer_saw = tokio::time::timeout(std::time::Duration::from_secs(5), peer_task)
        .await
        .expect("peer side finished within 5s")
        .unwrap()
        .expect("the peer verified rmule's identity");
    assert_eq!(peer_saw.0, UserHash::from_bytes([0x01; UserHash::BYTE_LEN]));
    assert_eq!(peer_saw.1, rmule_public);
}

/// The serve-side half of ADR-0041: an inbound peer that dials a
/// *serving* rmule and completes SUI becomes a Secured Identity in the serving
/// core's credit ledger — the production accept path (`RuntimeServeRuntimeService`)
/// runs the exchange, so upload-queue credit cannot be claimed by a spoofed
/// User Hash. Distinct keys and hashes per side, as everywhere in this file.
#[tokio::test]
async fn an_inbound_sui_peer_becomes_a_secured_identity_on_the_serving_side() {
    let store = rmule_testkit::memory_store();
    let key_server = the_core_s_key(&store); // serving rmule
    let key_dialer = Arc::new(SecureIdentKey::generate().unwrap()); // inbound peer
    let dialer_public = key_dialer.public_key_der();
    let dialer_hash = UserHash::from_bytes([0x0D; UserHash::BYTE_LEN]);

    let credit = DurableCreditStore::new(store.clone());
    let mut core = Core::builder(CoreConfig::default(), store)
        .settings(rmule_core::CoreSettings {
            udp_port: free_udp_port(),
            ..rmule_core::CoreSettings::default()
        })
        .user_hash(UserHash::from_bytes([0x01; UserHash::BYTE_LEN]))
        .source_lookup(PendingSourceLookup)
        .peer_transfer(RefusingPeerTransfer)
        // The woven production serve adapter: its accept pump reads the Hello
        // Adverts the builder loaded the keypair into.
        .build();
    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
    }))
    .await
    .unwrap();
    let listen = serving_started(&mut core).await;
    // A later credentialed start: before, the last start's key
    // won and one carrying none cleared it. No command carries a key now, so
    // the accept pump still proves with the Core's.
    core.send(CoreCommand::EnableKad(crate::fixture::kad_enable_config()))
        .await
        .unwrap();

    // An inbound peer dials with its own keypair and holds the connection open
    // while the exchange completes.
    let dial_task = tokio::spawn(async move {
        let ctx = PeerHandshakeContext {
            identity: ClientIdentity::new(
                dialer_hash,
                Ed2kText::from_utf8("sui-inbound-peer"),
                4662,
                60,
            ),
            client_id: ClientId::from_u32(0x0100_007F),
            ed2k_client_id: ClientId::from_u32(0x0100_007F),
            public_ip: None,
            connected_server: None,
        };
        let options = ConnectOptions {
            secure_ident: Some(SecureIdentConfig {
                key: key_dialer,
                challenge: 0xB00B_0004,
            }),
            ..ConnectOptions::default()
        };
        let peer = PeerEndpoint::V4(rmule_primitives::Ipv4Endpoint::new(
            *listen.ip(),
            listen.port(),
        ));
        let mut conn = Connection::connect(peer, ctx, options).await.unwrap();
        // Report whether we verified the serving core, then hold until closed.
        let mut verified_server = None;
        loop {
            match tokio::time::timeout(std::time::Duration::from_secs(5), conn.next_event()).await {
                Ok(Some(PeerEvent::Connection(ConnectionEvent::IdentityVerified {
                    user_hash,
                    public_key,
                }))) => verified_server = Some((user_hash, public_key)),
                Ok(Some(PeerEvent::Connection(ConnectionEvent::Disconnected { .. })))
                | Ok(None)
                | Err(_) => break,
                Ok(Some(_)) => {}
            }
        }
        verified_server
    });

    // The serving core binds the dialer's proven key. Poll the shared store
    // while draining serve events (binding emits no event on success).
    let bound = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            tokio::select! {
                event = core.next_event() => {
                    if let Some(CoreEvent::SecuredIdentityMismatch { .. }) = event {
                        panic!("unexpected mismatch for a fresh identity");
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {
                    if let Some(key) = credit.public_key(dialer_hash).unwrap() {
                        return key;
                    }
                }
            }
        }
    })
    .await
    .expect("the serving side bound the inbound peer within 10s");
    assert_eq!(
        bound, dialer_public,
        "the inbound peer's exact key DER is its Secured Identity"
    );

    drop(core); // closes the listener; the dialer's loop ends
    let verified_server = dial_task.await.unwrap();
    let (server_hash, server_key) =
        verified_server.expect("the inbound peer verified the serving core");
    assert_eq!(
        server_hash,
        UserHash::from_bytes([0x01; UserHash::BYTE_LEN])
    );
    assert_eq!(server_key, key_server.public_key_der());
}

/// A Kad-only node — Kad enabled, never serving — proves itself on
/// its ADR-0058 firewall-check dial-back like any other hello: the keypair is
/// the Core's from build, not a serve start's (aMule lights the
/// nibble on every hello, `BaseClient.cpp:1508`, `:1522-1529`).
#[tokio::test]
async fn a_kad_only_node_s_dial_back_hello_carries_sui() {
    let udp_port = free_udp_port();
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings {
            udp_port,
            ..rmule_core::CoreSettings::default()
        })
        .build();
    core.send(CoreCommand::EnableKad(crate::fixture::kad_enable_config()))
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            core.send(CoreCommand::DumpDiagnostics).await.unwrap();
            if let Some(CoreEvent::DiagnosticsSnapshot { snapshot }) = core.next_event().await
                && snapshot.kad.is_some()
            {
                return;
            }
        }
    })
    .await
    .expect("Kad started within 10s");
    let drain = tokio::spawn(async move { while core.next_event().await.is_some() {} });

    // A v7+ requester asks for a TCP check: `0x53` naming the port it listens
    // on, its User Hash, and no crypt (`<tcpport 2><userhash 16><options 1>`).
    let requester = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let mut request = vec![0xE4, 0x53];
    request.extend_from_slice(&requester.local_addr().unwrap().port().to_le_bytes());
    request.extend_from_slice(&[0xB3; UserHash::BYTE_LEN]);
    request.push(0);
    let udp = tokio::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    udp.send_to(&request, (Ipv4Addr::LOCALHOST, udp_port))
        .await
        .unwrap();

    let (mut stream, _) =
        tokio::time::timeout(std::time::Duration::from_secs(5), requester.accept())
            .await
            .expect("the dial-back arrives within 5s")
            .unwrap();
    let hello = first_hello_tags(&mut stream).await;
    assert_eq!(
        rmule_peer::MiscOptions1::from_tags(&hello)
            .map(rmule_peer::MiscOptions1::secure_identification_version),
        Some(3),
        "the dial-back's MiscOptions1 advertises SUI v1 and v2",
    );
    drain.abort();
}

/// The keypair a Core built over `store` proves with: the store's generate-once
/// row, which `Core::builder` loads.
fn the_core_s_key(store: &Arc<rmule_core::DurableStore>) -> Arc<SecureIdentKey> {
    Arc::new(
        DurableAppConfig::new(Arc::clone(store))
            .ensure_secure_ident_key()
            .unwrap(),
    )
}

/// A UDP port free right now, for a Core whose Kad node binds it.
fn free_udp_port() -> u16 {
    let probe = std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    probe.local_addr().unwrap().port()
}

/// Read one plaintext hello frame off `stream` and return its tags.
async fn first_hello_tags(stream: &mut tokio::net::TcpStream) -> Vec<rmule_primitives::Tag> {
    use tokio::io::AsyncReadExt;
    let mut header = [0u8; 5];
    stream.read_exact(&mut header).await.unwrap();
    let len = u32::from_le_bytes(header[1..].try_into().unwrap()) as usize;
    let mut frame = header.to_vec();
    frame.resize(header.len() + len, 0);
    stream.read_exact(&mut frame[header.len()..]).await.unwrap();
    let packet = rmule_primitives::Packet::decode_exact(&frame).unwrap();
    rmule_peer::Hello::decode_packet(&packet)
        .unwrap()
        .into_body()
        .tags
}
