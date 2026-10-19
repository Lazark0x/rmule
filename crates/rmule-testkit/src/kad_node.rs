//! The shared vocabulary of the sans-I/O `KadNode` tests: the node under test,
//! the endpoints and identities it talks to, and the readers that turn its
//! output queue into messages, events or diagnostics. Every helper is
//! explicit-time — the caller stamps the instant.

use std::net::Ipv4Addr;

use rmule_primitives::{
    ClientDecryptKeys, ClientEncryptKey, DatagramNonce, decrypt_datagram_client,
    encrypt_datagram_client,
};

use rmule_kad::{
    Kad2Message, Kad2NodeInfo, KadCommand, KadEvent, KadId, KadInstant, KadNode, KadNodeConfig,
    KadNodeDiagnostic, KadNodeEndpoint, KadNodeStart, KadObfuscation, KadOutput, KadProtocol,
    KadSelfCheck, udp_verify_key,
};
use rmule_primitives::session::drain;

/// The instant every fixture stamps unless a leg is testing time itself —
/// explicit-time means the caller owns the clock, so one shared zero keeps
/// deltas readable.
pub const T0: KadInstant = KadInstant::EPOCH;

/// A Kad ID of one repeated byte — legible in a failure message, and far
/// enough apart in XOR distance that `id(0x01)` and `id(0x02)` never collide
/// in a bucket assertion.
pub fn id(byte: u8) -> KadId {
    KadId::from_bytes([byte; KadId::BYTE_LEN])
}

/// Counterparty `host`'s address, `45.55.<host>.1`: fake-public, and alone in
/// its /24.
///
/// Fake-public because the publish-tolerance gates and the flood limiter wave
/// a LAN address through. Alone in its /24 because the routing table admits
/// at most two contacts per /24 in a bucket and ten across the table
/// (ADR-0064): counterparties sharing one /24 would be refused as soon as a
/// third landed in one bucket. The address space is the fake-public plan's
/// (the interop harness's `45.55` slot); every Kad leg is sans-I/O, so no
/// datagram to it leaves the process.
pub const fn host_ip(host: u8) -> Ipv4Addr {
    Ipv4Addr::new(45, 55, host, 1)
}

/// Counterparty `host`'s endpoint at `port` (its address is [`host_ip`]).
pub const fn endpoint(host: u8, port: u16) -> KadNodeEndpoint {
    KadNodeEndpoint::new(host_ip(host), port)
}

/// The default config of the node under test: ID `0xAA…`, the default eD2k/Kad
/// port pair.
pub fn node_config() -> KadNodeConfig {
    KadNodeConfig {
        id: id(0xAA),
        tcp_port: 4662,
        udp_port: 4672,
        user_hash: rmule_kad::UserHash::from_bytes([0xEE; 16]),
    }
}

/// The node under test: [`node_config`], routing-only and plaintext (see
/// [`crypt_node`] for the keyed posture).
pub fn node() -> KadNode {
    KadNode::new(start())
}

/// The start-up value of [`node`], for a test that adds to it.
pub fn start() -> KadNodeStart {
    KadNodeStart::new(node_config(), T0)
}

/// A [`node`] running its own firewall self-check (ADR-0058) from [`T0`].
pub fn self_checking_node() -> KadNode {
    KadNode::new(start().self_check(KadSelfCheck::new()))
}

/// A v8 contact record for `id_byte`. `udp_port_tag` present means the peer
/// advertised its UDP port in the tag — the fact that decides whether we may
/// reach it by datagram at all.
pub fn info(id_byte: u8, udp_port_tag: Option<u16>) -> Kad2NodeInfo {
    Kad2NodeInfo {
        id: id(id_byte),
        tcp_port: 4761,
        version: 8,
        udp_port_tag,
        misc_options: 0,
    }
}

/// Hand `message` to the node as it would arrive on the wire — encoded, then
/// framed — so the decode path is exercised rather than bypassed.
pub fn deliver(node: &mut KadNode, now: KadInstant, from: KadNodeEndpoint, message: &Kad2Message) {
    node.handle_datagram(now, from, &message.encode().encode());
}

/// The datagrams among `outputs`, decoded back to messages. Panics if the
/// node emitted bytes that are not a valid plain envelope — a malformed emit
/// is a node bug, not a test condition; see [`datagrams`] for the raw view.
pub fn sent_messages(outputs: &[KadOutput]) -> Vec<(KadNodeEndpoint, Kad2Message)> {
    outputs
        .iter()
        .filter_map(|output| match output {
            KadOutput::Datagram { to, bytes } => {
                let rmule_kad::KadDecoded::Plain(envelope) =
                    rmule_kad::decode_exact(bytes).expect("node emits valid envelopes")
                else {
                    panic!("the node emits plain envelopes only");
                };
                Some((
                    *to,
                    Kad2Message::decode(&envelope).expect("node emits valid messages"),
                ))
            }
            KadOutput::Event(_) => None,
        })
        .collect()
}

/// The events among `outputs`, in emission order, with the datagrams dropped.
pub fn events(outputs: &[KadOutput]) -> Vec<KadEvent> {
    outputs
        .iter()
        .filter_map(|output| match output {
            KadOutput::Event(event) => Some(event.clone()),
            KadOutput::Datagram { .. } => None,
        })
        .collect()
}

/// The diagnostics among `outputs` — the node's own account of why it did
/// what it did, which is how a refusal is asserted when nothing is emitted.
pub fn diagnostics(outputs: &[KadOutput]) -> Vec<KadNodeDiagnostic> {
    diagnostics_of(&events(outputs))
}

/// The diagnostics among events a caller already has in hand — the same filter
/// as [`diagnostics`], for a leg that split the outputs itself.
pub fn diagnostics_of(events: &[KadEvent]) -> Vec<KadNodeDiagnostic> {
    events
        .iter()
        .filter_map(|event| match event {
            KadEvent::Diagnostic(diagnostic) => Some(*diagnostic),
            _ => None,
        })
        .collect()
}

/// Bootstrap a node against a responder at `responder_endpoint` with the given
/// row contacts, returning the outputs of processing the response.
pub fn bootstrapped(
    node: &mut KadNode,
    responder: Kad2NodeInfo,
    responder_endpoint: KadNodeEndpoint,
    rows: Vec<rmule_kad::KadContact>,
) -> Vec<KadOutput> {
    node.handle_command(
        T0,
        KadCommand::Bootstrap {
            endpoint: responder_endpoint,
        },
    );
    drain(|| node.poll_output());
    deliver(
        node,
        T0,
        responder_endpoint,
        &Kad2Message::BootstrapRes {
            sender: responder,
            contacts: rows,
        },
    );
    drain(|| node.poll_output())
}

/// The raw `(endpoint, bytes)` datagrams a node emitted, kept unparsed — the
/// firewall `0x58` responses are not `Kad2Message`s.
pub fn datagrams(outputs: &[KadOutput]) -> Vec<(KadNodeEndpoint, Vec<u8>)> {
    outputs
        .iter()
        .filter_map(|output| match output {
            KadOutput::Datagram { to, bytes } => Some((*to, bytes.clone())),
            KadOutput::Event(_) => None,
        })
        .collect()
}

/// The node's own intern Kad UDP port ([`node`]'s `udp_port`).
pub const OUR_INTERN_UDP: u16 = 4672;

// --- verify-key vocabulary (ADR-0064) ----------------------------------------

/// [`node`]'s own Kad ID as a constant — needed by the datagram-crypt helpers,
/// which key on the receiver's ID before a node value exists.
pub const NODE_ID: KadId = KadId::from_bytes([0xAA; KadId::BYTE_LEN]);

/// The node's verify-key derivation secret — aMule's
/// `thePrefs::GetKadUDPKey()`. Half of the state
/// [`KadObfuscation::with_verify_keys`] arms; [`OWN_IP`] is the other half.
pub const SECRET: u32 = 0x5EED_1234;
/// The public IP the node believes it has. A verify key is derived from the
/// *peer's* IP and this secret, so the pair must be fixed for a key to be
/// reproducible across a test.
pub const OWN_IP: Ipv4Addr = Ipv4Addr::new(198, 51, 100, 4);

/// A node that obfuscates its sends under [`fixed_nonce`] with verify-key
/// checking armed ([`SECRET`], [`OWN_IP`]): every request it sends carries a
/// key, every reply it accepts must echo one back, and it asks for and answers
/// a `0x22` (ADR-0064) — the ACK's proof is a key carried in the crypt trailer.
pub fn crypt_node() -> KadNode {
    KadNode::new(crypt_start())
}

/// The start-up value of [`crypt_node`], for a test that adds to it.
pub fn crypt_start() -> KadNodeStart {
    start().obfuscation(KadObfuscation::new(fixed_nonce).with_verify_keys(SECRET, OWN_IP))
}

/// [`sent_messages`] for a [`crypt_node`]: every datagram opened the way the
/// recipient `peer` would — under its Kad ID (the NodeID family a stored
/// contact's `HELLO_RES` rides), under the verify key it handed us (`handed`,
/// the family a handler reply rides), or as plaintext.
///
/// # Panics
/// On an obfuscated datagram neither key opens: `peer` would drop it, so a
/// mis-keyed send fails the leg instead of being read as if it were plain. A
/// datagram led by a Kad protocol byte is plaintext; an obfuscated one never
/// starts with one.
pub fn opened_messages(
    outputs: &[KadOutput],
    peer: KadId,
    handed: Option<u32>,
) -> Vec<(KadNodeEndpoint, Kad2Message)> {
    let keys = ClientDecryptKeys {
        kad_id: Some(peer.as_bytes()),
        receiver_verify_key: handed,
        ..Default::default()
    };
    let opened: Vec<KadOutput> = outputs
        .iter()
        .map(|output| match output {
            KadOutput::Datagram { to, bytes } => KadOutput::Datagram {
                to: *to,
                bytes: if bytes
                    .first()
                    .copied()
                    .and_then(KadProtocol::from_byte)
                    .is_some()
                {
                    bytes.clone()
                } else {
                    decrypt_datagram_client(bytes, &keys)
                        .unwrap_or_else(|| {
                            panic!("no key {peer:?} holds opens the obfuscated datagram to {to:?}")
                        })
                        .payload
                },
            },
            KadOutput::Event(_) => output.clone(),
        })
        .collect();
    sent_messages(&opened)
}

/// The verify key our node hands `peer` — what a counterparty must echo back in
/// the receiver-key slot for `validReceiverKey` to hold.
pub fn our_key_for(peer: KadNodeEndpoint) -> u32 {
    udp_verify_key(SECRET, peer.ip())
}

/// The contact record a peer introduces itself with, with `version` and
/// `misc_options` left to the caller — the two fields that decide which
/// capabilities (crypt, direct callback) the exchange may use.
pub fn hello(id: KadId, endpoint: KadNodeEndpoint, version: u8, misc_options: u8) -> Kad2NodeInfo {
    Kad2NodeInfo {
        id,
        tcp_port: 4662,
        version,
        udp_port_tag: Some(endpoint.udp_port()),
        misc_options,
    }
}

/// A pinned obfuscation nonce. Encryption draws randomness; pinning it is what
/// makes an encrypted datagram a byte-comparable golden.
pub fn fixed_nonce() -> DatagramNonce {
    DatagramNonce {
        marker_byte: 0x40,
        random_key: 0xB19E,
        padding: vec![0xA5, 0x5A, 0x11],
    }
}

/// Encrypt a plaintext Kad datagram to the node under the KadNodeId family with
/// an explicit verify-key trailer — the shape aMule's `SendMyDetails` puts on
/// the wire (NodeID-keyed hello, keys riding the trailer).
pub fn crypt_to_node(plain: &[u8], receiver_verify_key: u32, sender_verify_key: u32) -> Vec<u8> {
    encrypt_datagram_client(
        plain,
        &ClientEncryptKey::KadNode {
            kad_id: NODE_ID.as_bytes(),
            receiver_verify_key,
            sender_verify_key,
        },
        &fixed_nonce(),
    )
}

/// Poll the node until its output queue is empty — the sans-I/O driver's job,
/// done by hand.
pub fn drain_outputs(node: &mut KadNode) -> Vec<KadOutput> {
    rmule_primitives::session::drain(|| node.poll_output())
}

/// Bootstrap the node against `responder` so a hello probe toward it is
/// outstanding (the role-B precondition: only a *solicited* HELLO_RES is
/// consumed).
pub fn solicit_hello_res(node: &mut KadNode, responder: KadNodeEndpoint, responder_id: KadId) {
    node.handle_command(
        T0,
        KadCommand::Bootstrap {
            endpoint: responder,
        },
    );
    let _ = drain_outputs(node);
    node.handle_datagram(
        T0,
        responder,
        &Kad2Message::BootstrapRes {
            sender: Kad2NodeInfo {
                id: responder_id,
                tcp_port: 4662,
                version: 8,
                udp_port_tag: None,
                misc_options: 0,
            },
            contacts: vec![],
        }
        .encode()
        .encode(),
    );
    let _ = drain_outputs(node);
}

// --- datagrams a counterparty sends us ---------------------------------------

/// The bytes of a `HELLO_REQ` announcing `id` at `endpoint` — what a v8 peer
/// introduces itself with, and the cheapest way to seat a contact as
/// responded without driving a probe round trip.
pub fn hello_req_from(id: KadId, endpoint: KadNodeEndpoint) -> Vec<u8> {
    hello_req_at_version(id, endpoint, 8)
}

/// [`hello_req_from`] from a peer at Kad `version` — a storer whose answers
/// a searcher reads by its version (`TAG_KADAICHHASHRESULT` from v9 on).
pub fn hello_req_at_version(id: KadId, endpoint: KadNodeEndpoint, version: u8) -> Vec<u8> {
    Kad2Message::HelloReq(Kad2NodeInfo {
        id,
        tcp_port: 4662,
        version,
        udp_port_tag: Some(endpoint.udp_port()),
        misc_options: 0,
    })
    .encode()
    .encode()
}

/// The bytes of a `LOOKUP_RES` handing back `contacts` for `target` — the
/// answer every walk (source, keyword, notes) advances on.
pub fn lookup_res_bytes(target: KadId, contacts: &[rmule_kad::KadContact]) -> Vec<u8> {
    Kad2Message::LookupRes {
        target,
        contacts: contacts.to_vec(),
    }
    .encode()
    .encode()
}
