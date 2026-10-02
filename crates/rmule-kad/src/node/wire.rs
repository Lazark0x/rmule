//! The datagram boundary: inbound bytes to a dispatched message and outbound
//! messages to bytes. Receive walks the dual plaintext/obfuscated path,
//! recovers crypt provenance, flood-limits by `(IP, opcode)` and dispatches by
//! opcode; send picks the key aMule would (ADR-0046) and pushes the datagram
//! into the output queue.

use std::net::Ipv4Addr;

use rmule_primitives::{
    ClientDecryptKeys, ClientEncryptKey, DatagramNonce, decrypt_datagram_client,
    encrypt_datagram_client,
};

use super::{KadEvent, KadNode, KadNodeDiagnostic, KadOutput, ReceivedKey, VerifyKeyState};
use crate::buddy::is_buddy_opcode;
use crate::flood::{DNS_CONFUSION_PORT, FloodVerdict};
use crate::messages::Kad2Message;
use crate::net;
use crate::reachability::{KADEMLIA2_FIREWALLUDP, is_firewall_check_req, is_firewall_check_res};
use crate::{
    KadContact, KadDecoded, KadEnvelope, KadId, KadInstant, KadNodeEndpoint, decode_exact,
    opcode::{
        KADEMLIA2_HELLO_RES, KADEMLIA2_PUBLISH_KEY_REQ, KADEMLIA2_PUBLISH_NOTES_REQ,
        KADEMLIA2_SEARCH_KEY_REQ, KADEMLIA2_SEARCH_NOTES_REQ, KADEMLIA2_SEARCH_RES,
    },
};

/// The crypt family an outbound Kad datagram rides (ADR-0046 key matrix).
pub(super) enum OutboundFamily {
    /// Keyed on the recipient's handed-out verify key (handler replies).
    Verify(u32),
    /// Keyed on a stored crypt-era contact's Kad ID.
    Node(KadId),
}

/// The key an outbound Kad datagram would be encrypted under, with the
/// `<receiverVerifyKey><senderVerifyKey>` trailer it would carry (`0` = empty).
pub(super) struct OutboundKey {
    pub(super) family: OutboundFamily,
    pub(super) receiver_verify_key: u32,
    pub(super) sender_verify_key: u32,
}

impl KadNode {
    /// The lowest contact version aMule will encrypt toward: obfuscation
    /// shipped with Kad version 6 (eMule 0.49a), and every own-initiated send
    /// goes plaintext below it — `SendMyDetails` asserts `targetKey.IsEmpty()`
    /// and passes `NULL` (`KademliaUDPListener.cpp#L152`), `SendNullPacket` and
    /// `Bootstrap` gate on the same `>= 6`. Encrypting toward an older contact
    /// would hand it a datagram it can never decrypt.
    const MIN_CRYPT_CONTACT_VERSION: u8 = 6;

    /// Enable per-datagram UDP send-obfuscation (ADR-0046). Once enabled,
    /// outbound datagrams are RC4-encrypted per aMule's key-choice matrix
    /// (`obfuscate_outbound`): NodeID-keyed toward a stored v≥6 contact,
    /// receiver-key-keyed for handler replies. Receive stays dual-path
    /// regardless (a crypt datagram keyed on this node's own Kad ID always
    /// decrypts, plaintext always dispatches).
    ///
    /// `nonce` injects the per-packet entropy (marker byte, 2-byte key seed,
    /// padding) the sans-I/O node cannot draw itself; production supplies an
    /// OS-entropy source from the driver, a test a fixed one — the seam the
    /// status-ping sweep uses. Default-off: the node is plaintext until its
    /// owner arms it — `rmule-core` does whenever its one obfuscation policy
    /// (`CoreConfig::peer_crypt`) is set.
    pub fn enable_datagram_obfuscation(&mut self, nonce: fn() -> DatagramNonce) {
        self.outbound_obfuscation = Some(nonce);
    }

    /// Arm the Kad UDP verify-key state (ADR-0046 keys; ADR-0064's
    /// verification cluster activates on it): `secret` is the private
    /// per-installation derivation seed, `public_ip` this node's current
    /// public address. The secret is **caller-supplied**: `rmule-core` passes
    /// its persisted **Kad UDP Key**, the way aMule persists
    /// `s_dwKadUDPKey` across restarts (`/Obfuscation/CryptoKadUDPKey`,
    /// defaulted to one `GetRandomUint32()`), while the single-run
    /// `kad-join-node` mints one per run — a fresh secret each run invalidates
    /// every key peers learned for us, forcing the network back through the
    /// three-way.
    ///
    /// From here the node derives per-IP [`udp_verify_key`](crate::udp_verify_key)s: it offers the
    /// receiver-key decrypt family, judges every inbound trailer for
    /// `validReceiverKey`, stores counterparties' sender keys on their
    /// contacts (bound to `public_ip`), trails
    /// `<receiverVerifyKey><senderVerifyKey>` on obfuscated sends, and answers
    /// `0x22` ack-requests. Re-arm on an IP change: keys learned under the old
    /// address silently retire ([`KadUdpKey::key_value`](crate::KadUdpKey::key_value) collapses to `0`),
    /// exactly aMule's posture.
    ///
    /// Unarmed (the default), the node is plaintext-faithful to a keyless
    /// aMule: no verification fires and no `0x22` is answered.
    pub fn enable_verify_keys(&mut self, secret: u32, public_ip: Ipv4Addr) {
        self.own_public_ip = Some(public_ip);
        self.verify_keys = Some(VerifyKeyState { secret, public_ip });
        self.routing.set_own_public_ip(public_ip);
    }

    /// Move the public IP the verify-key state is bound to:
    /// aMule re-reads `theApp->GetPublicIP()` on every send
    /// (`CPrefs::GetUDPVerifyKey`, `Prefs.cpp:235-243` takes only the
    /// *target's* IP, never our own — the own key this node hands a target
    /// via `own_verify_key_for` is unaffected by
    /// this call). What our own IP binds is the other half: a
    /// counterparty's *learned* key, stored as `(key, our IP at learn time)`
    /// (aMule's `CKadUDPKey`, `KadUDPKey.h`). Moving it here is
    /// `enable_verify_keys`'s own "re-arm on an IP change" documented for —
    /// every stored [`KadUdpKey::key_value`](crate::KadUdpKey::key_value)
    /// evaluated at the old address now reads `0`, exactly aMule's
    /// `GetKeyValue(myIP)` collapsing the moment `myIP` moves, and the next
    /// send toward that contact goes out unkeyed until a fresh three-way
    /// re-learns it.
    ///
    /// The verify-key half is a no-op while crypt is unarmed:
    /// [`enable_verify_keys`](Self::enable_verify_keys) never ran, so there is
    /// no verify-key state to move and no stored key reads `own_public_ip`
    /// yet. The address itself is kept either way, for the UDP check's "not
    /// ourselves" rule (`UDPFirewallTester.cpp:272-276`).
    pub fn set_own_public_ip(&mut self, public_ip: Ipv4Addr) {
        self.own_public_ip = Some(public_ip);
        let Some(state) = self.verify_keys.as_mut() else {
            return;
        };
        state.public_ip = public_ip;
        self.routing.set_own_public_ip(public_ip);
    }

    /// Process one inbound datagram.
    pub fn handle_datagram(&mut self, now: KadInstant, from: KadNodeEndpoint, bytes: &[u8]) {
        // Dual-path receive (ADR-0046), always on like aMule's
        // `DecryptReceivedClient`: a known plaintext Kad marker (`0xE4`/`0xE5`)
        // bypasses decryption, any other first byte is trial-decrypted keyed on
        // this node's own Kad ID (and, once armed, its own UDP verify key). A hit
        // yields the recovered plaintext Kad datagram; a miss (garbage, or a
        // datagram for another node's key) falls through to plaintext decode,
        // which then diagnoses it — byte-for-byte aMule's decrypt-then-plain
        // fall-back.
        //
        // This runs **before** the ADR-0064 entry gates because gate 1 (the
        // DNS-confusion guard) is itself sender-key-conditional: aMule decrypts
        // in the socket, then drops a port-53 datagram only when it arrived
        // without a sender key.
        let decrypted = decrypt_datagram_client(bytes, &self.datagram_decrypt_keys(from.ip()));
        // Crypt provenance for the verification handlers (ADR-0064): our own
        // derived key for this sender's IP judges the trailer's receiver key.
        let received_key = ReceivedKey::of(decrypted.as_ref(), self.own_verify_key_for(from.ip()));

        // ADR-0064 entry gate 1: the DNS-confusion guard
        // (`KademliaUDPListener.cpp#L216`) — a source-port-53 datagram with no
        // sender key is dropped before anything else. A keyed one is exempt (it
        // cannot be a confused DNS reply), which is the activation the plaintext
        // drop-all-port-53 posture was standing in for (`flood.rs`).
        if from.udp_port() == DNS_CONFUSION_PORT && received_key.sender_key.is_none() {
            self.emit_diagnostic(KadNodeDiagnostic::Port53Dropped { from });
            return;
        }

        let plain = decrypted.as_ref().map_or(bytes, |d| d.payload.as_slice());
        let envelope = match decode_exact(plain) {
            // A packed datagram is already inflated to its logical plain twin.
            Ok(KadDecoded::Plain(envelope) | KadDecoded::Packed(envelope)) => envelope,
            Err(error) => {
                self.emit_diagnostic(KadNodeDiagnostic::UndecodableEnvelope { from, error });
                return;
            }
        };

        // ADR-0064 entry gate 2: the per-(IP, opcode) leaky flood limiter,
        // LAN-exempt like the publish-tolerance gate. An untracked opcode —
        // every response, solicitation correlation owns those — always
        // admits without allocating a bucket.
        if !net::is_lan_ip(from.ip()) {
            let opcode = envelope.opcode();
            if let FloodVerdict::Drop { offender } = self.flood.gate(now, from.ip(), opcode) {
                self.emit_diagnostic(KadNodeDiagnostic::FloodLimited { from, opcode });
                if offender {
                    self.emit_event(KadEvent::FloodOffenderDetected {
                        ip: from.ip(),
                        opcode,
                    });
                }
                return;
            }
        }

        // Past both ADR-0064 entry gates, this is a well-formed Kad datagram from
        // a non-DNS, non-flooded source: stamp last-contact (aMule's
        // `SetLastContact`), so `HasHadContact` — the network-joined predicate
        // (ADR-0067) — holds for the next 20 min. Every opcode counts, not only
        // ones that add a contact, so an unsolicited-but-valid answer still keeps
        // the node connected. The silent→heard edge is surfaced as
        // [`KadEvent::HadContact`]: the join observable a driver's
        // diagnostics report, emitted on the transition rather than per
        // datagram.
        let was_joined = self.routing.has_had_contact(now);
        self.routing.note_contact(now);
        if !was_joined {
            self.emit_event(KadEvent::HadContact { from });
        }

        // aMule replies to a request under the *requester's own* sender key
        // (every `Process*` handler passes its `senderKey` straight into
        // `SendPacket`), which is how a stranger's request — one whose sender is
        // in no routing table — still draws an obfuscated answer. Scope that key
        // to this dispatch and to this endpoint; `dispatch_datagram` owns the
        // handler fan-out so the key is cleared on every path out.
        self.reply_key = received_key.sender_key.map(|key| (from, key));
        self.dispatch_datagram(now, from, &envelope, received_key);
        self.reply_key = None;
        // aMule's `CUDPFirewallTester::Connected()` runs for every received
        // packet (`KademliaUDPListener.cpp:254`). After dispatch, so a first
        // datagram's sender is already a seed the lookup can walk from.
        self.launch_udp_helper_lookup(now);
    }

    /// Route one gate-passed, decoded datagram to its handler.
    ///
    /// Separate from [`handle_datagram`](Self::handle_datagram) so the
    /// per-datagram reply key has exactly one scope: the caller sets it, calls
    /// this, and clears it, so no handler's early return can leave a key armed
    /// for the next datagram.
    fn dispatch_datagram(
        &mut self,
        now: KadInstant,
        from: KadNodeEndpoint,
        envelope: &KadEnvelope,
        received_key: ReceivedKey,
    ) {
        // Search results route through the sealed projection boundary
        // (`decode_source_result`), not the node-maintenance codec. A keyword
        // result rides the same `0x3B`; `on_search_res` disambiguates by the
        // owning walk (ADR-0062).
        if envelope.opcode() == KADEMLIA2_SEARCH_RES {
            self.on_search_res(now, from, envelope);
            return;
        }
        // Firewall self-check requests (`0x50`/`0x53`) route to the reachability
        // responder (ADR-0058), not the node-maintenance codec.
        if is_firewall_check_req(envelope.opcode()) {
            self.on_firewall_check_req(now, from, envelope);
            return;
        }
        // Firewall self-check responses (`0x58`/`0x59`) feed our own requester
        // cycle (ADR-0058 requester); like the requests, they are not
        // node-maintenance messages.
        if is_firewall_check_res(envelope.opcode()) {
            self.on_firewall_check_res(now, from, envelope);
            return;
        }
        // The UDP firewall-check result (`0x62`) feeds our own UDP tester
        // (ADR-0058 requester, breakdown 3) — like the TCP checks, decoded before
        // the node-maintenance codec, and unrequested unless our check is armed.
        if envelope.opcode() == KADEMLIA2_FIREWALLUDP {
            self.on_firewall_udp_result(now, from, envelope);
            return;
        }
        // Buddy / callback rows (`0x51`/`0x5A`/`0x52`, ADR-0061): the Kad-UDP
        // codec, self-contained from the node-maintenance surface exactly like the
        // firewall cluster above. The node decodes and consumes; the buddy-slot and
        // relay *decisions* the events feed are core-side.
        if is_buddy_opcode(envelope.opcode()) {
            self.on_buddy_message(now, from, envelope);
            return;
        }
        // Keyword layer requests (ADR-0062): the storer's accept (`0x43`) and
        // serve (`0x33`) route to the keyword store's own codec, the same
        // before-`Kad2Message::decode` split the firewall checks use — so both
        // stay self-contained from the node-maintenance surface. The notes
        // layer's `0x45`/`0x35` (ADR-0063 Empty-Storer Parity) join the same
        // split, self-contained in exactly the same way.
        match envelope.opcode() {
            KADEMLIA2_PUBLISH_KEY_REQ => {
                self.on_publish_key_req(now, from, envelope);
                return;
            }
            KADEMLIA2_SEARCH_KEY_REQ => {
                self.on_search_key_req(now, from, envelope);
                return;
            }
            KADEMLIA2_PUBLISH_NOTES_REQ => {
                self.on_publish_notes_req(from, envelope);
                return;
            }
            KADEMLIA2_SEARCH_NOTES_REQ => {
                self.on_search_notes_req(from, envelope);
                return;
            }
            _ => {}
        }
        let message = match Kad2Message::decode(envelope) {
            Ok(message) => message,
            Err(error) => {
                self.emit_diagnostic(KadNodeDiagnostic::UndecodableMessage { from, error });
                return;
            }
        };

        match message {
            Kad2Message::BootstrapReq => self.on_bootstrap_req(from),
            Kad2Message::BootstrapRes { sender, contacts } => {
                self.on_bootstrap_res(now, from, sender, contacts);
            }
            Kad2Message::HelloReq(info) => self.on_hello_req(now, from, &info, received_key),
            Kad2Message::HelloRes(info) => self.on_hello_res(now, from, &info, received_key),
            Kad2Message::HelloResAck { id } => self.on_hello_res_ack(from, id, received_key),
            Kad2Message::Ping => self.send(
                from,
                &Kad2Message::Pong {
                    udp_port: from.udp_port(),
                },
            ),
            Kad2Message::Pong { udp_port } => self.on_kad_pong(now, from, udp_port),
            Kad2Message::LookupReq {
                count,
                target,
                check,
            } => self.on_lookup_req(from, count, target, check),
            Kad2Message::LookupRes { target, contacts } => {
                self.on_lookup_res(now, from, target, &contacts);
            }
            Kad2Message::SearchSourceReq {
                target,
                start_position,
                file_size,
            } => self.on_search_source_req(now, from, target, start_position, file_size),
            Kad2Message::PublishSourceReq {
                file,
                source_id,
                source,
            } => self.on_publish_source_req(now, from, file, source_id, &source),
            Kad2Message::PublishRes {
                file,
                load,
                options,
            } => self.on_publish_res(now, from, file, load, options),
        }
    }

    /// The crypt sender key the datagram under dispatch handed us, if it came
    /// from `from` — the ADR-0062 `0x4C` gate and the ADR-0064 role-B `0x22`
    /// gate read the same provenance (aMule's one `senderKey` parameter).
    pub(super) fn crypt_sender_key(&self, from: KadNodeEndpoint) -> Option<u32> {
        self.reply_key
            .filter(|&(at, _)| at == from)
            .map(|(_, key)| key)
    }

    pub(super) fn send(&mut self, to: KadNodeEndpoint, message: &Kad2Message) {
        self.send_envelope(to, &message.encode());
    }

    pub(super) fn send_envelope(&mut self, to: KadNodeEndpoint, envelope: &KadEnvelope) {
        let bytes = self.obfuscate_outbound(to, envelope.opcode(), envelope.encode());
        self.outputs.push_back(KadOutput::Datagram { to, bytes });
    }

    /// Encrypt (or leave plain) a datagram under an explicit verify key,
    /// bypassing the reply/contact matrix [`obfuscate_outbound`] applies —
    /// the shape the **UDP Firewall Helper**'s `0x62` answer needs:
    /// aMule keys it on the value the `0xA7` request carried and
    /// nothing else, never a stored contact's NodeID —
    /// `ProcessFirewallCheckUDPRequest` passes `NULL` for `cryptTargetID`
    /// unconditionally (`BaseClient.cpp:4008-4013`), and
    /// `CKadUDPKey(senderKey, ourIP).GetKeyValue(ourIP)` is `senderKey`
    /// verbatim — the key is constructed and unwrapped against the same IP
    /// (`KadUDPKey.h`). `verify_key == 0` (the request carried none) sends
    /// plaintext, matching `CMuleUDPSocket::SendPacket`'s
    /// `bKad && nReceiverVerifyKey != 0` encrypt gate
    /// (`MuleUDPSocket.cpp:271-274`); so does an unarmed
    /// [`outbound_obfuscation`](Self::enable_datagram_obfuscation) regardless
    /// of `verify_key`, exactly as every other send stays plaintext until a
    /// driver arms it.
    ///
    /// [`obfuscate_outbound`]: Self::obfuscate_outbound
    pub(super) fn send_envelope_keyed(
        &mut self,
        to: KadNodeEndpoint,
        envelope: &KadEnvelope,
        verify_key: u32,
    ) {
        let bytes = match (self.outbound_obfuscation, verify_key) {
            (Some(nonce), key) if key != 0 => encrypt_datagram_client(
                &envelope.encode(),
                &ClientEncryptKey::KadVerify {
                    verify_key: key,
                    receiver_verify_key: key,
                    sender_verify_key: self.own_verify_key_for(to.ip()).unwrap_or(0),
                },
                &nonce(),
            ),
            _ => envelope.encode(),
        };
        self.outputs.push_back(KadOutput::Datagram { to, bytes });
    }

    /// Encrypt an outbound datagram when send-obfuscation is enabled, following
    /// aMule's key-choice matrix (`EncryptedDatagramSocket.cpp#L260`,
    /// `MuleUDPSocket.cpp#L237`, emit sites in `KademliaUDPListener.cpp`):
    ///
    /// - **receiver-key family** for handler replies: aMule answers every
    ///   `Process*` under the packet's `senderKey` with no crypt-target ID —
    ///   `SendPacket(…, senderKey, NULL)` at the bootstrap-res (`#L479`),
    ///   `0x22` (`#L618`), lookup-res (`#L682`), publish-res (`#L1085`), pong
    ///   (`#L1526`) and firewall (`#L1360`) sites — so even a stored contact is
    ///   answered on this family (the genuine captured aMule `0x22` pins family
    ///   bits 2 while aMule held us as a contact). Sole exception: `HELLO_RES`
    ///   rides `SendMyDetails` with the requester's just-parsed ID (`#L150`)
    ///   and stays NodeID-keyed.
    /// - **NodeID family** for own-initiated sends to a stored contact of
    ///   version ≥ [`Self::MIN_CRYPT_CONTACT_VERSION`] — the key every
    ///   crypt-era Kad node necessarily holds; below v6 aMule sends plaintext.
    /// - **plaintext** when neither applies — nothing to encrypt under.
    ///
    /// Both Kad families carry the 8-byte trailer: `receiver_verify_key` is the
    /// key the recipient handed *us* (echoed back so it reads
    /// `validReceiverKey`, the whole IP proof) — on a reply the *dispatch's
    /// fresh* key, never the stored one (aMule threads `senderKey` straight
    /// into `SendPacket`, echoed via `targetKey.GetKeyValue` at `#L1599`; a
    /// peer that restarted onto a new secret must get its NEW key back, or it
    /// reads `validReceiverKey = false` and burns an extra three-way until the
    /// stale entry ages) — else the stored contact key. `sender_verify_key` is
    /// *our* key for the recipient's IP, freshly derived per send exactly as
    /// aMule does (`GetUDPVerifyKey(item.IP)` at flush time).
    pub(super) fn obfuscate_outbound(
        &self,
        to: KadNodeEndpoint,
        opcode: u8,
        plain: Vec<u8>,
    ) -> Vec<u8> {
        let (Some(nonce), Some(outbound)) =
            (self.outbound_obfuscation, self.outbound_key(to, opcode))
        else {
            return plain;
        };
        let OutboundKey {
            family,
            receiver_verify_key,
            sender_verify_key,
        } = outbound;
        let key = match &family {
            OutboundFamily::Verify(verify_key) => ClientEncryptKey::KadVerify {
                verify_key: *verify_key,
                receiver_verify_key,
                sender_verify_key,
            },
            OutboundFamily::Node(id) => ClientEncryptKey::KadNode {
                kad_id: id.as_bytes(),
                receiver_verify_key,
                sender_verify_key,
            },
        };
        encrypt_datagram_client(&plain, &key, &nonce())
    }

    /// The key a datagram to `to` would be encrypted under right now — the
    /// matrix [`obfuscate_outbound`](Self::obfuscate_outbound) applies — or
    /// `None` when it would go out plaintext (send-obfuscation unarmed, or
    /// nothing to key on). The `0x22` three-way reads it before sending
    /// An ack-request is only meaningful in a datagram whose
    /// trailer carries our sender key, and an ACK only when its trailer echoes
    /// the requester's key — a plaintext one is dropped as "invalid receiver
    /// key" by every reference.
    pub(super) fn outbound_key(&self, to: KadNodeEndpoint, opcode: u8) -> Option<OutboundKey> {
        self.outbound_obfuscation?;
        let contact = self.routing.contacts().find(|c| c.endpoint() == to);
        let reply_key = self.reply_key.filter(|&(at, _)| at == to).map(|(_, k)| k);
        let stored_key = contact
            .map(|c| {
                self.verify_keys
                    .map_or(0, |state| c.udp_key().key_value(state.public_ip))
            })
            .filter(|&key| key != 0);
        // Fresh dispatch key first, stored key as fallback (see the doc above).
        let receiver_verify_key = reply_key.or(stored_key).unwrap_or(0);
        let sender_verify_key = self.own_verify_key_for(to.ip()).unwrap_or(0);
        // NodeID keying wants a crypt-era contact: a v<6 peer could never
        // decrypt (aMule's `SendMyDetails`/`SendNullPacket` `>= 6` gates).
        let contact_id = contact
            .filter(|c| c.version() >= Self::MIN_CRYPT_CONTACT_VERSION)
            .map(KadContact::id);
        let family = match reply_key {
            // A handler reply — except the NodeID-keyed hello res — rides the
            // receiver-key family regardless of any stored contact.
            Some(verify_key) if !(opcode == KADEMLIA2_HELLO_RES && contact_id.is_some()) => {
                OutboundFamily::Verify(verify_key)
            }
            _ => OutboundFamily::Node(contact_id?),
        };
        Some(OutboundKey {
            family,
            receiver_verify_key,
            sender_verify_key,
        })
    }

    /// The keys this node offers the dual-path receive: its own Kad ID (the
    /// `KadNodeId` family) and, once armed, its own UDP verify key for the
    /// sender's IP (the `KadVerifyKey` family — how a peer that only holds our
    /// handed-out key reaches us). The ed2k user-hash family belongs to the
    /// peer-UDP socket, not this Kad one, so it is deliberately absent.
    fn datagram_decrypt_keys(&self, sender_ip: Ipv4Addr) -> ClientDecryptKeys<'_> {
        ClientDecryptKeys {
            kad_id: Some(self.config.id.as_bytes()),
            receiver_verify_key: self.own_verify_key_for(sender_ip),
            ..Default::default()
        }
    }
}
