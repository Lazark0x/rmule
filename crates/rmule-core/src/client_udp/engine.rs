//! The socket-owning demux front of the one client-UDP socket (ADR-0057),
//! the server-UDP engine's sibling over a deliberately disjoint protocol set:
//! one task drains the transport, runs the armed dual-path crypt receive
//! (ADR-0046), classifies each plaintext datagram by its leading protocol
//! byte (`0xC5` peer-UDP; `0xB2` NAT-T transport; `0xE4`/`0xE5` Kad), and
//! routes peer-UDP by opcode — the reask ping to the serve reply matrix, the
//! reask reply quartet to the Remote-Queued Pool, the `0x94` buddy relay
//! through the held buddy link, the `0x95` direct callback and the standalone
//! `0xA0` rendezvous to the **firewalled front**, and the `0xA1`/`0xAA` NAT-T
//! signalling to the **NAT-T Front**'s inbox beside the `0xB2` frames it
//! drives.
//!
//! The Kad arms are the socket unification ADR-0057 promised: an eMule-family
//! client runs Kad and client-UDP on one UDP socket, so the running node's
//! datagrams arrive here and leave by this same bind. A leading byte **no**
//! protocol claims goes to the Kad inlet too, once the peer-UDP key has
//! missed: an obfuscated Kad datagram opens with the sender's random marker
//! byte, and only the node's own key families can tell it from junk.
//!
//! It is also where the **family ruling** is enacted — the parent module's
//! table (ADR-0087). The transport hands every datagram up in the family it
//! truly arrived in, so the crypt layout is selected rather than guessed, and
//! the one opcode whose relay cannot name an IPv6 requester is dropped and
//! counted here at the driver rather than truncated downstream.

use std::future::Future;

use rmule_kad::KadId;
use std::time::Instant;

use rmule_peer::natt::{EndpointHint, RendezvousBody};
use rmule_peer::{ClientUdpOpcode, ReaskCallbackUdp};
use rmule_primitives::{DatagramSenderAddress, Ipv4Endpoint, PacketProtocol, PeerEndpoint};
use tokio::sync::mpsc;

use super::peer_crypt::PeerUdpCrypt;
use super::{ClientUdpDatagram, ClientUdpSend, SharedKadInlet};
use crate::buddy_link::{RendezvousRelay, SharedBuddySlot};
use crate::diagnostics::DiagnosticsState;
use crate::firewalled::front::{
    SharedFirewalledFront, route_direct_callback, route_standalone_rendezvous,
};

#[cfg(test)]
mod tests;

/// eMule `OP_KADEMLIAHEADER` (`0xE4`): a plaintext Kad2 datagram.
const KAD_PROTOCOL: u8 = 0xE4;

/// eMule `OP_KADEMLIAPACKEDPROT` (`0xE5`): a zlib-packed Kad2 datagram.
const KAD_PACKED_PROTOCOL: u8 = 0xE5;

/// How certain the front is that a datagram is Kad — which is what decides
/// whether an IPv6 one is *counted* as a dialect gap or merely dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KadForm {
    /// A leading `0xE4`/`0xE5`: Kad by its protocol byte, whatever follows.
    Declared,
    /// A byte no protocol claims, after the peer-UDP key missed — possibly
    /// obfuscated Kad, possibly noise. Only the node's keys can say.
    Possible,
}

/// How many demuxed reask pings (and, separately, reask replies) an inbox
/// buffers before the front drops one (the actor-channel depth used across
/// `service`). Never awaited, for the reason [`NATT_INBOX_CAPACITY`] states:
/// the `0x90` inbox is parked unpolled whenever no serve activity runs, so an
/// awaiting send would let any sender of seventeen spoofable pings stall
/// every protocol on this socket.
const INBOX_CAPACITY: usize = 16;

/// How many NAT-T datagrams the **NAT-T Front**'s inbox holds before one is
/// dropped. Deep, and drained with `try_send` rather than awaited, for the
/// reason `rmule_net::natt`'s own inject queue is (`INJECT_QUEUE_LEN`): a
/// datagram queue must never back-pressure a socket every reask and every Kad
/// datagram shares. A full inbox costs one frame — which is what a lossy UDP
/// path does anyway, and uTP retransmits — never a stalled front.
const NATT_INBOX_CAPACITY: usize = 256;

/// Where the leading protocol byte routes a (plaintext) client-UDP datagram
/// (aMule `CClientUDPSocket::OnPacketReceived`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClientUdpRoute {
    /// `OP_EMULEPROT` (`0xC5`): a peer-UDP datagram — the reask quartet and the
    /// callback opcodes.
    PeerUdp,
    /// `OP_UDPRESERVEDPROT2` (`0xB2`): a NAT-T transport frame (ADR-0091) —
    /// uTP, QUIC, CAPS or KEY. Carried in **both** Address Families: ADR-0046's
    /// whitelist amendment states the rule, and no `0xB2` body names an
    /// address, so there is nothing a family could make unreadable.
    Natt,
    /// `0xE4`: a plaintext Kad2 datagram.
    Kad,
    /// `0xE5`: a zlib-packed Kad2 datagram (inflate, then Kad).
    KadPacked,
    /// A leading byte no client-UDP protocol claims — a server-UDP `0xE3`, a
    /// packed-ed2k `0xD4`, junk… **or an obfuscated Kad datagram**, whose
    /// first byte is the sender's random marker.
    ///
    /// The peer-UDP dual-path receive has already run and missed by the time
    /// this verdict is read, so what is left is either foreign or keyed to a
    /// family this surface holds no key for. Only [`KadNode`]'s own keys — the
    /// Kad-ID and receiver-verify families — can tell the two apart, so the
    /// datagram goes to the Kad inlet and the node's **magic-value check** is
    /// what rejects it (aMule `CEncryptedDatagramSocket::DecryptReceivedClient`
    /// tries the key families in turn and accepts only on the magic value).
    ///
    /// [`KadNode`]: rmule_kad::KadNode
    Unclaimed,
    /// Shorter than the two-byte `[protocol][opcode]` header — no packet in
    /// any protocol, and too short to carry a crypt header either.
    Undersized,
}

/// Classify one already-plaintext datagram by its leading protocol byte. A
/// datagram shorter than the two-byte `[protocol][opcode]` header carries no
/// packet and is dropped (aMule's `size >= 2` gate).
pub(crate) fn demux_protocol(datagram: &[u8]) -> ClientUdpRoute {
    if datagram.len() < 2 {
        return ClientUdpRoute::Undersized;
    }
    match datagram[0] {
        b if b == PacketProtocol::Emule.as_byte() => ClientUdpRoute::PeerUdp,
        rmule_peer::natt::NATT_PROTOCOL => ClientUdpRoute::Natt,
        KAD_PROTOCOL => ClientUdpRoute::Kad,
        KAD_PACKED_PROTOCOL => ClientUdpRoute::KadPacked,
        _ => ClientUdpRoute::Unclaimed,
    }
}

/// Whether `datagram` is shaped like an obfuscated one — long enough for the
/// eight-byte crypt header (marker, random key, sync, pad length) and not
/// opening with a plaintext marker, which the crypt receive passes through.
fn bears_crypt_header(datagram: &[u8]) -> bool {
    datagram.len() >= 8 && !rmule_primitives::is_udp_plaintext_marker(datagram[0])
}

/// The receive seam of the shared client-UDP socket — what the demux front
/// drains, mirroring [`ServerUdpTransport`](crate::adapters)'s `recv`. The
/// front only receives; a reply rides the serve task's `client_udp` send half
/// back to the datagram's UDP source (the `SendClientUdp` decision). The
/// production impl is [`RuntimeClientUdpTransport`](crate::adapters) over the
/// one bound socket.
pub(crate) trait ClientUdpTransport: Send + Sync + 'static {
    fn recv(&self) -> impl Future<Output = Option<ClientUdpDatagram>> + Send;
}

/// The demuxed inboxes [`ClientUdpEngine::new`] hands out, one per consuming
/// concern that runs outside the front.
pub(crate) struct ClientUdpInboxes {
    /// `OP_REASKFILEPING` (`0x90`) → the serve activity's reply matrix
    /// (ADR-0057 uploader side). The reply rides the same transport back to
    /// the datagram's UDP source.
    pub(crate) reask_ping: mpsc::Receiver<ClientUdpDatagram>,
    /// `OP_REASKACK` / `OP_FILENOTFOUND` / `OP_QUEUEFULL` (`0x91`/`0x92`/`0x93`)
    /// → the downloader's **Remote-Queued Pool** (ADR-0057 downloader side).
    /// Tagged with the source's UDP endpoint, the reply-routing key the
    /// pool matches a pooled source on (aMule `FindClientByIP_UDP`); the pool
    /// decodes and consumes it via `RemoteQueuedPool::on_reply_datagram`.
    pub(crate) reask_reply: mpsc::Receiver<ClientUdpDatagram>,
    /// Everything the **NAT-T Front** (`crate::natt::front`) drives: every
    /// `0xB2` transport frame, plus the `0xC5` `0xA1` holepunch trigger and the
    /// `0xC5` `0xAA` endpoint hint. One inbox rather than three because one
    /// task owns all three ledgers — the requester's, the punched paths' and
    /// the tunnel registry's — and splitting the feed would only let those
    /// ledgers observe the same instant in a different order.
    pub(crate) natt: mpsc::Receiver<ClientUdpDatagram>,
    /// A second way into the `0x90` inbox above, for the one consumer that
    /// produces a reask ping without a datagram ever arriving: the firewalled
    /// front, re-entering the reply matrix with the tail its buddy relayed
    /// over TCP (ADR-0061, aMule's own `ProcessPacket(..., OP_REASKFILEPING,
    /// destip, destport)`). One shape reaches `ServeState` either way.
    ///
    /// **Weak**, for the reason [`SharedTunnelAdmit`]'s accept sender is: this
    /// front's own sender closing is what tells the serve task the socket is
    /// gone, and a strong clone parked in another task would keep that signal
    /// from ever firing.
    ///
    /// [`SharedTunnelAdmit`]: crate::adapters::SharedTunnelAdmit
    pub(crate) reask_ping_injector: mpsc::WeakSender<ClientUdpDatagram>,
}

/// The socket-owning demux front. Construction hands out one inbox per
/// consuming concern; [`run`](Self::run) is spawned once and ends when the
/// transport closes, dropping every inbox sender so consumers wind down — the
/// server-UDP engine's shape.
pub(crate) struct ClientUdpEngine<T> {
    transport: T,
    /// The armed peer-UDP crypt layer for the dual-path receive (ADR-0046), or
    /// `None` — the default, with no `CoreConfig::peer_crypt` policy —
    /// to leave every datagram plaintext.
    crypt: Option<PeerUdpCrypt>,
    /// `OP_REASKFILEPING` (`0x90`) → the serve reply matrix.
    reask_tx: mpsc::Sender<ClientUdpDatagram>,
    /// `OP_REASKACK` / `OP_FILENOTFOUND` / `OP_QUEUEFULL` (`0x91`/`0x92`/`0x93`)
    /// → the downloader's Remote-Queued Pool (ADR-0057).
    reask_reply_tx: mpsc::Sender<ClientUdpDatagram>,
    /// `0xB2` plus the `0xA1`/`0xAA` signalling → the **NAT-T Front**
    /// (ADR-0091). Never awaited; see [`NATT_INBOX_CAPACITY`].
    natt_tx: mpsc::Sender<ClientUdpDatagram>,
    /// `0xE4`/`0xE5` — and every unclaimed leading byte, which may be an
    /// obfuscated Kad datagram — → the running Kad node (ADR-0057). Empty
    /// while no node runs, and never awaited; see [`SharedKadInlet`].
    kad_inlet: SharedKadInlet,
    /// The enacted buddy slot (ADR-0061): an inbound `0x94`
    /// (`OP_REASKCALLBACKUDP`) verifies + relays through it as
    /// `OP_REASKCALLBACKTCP` (`0x9A`) over the held buddy link — this front's
    /// own relay, exactly where aMule's lives
    /// (`CClientUDPSocket::OnPacketReceived`, not the Kad pump).
    buddy_slot: SharedBuddySlot,
    /// The firewalled-node front (ADR-0061/0091): a standalone
    /// `0xA0` rendezvous and an inbound `0x95` direct callback are both its
    /// business, and both are handed on rather than decided here — the front
    /// owns the buddy slot they are gated against. Empty until it starts.
    firewalled: SharedFirewalledFront,
    /// Where a datagram dropped for its **Address Family** is counted
    /// (`unanswerable_family_datagrams_total`). The front is the only place
    /// that takes that decision, so it is the only place that reports it.
    diagnostics: DiagnosticsState,
    /// The send half of this same socket — the one thing the front itself
    /// ever sends: the `OP_NATT_ENDPOINT_HINT` that answers a rendezvous it
    /// relayed (ADR-0091). It must leave by the socket the requester's `0x94`
    /// arrived on, or the requester's NAT drops it.
    send_tx: mpsc::Sender<ClientUdpSend>,
}

impl<T: ClientUdpTransport> ClientUdpEngine<T> {
    pub(crate) fn new(
        transport: T,
        crypt: Option<PeerUdpCrypt>,
        buddy_slot: SharedBuddySlot,
        firewalled: SharedFirewalledFront,
        diagnostics: DiagnosticsState,
        send_tx: mpsc::Sender<ClientUdpSend>,
        kad_inlet: SharedKadInlet,
    ) -> (Self, ClientUdpInboxes) {
        let (reask_tx, reask_rx) = mpsc::channel(INBOX_CAPACITY);
        let reask_tx_injector = reask_tx.downgrade();
        let (reask_reply_tx, reask_reply_rx) = mpsc::channel(INBOX_CAPACITY);
        let (natt_tx, natt_rx) = mpsc::channel(NATT_INBOX_CAPACITY);
        (
            Self {
                transport,
                crypt,
                reask_tx,
                reask_reply_tx,
                natt_tx,
                kad_inlet,
                buddy_slot,
                firewalled,
                diagnostics,
                send_tx,
            },
            ClientUdpInboxes {
                reask_ping: reask_rx,
                reask_reply: reask_reply_rx,
                natt: natt_rx,
                reask_ping_injector: reask_tx_injector,
            },
        )
    }

    /// Drain the transport until it closes. Ending drops the inbox senders, so
    /// every consumer's next recv yields `None`.
    pub(crate) async fn run(self) {
        while let Some((udp_src, datagram)) = self.transport.recv().await {
            self.demux(udp_src, datagram).await;
        }
        // The production transport (`RuntimeClientUdpTransport::recv`) closes
        // only when its consecutive-error budget is exhausted —
        // Kad, the reask surface and NAT-T all rode this one socket
        // (ADR-0057), so this is the "the front went dark" diagnostic.
        self.diagnostics.count_client_udp_transport_ended();
    }

    /// Route one datagram by its leading protocol byte, then — for peer-UDP —
    /// by its opcode.
    async fn demux(&self, udp_src: PeerEndpoint, datagram: Vec<u8>) {
        // Crypt receive-transform (ADR-0046), the plaintext-under-crypt split
        // the server-UDP front and the Kad node also run:
        // when the peer-UDP crypt layer is armed, dual-path decrypt keyed on our
        // own user hash + this datagram's UDP source IP before the demux. A
        // plaintext-marker first byte bypasses and a miss (garbage / another
        // peer's key) falls through — both leave the datagram as the plaintext
        // the demux then diagnoses. Disarmed ⇒ the datagram is the plaintext it
        // already is.
        //
        // The decrypt runs *before* the per-opcode family ruling, and must:
        // the opcode is inside the ciphertext, so an obfuscated `0x94` is not
        // an opcode at all until the key has been tried. This is also the one
        // place the 23-byte / 35-byte key layouts diverge on the wire.
        let datagram = match &self.crypt {
            // The key layout follows the datagram's *actual* source family and
            // is never probed (ADR-0087). The Family Pair reports that family
            // (`IPV6_V6ONLY`, so never a mapped address), so the selection is
            // a read, not a guess.
            Some(crypt) => crypt.receive(DatagramSenderAddress::from_ip(udp_src.ip()), datagram),
            None => datagram,
        };
        match demux_protocol(&datagram) {
            ClientUdpRoute::PeerUdp => self.route_peer_udp(udp_src, datagram).await,
            ClientUdpRoute::Natt => self.route_natt(udp_src, datagram),
            // The sockets are unified (ADR-0057): `rmule_net::kad`'s own bind
            // is gone and this front is where a Kad datagram arrives.
            ClientUdpRoute::Kad | ClientUdpRoute::KadPacked => {
                self.route_kad(udp_src, datagram, KadForm::Declared);
            }
            // Possibly an obfuscated Kad datagram — the peer-UDP key already
            // missed, and only the node's own keys can tell. Handing it on
            // costs a failed magic-value check there; refusing it here would
            // lose every obfuscated Kad datagram rmule is sent.
            ClientUdpRoute::Unclaimed => self.route_kad(udp_src, datagram, KadForm::Possible),
            ClientUdpRoute::Undersized => {
                tracing::trace!(
                    %udp_src,
                    len = datagram.len(),
                    "client-UDP datagram below the two-byte header; dropped"
                );
            }
        }
    }

    /// Hand one datagram to the running Kad node's inlet (ADR-0057), never
    /// awaiting it — the `natt` inbox's posture, for the same reason: this
    /// task drains the one socket every reask, every NAT-T frame and every Kad
    /// datagram shares.
    ///
    /// **IPv4 only.** Kad packs a 32-bit address end to end (ADR-0085/0087),
    /// so the v6 half of this Family Pair carries no Kad, ever: a Kad datagram
    /// that arrives there names a contact no Kad2 message could answer, and
    /// the node would have no form to store it in.
    ///
    /// A [`Declared`](KadForm::Declared) one is **counted** there, because a
    /// dialect gap must look like a gap and not like packet loss; a merely
    /// [`Possible`](KadForm::Possible) one is not, for the reason the `0x94`
    /// arm decodes before it counts — junk is junk in either family, and
    /// counting it would make noise read as a dialect gap.
    ///
    /// The one `Possible` that *is* counted, apart, is a v6 datagram bearing
    /// a crypt header our own key did not open: with no Kad on this half,
    /// nothing else could, and that is where eMuleAI's IPv6 key — which
    /// differs from emule-qt's in a byte eMuleAI never writes — lands
    /// (ADR-0087's divergence note).
    fn route_kad(&self, udp_src: PeerEndpoint, datagram: Vec<u8>, form: KadForm) {
        // The family is the question, not an ed2k id's packing: a Kad contact
        // at `x.y.z.0` is a contact.
        let Some(from) = udp_src.as_v4() else {
            if form == KadForm::Declared {
                self.diagnostics.count_unanswerable_family_datagram();
                tracing::debug!(
                    %udp_src,
                    "Kad datagram on the IPv6 half of the client-UDP pair; dropped (Kad is IPv4-only)"
                );
            } else if self.crypt.is_some() && bears_crypt_header(&datagram) {
                self.diagnostics.count_ipv6_undecryptable_datagram();
                tracing::debug!(
                    %udp_src,
                    "obfuscated datagram on the IPv6 half our key did not open; dropped"
                );
            }
            return;
        };
        let installed = self
            .kad_inlet
            .lock()
            .expect("kad inlet mutex poisoned")
            .clone();
        let Some(inlet) = installed else {
            // No node running: there is nothing this could be handed to, and
            // a stopped Kad node is not a drop worth counting.
            tracing::trace!(%udp_src, "Kad datagram with no Kad node running; dropped");
            return;
        };
        if inlet.try_send((from, datagram)).is_err() {
            // Full, or the node stopped between the read above and this send.
            // Both are a Kad datagram this node will not act on, which is the
            // fact the count is about.
            self.diagnostics.count_kad_inlet_drop();
            tracing::debug!(%udp_src, "Kad inlet full or gone; datagram dropped");
        }
    }

    /// Hand one datagram to the **NAT-T Front**'s inbox without ever awaiting
    /// it (ADR-0091). The front's ledgers live on their own task, and this one
    /// drains a socket every reask and every Kad datagram shares, so a front
    /// that falls behind costs its own frames and nothing else.
    fn route_natt(&self, udp_src: PeerEndpoint, datagram: Vec<u8>) {
        if self.natt_tx.try_send((udp_src, datagram)).is_err() {
            // Full, or the front is gone. Both are a NAT-T frame this node
            // will not act on, which is the fact the count is about.
            self.diagnostics.count_natt_inbox_drop();
            tracing::debug!(%udp_src, "NAT-T inbox full or absent; datagram dropped");
        }
    }

    /// Serve one rendezvous relay as the target's buddy (ADR-0091): forward
    /// it on the held link through the relay service's admission, and — when
    /// the requester asked (`CONNECT_OPT_NATT_ENDPOINT_HINT`) and the relay
    /// went out — answer with the target's endpoint as we observed it.
    ///
    /// The hint is sent only after a forward that succeeded. A hint for a
    /// relay that was refused would make the requester punch at a target that
    /// was never told to expect it.
    async fn relay_rendezvous(
        &self,
        requester: Ipv4Endpoint,
        relay: ReaskCallbackUdp,
        body: &RendezvousBody,
    ) {
        let buddy_id = relay.buddy_id;
        let outcome = self.buddy_slot.relay_rendezvous(
            KadId::from_bytes(buddy_id),
            requester,
            relay.forwarded,
            Instant::now(),
        );
        tracing::debug!(?requester, ?outcome, "inbound rendezvous relay (ADR-0091)");
        let RendezvousRelay::Sent {
            target,
            target_udp: target_endpoint,
        } = outcome
        else {
            self.diagnostics.count_natt_relay(false);
            return;
        };
        self.diagnostics.count_natt_relay(true);
        if !body.options.requests_endpoint_hint() {
            return;
        }
        let hint = EndpointHint {
            target,
            buddy_id,
            file_hash: body.file_hash,
            target_endpoint,
            // The target's connect options are its hello's to state, and that
            // hello is not threaded to this front. Zero claims nothing; the
            // requester already chose NAT-T from the target's own source
            // record, which is a better authority than a buddy's guess.
            options: rmule_peer::natt::NattConnectOptions::from_byte(0),
        };
        let send = ClientUdpSend::plaintext(PeerEndpoint::V4(requester), hint.encode_udp());
        if self.send_tx.send(send).await.is_err() {
            tracing::debug!(
                ?requester,
                "endpoint hint not sent: the client-UDP send half is gone"
            );
        }
    }

    /// Route one `OP_EMULEPROT` datagram by its opcode: the `0x90` reask ping
    /// to the uploader's inbox, the `0x91`/`0x92`/`0x93` replies to the
    /// downloader's, the `0x94` buddy relay through the slot, and the `0x95`
    /// direct callback and standalone `0xA0` rendezvous to the firewalled
    /// front.
    ///
    /// This is where the module doc's family ruling is enacted: the reask
    /// quartet, `0x95`, `0xA1` and `0xA0` name no address their consume
    /// cannot handle and pass in either family, while `0x94` and `0xAA` —
    /// whose relay output and acceptance rule are each 32 bits wide — drop
    /// and count an IPv6 requester.
    async fn route_peer_udp(&self, udp_src: PeerEndpoint, datagram: Vec<u8>) {
        match ClientUdpOpcode::try_from_u8(datagram[1]) {
            Some(ClientUdpOpcode::ReaskFilePing) => {
                // Full (no serve activity polling it, or one behind) or gone:
                // either way one reask this node will not answer, never a
                // stalled front.
                if self.reask_tx.try_send((udp_src, datagram)).is_err() {
                    self.diagnostics.count_peer_udp_inbox_drop();
                    tracing::debug!(%udp_src, "reask ping inbox full or absent; datagram dropped");
                }
            }
            Some(
                ClientUdpOpcode::ReaskAck
                | ClientUdpOpcode::FileNotFound
                | ClientUdpOpcode::QueueFull,
            ) => {
                // Downloader-consumed reask replies (ADR-0057): route to the
                // Remote-Queued Pool, which matches the source by this UDP endpoint
                // and consumes it. Never awaited: a full or dropped receiver
                // costs this reply, not the front.
                if self.reask_reply_tx.try_send((udp_src, datagram)).is_err() {
                    self.diagnostics.count_peer_udp_inbox_drop();
                    tracing::debug!(%udp_src, "reask reply inbox full or absent; datagram dropped");
                }
            }
            Some(ClientUdpOpcode::ReaskCallbackUdp) => {
                // `0x94` (`OP_REASKCALLBACKUDP`) — the open-node reask relay
                // (ADR-0061, over the held buddy link): parse the datagram
                // into the claimed buddy-ID + the forwarded reask tail, verify
                // the ID against our registered buddy (the tightening, both
                // opcodes), and queue the framed `OP_REASKCALLBACKTCP` (`0x9A`)
                // — this datagram's `udp_src` injected ahead of the forwarded
                // tail — on the buddy's HELD persistent TCP link. Exactly
                // aMule's `CClientUDPSocket::OnPacketReceived` relay
                // (`buddy->GetSocket()->SendPacket`); an undeliverable relay
                // (no buddy, spoofed ID, no held link) drops silently.
                //
                // This is the one arm on this front that refuses a datagram
                // for its **Address Family**: the `0x9A` it becomes injects
                // the requester as `WriteUInt32(ip)`, a field an IPv6
                // requester has no form in (ADR-0087's `HasEd2kWireForm` —
                // `ed2k_wire_form` is that rule). Relaying one would point a
                // firewalled client at an address that is not the
                // requester's; dropping it costs that one reask, and it is
                // counted so the gap is visible.
                //
                // The decode runs first so the count stays honest: a
                // malformed `0x94` would be dropped in either family, and
                // counting it here would make garbage read as a dialect gap.
                match ReaskCallbackUdp::decode_udp(&datagram) {
                    Ok(relay) => {
                        let Some(requester) = udp_src.ed2k_wire_form() else {
                            self.diagnostics.count_unanswerable_family_datagram();
                            tracing::debug!(
                                %udp_src,
                                "0x94 reask-callback from an address the 0x9A relay cannot carry; dropped"
                            );
                            return;
                        };
                        // An embedded `OP_RENDEZVOUS` (ADR-0091) rides this
                        // same opcode and is forwarded byte for byte the same
                        // way — but it is a different *service*, with its own
                        // admission, and it may be owed an answer.
                        match RendezvousBody::from_forwarded(&relay.forwarded) {
                            Some(Ok(body)) => {
                                return self.relay_rendezvous(requester, relay, &body).await;
                            }
                            Some(Err(error)) => {
                                // It claimed the marker and was malformed.
                                // Never the reask path: that would forward a
                                // null file hash for the target to answer.
                                self.diagnostics.count_natt_relay(false);
                                tracing::debug!(%udp_src, %error, "malformed embedded rendezvous dropped");
                                return;
                            }
                            None => {}
                        }
                        let disposition = self.buddy_slot.relay_reask(
                            KadId::from_bytes(relay.buddy_id),
                            requester,
                            relay.forwarded,
                        );
                        tracing::debug!(
                            ?requester,
                            ?disposition,
                            "inbound 0x94 reask-callback relayed via the buddy slot"
                        );
                    }
                    Err(error) => {
                        tracing::trace!(
                            %udp_src,
                            %error,
                            "malformed 0x94 reask-callback dropped"
                        );
                    }
                }
            }
            Some(ClientUdpOpcode::DirectCallbackReq) => {
                // `0x95` (`OP_DIRECTCALLBACKREQ`) — the firewalled-node direct
                // callback consume (ADR-0061): `rmule_peer::DirectCallbackReq`
                // parses this datagram into the requester's TCP port + user hash
                // + connect
                // options, and the core firewalled-node (`crate::firewalled`)
                // rate-limits it per this datagram's `udp_src` IP, honors it only
                // while we are actually still firewalled and Kad runs (the ADR-0058
                // Reachability gate), and returns the dial-back verdict. The live
                // routing — a firewalled-node handle on this front and the
                // obfuscated TCP dial-back — is the firewalled-node front's own
                // work, so it stays traced until then.
                //
                // `0x95` (`OP_DIRECTCALLBACKREQ`) — the firewalled-node
                // direct callback consume (ADR-0061 route 2), the one
                // callback route that needs no buddy. The firewalled front
                // rate-limits it per source IP, honours it only while we are
                // actually still firewalled and Kad runs (the ADR-0058
                // Reachability gate), and dials back.
                //
                // Family-generic: the body names no address, so the requester
                // *is* this datagram's source and the dial-back goes straight
                // back to it — ADR-0087's route-tree rung 0 for an IPv6 one.
                // The rate limit buckets by **Accounting Key** (per `/64`), so
                // an IPv6 requester is limited, not exempted.
                if !route_direct_callback(&self.firewalled, udp_src, &datagram) {
                    tracing::trace!(
                        %udp_src,
                        "0x95 direct-callback dropped: malformed, or no firewalled front running"
                    );
                }
            }
            Some(ClientUdpOpcode::Holepunch) => {
                // `0xA1` (`OP_HOLEPUNCH`) — the punch itself, and an empty
                // body: purely a trigger that refreshes the sender's mapping
                // and asks us to try a transport connect. Family-generic
                // for the same reason the reask quartet is — it names no
                // address, the sender *is* the source — so both halves of the
                // Family Pair pass it on and the front's expectation table
                // decides whether anything was expected from there.
                self.route_natt(udp_src, datagram);
            }
            Some(ClientUdpOpcode::NattEndpointHint) => {
                // `0xAA` (`OP_NATT_ENDPOINT_HINT`) — a serving buddy's answer
                // to a rendezvous we emitted. The second opcode on this front
                // ruled **IPv4 only** (ADR-0087), and for the same shape of
                // reason as `0x94`: the acceptance rule is
                // `EndpointHint::is_from`, which compares the observed source
                // against the buddy's `Ipv4Endpoint` — a field an IPv6 source
                // has no form in. A hint we cannot attribute is a hint we must
                // not act on, so it drops here at the driver rather than being
                // half-checked downstream.
                //
                // The decode runs first so the count stays honest: a malformed
                // hint would drop in either family, and counting it here would
                // make garbage read as a dialect gap (the `0x94` rule).
                if udp_src.ed2k_wire_form().is_none() {
                    if EndpointHint::decode_udp(&datagram).is_ok() {
                        self.diagnostics.count_unanswerable_family_datagram();
                        tracing::debug!(
                            %udp_src,
                            "0xAA endpoint hint from an address its acceptance rule cannot name; dropped"
                        );
                    }
                    return;
                }
                self.route_natt(udp_src, datagram);
            }
            Some(ClientUdpOpcode::Rendezvous) => {
                // `0xA0` standalone (`OP_RENDEZVOUS`) — a rendezvous relayed
                // *to us*, kno's branch's emit form. Acting on one needs a
                // recruited buddy to gate the sender against
                // (`crate::natt::acting`'s carrier rule), so it goes to the
                // firewalled front, which holds that slot. Family-generic:
                // the gate compares the whole source endpoint against our
                // buddy's, and an IPv6 source simply never matches an IPv4
                // buddy — a refusal the gate states rather than a dialect gap
                // this front should answer twice.
                if !route_standalone_rendezvous(&self.firewalled, udp_src, &datagram) {
                    tracing::trace!(
                        %udp_src,
                        "standalone 0xA0 rendezvous dropped: malformed, or no firewalled front running"
                    );
                }
            }
            None => {
                tracing::trace!(
                    opcode = datagram[1],
                    "client-UDP peer datagram with unrouted opcode; dropped"
                );
            }
        }
    }
}
