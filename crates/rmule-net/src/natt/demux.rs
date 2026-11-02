//! The **NAT-T Demux**: the `0xB2` arm of the client-UDP **Family Pair**.
//!
//! The client-UDP front demuxes by protocol byte — `0xC5` peer-UDP, `0xE4`/
//! `0xE5` Kad, `0xB2` here — and this module takes it the second level down, by
//! frame type. Five types, and every one of them either reaches an engine,
//! teaches us something, or is dropped in silence. Nothing here ever answers a
//! frame it could not read: the dialect defines no failure frame, so a reply to
//! a malformed datagram would be rmule's invention and a reflector.
//!
//! By the time a datagram arrives here it is already plaintext. An obfuscated
//! NAT-T frame led with a random crypt marker, not `0xB2`, and the front's
//! dual-path decrypt (ADR-0046) recovered it before the protocol demux ran — so
//! this layer reads one form and the send path owns the other.

use parking_lot::{Mutex, MutexGuard};
use std::sync::Arc;
use std::time::Instant;

use rmule_peer::natt::{
    CapsFrame, HelloNattClaim, NattConnectOptions, NattFrame, NattFrameDecodeError, NattTransport,
};
use rmule_primitives::{FileHash, PeerEndpoint, UserHash};

use super::registry::{Admission, ExpectsSource, TunnelRegistry};
use super::send::{NattDatagramSink, NattOwnHash, NattSender};
use super::utp::UtpEngine;

/// Why a NAT-T front could not start. Both arms are configuration failures at
/// startup, never a datagram's fault.
#[derive(Debug, thiserror::Error)]
pub enum NattStartError {
    /// `librqbit-utp` refused its socket options.
    #[error("the uTP engine could not start: {0}")]
    Utp(librqbit_utp::Error),

    /// The QUIC engine's TLS parameters or endpoint were refused.
    #[error("the QUIC engine could not start: {0}")]
    Quic(super::quic::QuicNattError),
}

/// Who rmule is on this surface, and what it will actually serve.
///
/// The user hash is deliberately **not** a field here: it used to be, and
/// being `Copy` is exactly what let it be captured at [`NattDemux::start`]
/// and go stale — a node's own hash arrives with whichever
/// credentialed activity starts first, which is after the client-UDP socket
/// binds and this type is built. [`NattDemux::start`] instead takes a
/// [`NattOwnHash`] it reads per use, so what remains here really is static
/// for the surface's whole life. The crypt-ladder bits a CAPS answer states
/// are not here either: the policy behind them changes live, so they come
/// from the sender's [`NattCrypt`](super::NattCrypt) per frame.
#[derive(Clone, Copy, Debug)]
pub struct NattIdentity {
    /// The transports this build serves. `quic` is false until a live handshake
    /// is proven (ADR-0091), which is the same discipline
    /// `CT_MOD_MISCOPTIONS` bit 4 follows — rmule is uTP-only exactly like an
    /// eMuleAI build with no QUIC runtime.
    pub local: HelloNattClaim,
}

/// What the demux did with one datagram — the observable a deterministic test
/// reads and the diagnostics surface counts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NattDisposition {
    /// A uTP packet, with the registry's verdict on it.
    Utp(Admission),
    /// A QUIC datagram, with the registry's verdict on it.
    Quic(Admission),
    /// A QUIC datagram arrived and this build serves no QUIC. Dropped, not
    /// answered: a version-negotiation reply would claim a runtime rmule does
    /// not have.
    QuicUnavailable,
    /// A CAPS probe was read and answered with exactly one CAPS-ACK. The
    /// sender's hash is carried up so the caller may adopt it.
    CapsAnswered {
        /// The hash the sender asserted.
        sender: UserHash,
        /// The transport the exchange settled on, if any.
        transport: Option<NattTransport>,
    },
    /// A CAPS-ACK was read. Never answered — that would be a probe loop.
    CapsAckAdopted {
        /// The hash the sender asserted.
        sender: UserHash,
        /// The transport the exchange settled on, if any.
        transport: Option<NattTransport>,
    },
    /// A CAPS frame naming a recipient that is not us. Dropped in silence: a
    /// reply would confirm an identity to whoever misrouted it.
    CapsNotOurs,
    /// A CAPS or CAPS-ACK frame arrived before this front's own identity was
    /// known — distinct from [`Self::CapsNotOurs`], which would claim this
    /// frame was judged and missed us, when in fact no judgement was
    /// possible yet. Dropped in silence: a CAPS-ACK with a fabricated
    /// zero-hash sender would teach the peer a false identity, and the
    /// dialect's only safe answer to anything it cannot handle is silence.
    CapsBeforeIdentity,
    /// A CAPS frame whose sender hash contradicts what this endpoint asserted
    /// in its **Key Frame**. Dropped.
    CapsContradictsKey,
    /// A KEY frame; the endpoint's hash is now known, and transport frames to
    /// it go out obfuscated once nothing charges it as unidentified.
    KeyLearned(UserHash),
    /// A KEY frame naming a hash other than the live one, from an endpoint
    /// that holds a tunnel, or other than the endpoint's name, key or no key
    /// yet. Dropped: a NAT rebinding moves the endpoint, never the hash at one,
    /// so this can only be a spoof (ADR-0091, security rule 11).
    KeyContradictsTunnel,
    /// A KEY or CAPS frame from an endpoint with no slot that may not open
    /// one: the same stranger an opener would be, and the same answer
    /// (ADR-0091, security rule 10). Dropped in silence, before any table.
    Unadmitted,
    /// The datagram did not decode. Dropped in silence.
    Malformed(NattFrameDecodeError),
}

/// The node's NAT-T front: the frame demux and the engines behind it, over
/// the one **Tunnel Registry** their send path keys from.
pub struct NattDemux<S> {
    identity: NattIdentity,
    own_hash: Arc<dyn NattOwnHash>,
    sender: Arc<NattSender<S>>,
    utp: UtpEngine<S>,
    quic: Option<super::quic::QuicEngine<S>>,
    registry: Arc<Mutex<TunnelRegistry>>,
}

impl<S: NattDatagramSink> NattDemux<S> {
    /// Assemble the front over `sender`'s pump. `own_hash` is read per CAPS
    /// frame and per QUIC handshake, never at this call — see
    /// [`NattIdentity`]'s docs for why.
    ///
    /// # Errors
    /// Whatever an engine rejected in its own configuration.
    pub fn start(
        identity: NattIdentity,
        own_hash: Arc<dyn NattOwnHash>,
        sender: Arc<NattSender<S>>,
    ) -> Result<Self, NattStartError> {
        let registry = sender.registry();
        let utp = UtpEngine::start(Arc::clone(&sender), Arc::clone(&registry))
            .map_err(NattStartError::Utp)?;
        let quic = identity
            .local
            .quic
            .then(|| {
                super::quic::QuicEngine::start(
                    Arc::clone(&own_hash),
                    Arc::clone(&sender),
                    Arc::clone(&registry),
                )
            })
            .transpose()
            .map_err(NattStartError::Quic)?;
        Ok(Self {
            identity,
            own_hash,
            sender,
            utp,
            quic,
            registry,
        })
    }

    /// The uTP engine — where a caller dials, accepts and releases tunnels.
    #[must_use]
    pub const fn utp(&self) -> &UtpEngine<S> {
        &self.utp
    }

    /// The QUIC engine, present only when this build serves QUIC.
    #[must_use]
    pub const fn quic(&self) -> Option<&super::quic::QuicEngine<S>> {
        self.quic.as_ref()
    }

    /// The send path, for the frames a caller originates (a CAPS probe, a dial).
    #[must_use]
    pub fn sender(&self) -> &Arc<NattSender<S>> {
        &self.sender
    }

    /// Route one already-plaintext `0xB2` datagram from `peer`. `expects` is
    /// asked, only for a frame that would leave state from an endpoint with no
    /// slot, whether its IP is one the caller expects a tunnel from (ADR-0091,
    /// security rule 10).
    pub async fn on_datagram(
        &self,
        peer: PeerEndpoint,
        datagram: &[u8],
        expects: &ExpectsSource<'_>,
        now: Instant,
    ) -> NattDisposition {
        let frame = match NattFrame::decode(datagram) {
            Ok(frame) => frame,
            Err(error) => {
                tracing::trace!(%peer, %error, "malformed NAT-T frame dropped");
                return NattDisposition::Malformed(error);
            }
        };
        match frame {
            NattFrame::Utp(packet) => {
                NattDisposition::Utp(self.utp.inject(peer, packet, expects, now))
            }
            NattFrame::Quic(packet) => match &self.quic {
                Some(engine) => NattDisposition::Quic(engine.inject(peer, packet, expects, now)),
                None => {
                    tracing::trace!(%peer, "QUIC NAT-T frame with no QUIC runtime; dropped");
                    NattDisposition::QuicUnavailable
                }
            },
            NattFrame::Caps(caps) => self.on_caps(peer, caps, true, expects, now).await,
            NattFrame::CapsAck(caps) => self.on_caps(peer, caps, false, expects, now).await,
            NattFrame::Key(hash) => self.on_key(peer, hash, expects, now),
        }
    }

    /// The registry, under its one lock.
    fn registry(&self) -> MutexGuard<'_, TunnelRegistry> {
        self.registry.lock()
    }

    /// Learn the hash a KEY frame carried, if its endpoint may leave a row.
    fn on_key(
        &self,
        peer: PeerEndpoint,
        hash: UserHash,
        expects: &ExpectsSource<'_>,
        now: Instant,
    ) -> NattDisposition {
        let mut registry = self.registry();
        if registry.admit(peer, true, expects, now) == Admission::Drop {
            tracing::trace!(%peer, "NAT-T key frame from an unadmitted endpoint; dropped");
            return NattDisposition::Unadmitted;
        }
        if !registry.learn_key(peer, hash, now) {
            tracing::debug!(%peer, "NAT-T key frame contradicts the held tunnel's key; dropped");
            return NattDisposition::KeyContradictsTunnel;
        }
        tracing::debug!(%peer, "NAT-T key frame adopted");
        NattDisposition::KeyLearned(hash)
    }

    /// Read a CAPS or CAPS-ACK body, adopt what it says about the endpoint, and
    /// answer a probe (never an answer).
    async fn on_caps(
        &self,
        peer: PeerEndpoint,
        caps: CapsFrame,
        probe: bool,
        expects: &ExpectsSource<'_>,
        now: Instant,
    ) -> NattDisposition {
        let Some(own_hash) = self.own_hash.user_hash() else {
            tracing::debug!(%peer, "NAT-T CAPS frame arrived before our own identity is known; dropped");
            return NattDisposition::CapsBeforeIdentity;
        };
        if !caps.addressed_to(&own_hash) {
            tracing::debug!(%peer, "NAT-T CAPS frame addressed to another node; dropped");
            return NattDisposition::CapsNotOurs;
        }
        let (transport, answer_due) = {
            let mut registry = self.registry();
            if registry.admit(peer, true, expects, now) == Admission::Drop {
                tracing::trace!(%peer, "NAT-T CAPS frame from an unadmitted endpoint; dropped");
                return NattDisposition::Unadmitted;
            }
            // The endpoint's own **Key Frame** is the only hash claim this
            // layer stores, so it is the only thing a CAPS sender hash can
            // contradict. A CAPS hash is *reported* rather than written into
            // the crypt key map: eMuleAI keys obfuscation from the KEY frame's
            // map alone, and widening that here would obfuscate to an endpoint
            // that never asked us to.
            if registry
                .key_for(peer, now)
                .is_some_and(|known| known != caps.sender)
            {
                tracing::debug!(%peer, "NAT-T CAPS sender hash contradicts its key frame; dropped");
                return NattDisposition::CapsContradictsKey;
            }
            let state = registry
                .negotiations
                .touch(peer, HelloNattClaim::default(), now);
            state.caps_answered(caps.connect_options);
            let transport = match state.verdict(now, self.identity.local) {
                rmule_peer::natt::TransportVerdict::Ready(transport) => Some(transport),
                _ => None,
            };
            (
                transport,
                probe && registry.negotiations.claim_answer(peer, now),
            )
        };
        if answer_due {
            let answer = NattFrame::CapsAck(self.our_caps(own_hash, caps.sender, now, peer));
            if let Err(error) = self.sender.send_frame(peer, &answer).await {
                tracing::debug!(%peer, %error, "NAT-T CAPS answer could not be sent");
            }
        }
        if probe {
            return NattDisposition::CapsAnswered {
                sender: caps.sender,
                transport,
            };
        }
        NattDisposition::CapsAckAdopted {
            sender: caps.sender,
            transport,
        }
    }

    /// Record that a CAPS probe went out to `peer`, starting its 1500 ms
    /// legacy window, and what the peer's hello claimed.
    pub fn probe_sent(&self, peer: PeerEndpoint, hello: HelloNattClaim, now: Instant) {
        self.registry()
            .negotiations
            .touch(peer, hello, now)
            .probe_sent(now);
    }

    /// Blacklist QUIC on `peer` for 120 s — what a failed QUIC handshake does.
    pub fn quic_failed(&self, peer: PeerEndpoint, now: Instant) {
        self.registry()
            .negotiations
            .touch(peer, HelloNattClaim::default(), now)
            .quic_failed(now);
    }

    /// The transport rmule would raise toward `peer` right now, given what it
    /// has learned. `hello` seeds an endpoint never heard from before.
    #[must_use]
    pub fn verdict(
        &self,
        peer: PeerEndpoint,
        hello: HelloNattClaim,
        now: Instant,
    ) -> rmule_peer::natt::TransportVerdict {
        self.registry()
            .negotiations
            .touch(peer, hello, now)
            .verdict(now, self.identity.local)
    }

    /// The CAPS body rmule sends to `peer`.
    ///
    /// The QUIC bit follows the *endpoint*, not the build: a blacklisted
    /// endpoint is told "no QUIC" for this exchange while the local capability
    /// is unchanged. The file-hash slot is all-zero because this layer has no
    /// file context — the rendezvous layer carries one — and eMuleAI
    /// writes its own request/upload file id there, never an echo of the
    /// requester's, so echoing would be a divergence rather than a courtesy.
    fn our_caps(
        &self,
        own_hash: UserHash,
        expected: UserHash,
        now: Instant,
        peer: PeerEndpoint,
    ) -> CapsFrame {
        let quic = self.identity.local.quic && !self.quic_blacklisted(peer, now);
        CapsFrame {
            connect_options: NattConnectOptions::advertise(
                // The crypt half's bits as the policy stands at this frame.
                self.sender.crypt_options(),
                self.identity.local.utp,
                quic,
            ),
            sender: own_hash,
            expected_recipient: expected,
            file_hash: FileHash::from_bytes([0; FileHash::BYTE_LEN]),
        }
    }

    fn quic_blacklisted(&self, peer: PeerEndpoint, now: Instant) -> bool {
        self.registry()
            .negotiations
            .get(peer)
            .is_some_and(|state| state.quic_blacklisted(now))
    }
}
