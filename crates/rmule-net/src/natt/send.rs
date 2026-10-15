//! The NAT-T **send path**: the datagram seam every engine emits through, and
//! the two things that happen between an engine's bytes and the wire — the
//! `0xB2` envelope, and obfuscation when a key exists.
//!
//! Neither engine owns a socket. Both hand a payload here, and this layer
//! frames it, decides whether to encrypt it, arms the **Key Frame** when the
//! payload is an opening one, and pushes it through the client-UDP **Family
//! Pair** — the same bind, and therefore the same NAT pinhole, the punch
//! opened.
//!
//! The crypt parameters travel *down* with the destination and are never
//! recovered by a reverse `(ip, port) → peer` lookup. That is aMule's deferred
//! item A1, and its own note on why: such a lookup "could not be made
//! correct".

use std::io;
use std::sync::Mutex;
use std::task::{Context, Poll};
use std::time::Instant;

use rmule_peer::natt::{NattFrame, NattFrameType, frame_transport};
use rmule_primitives::{
    AddressFamily, ClientEncryptKey, DatagramSenderAddress, PeerEndpoint, UserHash,
    encrypt_datagram_client,
};

use super::keys::NattKeyTable;

/// The client-UDP send half, narrowed to what NAT-T needs. The production impl
/// is the shared [`ClientUdpSocket`](crate::ed2k::ClientUdpSocket)'s Family
/// Pair; tests implement it over a queue.
///
/// Both shapes are required because the two engines differ: the QUIC engine
/// emits from an async task and awaits, while the uTP engine's `Transport`
/// seam hands rmule a `&mut Context` with nothing to await on.
pub trait NattDatagramSink: Send + Sync + 'static {
    /// Send one datagram to `peer`, awaiting the socket.
    ///
    /// The future is `Sync` as well as `Send` because `librqbit-utp`'s
    /// `Transport::send_to` demands it, and this future is awaited inside that
    /// one.
    ///
    /// # Errors
    /// Whatever the socket returned.
    fn send_to(
        &self,
        peer: PeerEndpoint,
        datagram: &[u8],
    ) -> impl std::future::Future<Output = io::Result<usize>> + Send + Sync;

    /// Send one datagram to `peer` without awaiting or registering a waker.
    ///
    /// # Errors
    /// [`io::ErrorKind::WouldBlock`] when the socket cannot take it now, else
    /// whatever the socket returned.
    fn try_send_to(&self, peer: PeerEndpoint, datagram: &[u8]) -> io::Result<usize>;

    /// Send one datagram to `peer` from a `poll` context.
    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        peer: PeerEndpoint,
        datagram: &[u8],
    ) -> Poll<io::Result<usize>>;

    /// A local address, for logging only — `librqbit-utp` says as much of its
    /// own `bind_addr`, and a Family Pair has two, so neither is *the* one.
    fn local_addr(&self) -> std::net::SocketAddr;
}

/// The self-facts the obfuscated send path needs, supplied by whoever holds
/// rmule's own identity (core's peer-UDP crypt layer in production), and
/// what a CAPS answer states about our crypt.
///
/// Every method is read per frame, never at construction, because the
/// policy behind it may change while the surface runs (ADR-0046). While
/// [`armed`](Self::armed) says no, every NAT-T frame goes plaintext and no
/// **Key Frame** is emitted — asserting our hash would invite a peer to
/// obfuscate toward a receiver that cannot dual-path decrypt. A surface built
/// with no crypt half at all is never armed and states no crypt bits.
pub trait NattCrypt: Send + Sync + 'static {
    /// Whether frames are obfuscated, and our hash asserted, from this frame.
    fn armed(&self) -> bool;

    /// The crypt-ladder bits a CAPS answer states in its connect-options
    /// byte, beside the transport bits the surface serves.
    fn crypt_options(&self) -> u8;

    /// Our own user hash — the KEY frame's whole body.
    fn own_user_hash(&self) -> UserHash;

    /// Our own external address in the family a datagram will leave by, or
    /// `None` to leave it plaintext.
    ///
    /// The family matters on the wire: the ed2k datagram key is `MD5` over 23
    /// bytes for an IPv4 sender and 35 for an IPv6 one, and the recipient
    /// selects by the source address it observes (ADR-0087). So the *sending*
    /// family picks the layout, which is aMule's `GetPublicIP() != 0` gate
    /// generalised rather than a new rule.
    fn sender_address(&self, family: AddressFamily) -> Option<DatagramSenderAddress>;

    /// Entropy for one datagram's crypt header, injected so a test can pin the
    /// bytes.
    fn nonce(&self) -> rmule_primitives::DatagramNonce;
}

/// A live source for rmule's own user hash, read per use rather than
/// captured — the demux binds at client-UDP socket start, ahead of any
/// credentialed activity that would fix it, so a value taken at
/// construction is stale for as long as the node has not identified itself.
///
/// [`NattCrypt::own_user_hash`] reads the same self-facts cell but
/// infallibly, tolerating a zero-hash placeholder in the KEY frame — a value
/// nobody yet holds a peer's mapping for anyway. A CAPS exchange has no such
/// tolerance: answering with a fabricated sender would teach the peer a false
/// identity, so this surface says outright when there isn't one yet rather
/// than defaulting to one.
pub trait NattOwnHash: Send + Sync + 'static {
    /// Our own user hash, or `None` before any credentialed activity ran.
    fn user_hash(&self) -> Option<UserHash>;
}

/// What one send did, beyond succeeding — the observable a deterministic test
/// reads instead of sniffing a socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SentFrame {
    /// Whether a KEY frame preceded this datagram.
    pub key_frame_sent: bool,
    /// Whether the datagram itself went out obfuscated.
    pub obfuscated: bool,
}

/// The framing, key-arming and obfuscating layer between an engine and the
/// socket. One per node, shared by both engines and by the demux's CAPS
/// answers.
pub struct NattSender<S> {
    sink: S,
    crypt: Option<Box<dyn NattCrypt>>,
    keys: Mutex<NattKeyTable>,
}

impl<S> std::fmt::Debug for NattSender<S> {
    /// Opaque on purpose: a `NattSender` holds the key table, and the whole
    /// point of the table is that its contents key other peers' obfuscation.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NattSender")
    }
}

impl<S: NattDatagramSink> NattSender<S> {
    /// Build the send path over `sink`. `crypt` armed ⇒ transport frames are
    /// obfuscated once a KEY frame has supplied the endpoint's hash, and rmule
    /// asserts its own hash in return.
    pub fn new(sink: S, crypt: Option<Box<dyn NattCrypt>>) -> Self {
        Self {
            sink,
            crypt,
            keys: Mutex::new(NattKeyTable::new()),
        }
    }

    /// The crypt-ladder bits our CAPS answer states now: the crypt half's,
    /// or none without one.
    pub(crate) fn crypt_options(&self) -> u8 {
        self.crypt.as_ref().map_or(0, |crypt| crypt.crypt_options())
    }

    /// Adopt the hash an inbound KEY frame carried, unless `held` — the
    /// endpoint holds a tunnel — and the hash contradicts the live one.
    /// Returns whether it was adopted.
    pub fn learn_key(&self, peer: PeerEndpoint, hash: UserHash, held: bool, now: Instant) -> bool {
        self.keys
            .lock()
            .expect("the NAT-T key table is never poisoned")
            .learn(peer, hash, held, now)
    }

    /// The hash a send to `peer` would obfuscate under, if any — the
    /// observable the KEY-interplay tests read.
    #[must_use]
    pub fn key_for(&self, peer: PeerEndpoint, now: Instant) -> Option<UserHash> {
        self.keys
            .lock()
            .expect("the NAT-T key table is never poisoned")
            .key_for(peer, now)
    }

    /// The local address, for logging.
    #[must_use]
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.sink.local_addr()
    }

    /// Send one already-built `0xB2` frame (a CAPS answer, a KEY frame) to
    /// `peer`. Signalling frames are *not* obfuscated even when a key exists:
    /// a CAPS exchange is how two endpoints find each other's capabilities,
    /// and one that fails to deobfuscate is indistinguishable from one that
    /// never arrived.
    ///
    /// # Errors
    /// Whatever the socket returned.
    pub async fn send_frame(&self, peer: PeerEndpoint, frame: &NattFrame<'_>) -> io::Result<()> {
        self.sink.send_to(peer, &frame.encode()).await.map(drop)
    }

    /// Send one transport payload (uTP or QUIC) to `peer`, awaiting the socket.
    ///
    /// `opens` marks an opening payload — a uTP `ST_SYN` or a QUIC long header
    /// — which is where a KEY frame is due, because that is the first moment
    /// the peer could need our hash and the last moment before data flows.
    ///
    /// # Errors
    /// Whatever the socket returned. A KEY frame that fails to send is *not*
    /// an error for the payload: the payload still goes, plaintext-keyed on the
    /// peer's side, and the next opening packet re-arms.
    pub async fn send_transport(
        &self,
        peer: PeerEndpoint,
        frame_type: NattFrameType,
        payload: &[u8],
        opens: bool,
        now: Instant,
    ) -> io::Result<SentFrame> {
        let (key_frame, datagram, obfuscated) = self.prepare(peer, frame_type, payload, opens, now);
        let mut key_frame_sent = false;
        if let Some(key_frame) = key_frame {
            key_frame_sent = self.sink.send_to(peer, &key_frame).await.is_ok();
            if !key_frame_sent {
                self.unclaim_key_frame(peer, now);
            }
        }
        self.sink.send_to(peer, &datagram).await?;
        Ok(SentFrame {
            key_frame_sent,
            obfuscated,
        })
    }

    /// [`send_transport`](Self::send_transport) from a `poll` context — the
    /// uTP `Transport` seam's shape.
    ///
    /// The KEY frame rides a `try_send`-shaped best effort here rather than
    /// awaiting: this is called from the uTP dispatcher's own poll, and
    /// parking it on a second socket write would stall every stream on the
    /// socket. A KEY frame the socket refuses or cannot take yet gives its
    /// window back, so the next opening packet retries it.
    pub fn poll_send_transport(
        &self,
        cx: &mut Context<'_>,
        peer: PeerEndpoint,
        frame_type: NattFrameType,
        payload: &[u8],
        opens: bool,
        now: Instant,
    ) -> Poll<io::Result<usize>> {
        let (key_frame, datagram, _) = self.prepare(peer, frame_type, payload, opens, now);
        if let Some(key_frame) = key_frame
            && !matches!(
                self.sink.poll_send_to(cx, peer, &key_frame),
                Poll::Ready(Ok(_))
            )
        {
            self.unclaim_key_frame(peer, now);
        }
        // The engine counts the payload it handed us, not the bytes the
        // envelope or the crypt header added — a short write it never asked
        // for would read as a partial uTP packet.
        match self.sink.poll_send_to(cx, peer, &datagram) {
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(payload.len())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }

    /// [`send_transport`](Self::send_transport) with neither an `await` nor a
    /// `Context` — `quinn`'s `AsyncUdpSocket::try_send` shape.
    ///
    /// # Errors
    /// Whatever the socket returned, including `WouldBlock`; the QUIC engine
    /// treats that as a dropped datagram and lets loss recovery repair it.
    pub fn try_send_transport(
        &self,
        peer: PeerEndpoint,
        frame_type: NattFrameType,
        payload: &[u8],
        opens: bool,
        now: Instant,
    ) -> io::Result<usize> {
        let (key_frame, datagram, _) = self.prepare(peer, frame_type, payload, opens, now);
        if let Some(key_frame) = key_frame
            && self.sink.try_send_to(peer, &key_frame).is_err()
        {
            self.unclaim_key_frame(peer, now);
        }
        self.sink
            .try_send_to(peer, &datagram)
            .map(|_| payload.len())
    }

    /// A KEY frame claimed at `now` did not leave: give its window back.
    fn unclaim_key_frame(&self, peer: PeerEndpoint, now: Instant) {
        self.keys
            .lock()
            .expect("the NAT-T key table is never poisoned")
            .unclaim_key_frame(peer, now);
    }

    /// Frame, key-arm and (maybe) obfuscate one transport payload. Pure given
    /// the key table, so both send shapes share every decision.
    fn prepare(
        &self,
        peer: PeerEndpoint,
        frame_type: NattFrameType,
        payload: &[u8],
        opens: bool,
        now: Instant,
    ) -> (Option<Vec<u8>>, Vec<u8>, bool) {
        let plain = frame_transport(frame_type, payload);
        let Some(crypt) = self.crypt.as_deref().filter(|crypt| crypt.armed()) else {
            return (None, plain, false);
        };
        let mut keys = self
            .keys
            .lock()
            .expect("the NAT-T key table is never poisoned");
        let key_frame = (opens && keys.claim_key_frame(peer, now))
            .then(|| NattFrame::Key(crypt.own_user_hash()).encode());
        let obfuscated = keys.key_for(peer, now).and_then(|peer_hash| {
            let sender = crypt.sender_address(peer.family())?;
            Some(encrypt_datagram_client(
                &plain,
                &ClientEncryptKey::Ed2k {
                    user_hash: &peer_hash,
                    sender,
                },
                &crypt.nonce(),
            ))
        });
        drop(keys);
        match obfuscated {
            Some(bytes) => (key_frame, bytes, true),
            None => (key_frame, plain, false),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddr};

    use rmule_primitives::{DatagramNonce, Ipv4Endpoint, is_udp_plaintext_marker};

    use super::*;

    /// A sink that records every datagram instead of binding anything.
    #[derive(Default)]
    struct Recorder {
        sent: Mutex<Vec<(PeerEndpoint, Vec<u8>)>>,
    }

    impl NattDatagramSink for std::sync::Arc<Recorder> {
        async fn send_to(&self, peer: PeerEndpoint, datagram: &[u8]) -> io::Result<usize> {
            self.sent
                .lock()
                .expect("recorder")
                .push((peer, datagram.to_vec()));
            Ok(datagram.len())
        }

        fn try_send_to(&self, peer: PeerEndpoint, datagram: &[u8]) -> io::Result<usize> {
            self.sent
                .lock()
                .expect("recorder")
                .push((peer, datagram.to_vec()));
            Ok(datagram.len())
        }

        fn poll_send_to(
            &self,
            _cx: &mut Context<'_>,
            peer: PeerEndpoint,
            datagram: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.sent
                .lock()
                .expect("recorder")
                .push((peer, datagram.to_vec()));
            Poll::Ready(Ok(datagram.len()))
        }

        fn local_addr(&self) -> SocketAddr {
            SocketAddr::from(([0, 0, 0, 0], 4672))
        }
    }

    /// Self-facts with a fixed nonce, so a crypt datagram's bytes are
    /// deterministic, armed while `on` holds — a policy a test can flip under
    /// a running sender.
    struct Armed {
        hash: UserHash,
        v4: Option<[u8; 4]>,
        on: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    fn on() -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true))
    }

    impl NattCrypt for Armed {
        fn armed(&self) -> bool {
            self.on.load(std::sync::atomic::Ordering::Relaxed)
        }

        fn crypt_options(&self) -> u8 {
            0x01
        }

        fn own_user_hash(&self) -> UserHash {
            self.hash
        }

        fn sender_address(&self, family: AddressFamily) -> Option<DatagramSenderAddress> {
            match family {
                AddressFamily::V4 => self.v4.map(DatagramSenderAddress::V4),
                AddressFamily::V6 => None,
            }
        }

        fn nonce(&self) -> DatagramNonce {
            DatagramNonce {
                marker_byte: 0x40,
                random_key: 0xBEEF,
                padding: vec![],
            }
        }
    }

    fn peer() -> PeerEndpoint {
        PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(203, 0, 113, 7), 4672))
    }

    fn hash(fill: u8) -> UserHash {
        UserHash::from_bytes([fill; UserHash::BYTE_LEN])
    }

    fn armed_sender() -> (
        std::sync::Arc<Recorder>,
        NattSender<std::sync::Arc<Recorder>>,
    ) {
        let recorder = std::sync::Arc::new(Recorder::default());
        let sender = NattSender::new(
            std::sync::Arc::clone(&recorder),
            Some(Box::new(Armed {
                hash: hash(0x11),
                v4: Some([192, 0, 2, 5]),
                on: on(),
            })),
        );
        (recorder, sender)
    }

    /// With no key for the endpoint, a transport frame goes out plaintext with
    /// the two-byte envelope intact — and the KEY frame precedes it, which is
    /// the only way the peer will ever be able to obfuscate toward us.
    #[tokio::test]
    async fn an_opening_payload_asserts_our_hash_and_still_goes_plaintext() {
        let (recorder, sender) = armed_sender();
        let sent = sender
            .send_transport(
                peer(),
                NattFrameType::Utp,
                &[0x41, 0x00],
                true,
                Instant::now(),
            )
            .await
            .expect("recorded");
        assert_eq!(
            sent,
            SentFrame {
                key_frame_sent: true,
                obfuscated: false
            }
        );
        let log = recorder.sent.lock().expect("recorder").clone();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].1, NattFrame::Key(hash(0x11)).encode());
        assert_eq!(log[1].1, vec![0xB2, 0x00, 0x41, 0x00]);
    }

    /// Once a KEY frame supplied the endpoint's hash, the *same* payload goes
    /// out obfuscated — and its first byte is no longer `0xB2`, which is what
    /// keeps the never-obfuscated whitelist unambiguous on the far side
    /// (ADR-0046's amendment).
    #[tokio::test]
    async fn a_learned_key_turns_the_very_next_transport_frame_obfuscated() {
        let (recorder, sender) = armed_sender();
        let now = Instant::now();
        sender.learn_key(peer(), hash(0x99), false, now);
        let sent = sender
            .send_transport(peer(), NattFrameType::Utp, &[0x41, 0x00], false, now)
            .await
            .expect("recorded");
        assert!(sent.obfuscated && !sent.key_frame_sent);
        let log = recorder.sent.lock().expect("recorder").clone();
        assert_eq!(log.len(), 1);
        assert!(
            !is_udp_plaintext_marker(log[0].1[0]),
            "an obfuscated NAT-T datagram must not lead with a whitelisted byte"
        );
        assert_ne!(log[0].1, vec![0xB2, 0x00, 0x41, 0x00]);
    }

    /// A signalling frame is never obfuscated, key or no key: the CAPS
    /// exchange is how endpoints discover each other, and one that fails to
    /// deobfuscate is indistinguishable from one that never arrived.
    #[tokio::test]
    async fn a_caps_frame_stays_plaintext_even_with_a_key_in_hand() {
        let (recorder, sender) = armed_sender();
        let now = Instant::now();
        sender.learn_key(peer(), hash(0x99), false, now);
        let frame = NattFrame::Key(hash(0x11));
        sender.send_frame(peer(), &frame).await.expect("recorded");
        let log = recorder.sent.lock().expect("recorder").clone();
        assert_eq!(log[0].1[0], 0xB2);
    }

    /// Holding no address in the destination's family means plaintext, not a
    /// guess at the other layout: the recipient keys its decrypt on the source
    /// address it observes, so a key built from the wrong family would decrypt
    /// to nothing on arrival.
    #[tokio::test]
    async fn no_address_in_the_destinations_family_means_plaintext() {
        let recorder = std::sync::Arc::new(Recorder::default());
        let sender = NattSender::new(
            std::sync::Arc::clone(&recorder),
            Some(Box::new(Armed {
                hash: hash(0x11),
                v4: None,
                on: on(),
            })),
        );
        let now = Instant::now();
        sender.learn_key(peer(), hash(0x99), false, now);
        let sent = sender
            .send_transport(peer(), NattFrameType::Utp, &[0x41], false, now)
            .await
            .expect("recorded");
        assert!(!sent.obfuscated);
        assert_eq!(
            recorder.sent.lock().expect("recorder")[0].1,
            vec![0xB2, 0x00, 0x41]
        );
    }

    /// Disarmed: no KEY frame is asserted at all. Inviting a peer to obfuscate
    /// toward a receiver with no dual-path decrypt would break the tunnel it
    /// was meant to protect.
    #[tokio::test]
    async fn a_disarmed_sender_never_asserts_a_hash() {
        let recorder = std::sync::Arc::new(Recorder::default());
        let sender = NattSender::new(std::sync::Arc::clone(&recorder), None);
        let sent = sender
            .send_transport(peer(), NattFrameType::Utp, &[0x41], true, Instant::now())
            .await
            .expect("recorded");
        assert_eq!(
            sent,
            SentFrame {
                key_frame_sent: false,
                obfuscated: false
            }
        );
        assert_eq!(recorder.sent.lock().expect("recorder").len(), 1);
    }

    /// The policy behind the crypt half changes live (ADR-0046): disarmed,
    /// the very next frame goes plaintext with no KEY frame even toward a
    /// keyed endpoint, and re-armed, the one after is obfuscated again — the
    /// learned key kept across.
    #[tokio::test]
    async fn a_policy_change_reaches_the_very_next_frame() {
        let recorder = std::sync::Arc::new(Recorder::default());
        let switch = on();
        let sender = NattSender::new(
            std::sync::Arc::clone(&recorder),
            Some(Box::new(Armed {
                hash: hash(0x11),
                v4: Some([192, 0, 2, 5]),
                on: std::sync::Arc::clone(&switch),
            })),
        );
        let now = Instant::now();
        sender.learn_key(peer(), hash(0x99), false, now);
        let send = || sender.send_transport(peer(), NattFrameType::Utp, &[0x41], true, now);

        assert!(send().await.expect("recorded").obfuscated);
        switch.store(false, std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            send().await.expect("recorded"),
            SentFrame {
                key_frame_sent: false,
                obfuscated: false
            }
        );
        assert_eq!(sender.crypt_options(), 0x01, "the bits are the half's own");
        switch.store(true, std::sync::atomic::Ordering::Relaxed);
        assert!(send().await.expect("recorded").obfuscated);
    }

    /// The poll shape makes the same decisions and reports the payload length
    /// the engine handed down, never the envelope's or the crypt header's — a
    /// count the uTP dispatcher would read as a partial packet.
    #[test]
    fn the_poll_send_reports_the_payload_length_not_the_datagrams() {
        let (recorder, sender) = armed_sender();
        let now = Instant::now();
        sender.learn_key(peer(), hash(0x99), false, now);
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        let payload = [0x41u8, 0x00, 0x01, 0x02];
        let Poll::Ready(Ok(len)) =
            sender.poll_send_transport(&mut cx, peer(), NattFrameType::Utp, &payload, true, now)
        else {
            panic!("the recorder always accepts");
        };
        assert_eq!(len, payload.len());
        let log = recorder.sent.lock().expect("recorder").clone();
        assert_eq!(log.len(), 2, "the KEY frame rode alongside");
        assert!(log[1].1.len() > payload.len() + 2, "crypt header present");
    }

    /// A sink that refuses its first `refuse` datagrams with `WouldBlock`.
    #[derive(Default)]
    struct Refusing {
        refuse: Mutex<usize>,
        sent: Mutex<Vec<Vec<u8>>>,
    }

    impl NattDatagramSink for std::sync::Arc<Refusing> {
        async fn send_to(&self, peer: PeerEndpoint, datagram: &[u8]) -> io::Result<usize> {
            self.try_send_to(peer, datagram)
        }

        fn try_send_to(&self, _peer: PeerEndpoint, datagram: &[u8]) -> io::Result<usize> {
            let mut refuse = self.refuse.lock().expect("refusing");
            if *refuse > 0 {
                *refuse -= 1;
                return Err(io::ErrorKind::WouldBlock.into());
            }
            self.sent.lock().expect("refusing").push(datagram.to_vec());
            Ok(datagram.len())
        }

        fn poll_send_to(
            &self,
            _cx: &mut Context<'_>,
            peer: PeerEndpoint,
            datagram: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(self.try_send_to(peer, datagram))
        }

        fn local_addr(&self) -> SocketAddr {
            SocketAddr::from(([0, 0, 0, 0], 4672))
        }
    }

    /// A KEY frame the socket refused does not spend the ten-second window:
    /// the very next opening packet asserts our hash again, instead of the peer
    /// going a whole window unable to obfuscate toward us.
    #[test]
    fn a_refused_key_frame_does_not_spend_its_window() {
        let sink = std::sync::Arc::new(Refusing {
            refuse: Mutex::new(1),
            ..Refusing::default()
        });
        let sender = NattSender::new(
            std::sync::Arc::clone(&sink),
            Some(Box::new(Armed {
                hash: hash(0x11),
                v4: Some([192, 0, 2, 5]),
                on: on(),
            })),
        );
        let now = Instant::now();
        let key = NattFrame::Key(hash(0x11)).encode();
        sender
            .try_send_transport(peer(), NattFrameType::Utp, &[0x41], true, now)
            .expect("the payload itself went");
        assert!(!sink.sent.lock().expect("refusing").contains(&key));
        sender
            .try_send_transport(peer(), NattFrameType::Utp, &[0x41], true, now)
            .expect("sent");
        assert_eq!(
            sink.sent.lock().expect("refusing")[1],
            key,
            "the retried opener carries the KEY frame the first one lost"
        );
    }
}
