//! The **accept pump**: the task that owns the bound listener, and the error
//! policy deciding whether one failed accept is that connection's problem or
//! the listener's.
//!
//! Its own task by necessity, not by taste: with obfuscation
//! armed `PeerListener::accept` holds an already-accepted `TcpStream` across
//! the byte-0 peek await, so it must never run inside a future some caller's
//! `select!` can cancel — a cancelled mid-peek accept drops the socket and the
//! peer sees a silent FIN before it ever sent its hello (a stock aMule then
//! dead-lists the source). The pump's only cancellation point is serve
//! shutdown.

use std::sync::Arc;
use std::time::{Duration, Instant};

use rmule_net::peer::{
    Admitted, ConnectOptions as PeerConnectOptions, Connection as PeerConnection, PeerListener,
    PeerNetError, PeerStreamRole,
};
use rmule_primitives::{PeerCrypt, PeerEndpoint, UserHash};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use crate::adapters::HelloAdverts;
use crate::awaited_testers::{AwaitedServer, SharedAwaitedTesters};
use crate::server_session::HelloSource;
use crate::service::{LoginStep, PortTestAdmission, PortTestLateAdmission};

/// How long a callback dial-back's TCP connect is given. A requester that
/// asked to be dialed is waiting for it, so a connect that does not come up
/// quickly is a requester that is gone.
const DIAL_BACK_TIMEOUT: Duration = Duration::from_secs(15);

/// Per-accept connect options, built fresh for every accept from the one
/// [`HelloAdverts`] read every hello starts from — SUI with a
/// fresh challenge per accepted connection among them (ADR-0041).
/// The peer's crypt side is unknown here and unused: a responder keys from its
/// own User Hash.
fn build_accept_options(adverts: &HelloAdverts) -> PeerConnectOptions {
    adverts.connect_options(PeerCrypt::unknown())
}

/// Where a stream core opened or raised elsewhere enters the serve pipeline:
/// a risen NAT-T **Tunnel** (ADR-0091) and a **callback dial-back** (ADR-0061 routes 2/4).
///
/// Both carry an ordinary inbound peer — a punched path because it is one, a
/// dial-back because the requester asked us to connect precisely so that *it*
/// could ask *us* for a file — so both must meet the ordinary inbound gates:
/// the IP filter, the ban store, `inbound_triage`'s callback adoption. The one
/// place all three already apply is the channel this pump feeds. So neither
/// gets a pipeline of its own: the stream is wrapped in a `PeerConnection`
/// with the very handshake context and per-accept options the pump builds, and
/// pushed down the pump's own channel. Nothing above that line can tell a
/// punched path, a dialed-back socket and an accepted one apart — which is why
/// `role` is a parameter: a dial-back's hello goes first.
///
/// The sender is **weak** on purpose. The pump ends when the serve activity
/// drops the receiver (`accept_tx.closed()`), and a strong clone parked in
/// this cell would keep that signal from ever firing — so serving could never
/// release its port.
#[derive(Clone, Default)]
pub(crate) struct SharedTunnelAdmit(Arc<std::sync::Mutex<Option<TunnelAdmit>>>);

/// Why a tunnel could not enter the serve pipeline. Both arms mean the same
/// thing to the caller — close the tunnel — and differ only in what they say
/// about the node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TunnelAdmitRefusal {
    /// This node is not serving, so there is no handshake context to build a
    /// hello from. A punched path with nothing to say on it is not a path.
    NotServing,
    /// The serve pipeline is shutting down: its accept channel is closed.
    PipelineClosed,
}

/// One connection the serve pipeline is about to triage, and the one thing a
/// socket cannot say about itself.
///
/// `dialed_toward` is the target **User Hash** a NAT-T punch raised this
/// stream toward (ADR-0091). It is `None` for every road but one — a TCP
/// accept, an accepted (Responder) tunnel, a callback dial-back — because none
/// of them was opened toward a hash *this* node named. Only the NAT-T front
/// knows it, and only for a tunnel it dialed, so it travels with the
/// connection rather than being re-derived from the stream's role: a Dialer
/// role alone says who spoke first, not who was aimed at.
pub(crate) struct AdmittedPeer {
    pub(crate) conn: PeerConnection,
    pub(crate) dialed_toward: Option<UserHash>,
    /// A **Test Connection** (ADR-0046): a plain dial the listener admitted
    /// under `Required` only because a reachability test is awaited from its
    /// address. It meets the same gates, then is answered by
    /// [`answer_test_connection`](super::test_connection::answer_test_connection)
    /// and never reaches the triage — no serving, no adoption.
    pub(crate) test_connection: bool,
    /// The awaited server, when this connection came from its address inside
    /// its port test's window: where the test's end is reported.
    pub(crate) awaited_server: Option<AwaitedServer>,
}

/// The live half of [`SharedTunnelAdmit`] — everything the pump reads per
/// accept, so an admitted tunnel is answered exactly as an accepted socket is.
struct TunnelAdmit {
    accept_tx: mpsc::WeakSender<AdmittedPeer>,
    hello: HelloSource,
    adverts: HelloAdverts,
}

impl SharedTunnelAdmit {
    /// Hand one open stream to the serve pipeline as `role`'s side of a peer
    /// conversation. The ordinary road: nothing in this node aimed the stream
    /// at a named peer, so no download can claim it.
    ///
    /// # Errors
    /// [`TunnelAdmitRefusal`] when this node is not serving, or its pipeline
    /// has closed.
    pub(crate) async fn admit<S>(
        &self,
        stream: S,
        peer: PeerEndpoint,
        role: PeerStreamRole,
    ) -> Result<(), TunnelAdmitRefusal>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.push(stream, peer, role, None).await
    }

    /// Hand one open stream to the serve pipeline, saying which target's punch
    /// raised it (ADR-0091). A download that claimed `target` adopts it once
    /// the hello agrees; nobody claimed it, or the hello names somebody else,
    /// and the ordinary road decides — the gates are the same either way,
    /// because it is the same road up to the triage.
    ///
    /// # Errors
    /// [`TunnelAdmitRefusal`] when this node is not serving, or its pipeline
    /// has closed.
    pub(crate) async fn admit_dialed_toward<S>(
        &self,
        stream: S,
        peer: PeerEndpoint,
        role: PeerStreamRole,
        target: UserHash,
    ) -> Result<(), TunnelAdmitRefusal>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.push(stream, peer, role, Some(target)).await
    }

    async fn push<S>(
        &self,
        stream: S,
        peer: PeerEndpoint,
        role: PeerStreamRole,
        dialed_toward: Option<UserHash>,
    ) -> Result<(), TunnelAdmitRefusal>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        // The guard never crosses the send await: it holds the pump's cell.
        let (accept_tx, connection) = {
            let held = self.0.lock().expect("tunnel admit cell");
            let admit = held.as_ref().ok_or(TunnelAdmitRefusal::NotServing)?;
            let accept_tx = admit
                .accept_tx
                .upgrade()
                .ok_or(TunnelAdmitRefusal::PipelineClosed)?;
            let options = build_accept_options(&admit.adverts);
            let handshake = admit.hello.now();
            (
                accept_tx,
                PeerConnection::over_stream(stream, peer, role, handshake, options),
            )
        };
        accept_tx
            .send(AdmittedPeer {
                conn: connection,
                dialed_toward,
                test_connection: false,
                awaited_server: None,
            })
            .await
            .map_err(|_| TunnelAdmitRefusal::PipelineClosed)
    }

    /// Enact one callback dial-back (ADR-0061 routes 2/4) on its own task:
    /// [`callback_dial_back`](Self::callback_dial_back), fire-and-forget.
    /// Every dial-back — the firewalled front's `0x99`/`0x95` and a served
    /// link's `0x99` — goes through here; a server-relayed one awaits
    /// [`callback_dial_back`](Self::callback_dial_back) on a task that holds
    /// its in-flight claim.
    pub(crate) fn spawn_callback_dial_back(
        &self,
        requester: PeerEndpoint,
        obfuscate_toward: Option<UserHash>,
    ) {
        let admit = self.clone();
        tokio::spawn(async move { admit.callback_dial_back(requester, obfuscate_toward).await });
    }

    /// One callback dial-back: open the stream toward `requester` —
    /// obfuscated toward `obfuscate_toward` when the verdict named a key —
    /// and admit it as the dialer's side, so the peer that asked us to
    /// connect meets the IP filter, the ban store and the triage exactly as
    /// if it had dialed us. Ends once the pipeline took the link or the dial
    /// failed.
    ///
    /// Silent either way: aMule treats a refused callback dial as silent and
    /// the requester's own timeout is what notices. A crypt handshake that
    /// does not complete lands in the same place, because to the requester the
    /// two are the same silence.
    pub(crate) async fn callback_dial_back(
        &self,
        requester: PeerEndpoint,
        obfuscate_toward: Option<UserHash>,
    ) {
        let stream =
            match PeerConnection::dial_stream(requester, DIAL_BACK_TIMEOUT, obfuscate_toward).await
            {
                Ok(stream) => stream,
                Err(error) => {
                    tracing::debug!(?requester, %error, "callback dial-back refused; silent");
                    return;
                }
            };
        if let Err(refusal) = self.admit(stream, requester, PeerStreamRole::Dialer).await {
            tracing::debug!(
                ?requester,
                ?refusal,
                "callback dial-back opened but the serve pipeline would not take it"
            );
        }
    }

    /// Whether a stream admitted now would be taken: a pump filled the cell,
    /// so there is a hello to write, and its pipeline is still open.
    pub(crate) fn is_serving(&self) -> bool {
        self.0
            .lock()
            .expect("tunnel admit cell")
            .as_ref()
            .is_some_and(|admit| admit.accept_tx.strong_count() > 0)
    }

    /// Empty the cell: this node is not serving any more. Called
    /// by the adapter's release, so the refusal a tunnel meets between two
    /// serve activities names the node's state rather than the last pump's.
    pub(crate) fn clear(&self) {
        *self.0.lock().expect("tunnel admit cell") = None;
    }

    /// Fill the cell without a listener — the wiring seam the NAT-T leg needs
    /// to prove a risen tunnel is answered exactly as an accepted socket is,
    /// on a node with no TCP serve side to bind.
    ///
    /// It changes no policy: the options are the pump's own, built by the same
    /// function from `adverts`, and the tunnel still becomes an ordinary
    /// `PeerConnection`.
    #[cfg(test)]
    pub(crate) fn install_for_test(
        &self,
        accept_tx: &mpsc::Sender<AdmittedPeer>,
        ctx: rmule_peer::PeerHandshakeContext,
        adverts: HelloAdverts,
    ) {
        *self.0.lock().expect("tunnel admit cell") = Some(TunnelAdmit {
            accept_tx: accept_tx.downgrade(),
            hello: HelloSource::Fixed(ctx),
            adverts,
        });
    }
}

/// Accept errors that are one connection's problem, not the listener's: the
/// listener stays healthy and the pump keeps accepting. `TimedOut` is the
/// crypt-armed byte-0 peek's silent peer (`hello_timeout` elapsed with no
/// first byte), `Unsupported` a non-IPv4 dialer, aborted/reset a peer that
/// vanished between the TCP accept and the handshake, and
/// `PlaintextRefused` the `ObfuscationPolicy::Required` refusal of a dialer
/// no test is awaited from. Everything
/// else — a closed or broken listener, but also an fd-exhaustion burst whose
/// errnos have no stable `ErrorKind` — is retried with a bounded backoff and
/// winds the serve activity down only after [`ACCEPT_FATAL_AFTER`]
/// consecutive failures.
fn is_transient_accept_error(error: &PeerNetError) -> bool {
    match error {
        PeerNetError::PlaintextRefused { .. } => true,
        PeerNetError::Accept { source } => matches!(
            source.kind(),
            std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::Unsupported
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::ConnectionReset
        ),
        _ => false,
    }
}

/// How long the pump backs off after an accept error outside the transient
/// set before retrying. EMFILE/ENFILE/ENOBUFS — an fd-exhaustion burst — have
/// no stable `ErrorKind`, so by kind they are indistinguishable from a
/// genuinely dead listener; a bounded retry keeps the listener through
/// exhaustion (aMule never closes its listener on a failed accept) while a
/// truly closed listener fails instantly and repeatedly, hitting
/// [`ACCEPT_FATAL_AFTER`] within ~500 ms.
const ACCEPT_RETRY_BACKOFF: Duration = Duration::from_millis(100);

/// Consecutive non-transient accept failures before the pump declares the
/// listener dead and winds the serve activity down. Any accepted connection —
/// including one whose handshake then fails transiently, which proves the
/// listener itself still accepts — resets the count.
const ACCEPT_FATAL_AFTER: usize = 5;

/// Spawn the accept pump: a dedicated task that owns the bound listener and
/// feeds ready connections through a small channel. Ownership is the point
/// `PeerListener::accept` with obfuscation armed holds an
/// accepted `TcpStream` across the byte-0 peek await, so it must never run
/// inside a future a caller's `select!` can cancel — a cancelled mid-peek
/// accept drops the socket and the peer sees a silent FIN before it ever sent
/// its hello (a stock aMule then dead-lists the source). That holds for the
/// serve runner's loop *and* for `start`'s own during-login select, which is
/// why `start` spawns the pump before awaiting the login and `hello` is read
/// live — client id 0 and no server until a login lands, then that session's
/// server and its current id, which a mid-session `OP_IDCHANGE` moves. Inside the
/// pump the only cancellation point is serve shutdown (`tx.closed()`), where
/// dropping a mid-handshake stream is the intended teardown.
///
/// `awaited` is the **Awaited Testers** level (ADR-0046 "Test Connections"):
/// under `Required`, a plain dial from an address in it is admitted as a
/// Test Connection rather than refused.
pub(super) fn spawn_accept_pump(
    listener: PeerListener,
    hello: HelloSource,
    adverts: HelloAdverts,
    tunnel_admit: &SharedTunnelAdmit,
    awaited: SharedAwaitedTesters,
) -> AcceptPump {
    let (accept_tx, accept_rx) = mpsc::channel(16);
    // A risen NAT-T Tunnel joins this same channel (ADR-0091), answered with
    // this same context and these same per-accept options.
    *tunnel_admit.0.lock().expect("tunnel admit cell") = Some(TunnelAdmit {
        accept_tx: accept_tx.downgrade(),
        hello: hello.clone(),
        adverts: adverts.clone(),
    });
    let task = tokio::spawn(async move {
        // Errno-agnostic fatal detection (see [`ACCEPT_RETRY_BACKOFF`]):
        // count consecutive non-transient failures instead of trying to
        // classify resource-exhaustion errnos by `ErrorKind`.
        let mut failures = 0usize;
        loop {
            // Both are read once the peer has arrived, not when the wait began:
            // the listener can sit idle for as long as it likes, and a hello
            // must answer with what is true now.
            let fresh = || (hello.now(), build_accept_options(&adverts));
            tokio::select! {
                // Serve stopped (receiver dropped): exit, releasing the port.
                _ = accept_tx.closed() => break,
                accepted = listener.accept_with(fresh, &awaited) => match accepted {
                    Ok(admitted) => {
                        failures = 0;
                        let (conn, test_connection) = match admitted {
                            Admitted::Peer(conn) => (conn, false),
                            Admitted::TestConnection(conn) => (conn, true),
                        };
                        let ip = conn.peer_endpoint().ip();
                        let awaited_server = if let Some(server) = awaited.server_test_arrived(ip) {
                            let admission = if test_connection {
                                PortTestAdmission::TestConnection
                            } else {
                                PortTestAdmission::Peer
                            };
                            server.report(LoginStep::PortTestArrived { admission }).await;
                            Some(server)
                        } else if let Some((server, late_by)) =
                            awaited.late_server_test(ip, Instant::now())
                        {
                            let admission = PortTestLateAdmission::Peer;
                            server.report(LoginStep::PortTestLate { late_by, admission }).await;
                            Some(server)
                        } else {
                            if let Some(helper) = awaited.late_kad_test(ip, Instant::now()) {
                                helper.report(PortTestLateAdmission::Peer).await;
                            }
                            None
                        };
                        // A TCP accept was aimed at nobody: this node did not
                        // dial it, so no download may claim it (ADR-0091).
                        let accepted = AdmittedPeer {
                            conn,
                            dialed_toward: None,
                            test_connection,
                            awaited_server,
                        };
                        if accept_tx.send(accepted).await.is_err() {
                            break;
                        }
                    }
                    Err(error) if is_transient_accept_error(&error) => {
                        // The listener accepted a socket whose handshake then
                        // failed — the listener itself is alive.
                        failures = 0;
                        // A test refused for coming after its window is its
                        // tester's: a server's login step, or a Kad helper's
                        // late test — not a stranger's refused dial.
                        if let PeerNetError::PlaintextRefused { peer } = &error {
                            let admission = PortTestLateAdmission::Refused;
                            if let Some((server, late_by)) =
                                awaited.late_server_test(peer.ip(), Instant::now())
                            {
                                server.report(LoginStep::PortTestLate { late_by, admission }).await;
                            } else if let Some(helper) =
                                awaited.late_kad_test(peer.ip(), Instant::now())
                            {
                                helper.report(admission).await;
                            }
                        }
                        tracing::debug!(
                            %error,
                            "serve accept: per-connection failure; listener stays up"
                        );
                    }
                    Err(error) => {
                        failures += 1;
                        if failures >= ACCEPT_FATAL_AFTER {
                            tracing::warn!(%error, "serve listener accept failed; winding down");
                            break;
                        }
                        tracing::debug!(%error, failures, "serve accept failed; backing off");
                        // Cancel-safe bounded backoff: serve shutdown still
                        // wins instantly during the sleep.
                        tokio::select! {
                            _ = accept_tx.closed() => break,
                            () = tokio::time::sleep(ACCEPT_RETRY_BACKOFF) => {}
                        }
                    }
                },
            }
        }
    });
    AcceptPump {
        accepted: accept_rx,
        task,
    }
}

/// One running accept pump: where its connections arrive, and the task itself.
///
/// The task handle exists for the teardown: dropping `accepted`
/// tells the pump to stop, but only joining it proves the listener — and so
/// the port — is gone, which is what a restart on the same port needs.
pub(super) struct AcceptPump {
    pub(super) accepted: mpsc::Receiver<AdmittedPeer>,
    pub(super) task: tokio::task::JoinHandle<()>,
}

#[cfg(test)]
mod tests;
