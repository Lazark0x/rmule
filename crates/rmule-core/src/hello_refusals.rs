//! The **Hello Refusal** reporter (ADR-0050's amendment): the one cell
//! every peer connection's first reader — a dialed source's worker and the
//! accept path's triage — reports a refused hello to, so each refusal is
//! counted in the diagnostics and raised on the core's event bus exactly once.
//! The link's owners report here too when a **Peer Violation** ends the link,
//! so the operator reads why.
//!
//! Created once by the builder and cloned into the adapters that hold peer
//! connections (the Adapter Cells), then installed by the actor's prologue
//! with the diagnostics store and the event bus. Those two exist only once
//! the actor starts, and the adapters are wired before that. A refusal
//! reported before the install is lost; the prologue runs before any
//! adapter can open a connection.

use parking_lot::Mutex;
use std::sync::Arc;

use rmule_peer::{HelloRefusal, PeerCloseReason};

use crate::diagnostics::DiagnosticsState;
use crate::service::CoreEvent;

/// Where a refused peer hello is counted and raised (see the module docs).
#[derive(Clone, Debug, Default)]
pub(crate) struct SharedHelloRefusals {
    installed: Arc<Mutex<Option<Installed>>>,
}

#[derive(Clone, Debug)]
struct Installed {
    diagnostics: DiagnosticsState,
    events: crate::service::WeakOutbox,
}

impl SharedHelloRefusals {
    /// Bind the cell to the actor's diagnostics store and event bus. The
    /// sender is weak so this cell never keeps the bus open past the actor.
    pub(crate) fn install(
        &self,
        diagnostics: DiagnosticsState,
        events: crate::service::WeakOutbox,
    ) {
        *self.installed.lock() = Some(Installed {
            diagnostics,
            events,
        });
    }

    /// Count `refusal` and raise [`CoreEvent::PeerHelloRefused`] for it.
    pub(crate) async fn report(&self, refusal: HelloRefusal) {
        let installed = self.installed.lock().clone();
        let Some(installed) = installed else {
            return;
        };
        installed.diagnostics.count_peer_hello_refused();
        if let Some(events) = installed.events.upgrade() {
            events.send(CoreEvent::PeerHelloRefused { refusal });
        }
    }

    /// Raise [`CoreEvent::PeerLinkBroken`] when `reason` is a violation; any
    /// other close says nothing. Called once per link, by its owner.
    pub(crate) fn report_close(&self, reason: PeerCloseReason) {
        let PeerCloseReason::ProtocolViolation(violation) = reason else {
            return;
        };
        let events = self.installed.lock().as_ref().map(|i| i.events.clone());
        if let Some(events) = events.and_then(|events| events.upgrade()) {
            events.send(CoreEvent::PeerLinkBroken { violation });
        }
    }
}

#[cfg(test)]
mod tests {
    //! The dial road end to end: a source that answers with kno's captured
    //! short-count hello answer is counted and raised, and the worker reports
    //! it as the dead source it is.

    use std::time::Duration;

    use rmule_peer::HelloRefusalCode;
    use rmule_primitives::{Ed2kFileLink, Ed2kText, FileHash, Ipv4Endpoint, PeerEndpoint};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::timeout;

    use super::*;
    use crate::adapters::tests::dialed_serve_ctx;
    use crate::adapters::{
        AdapterCells, PeerTransferService, PeerWorkerEvent, RuntimePeerTransferService,
    };

    /// kno's `ab483654` answer over IPv6, 10 tags declared and 9 carried
    /// (captured; provenance in the fixture's `meta.toml`).
    const KNO_SHORT_COUNT_ANSWER: &[u8] = include_bytes!(
        "../../rmule-peer/tests/fixtures/hello_refusal/captured/amule-kno-ab483654-short-count-20260924/amule_kno_op_helloanswer_short_count.bin"
    );

    /// A close for a violation is raised under its code, and no other close is.
    #[tokio::test]
    async fn only_a_violation_close_reaches_the_bus() {
        let (events_tx, mut events) = crate::service::outbox(Default::default());
        let refusals = SharedHelloRefusals::default();
        refusals.install(DiagnosticsState::default(), events_tx.downgrade());
        refusals.report_close(PeerCloseReason::PeerClosed);
        let violation = rmule_peer::PeerViolation::WrongFile;
        refusals.report_close(PeerCloseReason::ProtocolViolation(violation));
        drop(events_tx);
        assert_eq!(
            events.recv().await.map(|event| matches!(
                event,
                CoreEvent::PeerLinkBroken { violation: read } if read == violation
            )),
            Some(true)
        );
        assert!(events.recv().await.is_none());
    }

    #[tokio::test]
    async fn a_source_whose_answer_counts_a_tag_it_never_wrote_is_counted_and_raised() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let source = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut hello = [0u8; 512];
            let _ = socket.read(&mut hello).await.unwrap();
            socket.write_all(KNO_SHORT_COUNT_ANSWER).await.unwrap();
            let _ = socket.read(&mut hello).await;
        });

        let diagnostics = DiagnosticsState::default();
        let (events_tx, mut events) = crate::service::outbox(Default::default());
        let refusals = SharedHelloRefusals::default();
        refusals.install(diagnostics.clone(), events_tx.downgrade());
        let mut cells = AdapterCells::detached();
        cells.hello_refusals = refusals;
        let mut transfer = RuntimePeerTransferService::new(crate::DEFAULT_SLOT_WAIT_TIMEOUT);
        transfer.adopt_cells(&cells);
        let file = Ed2kFileLink::new(
            Ed2kText::from_utf8("wanted"),
            4096,
            FileHash::from_bytes([0x3C; FileHash::BYTE_LEN]),
        )
        .expect("a size eD2k addresses");
        let peer = PeerEndpoint::V4(Ipv4Endpoint::new(std::net::Ipv4Addr::LOCALHOST, port));
        let mut worker = transfer
            .start_peer_worker(peer, dialed_serve_ctx(), file)
            .await
            .unwrap();

        let raised = timeout(Duration::from_secs(5), events.recv())
            .await
            .expect("raised within 5s")
            .expect("an event");
        let CoreEvent::PeerHelloRefused { refusal } = raised else {
            panic!("the refusal is raised, got {raised:?}");
        };
        assert_eq!(
            refusal.code,
            HelloRefusalCode::TagCountShort {
                declared: 10,
                written: 9
            }
        );
        assert_eq!(
            refusal.client_mod.map(|m| m.as_bytes().to_vec()),
            Some(b"aMule GIT".to_vec())
        );
        assert_eq!(
            worker.next_event().await,
            Some(PeerWorkerEvent::DialEnded {
                cause: crate::service::DialEnd::ProtocolViolation(crate::PeerViolation::BadHello)
            })
        );
        assert_eq!(
            worker.next_event().await,
            Some(PeerWorkerEvent::Disconnected)
        );
        assert_eq!(diagnostics.snapshot().session.peer_hellos_refused_total, 1);
        source.abort();
    }
}
