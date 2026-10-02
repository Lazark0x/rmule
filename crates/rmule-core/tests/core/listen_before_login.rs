//! **Listen Before Login** and the **Login Mapping Wait** through a live core
//! (ADR-0086).
//!
//! Measured on a home router that grants UPnP for both ports: a front end
//! built as `apps/rmule` builds its core — `Core::builder(..)
//! .mapping_backends(..)`, then `ConnectToServer` and nothing else — logged in
//! Low ID, because no listener existed, so nothing was mapped and nothing
//! answered the server's port check. These legs drive exactly that shape
//! against a Fake eD2k Server whose login runs the real High-ID port check.

use std::net::Ipv4Addr;
use std::sync::Arc;

use rmule_core::port_mapping::MappingStatus;
use rmule_core::{Core, CoreConfig, CoreEvent, SocketRole};
use rmule_net::portmap::{
    Gateway, MappedTransport, MappingBackend, MappingError, MappingFuture, MappingGrant,
    MappingProtocol, MappingRequest, ProbeReport,
};
use rmule_primitives::AddressFamily;
use rmule_testkit::{FakeEd2kServer, FakeGateways, ScriptedBackend};
use tokio::sync::watch;
use tokio::time::{Duration, timeout};

use crate::fixture::{connect_server_as, free_port, identity_with_port, list_server};

/// A UPnP gateway that grants exactly, but holds its TCP grant until the test
/// opens the gate — the ~2 s the measured router took, made a knob.
#[derive(Debug)]
struct GatedBackend {
    inner: Arc<ScriptedBackend>,
    tcp_asked: watch::Sender<bool>,
    open: watch::Receiver<bool>,
}

impl MappingBackend for GatedBackend {
    fn protocol(&self) -> MappingProtocol {
        self.inner.protocol()
    }

    fn probe(
        self: Arc<Self>,
        gateway: Gateway,
    ) -> MappingFuture<'static, Result<ProbeReport, MappingError>> {
        Arc::clone(&self.inner).probe(gateway)
    }

    fn map(
        self: Arc<Self>,
        gateway: Gateway,
        request: MappingRequest,
    ) -> MappingFuture<'static, Result<MappingGrant, MappingError>> {
        if request.transport != MappedTransport::Tcp {
            return Arc::clone(&self.inner).map(gateway, request);
        }
        self.tcp_asked.send_replace(true);
        let mut open = self.open.clone();
        let inner = Arc::clone(&self.inner);
        Box::pin(async move {
            let _ = open.wait_for(|open| *open).await;
            inner.map(gateway, request).await
        })
    }

    fn release(
        self: Arc<Self>,
        gateway: Gateway,
        request: MappingRequest,
        external_port: u16,
    ) -> MappingFuture<'static, ()> {
        Arc::clone(&self.inner).release(gateway, request, external_port)
    }
}

/// The front-end shape end to end: the connect binds the listener (a TCP row
/// joins the Desired Mapping Set), the login waits while the gateway is still
/// granting that port, and once it grants, the login advertises the mapped
/// port — which the server's port check reaches, so the id is High.
#[tokio::test]
async fn a_front_end_connect_listens_and_maps_its_port_before_the_login_leaves() {
    let server = FakeEd2kServer::start().await;
    let endpoint = server.endpoint();
    let port = free_port().await;
    let upnp = Arc::new(ScriptedBackend::available(MappingProtocol::Upnp));
    let (tcp_asked, mut asked) = watch::channel(false);
    let (gate, open) = watch::channel(false);
    let gated = Arc::new(GatedBackend {
        inner: Arc::clone(&upnp),
        tcp_asked,
        open,
    });
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .gateway_source(FakeGateways::home_lan())
        .mapping_backends(vec![gated])
        .build();
    list_server(&core, &endpoint).await;

    connect_server_as(&core, &endpoint, identity_with_port(port).into()).await;

    timeout(Duration::from_secs(10), asked.wait_for(|asked| *asked))
        .await
        .expect("the gateway was asked for the listener's port")
        .expect("the backend is alive");
    let rows = core.diagnostics_snapshot().mappings;
    let tcp = rows
        .iter()
        .find(|row| row.mapping.role == SocketRole::Tcp)
        .expect("the listener's bind put a TCP row in the Desired Mapping Set");
    assert_eq!(tcp.mapping.internal_port, port);
    assert_eq!(tcp.mapping.family, AddressFamily::V4);
    // While the grant is held, the login must not have gone out: a login
    // racing the grant is exactly the Low ID the live run drew. The clock is
    // paused, so the window runs only when every task has run as far as it
    // can: a login not held back has said `Connecting` by then. The window
    // stays inside the mapping wait's own bound.
    tokio::time::pause();
    let _ = timeout(Duration::from_secs(5), async {
        loop {
            if let CoreEvent::ServerConnection(edge) = core.next_event().await.expect("core alive")
            {
                panic!("the login started while the listener's mapping is still being granted: {edge:?}");
            }
        }
    })
    .await;
    tokio::time::resume();
    assert!(
        server.assigned_ids().await.is_empty(),
        "no login while the listener's mapping is still being granted"
    );

    gate.send_replace(true);
    let ids = timeout(Duration::from_secs(10), server.assigned_ids_after(1))
        .await
        .expect("the login went out once the row settled");
    assert_eq!(ids.len(), 1, "one login, the operator's");
    assert!(
        ids[0].is_high_id(),
        "the server's port check reached the advertised port"
    );
    let mapped = core
        .diagnostics_snapshot()
        .mappings
        .into_iter()
        .find(|row| row.mapping.role == SocketRole::Tcp)
        .expect("the listener's row");
    assert_eq!(mapped.status, MappingStatus::Mapped);
    assert_eq!(
        mapped.external.map(|endpoint| endpoint.port()),
        Some(port),
        "the login advertised the port the gateway mapped"
    );
    assert!(
        upnp.asked()
            .iter()
            .any(|request| request.transport == MappedTransport::Tcp
                && request.internal_port == port),
    );
}

/// A listener that cannot bind does not hold the login back: the connect
/// still goes out and lands Low ID, as aMule's does ("Port %u is not
/// available. You will be LOWID", `amule.cpp:1688`).
#[tokio::test]
async fn a_listener_that_cannot_bind_still_lets_the_login_out() {
    let server = FakeEd2kServer::start().await;
    let endpoint = server.endpoint();
    let port = free_port().await;
    // Something else holds the port on IPv4 — the family the server's port
    // check dials — and answers nothing.
    let _holder = std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, port)).expect("hold");
    let core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store()).build();
    list_server(&core, &endpoint).await;

    connect_server_as(&core, &endpoint, identity_with_port(port).into()).await;

    let ids = timeout(Duration::from_secs(15), server.assigned_ids_after(1))
        .await
        .expect("the login went out");
    assert!(
        ids[0].is_low_id(),
        "nothing of ours answered the port check"
    );
}
