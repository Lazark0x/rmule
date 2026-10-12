//! **Address Learning** end to end through a live core (ADR-0084): the
//! Interface Source a builder installs reaches the store, what the peer
//! listener's Family Pair bound reaches the store, and the two join into the
//! verdict a diagnostics snapshot reports.
//!
//! The store's own rules — ladders, quorum, freshness, the corroboration
//! filter, the NAT-hint matrix — are proven deterministically beside the store
//! itself, where thirty minutes cost a microsecond. What only a real core can
//! prove is the *wiring*: that the poll is armed at startup, that the bind is
//! recorded where it happens, and that the snapshot reads the store rather
//! than a copy that could drift from it.

use rmule_testkit::HANG_GUARD;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddrV4};

use rmule_core::{
    ConfidenceTier, Core, CoreCommand, CoreConfig, EndpointVerdict, ServeCommand, SocketRole,
};
use rmule_primitives::AddressFamily;
use rmule_testkit::FakeInterfaces;
use tokio::time::{Duration, timeout};

/// A routable IPv4 this host "holds" — the no-NAT case the interface tier is
/// for.
const HELD_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 5));

#[tokio::test]
async fn a_serving_core_reports_the_endpoint_its_interfaces_and_its_bind_agree_on() {
    // A host holding one routable IPv4 and one link-local IPv6. Only the first
    // can be an External Endpoint: a link-local address carries no scope on the
    // wire, so advertising one would name two different hosts to two different
    // readers.
    let interfaces = FakeInterfaces::holding(&[
        HELD_V4,
        IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
    ]);
    let core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(rmule_core::CoreSettings::default())
        .interface_source(interfaces)
        .build();

    // Nothing has bound, so there is no row — absence, not an empty address.
    assert!(
        core.diagnostics_snapshot().addresses.is_empty(),
        "a core with no socket names no endpoint"
    );

    core.send(CoreCommand::Serve(ServeCommand::StartServing {
        listen_addr: SocketAddrV4::new(Ipv4Addr::LOCALHOST, 0),
        // Nothing answers there; the serve binds regardless, which is the
        // point — the listener is what makes an endpoint real.
    }))
    .await
    .expect("serve accepted");

    let rows = timeout(HANG_GUARD, async {
        loop {
            let rows = core.diagnostics_snapshot().addresses;
            if rows.iter().any(|row| row.role == SocketRole::Tcp) {
                return rows;
            }
            // A polled level: the snapshot has no watch to
            // await, so this sleep-polls rather than spinning a core.
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the listener's bind reached the rows");

    // A literal loopback listen address binds that address's family alone
    // (ADR-0085), so IPv6 never appears for this role however much the host
    // holds — the rows report what bound, not what was configured.
    assert!(
        !rows
            .iter()
            .any(|row| row.role == SocketRole::Tcp && row.family == AddressFamily::V6),
        "a family the listener never bound is absent, not unknown"
    );
    let tcp = rows
        .iter()
        .find(|row| row.role == SocketRole::Tcp && row.family == AddressFamily::V4)
        .expect("the IPv4 TCP row");

    let EndpointVerdict::Known { endpoint, tier } = tcp.verdict else {
        panic!("expected a Known verdict, got {:?}", tcp.verdict);
    };
    assert_eq!(
        tier,
        ConfidenceTier::Interface,
        "no server and no NAT: the address this host holds is the answer"
    );
    assert_eq!(
        endpoint.ip(),
        HELD_V4,
        "the link-local address is not an External Endpoint"
    );
    assert_ne!(
        endpoint.port(),
        0,
        "the port is the listener's resolved one, never the requested 0"
    );
    assert!(tcp.hint.is_none(), "one source cannot disagree with itself");

    // The serve activity keeps its real listener; dropping the core is how
    // every other leg with a live listener ends, and the task dies with it.
    drop(core);
}
