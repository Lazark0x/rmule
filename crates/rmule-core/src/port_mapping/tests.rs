//! **Port Mapping** tests (ADR-0086), deterministic tier: the race and its two
//! graces, the grade matrix, the renewal ladders, the epoch re-add, the backoff
//! and the `Degraded` rules — every one driven by explicit time against a
//! scripted backend answer, with no gateway and no socket.
//!
//! The fixture below is the shared vocabulary; each leg owns one behaviour.

mod departure;
mod family;
mod lease;
mod race;
mod rerace;

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use rmule_net::family::FamilyBinds;
use rmule_net::portmap::{MappingError, MappingProtocol};
use rmule_primitives::{AddressFamily, Ipv4Endpoint, PeerEndpoint};

use crate::address_learning::{SharedAddressLearning, SocketRole};

use super::{
    DesiredMapping, GrantAnswer, MappingCommand, MappingResult, PortMapper, PortMappingConfig,
    ProbeAnswer,
};

/// The eD2k TCP listen port every fixture binds.
pub(super) const TCP_PORT: u16 = 4662;
/// The one client-UDP port — peer reask, NAT-T and Kad share it (ADR-0057).
pub(super) const UDP_PORT: u16 = 4672;

/// A store with both IPv4 roles bound — the ordinary home-node shape, and the
/// one the **Desired Mapping Set** is derived from.
pub(super) fn bound_v4_store() -> SharedAddressLearning {
    let store = SharedAddressLearning::new();
    let v4 = FamilyBinds {
        bound: vec![AddressFamily::V4],
        refused: Vec::new(),
    };
    store.record_bind(SocketRole::Tcp, &v4, TCP_PORT);
    store.record_bind(SocketRole::Udp, &v4, UDP_PORT);
    store
}

/// A mapper over `store` with a fixed jitter seed, so every renewal instant in
/// these tests is replayable.
pub(super) fn mapper(store: SharedAddressLearning) -> PortMapper {
    PortMapper::new(PortMappingConfig::default(), store, 7)
}

/// Every command the mapper has queued, drained.
pub(super) fn drain(mapper: &mut PortMapper) -> Vec<MappingCommand> {
    std::iter::from_fn(|| mapper.next_command()).collect()
}

/// A probe answer naming the families a protocol can map.
pub(super) fn probed(
    protocol: MappingProtocol,
    families: &[AddressFamily],
    now: Instant,
    mapper: &mut PortMapper,
) {
    mapper.on_result(
        MappingResult::Probed {
            protocol,
            outcome: Ok(ProbeAnswer {
                families: families.to_vec(),
                epoch_reset: false,
            }),
        },
        now,
    );
}

/// A probe answer that says the protocol is not there.
pub(super) fn probe_absent(protocol: MappingProtocol, now: Instant, mapper: &mut PortMapper) {
    mapper.on_result(
        MappingResult::Probed {
            protocol,
            outcome: Err(MappingError::Unsupported(protocol)),
        },
        now,
    );
}

/// An external IPv4 endpoint in the documentation range.
pub(super) fn external(port: u16) -> PeerEndpoint {
    PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(203, 0, 113, 7), port))
}

/// A grant of `external_port` with an hour's lease.
pub(super) fn granted(external_port: u16) -> Result<GrantAnswer, MappingError> {
    Ok(GrantAnswer {
        external: external(external_port),
        lease: Some(Duration::from_secs(3600)),
        epoch_reset: false,
    })
}

/// A refusal carrying no hold-off.
pub(super) fn refused(protocol: MappingProtocol) -> Result<GrantAnswer, MappingError> {
    Err(MappingError::Refused {
        protocol,
        refusal: rmule_net::portmap::MappingRefusal::NoResources,
        hold_off: None,
    })
}

/// Answer every `Map` command the mapper has queued with what `answer` says
/// about that mapping, and report which mappings were asked for.
pub(super) fn answer_maps(
    mapper: &mut PortMapper,
    now: Instant,
    mut answer: impl FnMut(DesiredMapping) -> Result<GrantAnswer, MappingError>,
) -> Vec<DesiredMapping> {
    let commands = drain(mapper);
    let mut asked = Vec::new();
    for command in commands {
        if let MappingCommand::Map {
            protocol, mapping, ..
        } = command
        {
            asked.push(mapping);
            mapper.on_result(
                MappingResult::Mapped {
                    protocol,
                    mapping,
                    outcome: answer(mapping),
                },
                now,
            );
        }
    }
    asked
}

/// Race to an installed `Exact` set over `protocol` and return the mapper,
/// its store and the instant everything was granted at — the shared fixture
/// every leg that starts from an already-mapped session builds on.
pub(super) fn mapped_over(
    protocol: MappingProtocol,
    lease: Option<Duration>,
) -> (PortMapper, SharedAddressLearning, Instant) {
    let t0 = Instant::now();
    let store = bound_v4_store();
    let mut mapper = PortMapper::new(
        PortMappingConfig {
            protocols: protocol.mask_bit(),
            ..PortMappingConfig::default()
        },
        store.clone(),
        7,
    );
    mapper.start(t0);
    let _ = drain(&mut mapper);
    probed(protocol, &[AddressFamily::V4], t0, &mut mapper);
    answer_maps(&mut mapper, t0, |mapping| {
        Ok(GrantAnswer {
            external: external(mapping.internal_port),
            lease,
            epoch_reset: false,
        })
    });
    let _ = drain(&mut mapper);
    (mapper, store, t0)
}

/// The store's verdict for one role in IPv4 — what an advert would read.
pub(super) fn verdict_port(store: &SharedAddressLearning, role: SocketRole) -> Option<u16> {
    store
        .endpoint(AddressFamily::V4, role)
        .known()
        .map(|endpoint| endpoint.port())
}
