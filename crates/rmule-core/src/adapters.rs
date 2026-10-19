//! The runtime seams (ADR-0031): every socket, datagram, and Kad-node concern
//! the core actor drives sits behind a trait declared here, so core owns policy
//! and never touches I/O itself. Each submodule carries one seam together with
//! the production adapter that implements it — source lookup, peer transfer,
//! serve, the UDP transports, and the Kad node — plus the shared handles those
//! adapters pass between one another.

// The **Awaited Inbound** registry: which download waits for which peer to
// reach us, by either key a pending callback has.
mod awaited_inbound;
// Every shared cell an adapter adopts from the builder.
mod cells;
mod dialed_serve;
// The Download Directory Scan's watch over `notify` (ADR-0103, "The watch").
mod directory_watch;
mod folder_watch;
// What every hello this node sends states about it.
mod hello_adverts;
// The wait for a peer's hello, dialed and accepted alike.
pub(crate) mod hello_wait;
mod inbound_triage;
mod ipv6_advert;
mod kad_runtime;
mod peer_transfer;
// The **Port Mapping** runtime (ADR-0086): the task that gives the sans-I/O
// `PortMapper` its sockets — one spawned backend call per emitted command, the
// answer fed back, the diagnostics level republished.
mod peer_link;
mod port_mapping;
mod serve_runtime;
mod served_link;
mod source_lookup;
mod udp_ports_advert;
mod udp_transport;

pub use kad_runtime::{
    ClientUdpBind, KadCells, KadEnableConfig, KadNodeIdentity, KadPumpStandIn, KadRuntimeFactory,
    KadShutdownHandle, KadShutdownSlot, KadSourceChannel, RuntimeKadChannel, RuntimeKadFactory,
};
pub use peer_transfer::{
    DownloadedPart, PeerDownloadOutcome, PeerTransferService, PeerWorker, PeerWorkerCommand,
    PeerWorkerEvent, RuntimePeerTransferService, WorkerBrief, WorkerOpening,
};
pub use serve_runtime::{
    AnnounceOutcome, DialBack, DialBackOutcome, RuntimeServeRuntimeService, ServeConnection,
    ServeInput, ServeOutput, ServeRuntimeService,
};
pub use source_lookup::{RuntimeSourceLookupService, SourceLookupOutcome, SourceLookupService};
pub(crate) use udp_transport::{RuntimeServerUdpTransport, ServerUdpTransport};

pub(crate) use awaited_inbound::{
    AdoptSender, AdoptionBrief, AwaitedInbound, AwaitedInboundHandle, CallbackKey, RetireSender,
};
// The question and its answer, named where a test outside the adapters asks
// the registry directly; production asks it only through the inbound triage.
#[cfg(test)]
pub(crate) use awaited_inbound::{InboundArrival, InboundVerdict};
pub(crate) use cells::AdapterCells;
pub(crate) use dialed_serve::SharedDialedServeSink;
pub(crate) use directory_watch::NotifyWatchStarter;
pub(crate) use folder_watch::NotifyFolderWatch;
pub(crate) use hello_adverts::HelloAdverts;
pub(crate) use ipv6_advert::SharedIpv6Advert;
#[cfg(test)]
pub(crate) use kad_runtime::KadPumpCommand;
pub(crate) use kad_runtime::{
    BuddyCallbackAsk, CallbackWalkAsk, CallbackWalkReply, KadPresenceChanges, KadPresenceLease,
    KadPresenceView, SharedKadBootstrap, SharedKadPump, request_kad_buddy_callback,
    request_kad_callback_walk, request_kad_recheck,
};
pub(crate) use peer_link::{AwaitedGrant, GrantSender, LinkName, LinkOffer, SharedPeerLinks};
pub(crate) use peer_transfer::advertises_complete;
pub(crate) use port_mapping::{
    DurablePortMappingPreferences, PortMappingControl, PortMappingHandle, PortMappingPreferences,
    SharedPeerPin, await_listener_mapping, spawn_port_mapping,
};
pub(crate) use serve_runtime::SharedTunnelAdmit;
// The admit channel's payload and the router behind it, named where a test
// drives the inbound path without a bound listener; the production path
// reaches both through the serve adapter.
pub(crate) use inbound_triage::InboundPeerDeps;
#[cfg(test)]
pub(crate) use inbound_triage::triage_inbound_connection;
#[cfg(test)]
pub(crate) use serve_runtime::AdmittedPeer;
pub(crate) use udp_ports_advert::SharedUdpPortsAdvert;
pub(crate) use udp_transport::{
    RuntimeClientUdpTransport, SERVER_UDP_OBFUSCATION_PORT_OFFSET, SERVER_UDP_PORT_OFFSET,
    relay_global_callbacks,
};

// Seam fixtures; `hello_wire` is shared with the firewalled front's tests,
// whose buddy dial sends a hello like every other road.
#[cfg(test)]
pub(crate) mod tests;
