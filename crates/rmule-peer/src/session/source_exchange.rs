//! Source exchange (ADR-0055): asking a peer for the sources it knows for a
//! file, and answering the same ask out of this node's own source set.
//!
//! Both directions are version-gated by the nibble the peers advertised in
//! their hellos — the answer's framing follows the asker's version, never
//! ours.

use rmule_primitives::{FileHash, PeerSource, SourceSighting};

use super::{PeerError, PeerEvent, PeerSession, ServerEvent};
use crate::RequesterEvent;
use crate::capability::{MiscOptions1, MiscOptions2};
use crate::multipacket::RequestItem;
use crate::source_exchange::ServedSourcesVersion;

/// What a peer's hello said about source exchange (ADR-0108): whether it
/// speaks the extended protocol, its SX1 nibble, and whether it advertised
/// SourceExchange2. The session reads its own ask gate off this value, and
/// the same value rides the [`PeerIdentity`](crate::PeerIdentity) to the
/// download, whose reask sweep needs the peer-side half of the gate after the
/// connection is gone.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SourceExchangeSupport {
    ext_protocol: bool,
    sx1_version: u8,
    sx2: bool,
}

impl SourceExchangeSupport {
    /// The facts as a hello states them.
    #[must_use]
    pub const fn new(ext_protocol: bool, sx1_version: u8, sx2: bool) -> Self {
        Self {
            ext_protocol,
            sx1_version,
            sx2,
        }
    }

    /// The peer-side conjuncts of aMule's `IsSourceRequestAllowed` (stock
    /// 2.3.3 `DownloadClient.cpp:191`): the extended protocol, and
    /// SourceExchange2 or an SX1 nibble above 1. A version-0 or version-1
    /// peer is never asked.
    #[must_use]
    pub const fn askable(self) -> bool {
        self.ext_protocol && (self.sx2 || self.sx1_version > 1)
    }

    /// Whether the peer speaks the extended (mule) protocol.
    #[must_use]
    pub const fn ext_protocol(self) -> bool {
        self.ext_protocol
    }

    /// The advertised SX1 nibble (`0` for none).
    #[must_use]
    pub const fn sx1_version(self) -> u8 {
        self.sx1_version
    }

    /// Whether the peer advertised SourceExchange2.
    #[must_use]
    pub const fn supports_sx2(self) -> bool {
        self.sx2
    }
}

impl PeerSession {
    /// The SX request sub-item per rmule's existing source-ask policy
    /// (ADR-0055): the v4 `0x83` ask iff the peer advertised SourceExchange2,
    /// else the v1 `0x81` — the ADR-0054 bundle composition's "SX request sub
    /// per the existing source-ask policy". Only a bundle carries the `0x83`
    /// form; the standalone framing sends either variant as the SX1 `0x81`
    /// (see `emit_standalone_file_request`).
    pub(super) fn sx_request_item(&self) -> RequestItem {
        if self
            .peer_misc_options2
            .is_some_and(MiscOptions2::supports_source_exchange2)
        {
            RequestItem::Sources2 {
                version: crate::source_exchange::SourceExchangeVersion::V4.as_u8(),
                options: 0,
            }
        } else {
            RequestItem::Sources
        }
    }

    /// What this peer's hello and any legacy `OP_EMULEINFO` said about source
    /// exchange — the facts the peer-side half of the ask gate reads.
    pub(super) fn source_exchange_support(&self) -> SourceExchangeSupport {
        SourceExchangeSupport {
            ext_protocol: self.peer_software.ext_protocol(),
            sx1_version: self
                .peer_misc_options
                .map_or(0, MiscOptions1::source_exchange_version),
            sx2: self
                .peer_misc_options2
                .is_some_and(MiscOptions2::supports_source_exchange2),
        }
    }

    /// Whether this peer may be asked for sources at all (ADR-0108): the
    /// peer-side half of the gate, [`SourceExchangeSupport::askable`]. The
    /// source-need and timing conjuncts are the core's, which states them as
    /// `want_sources`.
    pub(super) fn source_request_allowed(&self) -> bool {
        self.source_exchange_support().askable()
    }

    /// Ask a peer for more sources of `file_hash` with one standalone packet —
    /// always the bare-hash SX1 `OP_REQUESTSOURCES` (`0x81`), even to a peer
    /// that advertised `SupportsSourceEx2`: aMule 2.3.3's standalone `0x83`
    /// arm disconnects on the 19-byte SX2 form, and aMule itself
    /// only ever asks SX2 inside a multipacket (`SendFileRequest`,
    /// `DownloadClient.cpp`). The peer's `0x82`/`0x84` answer fans back
    /// through the same consume core (`route_answer_sources`). No-op before
    /// the hello exchange.
    pub(super) fn handle_request_sources(&mut self, file_hash: FileHash) {
        if !self.require_identified() || !self.source_request_allowed() {
            return;
        }
        // Record the solicitation: the consume core only accepts sources for a
        // file whose flow exists.
        self.per_file.entry(file_hash).or_default();
        self.emit_standalone_file_request(file_hash, &[RequestItem::Sources]);
    }

    /// Wire-event handler for an inbound `OP_ANSWERSOURCES` (`0x82`,
    /// ADR-0055) — a peer's answer to our SX1 ask. Its entries already carry
    /// each declaring server alongside the `SourceSighting` provenance, so
    /// they route straight through the shared consume core.
    pub(super) fn on_answer_sources(&mut self, a: crate::source_exchange::AnswerSources) {
        self.route_answer_sources(a.file_hash, a.sources);
    }

    /// Wire-event handler for an inbound `OP_ANSWERSOURCES2` (`0x84`, ADR-0055
    /// requester consume) — a peer's SX2 answer to our own `0x83` ask. Shares
    /// the entire consume core with `0x82`: same sanity filter, Low-ID routing,
    /// provenance survival, and per-file cap.
    pub(super) fn on_answer_sources2(&mut self, a: crate::source_exchange::AnswerSources2) {
        self.route_answer_sources(a.file_hash, a.sources);
    }

    /// The one consume core both source answers share (ADR-0055 "one semantic
    /// core"): the aMule-mirrored sanity filter, Low-ID routing rule, and
    /// per-file cap (`source_exchange::sanitize_and_route`). Sources are only
    /// accepted for a file we solicited — an unsolicited hash must not create
    /// per-file state. Emits `SourcesReceived` with only the
    /// surviving, actionable candidates; the cap is honored cumulatively via
    /// `FileFlow::sources_forwarded`.
    fn route_answer_sources(
        &mut self,
        file_hash: FileHash,
        entries: Vec<crate::source_exchange::SourceExchangeEntry>,
    ) {
        let own_endpoint =
            PeerSource::new(self.ctx.client_id, self.ctx.identity.tcp_port()).as_peer_endpoint();
        let Some(flow) = self.per_file.get_mut(&file_hash) else {
            return;
        };
        let sources = crate::source_exchange::sanitize_and_route(
            entries,
            own_endpoint,
            self.ctx.connected_server,
            flow.sources_forwarded,
        );
        flow.sources_forwarded += sources.len();
        self.core
            .push_event(PeerEvent::Requester(RequesterEvent::SourcesReceived {
                file_hash,
                sources,
            }));
    }

    /// Server Capability — surface a peer's source-exchange request to core
    /// (ADR-0055). The session picks the aMule-exact serve wire form here,
    /// since it holds the requester's advertised SX capability
    /// (`peer_misc_options`'s SX1 nibble, `peer_misc_options2`'s
    /// `SupportsSourceEx2`) plus the request's `requested` version byte, and
    /// keeps it for the answer; core applies its pools, filters and per-peer
    /// throttle to decide the list. `requested` is `0` for a plain
    /// `OP_REQUESTSOURCES` / `Sources` sub, or the SX2 `<ver>` byte of an
    /// `OP_REQUESTSOURCES2` / `Sources2` sub.
    pub(super) fn on_sources_requested(&mut self, file_hash: FileHash, requested: u8) {
        self.note_source_ask(file_hash, requested);
        self.core
            .push_event(PeerEvent::Server(ServerEvent::SourcesRequested {
                file_hash,
            }));
    }

    /// Keep the wire form `file_hash`'s answer goes out in.
    pub(super) fn note_source_ask(&mut self, file_hash: FileHash, requested: u8) {
        let version = self.served_sources_version(requested);
        self.served_sources.insert(file_hash, version);
    }

    /// The wire form a source ask carrying `requested` is answered in, picked
    /// from the asker's advertised source-exchange capability.
    fn served_sources_version(&self, requested: u8) -> ServedSourcesVersion {
        let nibble = self
            .peer_misc_options
            .map_or(0, MiscOptions1::source_exchange_version);
        let supports_sx2 = self
            .peer_misc_options2
            .is_some_and(MiscOptions2::supports_source_exchange2);
        ServedSourcesVersion::negotiate(nibble, supports_sx2, requested, self.peer_mod_misc())
    }

    /// Frame core's chosen source list as the answer opcode negotiated when
    /// the ask arrived and put it on the wire (ADR-0055). `Sx1` →
    /// `OP_ANSWERSOURCES` (`0x82`), `Sx2` → `OP_ANSWERSOURCES2` (`0x84`), both
    /// at the negotiated entry version's stride (the hybrid-id `>= v3`
    /// "uniform id rule" rides the codec). The framed answer is
    /// pack-attempted above `PEER_PACK_THRESHOLD` (354 bytes, ADR-0053): a
    /// popular file's long list ships as a `0xD4` packed frame; a short one
    /// stays plain. A list the entry form leaves empty sends nothing, aMule's
    /// `NULL` reply, and an answer to a file the peer never asked about is
    /// rejected.
    pub(super) fn answer_sources(&mut self, file_hash: FileHash, sources: Vec<SourceSighting>) {
        let Some(version) = self.served_sources.remove(&file_hash) else {
            self.reject(PeerError::SourcesNotAsked);
            return;
        };
        // `HasEd2kWireForm` (ADR-0087): a classic entry has one 32-bit id
        // field and no address block, so a native-IPv6 source is **omitted**
        // rather than written as its sentinel or a zero — either would name a
        // source the reader cannot resolve, and a zero would send it down a
        // callback nobody can broker. ExtSX records are the only shape that
        // can carry one.
        let entries = match version {
            ServedSourcesVersion::Sx1(_) | ServedSourcesVersion::Sx2(_) => classic_entries(sources),
            ServedSourcesVersion::Ext { .. } => sources
                .into_iter()
                .map(crate::source_exchange::SourceExchangeEntry::plain)
                .collect(),
        };
        if entries.is_empty() {
            return;
        }
        let count = entries.len();
        let entry_version = version.entry_version();
        let packet = match version {
            ServedSourcesVersion::Sx1(_) => crate::source_exchange::AnswerSources {
                file_hash,
                sources: entries,
            }
            .encode_packet(entry_version),
            ServedSourcesVersion::Sx2(_) => crate::source_exchange::AnswerSources2 {
                version: entry_version,
                file_hash,
                sources: entries,
            }
            .encode_packet(),
            // ExtSX (ADR-0087): the same two opcodes, the record form instead
            // of a stride.
            ServedSourcesVersion::Ext {
                sx2: true,
                emission,
            } => crate::source_exchange::AnswerSources2 {
                version: entry_version,
                file_hash,
                sources: entries,
            }
            .encode_ext_packet(emission),
            ServedSourcesVersion::Ext {
                sx2: false,
                emission,
            } => crate::source_exchange::AnswerSources {
                file_hash,
                sources: entries,
            }
            .encode_ext_packet(emission),
        };
        let packet = crate::compressed_frame::pack_peer_frame_if_over_threshold(packet);
        self.write_packet(packet);
        self.core
            .push_event(PeerEvent::Server(ServerEvent::SourcesAnswered {
                file_hash,
                count,
            }));
    }
}

/// The entries a **classic** source answer may carry: those with an ed2k wire
/// form (ADR-0087's `HasEd2kWireForm`). A native-IPv6 source has none, so it is
/// left out of the list rather than written as a value no reader can resolve.
fn classic_entries(
    sources: Vec<SourceSighting>,
) -> Vec<crate::source_exchange::SourceExchangeEntry> {
    sources
        .into_iter()
        .filter(|source| {
            source
                .as_peer_endpoint()
                .is_none_or(|endpoint| endpoint.ed2k_wire_form().is_some())
        })
        .map(crate::source_exchange::SourceExchangeEntry::plain)
        .collect()
}
