//! The Kad Storer and Publisher for **file sources**: serving inbound
//! `KADEMLIA2_PUBLISH_SOURCE_REQ` / `SEARCH_SOURCE_REQ` out of the bounded
//! source index, and driving this node's own publish registrations on their
//! republish cadence.
//!
//! The storer policy constants are this file's. The per-key cap, lifetime and
//! tolerance are aMule-matched (documentation-backed, framing note
//! "Source-publish layouts"); the total cap is rmule anti-flood policy —
//! aMule's source index is unbounded in key count.

use std::time::Duration;

use super::{KadEvent, KadNode, KadNodeDiagnostic, KadPublishRejection, ScheduledPublish};
use crate::lookup::kad_wire_id;
use crate::lookup_walk::KadWalkPurpose;
use crate::messages::{Kad2Message, KadPublishedSource};
use crate::net;
use crate::source_result::{
    OLD_MAX_FILE_SIZE, SOURCETYPE_BUDDY, SOURCETYPE_BUDDY_LARGE, SOURCETYPE_DIRECT,
    SOURCETYPE_DIRECT_LARGE, SOURCETYPE_FIREWALLED_UDP,
};
use crate::source_store::StoreOutcome;
use crate::{
    KadEnvelope, KadId, KadInstant, KadNodeEndpoint, KadPublishPosture, KadPublishRequest,
    KadSourceLookupRequest, KadSourceRow, encode_source_result, opcode::KADEMLIA2_PUBLISH_RES_ACK,
};

impl KadNode {
    /// Most stored entries per file key; a publish past it evicts the key's
    /// oldest entry (aMule's `KADEMLIAMAXSOURCEPERFILE`, held exactly).
    pub const MAX_SOURCES_PER_KEY: usize = 1000;

    /// Most stored entries across all keys; net-new entries past it are
    /// rejected with a diagnostic (rmule policy, no aMule counterpart).
    pub const MAX_SOURCE_INDEX_TOTAL: usize = 16_384;

    /// How long an indexed entry lives (aMule's `KADEMLIAREPUBLISHTIMES`,
    /// 5 h — publishers republish on the same cadence).
    pub const STORED_SOURCE_LIFETIME: Duration = Duration::from_secs(5 * 60 * 60);

    // Publisher policy constants. The republish cadence is aMule-matched;
    // the ack window is rmule policy, symmetric with the search window's
    // role (a deterministic bound for the sim tier, not wire compatibility).

    /// How long after a `0x44` fan-out solicited acks are consumed.
    pub const PUBLISH_ACK_WINDOW: Duration = Duration::from_secs(15);

    /// How often a registered publication re-walks and re-publishes
    /// (aMule's `KADEMLIAREPUBLISHTIMES`, the storer lifetime — entries are
    /// refreshed on the same cadence they expire).
    pub const SOURCE_REPUBLISH_INTERVAL: Duration = Duration::from_secs(5 * 60 * 60);

    /// Bit 0 of a `0x4B` publish response's options byte: the storer requests a
    /// `0x4C` publish-res-ack (ADR-0062, aMule `Process2PublishResponse`).
    const PUBLISH_RES_ACK_REQUEST_BIT: u8 = 0x01;

    /// The **Kad Storer**'s publish intake: gate by tolerance, project the
    /// parsed fields into a [`KadSourceRow`] whose IP is the *observed*
    /// datagram sender (never a published claim), index it bounded, and ack
    /// only what was actually indexed — rejects are wire-silent like aMule's.
    pub(super) fn on_publish_source_req(
        &mut self,
        now: KadInstant,
        from: KadNodeEndpoint,
        file: KadId,
        source_id: [u8; 16],
        source: &KadPublishedSource,
    ) {
        // aMule's tolerance gate with its LAN bypass: private-range senders
        // (the mesh tiers and the private capture harness) are always
        // acceptable; everyone else must publish near this node's ID.
        if !net::is_lan_ip(from.ip())
            && net::distance_top_word(self.config.id, file) > net::PUBLISH_TOLERANCE
        {
            self.emit_diagnostic(KadNodeDiagnostic::PublishOutsideTolerance { from });
            return;
        }
        let Some(source_type) = source.source_type else {
            self.emit_diagnostic(KadNodeDiagnostic::PublishRejected {
                from,
                reason: KadPublishRejection::MissingSourceType,
            });
            return;
        };
        let tcp_port = match source.tcp_port {
            Some(port) if port != 0 => port,
            _ => {
                self.emit_diagnostic(KadNodeDiagnostic::PublishRejected {
                    from,
                    reason: KadPublishRejection::MissingTcpPort,
                });
                return;
            }
        };

        let row = KadSourceRow {
            source_id,
            source_type,
            ip: from.ip(),
            tcp_port,
            udp_port: source.udp_port_tag.unwrap_or_else(|| from.udp_port()),
            encryption: source.encryption,
            // A buddy contact is indexed only for the source types that mean
            // one (3/5); on any other type the tags are noise, and re-serving
            // them would invent a callback route the publisher never claimed.
            // Its `bi6` rides inside, re-served beside `ip6`.
            buddy: match source_type {
                SOURCETYPE_BUDDY | SOURCETYPE_BUDDY_LARGE => source.buddy,
                _ => None,
            },
            // Re-served on the answer, as kno's storer does.
            ipv6: source.ipv6,
        };
        match self.source_store.publish(
            file,
            row,
            source.file_size,
            now + Self::STORED_SOURCE_LIFETIME,
        ) {
            StoreOutcome::Stored { load, rows_for_key } => {
                self.emit_event(KadEvent::SourceIndexed {
                    key: file,
                    rows_for_key,
                });
                self.send(
                    from,
                    &Kad2Message::PublishRes {
                        file,
                        load,
                        options: 0,
                    },
                );
            }
            StoreOutcome::RejectedIndexFull => {
                self.emit_diagnostic(KadNodeDiagnostic::PublishRejected {
                    from,
                    reason: KadPublishRejection::IndexFull,
                });
            }
        }
    }

    /// The **Kad Storer**'s search answer: select unexpired size-matching
    /// rows, apply the requester's start offset and the result budget, and
    /// RE-ENCODE them from parsed state (`encode_source_result`) — the answer
    /// can never contain publish-datagram bytes. Zero rows answer nothing on
    /// the wire (aMule posture); the served event is emitted either way.
    pub(super) fn on_search_source_req(
        &mut self,
        now: KadInstant,
        from: KadNodeEndpoint,
        target: KadId,
        start_position: u16,
        file_size: u64,
    ) {
        let rows: Vec<KadSourceRow> = self
            .source_store
            .lookup(now, target, file_size)
            .into_iter()
            .skip(usize::from(start_position))
            .take(Self::SOURCE_RESULT_BUDGET)
            .collect();
        for envelope in encode_source_result(self.config.id, target, &rows) {
            self.send_envelope(from, &envelope);
        }
        self.emit_event(KadEvent::SourceSearchServed {
            from,
            target,
            rows: rows.len(),
        });
    }

    /// Start the walk for a source-lookup request (see `lookup_walk.rs` for
    /// the state machine and its termination budgets).
    pub(super) fn start_source_search(&mut self, now: KadInstant, request: KadSourceLookupRequest) {
        let target = request.kad_target();
        if self.walks.iter().any(|walk| walk.target() == target) {
            self.emit_diagnostic(KadNodeDiagnostic::DuplicateSourceSearch { target });
            return;
        }
        self.start_walk(now, KadWalkPurpose::SearchSources(request));
    }

    /// Register a publication and publish it immediately; `tick` republishes
    /// it every [`Self::SOURCE_REPUBLISH_INTERVAL`] from each start.
    pub(super) fn register_publish(&mut self, now: KadInstant, request: KadPublishRequest) {
        let target = request.kad_target();
        if self
            .scheduled_publishes
            .iter()
            .any(|scheduled| scheduled.request.kad_target() == target)
        {
            self.emit_diagnostic(KadNodeDiagnostic::DuplicatePublish { target });
            return;
        }
        self.scheduled_publishes.push(ScheduledPublish {
            request,
            next_at: now + Self::SOURCE_REPUBLISH_INTERVAL,
        });
        self.start_publish_walk(now, request);
    }

    /// Stop republishing `request`'s file.
    pub(super) fn withdraw_publish(&mut self, request: KadPublishRequest) {
        let target = request.kad_target();
        self.scheduled_publishes
            .retain(|scheduled| scheduled.request.kad_target() != target);
    }

    /// Launch one publish walk now, unless the target is already being
    /// walked (a republish firing while the previous walk still runs).
    pub(super) fn start_publish_walk(&mut self, now: KadInstant, request: KadPublishRequest) {
        let target = request.kad_target();
        if self.walks.iter().any(|walk| walk.target() == target) {
            return;
        }
        self.start_walk(now, KadWalkPurpose::PublishSource(request));
    }

    /// Route a `KADEMLIA2_PUBLISH_RES` to the publish walk that fanned a
    /// `0x44` to `from` for `file`. The gate order mirrors the search side:
    /// endpoint first (an unsolicited ack is never consumed), then the acked
    /// key, then at most one count per fanned endpoint.
    pub(super) fn on_publish_res(
        &mut self,
        now: KadInstant,
        from: KadNodeEndpoint,
        file: KadId,
        load: u8,
        options: u8,
    ) {
        if !self.walks.iter().any(|walk| walk.is_publish_endpoint(from)) {
            self.emit_diagnostic(KadNodeDiagnostic::UnsolicitedPublishRes { from });
            return;
        }
        let Some(walk) = self
            .walks
            .iter_mut()
            .find(|walk| walk.is_publish_endpoint(from) && walk.target() == file)
        else {
            self.emit_diagnostic(KadNodeDiagnostic::PublishResTargetMismatch { from });
            return;
        };
        let purpose = walk.purpose();
        let (counted, actions) = walk.accept_publish_ack(from);
        if counted {
            if matches!(purpose, KadWalkPurpose::PublishKeyword { .. }) {
                // Collect the load for the keyword's re-publish embargo, folded
                // in when the walk completes.
                if let Some(round) = self
                    .keyword_publishes
                    .iter_mut()
                    .find(|r| r.keyword == file)
                {
                    round.loads.push(load);
                }
                self.emit_event(KadEvent::KeywordPublishAcked {
                    keyword: file,
                    from,
                    load,
                });
            } else {
                self.emit_event(KadEvent::PublishAcked {
                    target: file,
                    from,
                    load,
                });
            }
        }
        self.apply_walk_actions(now, purpose, actions);

        // The `0x4C` hook (ADR-0062), live on the threaded crypt provenance:
        // aMule answers a `0x4B` that set options bit 0 with a null-payload
        // KADEMLIA2_PUBLISH_RES_ACK, but only when the datagram carried a crypt
        // sender key (`Process2PublishResponse`) — a plaintext `0x4B` still
        // draws nothing, byte-identical to a keyless aMule.
        if options & Self::PUBLISH_RES_ACK_REQUEST_BIT != 0 && self.crypt_sender_key(from).is_some()
        {
            self.send_envelope(
                from,
                &KadEnvelope::plain(KADEMLIA2_PUBLISH_RES_ACK, Vec::new()),
            );
        }
    }

    /// This node as a `0x44` announcement: own TCP port, the size (narrowed or widened to
    /// `TAG_FILESIZE`'s `CTagVarInt` width), the source
    /// ID as the User Hash in Kad wire order, and — only while the chooser
    /// reports a Known IPv6 — the `ip6` tag (ADR-0087).
    ///
    /// The **source type** follows aMule's ladder (aMule
    /// `src/kademlia/kademlia/Search.cpp:820-880`, Fork Pin `ab483654`), and
    /// the node decides none of its rungs itself:
    ///
    /// 1. a publisher that can be called back by **direct UDP** publishes
    ///    type 6 — no buddy trio, whatever the size. aMule tests
    ///    this first (`:823-835`) with the very predicate that lights bit 3
    ///    of its `TAG_ENCRYPTION` (`CPrefs::GetMyConnectOptions`,
    ///    `Prefs.cpp:224-226`), so rmule reads it *from that bit* of the byte
    ///    [`crate::KadCommand::SetPublishConnectOptions`] stated: the row type
    ///    and the byte cannot disagree, and core's `ConnectOptionsFeed` stays
    ///    the one owner of both;
    /// 2. otherwise a firewalled posture with a held buddy makes type 3 (5
    ///    above the u32 size range) carrying `TAG_SERVERIP`/`TAG_SERVERPORT`/
    ///    `TAG_BUDDYHASH` — and `bi6` when the buddy's IPv6 is known — read
    ///    from [`crate::KadCommand::SetPublishPosture`] alone — core's
    ///    `FirewalledSlot::publish_buddy_info`;
    /// 3. a firewalled posture with no buddy publishes **nothing** (`None`):
    ///    aMule's `PrepareToStop` (`Search.cpp:626-628`, `4e8f2b3c`) — a
    ///    direct row for a node nobody can dial costs the storer a slot and
    ///    sends every asker to a dead port (ADR-0058);
    /// 4. otherwise the direct type 1 (4 large).
    ///
    /// The layout is **capture-pinned** against a firewalled stock aMule's own
    /// `0x44` (`tests/fixtures/buddy/captured/amule-233-publish-source-req-20260922`):
    /// tag order `SOURCETYPE, SERVERIP, SERVERPORT, BUDDYHASH, SOURCEPORT,
    /// FILESIZE, ENCRYPTION`, the buddy trio at `UINT8`/`UINT32`/`UINT16`/
    /// 32-character string, and `TAG_BUDDYHASH` in **upper-case** hex.
    ///
    /// Two departures from aMule, both deliberate:
    ///
    /// - `TAG_ENCRYPTION` carries what the driver stated
    ///   ([`crate::KadCommand::SetPublishConnectOptions`]) and is absent
    ///   until it states something. aMule always emits it — the captured row
    ///   carries `0x00`, last in the list — and rmule emitting a `0` nobody
    ///   stated would claim "no crypt, no NAT-T, no direct callback" as a
    ///   fact rather than as a silence. The uTP NAT-T bit is what lets a
    ///   Low-ID downloader punch this row through its buddy.
    /// - `TAG_SOURCEUPORT` is absent on both sides, for the same reason by
    ///   different routes: aMule's `CPrefs::m_useExternKadPort` starts `true`,
    ///   so its publisher skips the tag, and rmule has no internal port worth
    ///   preferring over the storer's own observation of where the datagram
    ///   came from.
    pub(super) fn publish_source_req(&self, request: &KadPublishRequest) -> Option<Kad2Message> {
        let file_size = request.target().file_size();
        let large = file_size > OLD_MAX_FILE_SIZE;
        let callable_by_udp = self.publish_connect_options.is_some_and(|byte| {
            rmule_primitives::SourceCryptOptions::from_byte(byte).supports_direct_udp_callback()
        });
        let (source_type, buddy) = match (callable_by_udp, self.publish_posture, large) {
            (true, _, _) => (SOURCETYPE_FIREWALLED_UDP, None),
            (false, KadPublishPosture::Firewalled { buddy: Some(buddy) }, false) => {
                (SOURCETYPE_BUDDY, Some(buddy))
            }
            (false, KadPublishPosture::Firewalled { buddy: Some(buddy) }, true) => {
                (SOURCETYPE_BUDDY_LARGE, Some(buddy))
            }
            (false, KadPublishPosture::Firewalled { buddy: None }, _) => return None,
            (false, KadPublishPosture::Reachable, false) => (SOURCETYPE_DIRECT, None),
            (false, KadPublishPosture::Reachable, true) => (SOURCETYPE_DIRECT_LARGE, None),
        };
        Some(Kad2Message::PublishSourceReq {
            file: request.kad_target(),
            source_id: kad_wire_id(*self.config.user_hash.as_bytes()),
            source: KadPublishedSource {
                source_type: Some(source_type),
                tcp_port: Some(self.config.tcp_port),
                // No `TAG_SOURCEUPORT`, as the captured publish carries none:
                // a publisher omitting it tells the storer to index the port
                // it *observed* the datagram arrive from, which is the only
                // one a NAT in the path leaves correct. The tag would
                // overwrite that observation with an internal port nothing
                // outside can reach.
                udp_port_tag: None,
                // The `TAG_FILESIZE` tag itself has no width ceiling:
                // `encode_published_source` narrows or widens it with
                // `CTagVarInt`'s own rule, so every size this node holds is
                // always `Some`. The `large` row-type choice above is a
                // separate fact, keyed on `OLD_MAX_FILE_SIZE` rather than on
                // the tag's width — this field does not gate it.
                file_size: Some(file_size),
                encryption: self.publish_connect_options,
                // The `ip6` tag is gated on a Known address (ADR-0087): it is
                // the fact, so publishing one rmule does not hold would invite
                // dials to nowhere. `bi6` rides inside `buddy`, as core's slot
                // stated it.
                ipv6: self.advertised_ipv6,
                buddy,
            },
        })
    }
}
