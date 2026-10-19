//! The iterative lookup walk: starting a walk for a purpose, folding
//! `KADEMLIA2_RES` rows back into it, and enacting the actions it asks for
//! (queries to send, contacts to remember, an outcome to report). The walk
//! state machine itself is [`crate::lookup_walk`].
//!
//! The walk policy constants are this file's. The α shape mirrors the captured
//! aMule behaviour (the requester fanned its lookup three wide); the concrete
//! timeouts and budgets are rmule policy — deterministic knobs for the sim
//! tier, not wire compatibility.

use std::net::IpAddr;
use std::time::Duration;

use rmule_primitives::Informant;

use super::{KadCallbackWalkEnd, KadEvent, KadNode, KadNodeDiagnostic};
use crate::buddy::BuddyMessage;
use crate::keyword_store::encode_search_key_req;
use crate::lookup_walk::{KadLookupWalk, KadWalkAction, KadWalkOutcome, KadWalkPurpose};
use crate::messages::Kad2Message;
use crate::routing::KadAnswerRefusal;
use crate::{KadContact, KadId, KadInstant, KadNodeEndpoint};

impl KadNode {
    /// Concurrent in-flight `KADEMLIA2_REQ` queries per walk.
    pub const LOOKUP_ALPHA: usize = 3;

    /// Contacts requested per `KADEMLIA2_REQ` — aMule's FIND_VALUE count,
    /// matching the captured `0x21` (count byte `0x02`).
    pub const LOOKUP_CONTACT_COUNT: u8 = 2;

    /// How long one queried contact may stay silent before its slot frees.
    pub const LOOKUP_QUERY_TIMEOUT: Duration = Duration::from_secs(3);

    /// Most `KADEMLIA2_REQ` queries one walk may ever send — the hard stop
    /// for steering adversaries that always offer a closer contact.
    pub const LOOKUP_QUERY_BUDGET: usize = 24;

    /// Contacts seeded into a walk from the routing table at start.
    pub const LOOKUP_SEED_CONTACTS: usize = 50;

    /// `KADEMLIA2_SEARCH_SOURCE_REQ` recipients after convergence — the α=3
    /// fan the capture recipe observed.
    pub const SEARCH_FANOUT: usize = 3;

    /// How long after the `0x34` fan-out solicited results are consumed.
    pub const SOURCE_SEARCH_WINDOW: Duration = Duration::from_secs(15);

    /// Most result rows one search consumes before completing early (aMule
    /// caps a search at 300 results). The storer serves at most this many
    /// rows per request for the same reason (aMule uses 300 on both sides).
    pub const SOURCE_RESULT_BUDGET: usize = 300;

    /// Most contacts one **Callback Walk** sends its `0x52` to. aMule's
    /// `FINDSOURCE` arm sends while its answer count has not passed
    /// `SEARCHFINDSOURCE_TOTAL` (20, `Defines.h:89`; the `>` check precedes
    /// the increment at `Search.cpp:1085`/`:1122`), so at most 21.
    pub const CALLBACK_WALK_ASK_BUDGET: usize = 21;

    /// Start a **Callback Walk** toward `buddy_id`, unless any
    /// walk already walks that target: aMule's `CSearchManager::StartSearch`
    /// refuses a second search for a target in its map
    /// (`SearchManager.cpp:153-160`), whatever its type, and the refusal is
    /// reported rather than swallowed — the caller is holding a slot on it.
    pub(super) fn start_callback_walk(
        &mut self,
        now: KadInstant,
        buddy_id: KadId,
        file_hash: rmule_primitives::FileHash,
        tcp_port: u16,
    ) {
        if self.walks.iter().any(|walk| walk.target() == buddy_id) {
            self.emit_event(KadEvent::CallbackWalkEnded {
                buddy_id,
                end: KadCallbackWalkEnd::AlreadyWalking,
            });
            return;
        }
        self.start_walk(
            now,
            KadWalkPurpose::CallbackWalk {
                buddy_id,
                file_hash,
                tcp_port,
            },
        );
    }

    pub(super) fn start_walk(&mut self, now: KadInstant, purpose: KadWalkPurpose) {
        let seeds: Vec<KadContact> = self
            .routing
            .select_closest_servable(purpose.kad_target(), Self::LOOKUP_SEED_CONTACTS)
            .into_iter()
            .copied()
            .collect();
        let (walk, actions) = KadLookupWalk::start(now, purpose, self.config.id, seeds);
        self.walks.push(walk);
        self.apply_walk_actions(now, purpose, actions);
    }

    /// Route a `KADEMLIA2_RES` to the walk that queried `from` for `target`.
    /// Anything else — echoed target no walk owns, an endpoint the walk never
    /// queried, a late answer past its query deadline — is unsolicited
    /// hearsay: diagnosed, payload discarded.
    pub(super) fn on_lookup_res(
        &mut self,
        now: KadInstant,
        from: KadNodeEndpoint,
        target: KadId,
        contacts: &[KadContact],
    ) {
        // A row no node can be at, then an IP-filtered one, is dropped before
        // any walk sees it (aMule `ProcessKademlia2Response`,
        // `KademliaUDPListener.cpp:732-733` — its checks run before the rows
        // reach the search manager *or* the routing zone), so a walk never
        // dials either. The responder is the party that named every row
        // (ADR-0085).
        let informant = Informant::Party(IpAddr::V4(from.ip()));
        let mut admitted = Vec::with_capacity(contacts.len());
        for &contact in contacts {
            let endpoint = contact.endpoint();
            if !crate::net::may_be_a_contact(informant, endpoint, contact.version()) {
                self.emit_diagnostic(KadNodeDiagnostic::ContactRefused { endpoint });
            } else if !self.contact_admission.admits(endpoint.ip()) {
                self.emit_diagnostic(KadNodeDiagnostic::ContactIpFiltered { endpoint });
            } else {
                admitted.push(contact);
            }
        }
        let Some(index) = self
            .walks
            .iter()
            .position(|walk| walk.target() == target && walk.awaits(from))
        else {
            self.emit_diagnostic(KadNodeDiagnostic::UnsolicitedLookupRes { from });
            return;
        };
        let purpose = self.walks[index].purpose();
        // A UDP firewall check's rows go to its tester as they are, never into
        // the table (`KademliaUDPListener.cpp:734-740`), and its walk dials
        // none of them. Any other walk's rows are taken one by one, in answer
        // order, as aMule takes them.
        let helper = matches!(purpose, KadWalkPurpose::UdpFirewallHelpers { .. });
        let mut dialable = Vec::with_capacity(admitted.len());
        if helper {
            dialable.clone_from(&admitted);
        } else {
            for &row in &admitted {
                let endpoint = row.endpoint();
                match self.take_answer_row(now, row) {
                    Ok(()) => dialable.push(row),
                    Err(KadAnswerRefusal::Kad1) => {
                        self.emit_diagnostic(KadNodeDiagnostic::ContactRefused { endpoint });
                    }
                    Err(KadAnswerRefusal::ContradictsStored) => {
                        self.emit_diagnostic(KadNodeDiagnostic::ContactContradictsStored {
                            endpoint,
                        });
                    }
                    Err(KadAnswerRefusal::Cap(cap)) => {
                        self.emit_diagnostic(KadNodeDiagnostic::ContactOverAdmissionCap {
                            endpoint,
                            cap,
                        });
                    }
                }
            }
        }
        let Some(actions) = self.walks[index].on_lookup_res(now, from, &dialable) else {
            self.emit_diagnostic(KadNodeDiagnostic::UnsolicitedLookupRes { from });
            return;
        };
        if helper {
            self.offer_udp_helper_rows(&admitted);
        }
        self.apply_walk_actions(now, purpose, actions);
    }

    /// Take one lookup-answer row as aMule's `ProcessKademlia2Response` does
    /// (`KademliaUDPListener.cpp:731-750`, ADR-0064). A Kad1 row never. A row
    /// of an ID the table does not hold is stored unverified and unqueried,
    /// under the bucket rules and admission caps of any add; a known ID's
    /// entry is left as it is (`AddUnfiltered` passes `update` false). The walk
    /// may dial the row when the table stored it or would accept it.
    fn take_answer_row(
        &mut self,
        now: KadInstant,
        row: KadContact,
    ) -> Result<(), KadAnswerRefusal> {
        if row.version() <= 1 {
            return Err(KadAnswerRefusal::Kad1);
        }
        if self.routing.get(row.id()).is_none() {
            let unverified =
                KadContact::new(row.id(), row.endpoint(), row.tcp_port(), row.version());
            let update = self.routing.upsert(now, unverified);
            if self.announce(unverified, update) {
                return Ok(());
            }
        }
        self.routing.accepts_answer_row(&row)
    }

    /// Translate walk actions into datagrams and events, then drop any walk
    /// that completed. A search/publish action's exact datagram (source `0x34`/
    /// `0x44` vs keyword `0x33`/`0x43`) and completion event are picked by the
    /// walk's purpose.
    pub(super) fn apply_walk_actions(
        &mut self,
        now: KadInstant,
        purpose: KadWalkPurpose,
        actions: Vec<KadWalkAction>,
    ) {
        let target = purpose.kad_target();
        for action in actions {
            match action {
                KadWalkAction::SendLookup { contact } => self.send(
                    contact.endpoint(),
                    &Kad2Message::LookupReq {
                        count: match purpose {
                            KadWalkPurpose::UdpFirewallHelpers { .. } => {
                                Self::UDP_HELPER_LOOKUP_CONTACT_COUNT
                            }
                            _ => Self::LOOKUP_CONTACT_COUNT,
                        },
                        target,
                        check: contact.id(),
                    },
                ),
                KadWalkAction::SendSearch { contact } => match purpose {
                    KadWalkPurpose::SearchSources(request) => self.send(
                        contact.endpoint(),
                        &Kad2Message::SearchSourceReq {
                            target,
                            start_position: 0,
                            file_size: request.target().file_size(),
                        },
                    ),
                    // The v1 requester emits the plain lead keyword — offset 0,
                    // no restrictive tree (aMule's unfiltered query).
                    KadWalkPurpose::SearchKeyword { target: keyword } => {
                        self.send_envelope(
                            contact.endpoint(),
                            &encode_search_key_req(keyword, 0, None),
                        );
                    }
                    _ => unreachable!("SendSearch is only emitted by search walks"),
                },
                KadWalkAction::SendPublish { contact } => match purpose {
                    // A firewalled node with no buddy states no row (aMule's `PrepareToStop`):
                    // the store is skipped.
                    KadWalkPurpose::PublishSource(request) => {
                        if let Some(publish) = self.publish_source_req(&request) {
                            self.send(contact.endpoint(), &publish);
                        }
                    }
                    KadWalkPurpose::PublishKeyword { target: keyword } => {
                        self.send_keyword_publish(contact.endpoint(), keyword);
                    }
                    _ => unreachable!("SendPublish is only emitted by publish walks"),
                },
                // ADR-0061: the convergence contact is asked to be our buddy.
                // `recruit_buddy` is the same emit the direct
                // [`KadCommand::RecruitBuddy`](crate::KadCommand::RecruitBuddy)
                // drives, so the `0x5A` answer passes the one recruit window.
                KadWalkAction::SendFindBuddy { contact } => {
                    self.recruit_buddy(now, contact.endpoint());
                }
                // aMule's `FINDSOURCE` arm sends through the Kad UDP listener
                // under the contact's key (`Search.cpp:1102-1119`), unlike the
                // endpoint-known `0x52` `TryToConnect` sends in the clear — a
                // walked contact's Kad version is known — so this rides the
                // node's obfuscation matrix like every other walk datagram.
                KadWalkAction::SendCallback { contact } => {
                    if let KadWalkPurpose::CallbackWalk {
                        buddy_id,
                        file_hash,
                        tcp_port,
                    } = purpose
                    {
                        let request = BuddyMessage::CallbackReq {
                            buddy_id,
                            file_hash,
                            requester_tcp_port: tcp_port,
                        };
                        self.send_envelope(contact.endpoint(), &request.encode());
                    }
                }
                KadWalkAction::Complete { outcome } => match outcome {
                    KadWalkOutcome::Search {
                        result_rows,
                        ended_by,
                    } => {
                        if let KadWalkPurpose::SearchKeyword { .. } = purpose {
                            self.keyword_searches
                                .retain(|search| search.target != target);
                            self.emit_event(KadEvent::KeywordSearchComplete {
                                keyword: target,
                                result_rows,
                                ended_by,
                            });
                        } else {
                            self.emit_event(KadEvent::SourceSearchComplete {
                                target,
                                result_rows,
                                ended_by,
                            });
                        }
                    }
                    KadWalkOutcome::Publish {
                        acked_stores,
                        ended_by,
                    } => {
                        if let KadWalkPurpose::PublishKeyword { .. } = purpose {
                            self.complete_keyword_publish(now, target, acked_stores, ended_by);
                        } else {
                            self.emit_event(KadEvent::PublishComplete {
                                target,
                                acked_stores,
                                ended_by,
                            });
                        }
                    }
                    // A self-lookup has no terminal fan-out and no completion
                    // event: the `SelfLookupStarted` at launch is the whole
                    // signal. The walk is dropped by the `retain` below.
                    KadWalkOutcome::SelfLookup | KadWalkOutcome::UdpFirewallHelpers => {}
                    KadWalkOutcome::FindBuddy { asked } => {
                        self.emit_event(KadEvent::BuddyWalkEnded { asked });
                    }
                    KadWalkOutcome::CallbackWalk { asked } => {
                        self.emit_event(KadEvent::CallbackWalkEnded {
                            buddy_id: target,
                            end: if asked == 0 {
                                KadCallbackWalkEnd::NoneNear
                            } else {
                                KadCallbackWalkEnd::Asked(asked)
                            },
                        });
                    }
                },
            }
        }
        self.walks.retain(|walk| !walk.is_complete());
    }
}
