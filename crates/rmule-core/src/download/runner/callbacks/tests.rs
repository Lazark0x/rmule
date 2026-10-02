//! The two-roads-one-key rule (ADR-0039 + ADR-0091), driven against the two
//! shared tables a pending callback is registered in.
//!
//! No sockets and no clock: the question is only which registrations exist
//! after each way a callback can end, because a registration left behind is
//! what would hand a download a second worker for a slot already taken.

use std::net::Ipv4Addr;

use rmule_primitives::{
    ClientId, Ed2kFileLink, Ed2kText, ExchangedSource, FileHash, PeerSource, SourceCryptOptions,
    UserHash,
};

use crate::adapters::{PendingCallbackEntry, TunnelClaimVerdict};

use super::*;

fn hash(byte: u8) -> UserHash {
    UserHash::from_bytes([byte; UserHash::BYTE_LEN])
}

fn file() -> Ed2kFileLink {
    Ed2kFileLink {
        name: Ed2kText::from_utf8("claimed"),
        size: 4096,
        file_hash: FileHash::from_bytes([0xCD; FileHash::BYTE_LEN]),
        part_hash_set: None,
        aich_root: None,
        ipv6_sources: Vec::new(),
        sources: Default::default(),
    }
}

/// A connected-server Low-ID candidate whose obfuscation-aware `0x44` item
/// carried the target's User Hash — the one rung-1 fact a source channel
/// really names, and the only key a claim can be filed under.
fn candidate_with_hash(low_id: u32, user_hash: UserHash) -> LowIdCandidate {
    LowIdCandidate::from_source(
        ExchangedSource::new(
            PeerSource::new(ClientId::from_u32(low_id), 4662),
            Some(user_hash),
            Some(SourceCryptOptions::from_byte(0x01)),
        ),
        None,
    )
    .expect("a Low-ID source is a candidate")
}

/// The same source as a plain `0x42` answer names it: an id and a port.
fn bare_candidate(low_id: u32) -> LowIdCandidate {
    LowIdCandidate::from_source(
        ExchangedSource::plain(PeerSource::new(ClientId::from_u32(low_id), 4662)),
        None,
    )
    .expect("a Low-ID source is a candidate")
}

/// One download's callback state, with the connected server the routing index
/// resolves a brain-side `server: None` against.
fn context() -> (CallbackContext, mpsc::Receiver<(CallbackKey, PeerWorker)>) {
    let (adopt_tx, adopt_rx) = mpsc::channel(4);
    (
        CallbackContext::new(
            Some(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 1), 4661)),
            super::CallbackFacts {
                reach: crate::reachability::SharedSelfReach::new(
                    crate::KadReachLevel::fixed(false),
                    crate::own_identity::SharedOwnIdentity::default(),
                    crate::natt::front::SharedNattFront::default(),
                ),
                our_tcp_port: 4662,
            },
            adopt_tx,
            mpsc::channel(4).0,
            SharedCallbackTable::default(),
            SharedTunnelClaims::default(),
        ),
        adopt_rx,
    )
}

/// Register the server-relayed road exactly as the `RequestCallback` arm
/// does: under the routing key the called-back peer will report.
async fn register_callback_road(
    ctx: &CallbackContext,
    callbacks: &SharedCallbackTable,
    key: CallbackKey,
) {
    callbacks.lock().await.register(
        ctx.routing_key(key),
        PendingCallbackEntry {
            own_status: rmule_peer::PartBitmap::downloader_empty(0),
            want_sources: true,
            file: file(),
            adopt_tx: ctx.adopt_tx.clone(),
        },
    );
}

/// The rule the callback model rests on: a callback is one pending thing with
/// two ways in, so ending it retracts *both* registrations and drops *both*
/// deadlines — whichever road landed, and whether it landed at all.
///
/// The endings differ only in which registration was already spent: a tunnel
/// adoption spent the claim on its way in, a callback adoption or a slot
/// release did not. Both must leave the same nothing behind.
#[tokio::test]
async fn ending_a_callback_retracts_both_roads_however_it_ended() {
    let target = hash(0xAB);
    let candidate = candidate_with_hash(7, target);
    let key = candidate.key();
    let callbacks = SharedCallbackTable::default();
    let claims = SharedTunnelClaims::default();

    for spent_by_tunnel in [true, false] {
        let (mut ctx, _adopt_rx) = context();
        register_callback_road(&ctx, &callbacks, key).await;
        ctx.deadlines.push(Reverse((
            tokio::time::Instant::now(),
            key,
            CallbackDeadline::SlotRelease,
        )));
        ctx.deadlines.push(Reverse((
            tokio::time::Instant::now(),
            key,
            CallbackDeadline::SilenceFallback,
        )));
        assert!(
            ctx.claim_tunnel(
                &claims,
                &candidate,
                &file(),
                rmule_peer::PartBitmap::downloader_empty(0),
                true
            )
            .await,
            "a candidate carrying a User Hash claims its Tunnel"
        );
        if spent_by_tunnel {
            assert!(matches!(
                claims.rule(target, target).await,
                TunnelClaimVerdict::Adopted(_)
            ));
        }

        ctx.end_callback(key, &callbacks, &claims).await;

        assert!(
            callbacks.lock().await.is_empty(),
            "the server-relayed road's routing entry is retracted"
        );
        assert!(
            matches!(
                claims.rule(target, target).await,
                TunnelClaimVerdict::Unclaimed
            ),
            "the punch's claim is retracted too, so no later Tunnel is adopted for it"
        );
        assert!(
            ctx.deadlines.is_empty(),
            "both deadlines under the one key are dropped"
        );
    }
}

/// A candidate no channel ever named a User Hash for claims nothing: there is
/// no key to file it under and no hello that could confirm one. Its fallback
/// is not cancelled — the server coordinator is asked by id — so what it
/// raises simply takes the serve road.
#[tokio::test]
async fn a_candidate_without_a_user_hash_claims_no_tunnel() {
    let claims = SharedTunnelClaims::default();
    let (mut ctx, _adopt_rx) = context();
    let candidate = bare_candidate(7);

    assert!(
        !ctx.claim_tunnel(
            &claims,
            &candidate,
            &file(),
            rmule_peer::PartBitmap::downloader_empty(0),
            true
        )
        .await,
        "a plain 0x42 candidate has no hash to be claimed under"
    );
    // Nothing was filed, so ending the callback has nothing to retract and
    // must not pretend otherwise.
    ctx.end_callback(candidate.key(), &SharedCallbackTable::default(), &claims)
        .await;
}

/// The claim is keyed by the *target's* hash while every deadline and
/// decision is keyed by the *callback*, so the two indexes must agree: a
/// download that claimed two targets retracts exactly the one whose callback
/// ended.
#[tokio::test]
async fn ending_one_callback_leaves_another_targets_claim_standing() {
    let claims = SharedTunnelClaims::default();
    let (mut ctx, _adopt_rx) = context();
    let first = candidate_with_hash(7, hash(0xAB));
    let second = candidate_with_hash(8, hash(0xCD));
    ctx.claim_tunnel(
        &claims,
        &first,
        &file(),
        rmule_peer::PartBitmap::downloader_empty(0),
        true,
    )
    .await;
    ctx.claim_tunnel(
        &claims,
        &second,
        &file(),
        rmule_peer::PartBitmap::downloader_empty(0),
        true,
    )
    .await;

    ctx.end_callback(first.key(), &SharedCallbackTable::default(), &claims)
        .await;

    assert!(
        matches!(
            claims.rule(hash(0xAB), hash(0xAB)).await,
            TunnelClaimVerdict::Unclaimed
        ),
        "the ended callback's claim is gone"
    );
    assert!(
        matches!(
            claims.rule(hash(0xCD), hash(0xCD)).await,
            TunnelClaimVerdict::Adopted(_)
        ),
        "the other target's claim still stands"
    );
}
