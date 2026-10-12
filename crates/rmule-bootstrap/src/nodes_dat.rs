//! The nodes.dat acquisition pipeline (ADR-0065 execution breakdown 3).
//!
//! Unlike server.met, aMule's nodes.dat fetch (`UpdateNotesDat`,
//! `amule.cpp#L2016`) is user-/EC-triggered only — no first-run auto-fetch
//! exists at all (an empty routing table just logs and waits,
//! `RoutingZone.cpp#L221`). rmule preserves that asymmetry in its *defaults*:
//! [`should_auto_fetch_nodes_dat`](crate::should_auto_fetch_nodes_dat) reads a
//! switch that is OFF out of the box, so the Join Sequence
//! (`rmule_core::join`) acquires nothing unattended unless a front-end asks.
//! One does — the `rmule` TUI (ADR-0067 amendment), whose only
//! other Kad recovery route is a peer handoff the user may never trigger.
//!
//! **Try-normal-then-fallback dispatch** (the two readers' handoff contract,
//! documented on `rmule_kad`'s own bootstrap module): [`decode_nodes_dat`]
//! tries the normal reader ([`NodesDat::decode`]) first; on
//! [`NodesDatError::BootstrapEdition`], it hands the *identical, unmodified*
//! bytes to [`BootstrapDialList::load_v3_bootstrap_edition`] — the dedicated
//! v3 reader re-parses from the leading marker rather than resuming a shared
//! position, so no offset bookkeeping crosses the two readers.
//!
//! The outcome is a [`NodesDatInstall`] *plan*, mirroring the server.met
//! pipeline's plan-not-effect posture: "v1/v2-merge" contacts
//! ([`NodesDatInstall::Contacts`]) are the caller's cue to inject them into a
//! running [`rmule_kad::KadNode`] via `KadCommand::MergeContacts` — no
//! bootstrap dial round trip needed, each contact already carries a known Kad
//! ID earned by the file itself. "v3-bootstrap-list" candidates
//! ([`NodesDatInstall::BootstrapCandidates`]) land in the caller's
//! [`BootstrapDialList`] and are never merged into a routing table directly;
//! the caller feeds them into the running node's one Bootstrap Dial List
//! (`KadCommand::SeedBootstrapDialList`, the same command the config-endpoint
//! seeds use — unifying both sources), which dials them one at a time on the
//! 15 s / 2 s cadence (ADR-0067).

use rmule_kad::{
    BootstrapDialList, BootstrapEditionError, KadBootstrapNode, KadContact, KadId, NodesDat,
    NodesDatError,
};
use thiserror::Error;

use crate::fetcher::{FetchError, Fetcher};

/// Why a nodes.dat acquisition produced no install plan.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum NodesDatPipelineError {
    /// The fetch itself failed — nothing was parsed.
    #[error("nodes.dat fetch failed: {0}")]
    Fetch(#[from] FetchError),

    /// The leading `u32` was nonzero: a legacy version-0 file, refused
    /// outright by the normal reader — contact Kad versions are unknowable
    /// (`NodesDatError::TooOld`).
    #[error("nodes.dat is a legacy version-0 file, refused outright")]
    TooOld,

    /// The v3 bootstrap-edition fallback reader also refused the bytes: an
    /// exact `count * 25 == remaining` mismatch, or the caller's
    /// [`BootstrapDialList`] already held candidates from an earlier load.
    #[error("v3 bootstrap-edition nodes.dat rejected: {0}")]
    BootstrapEdition(BootstrapEditionError),
}

/// The reconciled outcome of one nodes.dat acquisition — a *plan* the caller
/// injects into a running `KadNode`, never an applied effect (the
/// server.met pipeline's own plan-not-effect posture).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodesDatInstall {
    /// The normal reader (v1/v2/v3-non-bootstrap) decoded these contacts —
    /// aMule's "v1/v2-merge" semantics: each already carries a known Kad ID,
    /// endpoint, TCP port, version, and verified flag, so the caller merges
    /// them directly into the running node's routing table
    /// (`KadCommand::MergeContacts`) — no bootstrap dial round trip needed.
    Contacts(Vec<KadContact>),
    /// The v3 bootstrap-edition reader decoded and selected these
    /// closest-50-by-XOR-distance candidates, already loaded into the
    /// caller's [`BootstrapDialList`] — aMule's "v3-bootstrap-list"
    /// semantics: dial candidates only, never merged into the routing table
    /// directly.
    BootstrapCandidates(Vec<KadBootstrapNode>),
}

/// Run the try-normal-then-fallback dispatch against already-fetched bytes,
/// with no I/O of its own.
///
/// Tries the normal reader first ([`NodesDat::decode`]); on
/// [`NodesDatError::BootstrapEdition`], hands the identical `bytes` to
/// `dial_list`'s [`BootstrapDialList::load_v3_bootstrap_edition`] — the
/// two readers' handoff contract. `own_id` is this node's own Kad ID, needed
/// only by the bootstrap-edition reader's closest-50 XOR-distance selection.
pub fn decode_nodes_dat(
    bytes: &[u8],
    own_id: KadId,
    dial_list: &mut BootstrapDialList,
) -> Result<NodesDatInstall, NodesDatPipelineError> {
    match NodesDat::decode(bytes) {
        Ok(nodes_dat) => Ok(NodesDatInstall::Contacts(nodes_dat.into_contacts())),
        Err(NodesDatError::TooOld) => Err(NodesDatPipelineError::TooOld),
        Err(NodesDatError::BootstrapEdition) => dial_list
            .load_v3_bootstrap_edition(bytes, own_id)
            .map(|()| NodesDatInstall::BootstrapCandidates(dial_list.candidates().to_vec()))
            .map_err(NodesDatPipelineError::BootstrapEdition),
    }
}

/// Run the nodes.dat pipeline: bounded GET → [`decode_nodes_dat`]'s
/// try-normal-then-fallback dispatch.
///
/// **One-shot**: this makes exactly one [`Fetcher::get`] call, and only when
/// *called*. Its one automatic call site — the Join Sequence's Kad-seed leg
/// (`rmule_core::join`) — is gated by
/// [`should_auto_fetch_nodes_dat`](crate::should_auto_fetch_nodes_dat), whose
/// switch is OFF by default (aMule's own asymmetry: `UpdateNotesDat` is
/// user-/EC-triggered only).
pub async fn fetch_nodes_dat<F>(
    fetcher: &F,
    url: &str,
    max_bytes: usize,
    own_id: KadId,
    dial_list: &mut BootstrapDialList,
) -> Result<NodesDatInstall, NodesDatPipelineError>
where
    F: Fetcher + Sync,
{
    let bytes = fetcher.get(url, max_bytes).await?;
    decode_nodes_dat(&bytes, own_id, dial_list)
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use rmule_kad::{KadContactState, KadNodeEndpoint};

    use super::*;
    use crate::fixture::{FakeFetcher, NODES_DAT_CAP as CAP};

    // --- nodes.dat payload builders (deterministic-tier fixtures, NOT aMule
    // captures — same posture as the Kad readers' hand-built vectors) ------

    fn id(byte: u8) -> KadId {
        KadId::from_bytes([byte; KadId::BYTE_LEN])
    }

    fn ip(byte: u8) -> Ipv4Addr {
        Ipv4Addr::new(203, 0, 113, byte)
    }

    /// One 25-byte v1-shape contact row: `[id 16][ip 4, low octet
    /// first][udp 2 LE][tcp 2 LE][version 1]`.
    fn row_v1(kad_id: KadId, addr: Ipv4Addr, udp_port: u16, tcp_port: u16, version: u8) -> Vec<u8> {
        let mut bytes = kad_id.as_bytes().to_vec();
        let mut octets = addr.octets();
        octets.reverse();
        bytes.extend_from_slice(&octets);
        bytes.extend_from_slice(&udp_port.to_le_bytes());
        bytes.extend_from_slice(&tcp_port.to_le_bytes());
        bytes.push(version);
        bytes
    }

    /// A v2 row: the v1 row plus the 9-byte extension (`CKadUDPKey` + the
    /// verified byte).
    fn row_v2(
        kad_id: KadId,
        addr: Ipv4Addr,
        udp_port: u16,
        tcp_port: u16,
        version: u8,
        verified: bool,
    ) -> Vec<u8> {
        let mut bytes = row_v1(kad_id, addr, udp_port, tcp_port, version);
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.push(u8::from(verified));
        bytes
    }

    /// A whole nodes.dat normal-format payload: `[0u32][fileVersion
    /// u32]([bootstrapEdition u32])[count u32][rows...]`.
    fn normal_file(file_version: u32, rows: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = 0u32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&file_version.to_le_bytes());
        bytes.extend_from_slice(&u32::try_from(rows.len()).unwrap().to_le_bytes());
        for row in rows {
            bytes.extend_from_slice(row);
        }
        bytes
    }

    /// A whole v3 bootstrap-edition nodes.dat payload: `[0u32][3u32][1u32]
    /// [count u32][rows...]`.
    fn bootstrap_file(rows: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = 0u32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&u32::try_from(rows.len()).unwrap().to_le_bytes());
        for row in rows {
            bytes.extend_from_slice(row);
        }
        bytes
    }

    const OWN_ID: fn() -> KadId = || id(0xFF);

    const URL: &str = "http://mirror/nodes.dat";

    // --- command-only gate ---------------------------------------------------

    #[tokio::test]
    async fn the_pipeline_fetches_only_when_explicitly_invoked() {
        let bytes = normal_file(1, &[row_v1(id(1), ip(1), 4672, 4662, 8)]);
        let fetcher = FakeFetcher::serving(bytes);
        assert_eq!(
            fetcher.call_count(),
            0,
            "constructing the fetcher/fixture must not itself trigger a fetch"
        );

        let mut dial_list = BootstrapDialList::new();
        let install = fetch_nodes_dat(&fetcher, URL, CAP, OWN_ID(), &mut dial_list)
            .await
            .expect("explicit command succeeds");

        assert_eq!(
            fetcher.call_count(),
            1,
            "exactly one fetch, and only in response to the explicit call"
        );
        assert!(matches!(install, NodesDatInstall::Contacts(_)));
    }

    // --- try-normal-then-fallback dispatch ------------------------------------

    #[test]
    fn a_v1_normal_file_dispatches_to_the_normal_reader_as_a_contacts_plan() {
        let bytes = normal_file(
            1,
            &[
                row_v1(id(1), ip(1), 4672, 4662, 8),
                row_v1(id(2), ip(2), 4672, 4662, 8),
            ],
        );
        let mut dial_list = BootstrapDialList::new();

        let install =
            decode_nodes_dat(&bytes, OWN_ID(), &mut dial_list).expect("normal reader succeeds");

        let NodesDatInstall::Contacts(contacts) = install else {
            panic!("expected a Contacts plan, got {install:?}");
        };
        assert_eq!(
            contacts.iter().map(KadContact::id).collect::<Vec<_>>(),
            vec![id(1), id(2)]
        );
        assert!(
            dial_list.is_empty(),
            "the normal reader never touches the dial list"
        );
    }

    #[test]
    fn a_v2_normal_file_preserves_each_contacts_own_verified_bit_in_the_plan() {
        let bytes = normal_file(
            2,
            &[
                row_v2(id(1), ip(1), 4672, 4662, 8, true),
                row_v2(id(2), ip(2), 4672, 4662, 8, false),
            ],
        );
        let mut dial_list = BootstrapDialList::new();

        let install =
            decode_nodes_dat(&bytes, OWN_ID(), &mut dial_list).expect("normal reader succeeds");

        let NodesDatInstall::Contacts(contacts) = install else {
            panic!("expected a Contacts plan, got {install:?}");
        };
        let verified: Vec<(KadId, bool)> =
            contacts.iter().map(|c| (c.id(), c.verified())).collect();
        assert_eq!(verified, vec![(id(1), true), (id(2), false)]);
    }

    #[test]
    fn a_v3_bootstrap_edition_file_falls_back_to_the_dedicated_reader_as_a_dial_plan() {
        // Closer-to-own-ID row first is NOT required in the file; the reader
        // itself selects closest-first, proving the dispatch reaches the
        // real bootstrap-edition selection logic rather than a pass-through.
        let bytes = bootstrap_file(&[
            row_v1(id(0x02), ip(1), 4672, 4662, 8),
            row_v1(id(0x01), ip(2), 4672, 4662, 8),
        ]);
        let mut dial_list = BootstrapDialList::new();

        let install = decode_nodes_dat(&bytes, id(0), &mut dial_list)
            .expect("bootstrap-edition fallback succeeds");

        let NodesDatInstall::BootstrapCandidates(candidates) = install else {
            panic!("expected a BootstrapCandidates plan, got {install:?}");
        };
        assert_eq!(
            candidates.iter().map(|c| c.kad_id()).collect::<Vec<_>>(),
            vec![Some(id(0x01)), Some(id(0x02))],
            "closest-by-XOR-distance-to-0, closest first"
        );
        // The caller's own dial list is the thing actually loaded -- not
        // just the returned plan value.
        assert_eq!(dial_list.len(), 2);
        assert_eq!(dial_list.candidates(), candidates.as_slice());
    }

    #[test]
    fn a_legacy_v0_file_is_a_pipeline_error_with_no_install() {
        let bytes = 1u32.to_le_bytes().to_vec();
        let mut dial_list = BootstrapDialList::new();

        let outcome = decode_nodes_dat(&bytes, OWN_ID(), &mut dial_list);

        assert_eq!(outcome, Err(NodesDatPipelineError::TooOld));
        assert!(dial_list.is_empty());
    }

    #[test]
    fn a_bootstrap_edition_length_mismatch_leaves_the_dial_list_untouched() {
        // Declares 2 rows but the file only carries one row's worth of bytes.
        let mut bytes = 0u32.to_le_bytes().to_vec();
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&1u32.to_le_bytes());
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&row_v1(id(1), ip(1), 4672, 4662, 8));
        let mut dial_list = BootstrapDialList::new();

        let outcome = decode_nodes_dat(&bytes, OWN_ID(), &mut dial_list);

        assert_eq!(
            outcome,
            Err(NodesDatPipelineError::BootstrapEdition(
                BootstrapEditionError::LengthMismatch
            ))
        );
        assert!(
            dial_list.is_empty(),
            "a rejected fallback load must not mutate the list"
        );
    }

    #[test]
    fn a_second_bootstrap_edition_load_against_an_already_loaded_list_is_refused() {
        let first = bootstrap_file(&[row_v1(id(1), ip(1), 4672, 4662, 8)]);
        let second = bootstrap_file(&[row_v1(id(2), ip(2), 4672, 4662, 8)]);
        let mut dial_list = BootstrapDialList::new();

        decode_nodes_dat(&first, OWN_ID(), &mut dial_list).expect("first load succeeds");
        let outcome = decode_nodes_dat(&second, OWN_ID(), &mut dial_list);

        assert_eq!(
            outcome,
            Err(NodesDatPipelineError::BootstrapEdition(
                BootstrapEditionError::AlreadyLoaded
            ))
        );
        assert_eq!(
            dial_list.len(),
            1,
            "the refused second load changes nothing"
        );
        assert_eq!(dial_list.candidates()[0].kad_id(), Some(id(1)));
    }

    // --- transport-level behavior ---------------------------------------------

    #[tokio::test]
    async fn fetch_failure_surfaces_with_exactly_one_call() {
        let fetcher = FakeFetcher::failing(FetchError::Transport {
            url: URL.to_owned(),
            detail: "connection refused".to_owned(),
        });
        let mut dial_list = BootstrapDialList::new();

        let outcome = fetch_nodes_dat(&fetcher, URL, CAP, OWN_ID(), &mut dial_list).await;

        assert!(matches!(
            outcome,
            Err(NodesDatPipelineError::Fetch(FetchError::Transport { .. }))
        ));
        assert_eq!(fetcher.call_count(), 1);
    }

    #[tokio::test]
    async fn oversized_body_is_rejected_by_the_cap() {
        let big = normal_file(1, &[row_v1(id(1), ip(1), 4672, 4662, 8)]);
        let cap = big.len() - 1;
        let fetcher = FakeFetcher::serving(big);
        let mut dial_list = BootstrapDialList::new();

        let outcome = fetch_nodes_dat(&fetcher, URL, cap, OWN_ID(), &mut dial_list).await;

        assert_eq!(
            outcome,
            Err(NodesDatPipelineError::Fetch(FetchError::TooLarge { cap }))
        );
    }

    // --- injection determinism: the plan actually drives a real KadNode ------

    #[test]
    fn the_contacts_plan_injects_deterministically_into_a_real_kad_node() {
        let bytes = normal_file(
            2,
            &[
                row_v2(id(1), ip(1), 4672, 4662, 8, true),
                row_v2(id(2), ip(2), 4672, 4662, 8, false),
            ],
        );
        let mut dial_list = BootstrapDialList::new();
        let install = decode_nodes_dat(&bytes, OWN_ID(), &mut dial_list).expect("decode");
        let NodesDatInstall::Contacts(contacts) = install else {
            panic!("expected a Contacts plan");
        };

        let mut node = rmule_kad::KadNode::new(rmule_kad::KadNodeStart::new(
            rmule_kad::KadNodeConfig {
                id: OWN_ID(),
                tcp_port: 4662,
                udp_port: 4672,
                user_hash: rmule_kad::UserHash::from_bytes([0xEE; 16]),
            },
            rmule_kad::KadInstant::EPOCH,
        ));
        node.handle_command(
            rmule_kad::KadInstant::EPOCH,
            rmule_kad::KadCommand::MergeContacts { contacts },
        );
        let outputs = rmule_primitives::session::drain(|| node.poll_output());

        assert!(
            outputs
                .iter()
                .all(|output| !matches!(output, rmule_kad::KadOutput::Datagram { .. })),
            "injecting file-loaded contacts must never dial them"
        );
        let stored_verified = node.routing_table().get(id(1)).expect("merged");
        let stored_unverified = node.routing_table().get(id(2)).expect("merged");
        assert_eq!(stored_verified.state(), KadContactState::Responded);
        assert!(stored_verified.verified());
        assert!(!stored_unverified.verified());
        // The endpoint the pipeline decoded is exactly the endpoint the node
        // now holds -- the low-octet-first IP + LE port decode round-trips
        // all the way through to the live routing table.
        assert_eq!(
            stored_verified.endpoint(),
            KadNodeEndpoint::new(ip(1), 4672)
        );
    }
}
