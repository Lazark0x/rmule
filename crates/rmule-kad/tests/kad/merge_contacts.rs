//! `KadCommand::MergeContacts` (ADR-0065 execution breakdown 3): the
//! running-node injection surface for a nodes.dat normal-reader load
//! (`rmule-bootstrap`'s pipeline). Each contact already carries a known Kad
//! ID, endpoint, TCP port, version, and verified flag decoded from a file, so
//! it enters the routing table directly through the ordinary admission path
//! -- no `KADEMLIA2_BOOTSTRAP_REQ` round trip needed, unlike `Bootstrap`
//! (config-endpoint / v3-bootstrap-edition dial candidates, which must earn
//! their way in via a response).
//!
//! Out of scope here: the nodes.dat decode itself (`tests/nodes_dat.rs`)
//! and the pipeline that dispatches this command from fetched bytes
//! (`rmule-bootstrap`).

use rmule_kad::{KadCommand, KadContact, KadContactState, KadEvent, KadId, KadOutput};
use rmule_primitives::session::drain;
use rmule_testkit::kad_node::{T0, endpoint, id, node};

#[test]
fn merge_contacts_adds_them_without_any_dial_round_trip() {
    let mut node = node();
    let verified = KadContact::new(id(0x10), endpoint(1, 4672), 4662, 8).into_verified();
    let unverified = KadContact::new(id(0x20), endpoint(2, 4672), 4662, 8);

    node.handle_command(
        T0,
        KadCommand::MergeContacts {
            contacts: vec![verified, unverified],
        },
    );

    let outputs = drain(|| node.poll_output());
    assert!(
        outputs
            .iter()
            .all(|output| !matches!(output, KadOutput::Datagram { .. })),
        "merging file-loaded contacts must never dial them: {outputs:?}"
    );
    let added: Vec<KadId> = outputs
        .iter()
        .filter_map(|output| match output {
            KadOutput::Event(KadEvent::ContactAdded { id, .. }) => Some(*id),
            _ => None,
        })
        .collect();
    assert_eq!(added, vec![id(0x10), id(0x20)]);
}

#[test]
fn merge_contacts_marks_each_entry_responded_and_preserves_its_own_verified_bit() {
    let mut node = node();
    let verified = KadContact::new(id(0x10), endpoint(1, 4672), 4662, 8).into_verified();
    let unverified = KadContact::new(id(0x20), endpoint(2, 4672), 4662, 8);

    node.handle_command(
        T0,
        KadCommand::MergeContacts {
            contacts: vec![verified, unverified],
        },
    );
    drain(|| node.poll_output());

    let stored_verified = node.routing_table().get(id(0x10)).expect("stored");
    let stored_unverified = node.routing_table().get(id(0x20)).expect("stored");
    assert_eq!(
        stored_verified.state(),
        KadContactState::Responded,
        "a file-loaded contact must be immediately queryable, matching aMule's \
         AddUnfiltered load semantics -- not stranded behind a live probe"
    );
    assert!(
        stored_verified.verified(),
        "its own verified bit rides along"
    );
    assert_eq!(stored_unverified.state(), KadContactState::Responded);
    assert!(
        !stored_unverified.verified(),
        "an unverified file row must not be promoted to verified just by merging"
    );
}

#[test]
fn merge_contacts_reuses_the_ordinary_admission_path_a_self_id_row_is_rejected() {
    let mut node = node();
    // The node's own ID (0xAA) must never enter its own routing table -- the
    // same `RejectedSelf` rule ordinary network intake obeys. Proves this
    // command reuses the shared admission path rather than an unconditional
    // parallel insert.
    let self_claim = KadContact::new(id(0xAA), endpoint(9, 4672), 4662, 8);

    node.handle_command(
        T0,
        KadCommand::MergeContacts {
            contacts: vec![self_claim],
        },
    );

    let outputs = drain(|| node.poll_output());
    assert!(
        outputs.is_empty(),
        "a self-ID row must not be added or emit any event: {outputs:?}"
    );
    assert!(node.routing_table().is_empty());
}

#[test]
fn merge_contacts_with_an_empty_list_is_an_inert_no_op() {
    let mut node = node();
    node.handle_command(
        T0,
        KadCommand::MergeContacts {
            contacts: Vec::new(),
        },
    );

    assert!(drain(|| node.poll_output()).is_empty());
    assert!(node.routing_table().is_empty());
}
