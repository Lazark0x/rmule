//! Low-ID versus High-ID: the classification a `ClientId` carries and the
//! `PeerSource` that delegates to it.

use rmule_primitives::{ClientId, PeerSource};

#[test]
fn client_id_classifies_low_and_high_ids() {
    assert!(ClientId::from_u32(1).is_low_id());
    assert!(ClientId::from_u32(ClientId::LOW_ID_THRESHOLD - 1).is_low_id());
    assert!(ClientId::from_u32(ClientId::LOW_ID_THRESHOLD).is_high_id());
    assert!(ClientId::from_u32(u32::MAX).is_high_id());
}

#[test]
fn peer_source_delegates_low_id_classification() {
    let low = PeerSource::new(ClientId::from_u32(1), 4662);
    let high = PeerSource::new(ClientId::from_u32(ClientId::LOW_ID_THRESHOLD), 4662);

    assert!(low.is_low_id());
    assert!(high.is_high_id());
}
