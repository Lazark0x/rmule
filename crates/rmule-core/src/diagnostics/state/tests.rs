//! Tests for the live diagnostics store.
//! A snapshot taken before any bind carries no address rows — and that is the
//! honest answer, not an empty address.

use super::*;
use crate::address_learning::EndpointVerdict;

#[test]
fn address_rows_appear_only_for_the_families_a_role_bound() {
    let state = DiagnosticsState::new();
    assert!(
        state.snapshot().addresses.is_empty(),
        "no store installed: no rows to read"
    );

    let addresses = SharedAddressLearning::new();
    addresses.record_bind(
        SocketRole::Tcp,
        &rmule_net::family::FamilyBinds {
            bound: vec![AddressFamily::V4],
            refused: vec![(
                AddressFamily::V6,
                std::io::ErrorKind::AddrNotAvailable,
                "no route".to_owned(),
            )],
        },
        4662,
    );
    state.install_addresses(addresses);

    let rows = state.snapshot().addresses;
    assert_eq!(rows.len(), 1, "one bound family, one role: one row");
    assert_eq!(rows[0].family, AddressFamily::V4);
    assert_eq!(rows[0].role, SocketRole::Tcp);
    assert_eq!(
        rows[0].verdict,
        EndpointVerdict::Unknown,
        "bound is not learned"
    );
}
