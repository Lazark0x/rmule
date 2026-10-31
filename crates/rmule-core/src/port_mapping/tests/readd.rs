//! The epoch re-add outside `Mapped` and the wake it leaves behind (ADR-0086,
//! "Leases, renewal, failure"): the answer is the re-add's in any phase, and a
//! past-due row is fired or it is no wake.

use std::time::{Duration, Instant};

use rmule_net::family::FamilyBinds;
use rmule_net::portmap::{MappingError, MappingProtocol};
use rmule_primitives::AddressFamily;

use crate::address_learning::{SharedAddressLearning, SocketRole};
use crate::port_mapping::{
    MappingCommand, MappingResult, PortMapper, PortMappingConfig, ProbeAnswer,
};

use super::{
    TCP_PORT, answer_maps, bound_v4_store, drain, granted, mapped_over, probe_absent, probed,
    refused,
};

const HOUR: Duration = Duration::from_secs(3600);

/// Every `Map` in `commands`.
fn maps(commands: &[MappingCommand]) -> Vec<MappingCommand> {
    commands
        .iter()
        .filter(|command| matches!(command, MappingCommand::Map { .. }))
        .cloned()
        .collect()
}

/// A reset reported by `protocol`'s probe, in a round that already opened.
fn reset_probe(mapper: &mut PortMapper, protocol: MappingProtocol, now: Instant) {
    mapper.on_result(
        MappingResult::Probed {
            protocol,
            round: mapper.round,
            outcome: Ok(ProbeAnswer {
                families: vec![AddressFamily::V4],
                epoch_reset: true,
            }),
        },
        now,
    );
}

/// Re-bind the TCP listener, so the UDP row survives a set change and the next
/// `start` opens a round with its lease kept.
fn move_the_listener(store: &SharedAddressLearning) {
    let v4 = FamilyBinds {
        bound: vec![AddressFamily::V4],
        refused: Vec::new(),
    };
    store.record_bind(SocketRole::Tcp, &v4, TCP_PORT + 1);
}

/// Every row of the installed set renews at `due`: none is left waiting on a
/// re-add that already answered.
fn assert_every_row_renews(mapper: &mut PortMapper, installed_at: Instant) {
    assert!(
        mapper.next_wake().is_some_and(|wake| wake > installed_at),
        "nothing is past due once the re-add and the trial have answered"
    );
    mapper.tick(installed_at + HOUR);
    let renewals = maps(&drain(mapper));
    assert_eq!(renewals.len(), 2, "both rows renew: {renewals:?}");
}

#[test]
fn a_re_add_answered_while_a_round_is_open_leaves_its_row_renewing() {
    // Two protocols and a short TCP grant: PCP wins but is not learned, so the
    // next round asks both and stays open on the one that has not answered.
    let t0 = Instant::now();
    let store = bound_v4_store();
    let mut mapper = PortMapper::new(
        PortMappingConfig {
            protocols: MappingProtocol::Pcp.mask_bit() | MappingProtocol::Upnp.mask_bit(),
            ..PortMappingConfig::default()
        },
        store.clone(),
        7,
    );
    mapper.start(t0);
    let _ = drain(&mut mapper);
    probed(MappingProtocol::Pcp, &[AddressFamily::V4], t0, &mut mapper);
    probed(MappingProtocol::Upnp, &[AddressFamily::V4], t0, &mut mapper);
    answer_maps(&mut mapper, t0, |mapping| {
        if mapping.role == SocketRole::Tcp {
            granted(mapping.internal_port + 1)
        } else {
            granted(mapping.internal_port)
        }
    });
    answer_maps(&mut mapper, t0, |_| refused(MappingProtocol::Upnp));
    let _ = drain(&mut mapper);

    // A router reboot: the bind opens the round, PCP reports the reset, and
    // the surviving row's re-add goes out and is answered inside the round.
    let reboot = t0 + Duration::from_secs(60);
    move_the_listener(&store);
    mapper.start(reboot);
    let _ = drain(&mut mapper);
    reset_probe(&mut mapper, MappingProtocol::Pcp, reboot);
    mapper.tick(reboot);
    let readded = answer_maps(&mut mapper, reboot, |mapping| {
        granted(mapping.internal_port)
    });
    assert_eq!(readded.len(), 1, "the surviving row is re-added");

    probe_absent(MappingProtocol::Upnp, reboot, &mut mapper);
    assert_eq!(
        answer_maps(&mut mapper, reboot, |mapping| granted(
            mapping.internal_port
        ))
        .len(),
        2,
        "the trial asks for the whole set"
    );
    let _ = drain(&mut mapper);
    assert_every_row_renews(&mut mapper, reboot);
}

#[test]
fn a_re_add_answered_inside_a_trial_of_its_row_is_not_the_trials_answer() {
    let (mut mapper, store, t0) = mapped_over(MappingProtocol::Pcp, Some(HOUR));
    let reboot = t0 + Duration::from_secs(60);
    move_the_listener(&store);
    mapper.start(reboot);
    let _ = drain(&mut mapper);
    // The learned method's short round closes on this answer: the trial and
    // the re-add of the surviving row are out together.
    reset_probe(&mut mapper, MappingProtocol::Pcp, reboot);
    mapper.tick(reboot);
    let mut asked = maps(&drain(&mut mapper));
    assert_eq!(asked.len(), 3, "two trial rows and one re-add");
    // The doubled row answers first, both times, so the trial is still open
    // for the re-add's answer.
    asked.sort_by_key(|command| match command {
        MappingCommand::Map { mapping, .. } => mapping.role != SocketRole::Udp,
        _ => true,
    });
    for command in asked {
        let MappingCommand::Map {
            protocol, mapping, ..
        } = command
        else {
            continue;
        };
        mapper.on_result(
            MappingResult::Mapped {
                protocol,
                mapping,
                outcome: granted(mapping.internal_port),
            },
            reboot,
        );
    }
    let _ = drain(&mut mapper);
    assert_every_row_renews(&mut mapper, reboot);
}

#[test]
fn a_past_due_row_held_by_a_re_add_is_no_wake() {
    let (mut mapper, _store, t0) = mapped_over(MappingProtocol::Pcp, Some(HOUR));
    let reset = t0 + Duration::from_secs(60);
    reset_probe(&mut mapper, MappingProtocol::Pcp, reset);
    let mut when = reset;
    for _ in 0..3 {
        mapper.tick(when);
        when += Duration::from_millis(100);
    }
    assert_eq!(maps(&drain(&mut mapper)).len(), 2, "both re-adds are out");

    // Neither re-add has answered and both leases fall past due: there is
    // nothing a tick could do, so the runtime must not wake to do it.
    let past_due = reset + 2 * HOUR;
    mapper.tick(past_due);
    assert!(
        maps(&drain(&mut mapper)).is_empty(),
        "a re-add holds its row"
    );
    assert_ne!(
        mapper.next_wake().map(|wake| wake <= past_due),
        Some(true),
        "a wake with no work behind it spins the runtime"
    );

    // The answer ends the hold: a refused re-add leaves its row past due, and
    // that row now fires, climbing its rung.
    let refused = Err(MappingError::Timeout(MappingProtocol::Pcp));
    for mapping in mapper.diagnostics().iter().map(|row| row.mapping) {
        mapper.on_result(
            MappingResult::Mapped {
                protocol: MappingProtocol::Pcp,
                mapping,
                outcome: refused.clone(),
            },
            past_due,
        );
    }
    mapper.tick(past_due);
    assert_eq!(maps(&drain(&mut mapper)).len(), 2, "both rows fire again");
    assert!(
        mapper.next_wake().is_some_and(|wake| wake > past_due),
        "fired rows moved up their rung"
    );
}
