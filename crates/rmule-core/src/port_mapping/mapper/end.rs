//! The ends of a grant (ADR-0086, "Every grant has one owner and one end"):
//! a held lease that departs, is re-probed or is quit; an open race that is
//! interrupted; and an answer that lands after the trial that asked for it
//! closed. Each end leaves no holder behind — not the gateway, not the lease
//! table, and not the `MappingGrant` observation in **Address Learning**.

use super::{
    DesiredMapping, DesiredMappingSet, GrantAnswer, MappingCommand, MappingError, MappingProtocol,
    MappingStatus, Phase, PortMapper,
};

impl PortMapper {
    /// End every held lease whose row is not in `derived` (the row left the
    /// set: its socket re-bound on another port, or stopped).
    ///
    /// The gateway keeps forwarding a departed row until its lease expires
    /// unless told otherwise, so it is handed back with the same
    /// [`Release`](MappingCommand::Release) release-on-exit uses, ahead of the
    /// new row's `Map`. A row with no lease here was never granted — there is
    /// nothing to release.
    pub(super) fn end_departed(&mut self, derived: &DesiredMappingSet) {
        let departed: Vec<_> = self
            .leases
            .keys()
            .filter(|mapping| !derived.mappings().contains(mapping))
            .copied()
            .collect();
        for mapping in departed {
            self.end_lease(mapping, true);
        }
    }

    /// Drop `mapping`'s lease, released on the gateway when `release` says
    /// so, and withdraw what it fed Address Learning.
    pub(super) fn end_lease(&mut self, mapping: DesiredMapping, release: bool) {
        let Some(lease) = self.leases.remove(&mapping) else {
            return;
        };
        self.readd_queue.retain(|queued| *queued != mapping);
        self.readd_outstanding.remove(&mapping);
        if release {
            self.commands.push_back(MappingCommand::Release {
                protocol: lease.protocol,
                mapping,
                external_port: lease.external.port(),
            });
        }
        self.withdraw_grant(mapping);
    }

    /// Withdraw the `MappingGrant` observation `mapping` fed: its role's port
    /// always, its family's address only when no other `Mapped` lease in that
    /// family still stands behind the same gateway address.
    pub(super) fn withdraw_grant(&self, mapping: DesiredMapping) {
        let sibling_held = self.leases.iter().any(|(held, lease)| {
            *held != mapping
                && held.family == mapping.family
                && lease.status == MappingStatus::Mapped
        });
        self.addresses
            .withdraw_mapping_grant(mapping.role, mapping.family, sibling_held);
    }

    /// Close an open race without a winner — a set change, a reprobe or a
    /// quit landed while trials were open — and hand back every grant they
    /// hold, the challenger's included. Answers still in flight are released
    /// as they land ([`release_stray`](Self::release_stray)).
    pub(super) fn abandon_trials(&mut self) {
        let phase = std::mem::replace(&mut self.phase, Phase::Idle);
        let Phase::Trialling {
            current, completed, ..
        } = phase
        else {
            self.phase = phase;
            return;
        };
        self.release_trials(
            completed
                .into_iter()
                .map(|(trial, _)| trial)
                .chain(std::iter::once(current)),
        );
    }

    /// An answer no open trial and no held lease is waiting for: a trial that
    /// closed at its deadline, or a race a set change or reprobe interrupted.
    /// A grant in it is forwarding on the gateway with nothing here to renew
    /// or release it, so it is released at once — unless it names the very
    /// mapping a held lease of the same protocol already owns (the same
    /// internal port under PCP or NAT-PMP, the same external port under UPnP),
    /// which a release would take down.
    pub(super) fn release_stray(
        &mut self,
        protocol: MappingProtocol,
        mapping: DesiredMapping,
        outcome: &Result<GrantAnswer, MappingError>,
    ) {
        let Ok(grant) = outcome else {
            return;
        };
        let owned = self.leases.get(&mapping).is_some_and(|held| {
            held.protocol == protocol
                && (!protocol.keys_by_external_port()
                    || held.external.port() == grant.external.port())
        });
        if !owned {
            self.commands.push_back(MappingCommand::Release {
                protocol,
                mapping,
                external_port: grant.external.port(),
            });
        }
    }
}
