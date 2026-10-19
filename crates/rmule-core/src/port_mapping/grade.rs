//! One backend's **trial** of the whole **Desired Mapping Set**, and the rule
//! that grades it (ADR-0086).
//!
//! A probe only says a protocol is *there*. What a gateway will actually grant
//! is learned by asking it for the real set and reading the answer — which is
//! also why neither UDP backend uses PCP's `PREFER_FAILURE`: a pre-emptive
//! refusal would hide what the router *would* have given, and a mismatched UDP
//! grant is a useful fact rather than a failure.
//!
//! The grading rule is the one place the eD2k constraint becomes code. The
//! hello advertises one TCP port and has no external-port tag, so "granted" and
//! "granted on the port we asked for" are different outcomes and only the
//! second is a High-ID.
//!
//! A trial is graded **per family**, and only on the rows its protocol can
//! express. The High-ID, the hello and Kad all ride on IPv4, so the IPv4 grade
//! leads: an IPv4-only backend that grants every IPv4 row on its own port is
//! `Exact` where it matters even on a host that also wants IPv6 pinholes, and a
//! PCP trial that pinholes IPv6 but shifts the IPv4 TCP port cannot outrank it.

use std::collections::{BTreeMap, BTreeSet};

use rmule_net::portmap::{MappingError, MappingProtocol};
use rmule_primitives::AddressFamily;

use super::{DesiredMapping, DesiredMappingSet, GrantAnswer, MappingGrade};

/// Where a completed trial ranks (ADR-0086): the grade of the set's **lead
/// family**, then the grade of the other one. Ordered field by field, so the
/// lead family decides and the other only breaks a tie.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Standing {
    /// The grade over the lead family's rows — what decides a High-ID, ends a
    /// race and fires the reachability recheck.
    pub(crate) lead: MappingGrade,
    /// The grade over the other family's rows; `None` when the set wants none.
    pub(crate) other: MappingGrade,
}

impl Standing {
    /// Whether the trial granted anything at all worth installing.
    pub(crate) fn granted_anything(self) -> bool {
        self > Self::default()
    }
}

/// One protocol's attempt at the whole desired set: every answer it gave, and
/// how many are still outstanding.
#[derive(Clone, Debug)]
pub(crate) struct Trial {
    /// The protocol being trialled.
    pub(crate) protocol: MappingProtocol,
    /// The rows whose answer is still expected — only those `protocol` can
    /// express. The trial is judged only when this empties — grading a
    /// half-answered trial would rank a slow gateway below a fast one that
    /// granted less — and an answer for a row it is not awaiting (a renewal
    /// of the same protocol, a duplicate) is not this trial's.
    outstanding: BTreeSet<DesiredMapping>,
    /// What it granted, keyed by the mapping asked for.
    pub(crate) grants: BTreeMap<DesiredMapping, GrantAnswer>,
    /// The longest hold-off a refusal in this trial asked for, raw. RFC 6887
    /// §7.4 makes it attacker-controlled input, so the mapper clamps it before
    /// pacing anything on it.
    pub(crate) hold_off: Option<std::time::Duration>,
}

impl Trial {
    /// A trial of `protocol` awaiting one answer per mapping in `desired` it
    /// can express.
    pub(crate) fn new(protocol: MappingProtocol, desired: &DesiredMappingSet) -> Self {
        Self {
            protocol,
            outstanding: desired.expressible(protocol).collect(),
            grants: BTreeMap::new(),
            hold_off: None,
        }
    }

    /// Record one answer.
    pub(crate) fn record(
        &mut self,
        mapping: DesiredMapping,
        outcome: Result<GrantAnswer, MappingError>,
    ) {
        if !self.outstanding.remove(&mapping) {
            return;
        }
        match outcome {
            Ok(grant) => {
                self.grants.insert(mapping, grant);
            }
            Err(error) => self.hold_off = self.hold_off.max(error.hold_off()),
        }
    }

    /// Close the trial at its deadline (ADR-0086): every row still unanswered
    /// is given up on and handed back, so the caller records it as a
    /// [`Timeout`](MappingError::Timeout) and a gateway that never answers
    /// one row cannot hold the race open for the session.
    pub(crate) fn expire(&mut self) -> BTreeSet<DesiredMapping> {
        std::mem::take(&mut self.outstanding)
    }

    /// Whether every mapping has answered.
    pub(crate) fn is_complete(&self) -> bool {
        self.outstanding.is_empty()
    }

    /// This trial's rank against the set it was asked for.
    pub(crate) fn standing(&self, desired: &DesiredMappingSet) -> Standing {
        let lead = desired.lead_family();
        let other = match lead {
            AddressFamily::V4 => AddressFamily::V6,
            AddressFamily::V6 => AddressFamily::V4,
        };
        Standing {
            lead: grade_family(desired, &self.grants, lead),
            other: grade_family(desired, &self.grants, other),
        }
    }

    /// Whether this trial granted **every** row the set wants, each on its
    /// own port — nothing left for another protocol to improve on.
    pub(crate) fn is_whole_set_exact(&self, desired: &DesiredMappingSet) -> bool {
        desired.mappings().iter().all(|mapping| {
            self.grants
                .get(mapping)
                .is_some_and(|grant| grant.external.port() == mapping.internal_port)
        })
    }
}

/// The grading rule (ADR-0086) over one family's rows:
/// `Exact` > `Mismatched` > `Partial` > `None`. A family the set does not want
/// grades `None`, so it never separates two trials.
///
/// Kept as a free function so the matrix is provable without building a trial,
/// and so the one sentence that decides a High-ID — *every* external port
/// equals its internal port — has exactly one home.
pub(crate) fn grade_family(
    desired: &DesiredMappingSet,
    grants: &BTreeMap<DesiredMapping, GrantAnswer>,
    family: AddressFamily,
) -> MappingGrade {
    let rows = desired
        .mappings()
        .iter()
        .filter(|mapping| mapping.family == family);
    let (mut wanted, mut granted, mut exact) = (0_usize, 0_usize, true);
    for mapping in rows {
        wanted += 1;
        if let Some(grant) = grants.get(mapping) {
            granted += 1;
            exact &= grant.external.port() == mapping.internal_port;
        }
    }
    match (granted, wanted) {
        (0, _) => MappingGrade::None,
        (granted, wanted) if granted < wanted => MappingGrade::Partial,
        _ if exact => MappingGrade::Exact,
        _ => MappingGrade::Mismatched,
    }
}

/// Which of two completed trials wins (ADR-0086): the better standing, and on
/// a tie the preferred protocol.
///
/// Preference is *only* a tie-break. A UPnP grant on the exact port beats a PCP
/// grant on another port, because the second is a silent LowID and the first is
/// not — ranking by protocol first would pick the LowID.
pub(crate) fn better(
    challenger: (Standing, MappingProtocol),
    incumbent: (Standing, MappingProtocol),
) -> bool {
    match challenger.0.cmp(&incumbent.0) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => challenger.1 < incumbent.1,
    }
}
