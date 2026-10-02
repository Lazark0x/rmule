//! The claim vocabulary every NAT and IPv6 wave verdict is written in, and the
//! reader that turns a driver's own TOML row back into typed facts.
//!
//! Two things here are ADR-0045 posture rather than bookkeeping. First, every
//! claim carries an **evidence class** — `captured` when a counterparty's own
//! bytes settled it, `single-oracle` when exactly one implementation can
//! produce those bytes, `rmule-only` when both ends are rmule and no external
//! byte can exist, and `documented-absence` for a zero written down with its
//! reason. A verdict that said only "held" would lose the difference between a
//! row two bodies agreed on and a row one body asserted alone.
//!
//! Second, [`label`] takes the **weakest** claim: all `held` is `PASS`, a
//! `blocked` claim with no `absent` one is `OBSERVED`, and any `absent` claim
//! is `FAIL`. A `blocked` claim is one the bench *cannot drive at all* and
//! names why — the only honest alternative to a fabricated row.
//!
//! The vocabulary is shared across waves on purpose: a NAT-traversal negative and a
//! IPv6-dialect absence are the same kind of statement, and two copies of the scoring
//! rule would let them drift into two meanings of `OBSERVED`.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::nat::NatTypeProof;

/// What kind of evidence a claim rests on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum Evidence {
    /// A counterparty's own bytes settled it, and more than one implementation
    /// can produce them.
    Captured,
    /// A counterparty's own bytes settled it, but exactly one implementation
    /// exists that can produce them (ADR-0087's `0x26` and the `OP_SERVERLIST`
    /// v6 block, on eNode-go alone; a `0xB2` frame only kno's fork answers).
    /// Captured and flagged, never at parity.
    SingleOracle,
    /// No external byte can exist for this row — both ends are rmule (the
    /// ed2k-server-coordinated punch and the Tunnel it raises).
    RmuleOnly,
    /// A zero, written down with the reason it is zero.
    DocumentedAbsence,
}

/// One assertion a flow makes, and how it came out.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Claim {
    /// The claim's stable name.
    pub(crate) name: String,
    /// `held`, `absent`, or `blocked`.
    pub(crate) outcome: &'static str,
    /// What kind of evidence it rests on.
    pub(crate) evidence: Evidence,
    /// What was actually observed, quoting the counterparty where it spoke.
    pub(crate) note: String,
}

impl Claim {
    /// `held` when `condition`, else `absent` — the ordinary measured claim.
    pub(crate) fn about(
        name: impl Into<String>,
        condition: bool,
        evidence: Evidence,
        note: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            outcome: if condition { "held" } else { "absent" },
            evidence,
            note: note.into(),
        }
    }

    /// A claim this bench cannot drive at all, with the reason.
    pub(crate) fn blocked(name: impl Into<String>, note: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            outcome: "blocked",
            evidence: Evidence::DocumentedAbsence,
            note: note.into(),
        }
    }

    /// A zero that *is* the finding: measured, expected, and written down.
    ///
    /// `observed` is the measured count of the thing the claim's name says did
    /// not happen. The claim holds only on an exact zero: a positive count is
    /// the thing observed, and a negative one (`-1`, the rows' "never
    /// measured") is a zero nobody took, which ADR-0045 forbids publishing as
    /// one. Either reads `absent`, so the row fails rather than carrying a
    /// Documented Absence its own run contradicts.
    pub(crate) fn absence(name: impl Into<String>, observed: i64, note: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            outcome: if observed == 0 { "held" } else { "absent" },
            evidence: Evidence::DocumentedAbsence,
            note: note.into(),
        }
    }
}

/// The name of the claim every gateway-bearing flow makes on its gateways'
/// **NAT Type Proof**.
pub(crate) const GATEWAYS_PROBED_AS_CLAIMED: &str = "each-gateway-probed-as-its-claimed-nat-type";

/// Whether every gateway a flow stood up built the NAT type it claims: the
/// reflector probe from its own LAN observed both RFC 4787 axes the knob
/// names (`agrees`), one row per gateway in the note.
///
/// A flow behind a gateway that built something else measured a different
/// NAT than its row names, so the row fails instead of carrying the
/// disagreement in a note. No gateway at all is not agreement.
pub(crate) fn gateways_probed_as_claimed<'a>(
    gateways: impl IntoIterator<Item = (&'a str, &'a NatTypeProof)>,
) -> Claim {
    let mut all_agree = true;
    let mut rows = Vec::new();
    for (wan, proof) in gateways {
        all_agree &= proof.agrees;
        rows.push(format!(
            "{wan}: claimed {} ({}/{}), observed {}/{}, agrees = {}",
            proof.nat_type.knob(),
            proof.claimed_mapping,
            proof.claimed_filtering,
            proof.observed_mapping,
            proof.observed_filtering,
            proof.agrees,
        ));
    }
    Claim::about(
        GATEWAYS_PROBED_AS_CLAIMED,
        all_agree && !rows.is_empty(),
        Evidence::RmuleOnly,
        if rows.is_empty() {
            "no gateway's NAT Type Proof was taken".to_owned()
        } else {
            rows.join(" | ")
        },
    )
}

/// The total of several measured counts, or `-1` when any of them was never
/// measured.
///
/// A sum that let one row's `-1` cancel another's `1` would read as a zero the
/// run never took, so an unmeasured operand poisons the whole total instead.
pub(crate) fn measured_total(counts: impl IntoIterator<Item = i64>) -> i64 {
    let mut total: i64 = 0;
    for count in counts {
        if count < 0 {
            return -1;
        }
        total = total.saturating_add(count);
    }
    total
}

/// One counterparty body a flow stood up, and the pin it was built from.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Body {
    /// The body's short name.
    pub(crate) name: String,
    /// Its image tag.
    pub(crate) image: String,
    /// The Fork Pin or package the recipe builds from, as the ADR names it.
    pub(crate) pin: String,
    /// The IPv4 address it held on the WAN.
    pub(crate) address_v4: String,
    /// The IPv6 address it held on the WAN, or empty for an IPv4-only body.
    pub(crate) address_v6: String,
}

/// Label a claim set: the weakest claim wins.
pub(crate) fn label(claims: &[Claim]) -> (&'static str, String) {
    let absent = claims.iter().filter(|c| c.outcome == "absent").count();
    let blocked = claims.iter().filter(|c| c.outcome == "blocked").count();
    let held = claims.len() - absent - blocked;
    let detail = format!(
        "{held} of {} claims held; {absent} absent, {blocked} blocked.",
        claims.len()
    );
    let verdict = if claims.is_empty() {
        "OBSERVED"
    } else if absent > 0 {
        "FAIL"
    } else if blocked > 0 {
        "OBSERVED"
    } else {
        "PASS"
    };
    (verdict, detail)
}

/// One driver row, read back as a flat map of TOML scalars.
///
/// The drivers render their rows by hand and the harness parses them back; a
/// flat map is enough because every value a claim reads is a scalar or a list
/// of strings. A row that is **absent or unparseable is an error**, never an
/// empty map: the driver not finishing is a broken run, and reading it as "the
/// counterparty said nothing" would be exactly the fabricated zero ADR-0045
/// forbids.
pub(crate) struct DriverRow(BTreeMap<String, toml::Value>);

impl DriverRow {
    /// Read the row a driver container wrote.
    ///
    /// # Errors
    /// If the file is absent or does not parse.
    pub(crate) fn read(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("read the driver row {}", path.display()))?;
        Self::parse(&text).with_context(|| format!("the driver row {}", path.display()))
    }

    /// Parse a row's text, as [`DriverRow::read`] does once it has the file.
    ///
    /// # Errors
    /// If the text does not parse as a TOML table.
    pub(crate) fn parse(text: &str) -> Result<Self> {
        let value: toml::Value = toml::from_str(text).context("parse the driver row")?;
        let table = value
            .as_table()
            .context("the driver row is not a table")?
            .clone();
        Ok(Self(table.into_iter().collect()))
    }

    /// A boolean field; a missing or mistyped one reads `false`, which is what
    /// an unset flag means in every row these drivers write.
    pub(crate) fn flag(&self, key: &str) -> bool {
        self.0
            .get(key)
            .and_then(toml::Value::as_bool)
            .unwrap_or(false)
    }

    /// An integer field; `-1` when missing.
    pub(crate) fn int(&self, key: &str) -> i64 {
        self.0
            .get(key)
            .and_then(toml::Value::as_integer)
            .unwrap_or(-1)
    }

    /// A string field; empty when missing.
    pub(crate) fn text(&self, key: &str) -> String {
        self.0
            .get(key)
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_owned()
    }

    /// A list-of-strings field; empty when missing.
    pub(crate) fn list(&self, key: &str) -> Vec<String> {
        self.0
            .get(key)
            .and_then(toml::Value::as_array)
            .map(|items| {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(ToOwned::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::{Claim, Evidence, gateways_probed_as_claimed, label, measured_total};
    use crate::nat::{NatType, NatTypeProof, PinnedPortReach};

    #[test]
    fn a_blocked_claim_observes_while_an_absent_one_fails() {
        let blocked = vec![
            Claim::about("a", true, Evidence::Captured, ""),
            Claim::blocked("b", "no pinned body can drive it"),
        ];
        assert_eq!(label(&blocked).0, "OBSERVED");

        let absent = vec![
            Claim::about("a", true, Evidence::Captured, ""),
            Claim::about("b", false, Evidence::Captured, ""),
            Claim::blocked("c", "no pinned body can drive it"),
        ];
        assert_eq!(label(&absent).0, "FAIL");
    }

    /// A **Documented Absence** is a finding, not a failure: the zero was
    /// measured and its reason recorded, so the flow that reaches only those
    /// still reads `PASS` rather than pretending the row was never asked.
    #[test]
    fn a_measured_zero_is_a_held_absence() {
        let claims = vec![Claim::absence(
            "no-ipv6-at-this-pin",
            0,
            "the pin has no IPv6",
        )];
        assert_eq!(label(&claims).0, "PASS");
    }

    /// An absence whose own run observed the thing it names is not held, and
    /// neither is one whose count was never taken: both fail the row.
    #[test]
    fn an_absence_with_a_non_zero_observation_is_not_held() {
        for observed in [1, 7, -1] {
            let claim = Claim::absence("no-tunnel-rose", observed, "");
            assert_eq!(claim.outcome, "absent", "observed = {observed}");
            assert_eq!(label(&[claim]).0, "FAIL", "observed = {observed}");
        }
    }

    /// A gateway whose reflector probe disagreed with its knob fails the
    /// row it stands under; so does a row that took no proof at all.
    #[test]
    fn a_gateway_that_built_another_nat_type_fails_the_row() {
        let reached = PinnedPortReach {
            port: 4672,
            reachable: true,
        };
        let symmetric = NatTypeProof::new(
            NatType::Symmetric,
            "address-and-port-dependent",
            "address-and-port-dependent",
            reached,
        );
        let cone_as_symmetric = NatTypeProof::new(
            NatType::Symmetric,
            "endpoint-independent",
            "address-and-port-dependent",
            reached,
        );
        let held = gateways_probed_as_claimed([("a", &symmetric), ("b", &symmetric)]);
        assert_eq!(held.outcome, "held");
        let wrong = gateways_probed_as_claimed([("a", &symmetric), ("b", &cone_as_symmetric)]);
        assert_eq!(wrong.outcome, "absent");
        assert!(
            wrong.note.contains("b: claimed symmetric"),
            "{}",
            wrong.note
        );
        assert_eq!(gateways_probed_as_claimed([]).outcome, "absent");
    }

    #[test]
    fn an_unmeasured_operand_poisons_the_total() {
        assert_eq!(measured_total([0, 0, 0]), 0);
        assert_eq!(measured_total([2, 0, 1]), 3);
        assert_eq!(measured_total([1, -1]), -1);
        assert_eq!(measured_total([-1, 1]), -1);
    }
}
