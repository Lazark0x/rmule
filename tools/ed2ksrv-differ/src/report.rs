//! The divergence report — the differ's only output.
//!
//! Deliberately **not** a pass/fail gate (ADR-0033/0040 keep the Compatibility
//! Tier opt-in). Three implementations of this
//! protocol genuinely disagree, and the oracle has six filed bugs of its own, so
//! "these two decoders read the same bytes differently" carries no verdict about
//! which one is right. What the report owes its reader is enough to adjudicate:
//! what was fed, what each side made of it, and whether the disagreement is
//! already understood.
//!
//! Every row therefore carries an [`Origin`] (was this a frame rmule actually
//! emits, a byte string captured off the wire, or a boundary probe outside both)
//! and every divergence carries an [`Attribution`] that is either a named,
//! pre-registered deviation with a cite or the honest [`Attribution::Unattributed`]
//! — "look here". Attribution is looked up by `(case, field)`, never inferred, so
//! a *new* disagreement inside an already-known case still surfaces as
//! unattributed rather than hiding under its neighbour's excuse.

use std::fmt::Write as _;

/// Where a corpus entry's bytes came from — the axis that separates "rmule
/// would really send this" from "we went looking past the edge".
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Origin {
    /// Minted right here by an rmule encoder, so a divergence is live.
    RmuleEmit,
    /// Lifted from a promoted fixture under
    /// `crates/rmule-ed2k/tests/fixtures/server/captured/`.
    Fixture,
    /// A probe outside rmule's emit space, kept because it pins where the
    /// oracle's acceptance boundary actually sits. Its divergences are
    /// *expected* and pre-attributed in the deviation registry — they appear
    /// in the counts like any other row (the stale-registry check depends on
    /// that), but must never be read as live rmule defects.
    Boundary,
}

impl Origin {
    const fn label(self) -> &'static str {
        match self {
            Self::RmuleEmit => "rmule-emit",
            Self::Fixture => "fixture",
            Self::Boundary => "boundary",
        }
    }
}

/// One decoder's reading of a byte string.
pub enum Reading {
    /// Parsed, yielding these ordered `(field, value)` pairs.
    Read(Vec<(String, String)>),
    /// Refused, with the decoder's own message.
    Refused(String),
    /// Panicked — a crash on input is a finding, not an accident of the harness.
    Panicked(String),
    /// Fed to a live listener that never answered. Only the UDP surface can
    /// produce this, and it is the exact failure mode the crypt-ping bugs had:
    /// on the wire, indistinguishable from "unimplemented".
    Silent,
    /// The harness could not produce a reading at all — no reachable reader
    /// for these bytes, a dead oracle, a missing fixture. A row with an
    /// unreachable side is *incomparable*: it renders as SKIP and is excluded
    /// from the divergence count, because "the harness could not compare" is
    /// not "the decoders disagree" — conflating them would let an environment
    /// flake (a busy port, an overrun deadline) read as a protocol finding.
    Unreachable(String),
}

impl Reading {
    /// Field readings, or empty for every non-`Read` outcome.
    fn fields(&self) -> &[(String, String)] {
        match self {
            Self::Read(f) => f,
            _ => &[],
        }
    }

    fn summary(&self) -> String {
        match self {
            Self::Read(fields) => fields
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(" "),
            Self::Refused(why) => format!("REFUSED: {why}"),
            Self::Panicked(why) => format!("PANICKED: {why}"),
            Self::Silent => "SILENT (no reply within the deadline)".to_owned(),
            Self::Unreachable(why) => format!("n/a: {why}"),
        }
    }

    const fn kind(&self) -> u8 {
        match self {
            Self::Read(_) => 0,
            Self::Refused(_) => 1,
            Self::Panicked(_) => 2,
            Self::Silent => 3,
            Self::Unreachable(_) => 4,
        }
    }
}

/// Why a divergence is (or is not) already understood.
pub enum Attribution {
    /// Matches a pre-registered deviation of the oracle's.
    Known(&'static Deviation),
    /// Nothing in the registry covers it. **This is the row a human is here
    /// for**: either rmule is wrong, the oracle is wrong in a new way, or the
    /// protocol is genuinely ambiguous and nobody has written it down.
    Unattributed,
}

/// A deviation of the oracle's that is already understood, with the cite that
/// makes it checkable. `case` and `field` are matched exactly, so widening the
/// excuse requires editing this table on purpose.
pub struct Deviation {
    /// `ed2k-server#N` for a filed upstream report, or `audit §N` for one the
    /// audit recorded and judged not worth filing.
    pub id: &'static str,
    pub title: &'static str,
    pub cite: &'static str,
    pub case: &'static str,
    pub field: &'static str,
}

pub struct Row {
    pub surface: &'static str,
    pub case: String,
    pub origin: Origin,
    /// The bytes fed to both sides. Rendered as hex in divergence detail.
    pub input: Vec<u8>,
    pub rmule: Reading,
    pub ed2ksrv: Reading,
}

impl Row {
    /// The reason this row cannot be compared, when either side is
    /// [`Reading::Unreachable`]. Such a row is a harness limitation, not a
    /// decoder disagreement — it renders as SKIP instead of entering the
    /// divergence count.
    fn skip_reason(&self) -> Option<&str> {
        match (&self.rmule, &self.ed2ksrv) {
            (Reading::Unreachable(why), _) | (_, Reading::Unreachable(why)) => Some(why),
            _ => None,
        }
    }

    /// The fields the two sides read differently, plus any structural mismatch.
    ///
    /// A field present on one side and absent on the other counts: "their parser
    /// never recovered this at all" is exactly the kind of silent divergence the
    /// harness exists to surface. Two same-kind non-`Read` outcomes always
    /// agree, deliberately: refusal and panic *messages* are each decoder's
    /// prose, not wire behaviour, so comparing their text would only mint
    /// unattributable noise.
    fn diverging_fields(&self) -> Vec<String> {
        if self.skip_reason().is_some() {
            return Vec::new();
        }
        if self.rmule.kind() != self.ed2ksrv.kind() {
            return vec!["<outcome>".to_owned()];
        }
        let (ours, theirs) = (self.rmule.fields(), self.ed2ksrv.fields());
        let mut out = Vec::new();
        for (name, value) in ours {
            match theirs.iter().find(|(n, _)| n == name) {
                Some((_, other)) if other == value => {}
                Some(_) => out.push(name.clone()),
                None => out.push(name.clone()),
            }
        }
        for (name, _) in theirs {
            if !ours.iter().any(|(n, _)| n == name) {
                out.push(name.clone());
            }
        }
        out
    }
}

/// A row's disagreement, once attributed.
struct Divergence<'a> {
    row: &'a Row,
    fields: Vec<String>,
    attribution: Attribution,
}

pub struct Report {
    rows: Vec<Row>,
    /// Free-form facts the run measured that are not themselves disagreements —
    /// the oracle's executed acceptance windows, for instance. Kept separate so
    /// they cannot be mistaken for findings.
    observations: Vec<(&'static str, String)>,
    registry: &'static [Deviation],
}

impl Report {
    pub const fn new(registry: &'static [Deviation]) -> Self {
        Self {
            rows: Vec::new(),
            observations: Vec::new(),
            registry,
        }
    }

    pub fn push(&mut self, row: Row) {
        self.rows.push(row);
    }

    pub fn observe(&mut self, surface: &'static str, fact: impl Into<String>) {
        self.observations.push((surface, fact.into()));
    }

    fn divergences(&self) -> Vec<Divergence<'_>> {
        self.rows
            .iter()
            .filter_map(|row| {
                let fields = row.diverging_fields();
                if fields.is_empty() {
                    return None;
                }
                // Every diverging field must be covered for the row to count as
                // understood — one unexplained field is enough to flag the row.
                let attribution = fields
                    .iter()
                    .map(|field| {
                        self.registry
                            .iter()
                            .find(|d| d.case == row.case && d.field == *field)
                    })
                    .try_fold(None, |acc: Option<&'static Deviation>, hit| match hit {
                        Some(d) => Ok(Some(acc.unwrap_or(d))),
                        None => Err(()),
                    })
                    .ok()
                    .flatten()
                    .map_or(Attribution::Unattributed, Attribution::Known);
                Some(Divergence {
                    row,
                    fields,
                    attribution,
                })
            })
            .collect()
    }

    /// Render the whole report. No timestamps and no run-varying values in the
    /// body, so two runs at the same pin diff to nothing and a re-pin's effect
    /// is legible as a diff.
    pub fn render(&self) -> String {
        let mut out = String::new();
        let divergences = self.divergences();

        out.push_str("ed2ksrv differential decoding report\n");
        out.push_str("===================================\n\n");
        out.push_str(
            "Oracle : andrey23127/ed2k-server @ eacf7f1eb7ea40f71ae869aef6a10801e7e262b8\n\
             \x20        unpatched and pinned — ADR-0045 amendment 2026-08-02.\n\
             Parity : aMule 2.3.3 stays the reference. A divergence below means\n\
             \x20        \"adjudicate this\", never \"rmule is wrong\".\n\n",
        );

        for surface in self.surfaces() {
            let rows: Vec<_> = self.rows.iter().filter(|r| r.surface == surface).collect();
            let skipped = rows.iter().filter(|r| r.skip_reason().is_some()).count();
            let diverged = divergences
                .iter()
                .filter(|d| d.row.surface == surface)
                .count();
            let unattributed = divergences
                .iter()
                .filter(|d| {
                    d.row.surface == surface && matches!(d.attribution, Attribution::Unattributed)
                })
                .count();
            let _ = write!(
                out,
                "{surface:<12} {:>3} cases  {:>3} agree  {diverged:>3} diverge  \
                 ({} attributed, {unattributed} UNATTRIBUTED)",
                rows.len(),
                rows.len() - diverged - skipped,
                diverged - unattributed,
            );
            if skipped > 0 {
                let _ = write!(out, "  [{skipped} skipped — harness, not findings]");
            }
            out.push('\n');
        }
        out.push('\n');

        if !self.observations.is_empty() {
            out.push_str("MEASURED FACTS (executed against the pinned oracle, not transcribed)\n");
            out.push_str("-------------------------------------------------------------------\n");
            for (surface, fact) in &self.observations {
                let _ = writeln!(out, "  [{surface}] {fact}");
            }
            out.push('\n');
        }

        out.push_str("CASES\n-----\n");
        for surface in self.surfaces() {
            let _ = writeln!(out, "  {surface}");
            for row in self.rows.iter().filter(|r| r.surface == surface) {
                if let Some(why) = row.skip_reason() {
                    let _ = writeln!(
                        out,
                        "    SKIP    [{:<10}] {} — {why}",
                        row.origin.label(),
                        row.case
                    );
                    continue;
                }
                let mark = if row.diverging_fields().is_empty() {
                    "  ok  "
                } else {
                    "DIVERGE"
                };
                let _ = writeln!(out, "    {mark} [{:<10}] {}", row.origin.label(), row.case);
            }
        }
        out.push('\n');

        let stale = self.stale_registry_entries();
        if !stale.is_empty() {
            out.push_str("STALE REGISTRY ENTRIES (known deviations this run did not reproduce)\n");
            out.push_str("-------------------------------------------------------------------\n");
            for dev in stale {
                let _ = writeln!(out, "  {} — {} / {}", dev.id, dev.case, dev.field);
            }
            out.push_str(
                "  Either the case was renamed, or the oracle changed. Re-check before trusting\n\
                 \x20 the entry to explain anything.\n\n",
            );
        }

        if divergences.is_empty() {
            out.push_str("No divergences at this pin.\n");
            return out;
        }

        out.push_str("DIVERGENCES\n-----------\n");
        for (n, d) in divergences.iter().enumerate() {
            let _ = writeln!(out, "\n#{} [{}] {}", n + 1, d.row.surface, d.row.case);
            let _ = writeln!(out, "  origin  : {}", d.row.origin.label());
            let _ = writeln!(out, "  fed     : {}", hex(&d.row.input));
            let _ = writeln!(out, "  rmule   : {}", d.row.rmule.summary());
            let _ = writeln!(out, "  ed2ksrv : {}", d.row.ed2ksrv.summary());
            let _ = writeln!(out, "  differs : {}", d.fields.join(", "));
            match &d.attribution {
                Attribution::Known(dev) => {
                    let _ = writeln!(out, "  verdict : KNOWN third-party deviation {}", dev.id);
                    let _ = writeln!(out, "            {}", dev.title);
                    let _ = writeln!(out, "            {}", dev.cite);
                }
                Attribution::Unattributed => {
                    let _ = writeln!(out, "  verdict : UNATTRIBUTED — needs adjudication.");
                    let _ = writeln!(
                        out,
                        "            Nothing in the deviation registry covers this. Score it\n\
                         \x20           against aMule 2.3.3 before assuming either side is right."
                    );
                }
            }
        }
        out.push('\n');
        out
    }

    /// `true` when at least one divergence has no registered explanation.
    pub fn has_unattributed(&self) -> bool {
        self.divergences()
            .iter()
            .any(|d| matches!(d.attribution, Attribution::Unattributed))
    }

    /// Registry entries that no longer describe anything this run saw.
    ///
    /// A stale entry is a slow leak: it keeps standing by to excuse a case that
    /// has been renamed or a divergence that has been fixed upstream, so the
    /// first time that `(case, field)` disagrees again it is waved through with
    /// a cite that no longer applies. Surfaced in the report rather than
    /// asserted on, because the harmless reason for one is a re-pin.
    fn stale_registry_entries(&self) -> Vec<&'static Deviation> {
        self.registry
            .iter()
            .filter(|d| {
                !self
                    .rows
                    .iter()
                    .any(|r| r.case == d.case && r.diverging_fields().contains(&d.field.to_owned()))
            })
            .collect()
    }

    fn surfaces(&self) -> Vec<&'static str> {
        let mut seen: Vec<&'static str> = Vec::new();
        for row in &self.rows {
            if !seen.contains(&row.surface) {
                seen.push(row.surface);
            }
        }
        seen
    }
}

pub fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "<empty>".to_owned();
    }
    let shown = bytes.len().min(48);
    let mut s = bytes[..shown]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    if shown < bytes.len() {
        let _ = write!(s, " … ({} bytes)", bytes.len());
    }
    s
}

/// Run `f` with panics captured rather than printed.
///
/// The oracle's parsers take attacker-shaped input and at least one of them
/// indexes past a length it just checked, so a panic is a result the harness
/// must be able to record — killing the run instead would lose the finding.
pub fn guarded<T>(f: impl FnOnce() -> T) -> Result<T, String> {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    std::panic::set_hook(previous);
    outcome.map_err(|payload| {
        payload
            .downcast_ref::<&str>()
            .map(|s| (*s).to_owned())
            .or_else(|| payload.downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "<non-string panic payload>".to_owned())
    })
}

/// Build a `Reading::Read` from `(name, value)` pairs.
pub fn read<const N: usize>(fields: [(&str, String); N]) -> Reading {
    Reading::Read(fields.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    static ONE_FIELD: &[Deviation] = &[Deviation {
        id: "test#1",
        title: "size is read swapped",
        cite: "nowhere",
        case: "probe",
        field: "size",
    }];

    fn row(fields: [(&str, &str); 2], theirs: [(&str, &str); 2]) -> Row {
        let own = |f: [(&str, &str); 2]| {
            Reading::Read(
                f.into_iter()
                    .map(|(k, v)| (k.to_owned(), v.to_owned()))
                    .collect(),
            )
        };
        Row {
            surface: "probe",
            case: "probe".to_owned(),
            origin: Origin::RmuleEmit,
            input: vec![0x01],
            rmule: own(fields),
            ed2ksrv: own(theirs),
        }
    }

    /// A registered excuse covers the field it names and nothing else.
    ///
    /// This is the honesty property the whole harness rests on: attribution is
    /// per `(case, field)`, so a *new* disagreement inside an already-explained
    /// case must still reach a human. Getting this wrong would let the registry
    /// quietly absorb a real regression, and nothing in a normal run would show
    /// it, because a normal run never produces the second-field shape.
    #[test]
    fn a_registered_case_does_not_excuse_a_second_field() {
        let mut covered = Report::new(ONE_FIELD);
        covered.push(row(
            [("size", "1"), ("name", "a")],
            [("size", "2"), ("name", "a")],
        ));
        assert!(
            !covered.has_unattributed(),
            "the registered field alone must be attributed"
        );

        let mut spread = Report::new(ONE_FIELD);
        spread.push(row(
            [("size", "1"), ("name", "a")],
            [("size", "2"), ("name", "b")],
        ));
        assert!(
            spread.has_unattributed(),
            "an unregistered field diverging in the same case must reach a human"
        );
    }

    /// A row the harness could not compare is a SKIP, never a divergence.
    ///
    /// The failure this pins: an environment flake (dead oracle, busy port,
    /// overrun deadline) pairs `Unreachable` with some other outcome, the kind
    /// mismatch used to mint an `<outcome>` divergence, and under
    /// `--fail-on-unattributed` a harness hiccup exited as a protocol finding.
    #[test]
    fn an_unreachable_side_skips_the_row_instead_of_diverging() {
        let mut report = Report::new(ONE_FIELD);
        report.push(Row {
            surface: "probe",
            case: "oracle/start".to_owned(),
            origin: Origin::RmuleEmit,
            input: Vec::new(),
            rmule: Reading::Unreachable("oracle failed to start: no free port".to_owned()),
            ed2ksrv: Reading::Silent,
        });
        assert!(
            !report.has_unattributed(),
            "a harness-incomparable row must not exit --fail-on-unattributed"
        );
        let rendered = report.render();
        assert!(
            rendered.contains("SKIP") && rendered.contains("no free port"),
            "the skip and its reason must stay visible in CASES:\n{rendered}"
        );
        assert!(
            rendered.contains("1 skipped"),
            "the surface summary must count the skip:\n{rendered}"
        );
    }
}
