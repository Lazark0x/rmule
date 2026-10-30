//! What `sentinel-sources-legacy` writes down, and the one place its label is
//! decided.
//!
//! The flow carries two independent claims and the verdict keeps them apart.
//! **rmule's half** is the sentinel-safe reader gate: a probe that decodes
//! sentinel-bearing payloads through the compiled binary and whose own lines
//! the verdict keeps. **aMule's half** is
//! the legacy leg: a stock 2.3.3 handed the same shape on the wire, judged
//! solely on what it then dialled and whether its session survived. A run that
//! measures only the first says so, in a `note` that travels with every verdict
//! this flow has ever written.

use serde::Serialize;

use super::legacy::LegacyObservation;
use super::plan::{
    CONTROL_FIRST_RECORDS, CONTROL_SECOND_RECORDS, PACKED_FIRST_RECORDS, PACKED_SECOND_RECORDS,
    TCP_RECORDS, inline_misread,
};

/// One sink dial as the verdict records it: aMule naming the endpoint it
/// decoded out of a source record.
#[derive(Debug, Serialize)]
pub(crate) struct SinkDialRow {
    /// The sink endpoint the dial landed on.
    pub(crate) local: String,
    /// The dialling aMule.
    pub(crate) peer: String,
    /// Its first frame, hex.
    pub(crate) bytes: String,
}

/// One pcap row off the tap on aMule's own netns.
#[derive(Debug, Serialize)]
pub(crate) struct WireRow {
    /// The row's name.
    pub(crate) name: String,
    /// How many packets matched.
    pub(crate) count: u64,
}

/// The flow's verdict. Scalars first, arrays last: the TOML serialiser cannot
/// emit a value after a table.
#[derive(Debug, Serialize)]
pub(crate) struct SentinelVerdict {
    #[serde(rename = "scenario")]
    pub(crate) flow: &'static str,
    pub(crate) verdict: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) skip_reason: Option<String>,
    /// What this verdict does and does not claim, spelled out every time so a
    /// bare `PASS` is never over-read.
    pub(crate) note: &'static str,
    /// Whether rmule's sentinel-safe reader was found in the probed binary.
    pub(crate) sentinel_reader_present: bool,
    pub(crate) container_runtime: String,
    /// The legacy leg's own label, or `"NOT-RUN"`.
    pub(crate) legacy_leg: &'static str,
    /// Why the legacy leg landed where it did — the sentence a reader needs.
    pub(crate) legacy_detail: String,
    /// How many logins the stimulus answered.
    pub(crate) legacy_logins: i64,
    /// Whether the scripted list actually went out.
    pub(crate) legacy_emitted: bool,
    /// What fired the emission — `trigger-file` is the harness-controlled
    /// moment, after the tap is up and every named file is queued.
    pub(crate) legacy_emit_trigger: String,
    /// Whether aMule's server session survived the sentinel-bearing list.
    pub(crate) legacy_session_survived: bool,
    /// Did aMule dial the plain record *before* the sentinel?
    pub(crate) amule_dialled_before_sentinel: bool,
    /// Did aMule dial the plain record *after* it — at the right offset?
    pub(crate) amule_dialled_after_sentinel: bool,
    /// Did aMule dial anything at the sentinel record's own port? `-1` when
    /// the row was never counted.
    pub(crate) amule_dialled_sentinel_port: i64,
    /// Did aMule dial the broadcast address a `0xFFFFFFFF` id unpacks to?
    /// `-1` when the row was never counted.
    pub(crate) amule_dialled_broadcast_id: i64,
    /// SYNs at the endpoint the sentinel's first six inline bytes spell.
    pub(crate) amule_dialled_inline_misread: i64,
    /// Did aMule dial the packed datagram's first body?
    pub(crate) amule_dialled_packed_first: bool,
    /// Did aMule dial the packed datagram's second body — the one only a reader
    /// that got past the first body's sentinel tail can reach?
    pub(crate) amule_dialled_packed_second: bool,
    /// The control datagram's first body: the same two-packet shape with no
    /// Sentinel Source and no tail.
    pub(crate) amule_dialled_control_first: bool,
    /// The control's second body. Read together with
    /// `amule_dialled_packed_second`, this is what makes the packed leg's
    /// result attributable to the tail — or clears the tail of it.
    pub(crate) amule_dialled_control_second: bool,
    /// The packed leg's own label, reported beside the list leg rather than
    /// gating it.
    pub(crate) packed_leg: &'static str,
    /// aMule's `Status` after the window.
    pub(crate) amule_status: String,
    /// The probe argv that was (or was not) run.
    pub(crate) sentinel_reader_probe: Vec<String>,
    /// What the probe printed: rmule's own reader on the lists it decoded.
    pub(crate) sentinel_reader_lines: Vec<String>,
    /// aMule's own log lines naming the source list.
    pub(crate) amule_log_lines: Vec<String>,
    /// Every sink dial, in arrival order.
    pub(crate) legacy_sink_dial: Vec<SinkDialRow>,
    /// Every pcap row counted.
    pub(crate) legacy_wire_row: Vec<WireRow>,
}

/// How the legacy leg came out, and why.
pub(crate) struct LegacyLabel {
    /// `STRIDE-MISREAD`, `UNEXPECTED-READ`, `OBSERVED`.
    pub(crate) label: &'static str,
    /// The sentence that explains it.
    pub(crate) detail: String,
}

/// Judge the legacy leg on aMule's behaviour alone.
///
/// `STRIDE-MISREAD` is the row's claim: aMule dialled the record *before* the
/// sentinel, dialled the endpoint the sentinel's first six address bytes spell,
/// never reached the record *after* it, dialled nothing at the sentinel's own
/// port or id, and kept its session. Any other reaction to a list that went out
/// is `UNEXPECTED-READ`. A leg where the list never went out (or nobody logged
/// in) is `OBSERVED`: the topology stood up but the exchange did not fire,
/// which proves nothing either way.
pub(crate) fn judge_legacy(observation: &LegacyObservation) -> LegacyLabel {
    if observation.logins == 0 || !observation.emitted {
        return LegacyLabel {
            label: "OBSERVED",
            detail: format!(
                "the scripted list never went out ({} logins, emitted = {}), so nothing about \
                 the legacy body's reader was measured",
                observation.logins, observation.emitted
            ),
        };
    }
    let before = observation.was_dialled(TCP_RECORDS[0].label);
    let after = observation.was_dialled(TCP_RECORDS[2].label);
    let sentinel_row = format!("syn_{}", TCP_RECORDS[1].label);
    let (Some(sentinel_port), Some(broadcast), Some(misread)) = (
        observation.wire_row(&sentinel_row),
        observation.wire_row("syn_broadcast_id"),
        observation.wire_row("syn_inline_misread"),
    ) else {
        return LegacyLabel {
            label: "OBSERVED",
            detail: format!(
                "the pcap rows that settle the read were not counted ({sentinel_row} = {}, \
                 syn_broadcast_id = {}, syn_inline_misread = {}), so a zero at any of them \
                 would be one nobody measured",
                observation.wire_row_recorded(&sentinel_row),
                observation.wire_row_recorded("syn_broadcast_id"),
                observation.wire_row_recorded("syn_inline_misread"),
            ),
        };
    };
    let (misread_host, misread_port) = inline_misread(&TCP_RECORDS[1]);
    if before
        && !after
        && misread > 0
        && sentinel_port == 0
        && broadcast == 0
        && observation.session_survived
    {
        return LegacyLabel {
            label: "STRIDE-MISREAD",
            detail: format!(
                "stock aMule 2.3.3 dialled {} before the Sentinel Source, read the sentinel's \
                 id as an address and dropped it (nothing at its port or the broadcast address \
                 it unpacks to: {sentinel_port}, {broadcast}), then took the first six inline \
                 address bytes for a record and sent {misread} SYNs at \
                 {misread_host}:{misread_port}. Its declared count ran out there, so it never \
                 reached {}. The rest of the frame was ignored and the session survived.",
                TCP_RECORDS[0].host, TCP_RECORDS[2].host
            ),
        };
    }
    LegacyLabel {
        label: "UNEXPECTED-READ",
        detail: format!(
            "stock aMule 2.3.3 did not read the list the way a six-byte stride predicts: \
             dialled_before_sentinel = {before}, dialled_after_sentinel = {after}, \
             syn_inline_misread = {misread}, syn_at_sentinel_port = {sentinel_port}, \
             syn_at_broadcast_id = {broadcast}, session_survived = {}.",
            observation.session_survived
        ),
    }
}

/// Label the packed `OP_GLOBFOUNDSOURCES` leg against its own control.
///
/// Reported beside the list leg and never gating it: whether a stock aMule
/// accepts an unsolicited `0x9B` at all is a separate question, so a leg that
/// draws no dial at all is an absence, not a failure. The control — the same
/// two-packet datagram with no Sentinel Source — is what makes a *lost second
/// body* attributable:
///
/// - both bodies of the sentinel-bearing datagram dialled → `PASS`;
/// - second body lost while the control's second body arrived → the tail is the
///   difference, `TAIL-ENDED-DATAGRAM`;
/// - second body lost in **both** datagrams → the body never reads a second
///   packed packet in this framing at all, so the sentinel is not implicated:
///   `ONE-PACKET-PER-DATAGRAM`;
/// - no first-body dial anywhere → `ABSENT`;
/// - anything else → `INCONCLUSIVE`, which is what an unattributable result is.
pub(crate) fn judge_packed(observation: &LegacyObservation) -> &'static str {
    let first = observation.was_dialled(PACKED_FIRST_RECORDS[0].label);
    let second = observation.was_dialled(PACKED_SECOND_RECORDS[0].label);
    let control_first = observation.was_dialled(CONTROL_FIRST_RECORDS[0].label);
    let control_second = observation.was_dialled(CONTROL_SECOND_RECORDS[0].label);
    match (first, second, control_first, control_second) {
        (true, true, _, _) => "PASS",
        (true, false, true, true) => "TAIL-ENDED-DATAGRAM",
        (true, false, true, false) => "ONE-PACKET-PER-DATAGRAM",
        (false, _, false, _) => "ABSENT",
        _ => "INCONCLUSIVE",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::flow::nat::sentinel::legacy::observe;

    fn observation(journal: &str, rows: Vec<(String, u64)>, status: &str) -> LegacyObservation {
        observe(journal, rows, status.to_owned(), Vec::new())
    }

    /// The journal of the read run `1793352976` drew: the record before the
    /// sentinel is dialled, the one after it is not.
    const BEFORE_ONLY: &str = r#"
logins = 1
[[emitted]]
transport = "tcp"
peer = "p"
label = "l"
trigger = "t"
bytes = "e342"
[[sink_dial]]
local = "203.0.113.50:5001"
peer = "p"
bytes = ""
"#;

    /// The rows of a stride misread: the inline bytes dialled, the sentinel's
    /// own endpoints silent.
    fn misread_rows() -> Vec<(String, u64)> {
        vec![
            ("syn_sentinel".to_owned(), 0),
            ("syn_broadcast_id".to_owned(), 0),
            ("syn_inline_misread".to_owned(), 10),
        ]
    }

    #[test]
    fn the_inline_bytes_read_as_one_record_with_the_session_kept_is_the_stride_misread() {
        let judged = judge_legacy(&observation(BEFORE_ONLY, misread_rows(), "eD2k: Connected"));
        assert_eq!(judged.label, "STRIDE-MISREAD", "{}", judged.detail);
    }

    /// A tcpdump that could not count a row is not a zero: the leg reads
    /// `OBSERVED`, never the label a defaulted zero would give.
    #[test]
    fn an_uncounted_row_settles_nothing() {
        let judged = judge_legacy(&observation(BEFORE_ONLY, Vec::new(), "eD2k: Connected"));
        assert_eq!(judged.label, "OBSERVED", "{}", judged.detail);
        let two_rows = misread_rows().into_iter().take(2).collect();
        let judged = judge_legacy(&observation(BEFORE_ONLY, two_rows, "eD2k: Connected"));
        assert_eq!(judged.label, "OBSERVED", "{}", judged.detail);
    }

    /// A body that dials the record after the sentinel skipped the inline
    /// bytes, which is not what a six-byte stride does.
    #[test]
    fn reaching_the_record_after_the_sentinel_is_not_the_stride_read() {
        let both = format!(
            "{BEFORE_ONLY}[[sink_dial]]\nlocal = \"203.0.113.60:5003\"\npeer = \"p\"\nbytes = \"\"\n"
        );
        let judged = judge_legacy(&observation(&both, misread_rows(), "eD2k: Connected"));
        assert_eq!(judged.label, "UNEXPECTED-READ", "{}", judged.detail);
        assert!(judged.detail.contains("dialled_after_sentinel = true"));
    }

    #[test]
    fn no_dial_at_the_inline_bytes_is_not_the_stride_read() {
        let mut rows = misread_rows();
        rows[2].1 = 0;
        let judged = judge_legacy(&observation(BEFORE_ONLY, rows, "eD2k: Connected"));
        assert_eq!(judged.label, "UNEXPECTED-READ", "{}", judged.detail);
    }

    #[test]
    fn a_dial_at_the_broadcast_address_the_sentinel_id_unpacks_to_is_not_the_stride_read() {
        let mut rows = misread_rows();
        rows[1].1 = 1;
        let judged = judge_legacy(&observation(BEFORE_ONLY, rows, "eD2k: Connected"));
        assert_eq!(judged.label, "UNEXPECTED-READ", "{}", judged.detail);
    }

    #[test]
    fn a_dropped_session_is_not_the_stride_read() {
        let judged = judge_legacy(&observation(
            BEFORE_ONLY,
            misread_rows(),
            "eD2k: Not connected",
        ));
        assert_eq!(judged.label, "UNEXPECTED-READ", "{}", judged.detail);
    }

    #[test]
    fn a_list_that_never_went_out_measures_nothing() {
        let judged = judge_legacy(&observation("logins = 0", Vec::new(), ""));
        assert_eq!(judged.label, "OBSERVED", "{}", judged.detail);
    }

    /// One `sink_dial` row per endpoint, as a journal the reader parses.
    fn journal_dialling(endpoints: &[&str]) -> String {
        let mut text = String::from("logins = 1\n");
        for endpoint in endpoints {
            text.push_str(&format!(
                "[[sink_dial]]\nlocal = \"{endpoint}\"\npeer = \"p\"\nbytes = \"\"\n"
            ));
        }
        text
    }

    /// The packed datagram's second body is reachable only past the first
    /// body's sentinel tail — but "lost" only means the tail if the control
    /// datagram's own second body arrived.
    #[test]
    fn the_control_is_what_attributes_a_lost_second_body_to_the_tail() {
        let with_control = journal_dialling(&[
            "203.0.113.70:5004",
            "203.0.113.90:5007",
            "203.0.113.100:5008",
        ]);
        assert_eq!(
            judge_packed(&observation(&with_control, Vec::new(), "")),
            "TAIL-ENDED-DATAGRAM"
        );
    }

    /// A body that reads no second packed packet in either datagram has not
    /// been tripped by the sentinel, and the label must not say it was.
    #[test]
    fn losing_the_second_body_in_both_datagrams_exonerates_the_sentinel() {
        let neither = journal_dialling(&["203.0.113.70:5004", "203.0.113.90:5007"]);
        assert_eq!(
            judge_packed(&observation(&neither, Vec::new(), "")),
            "ONE-PACKET-PER-DATAGRAM"
        );
    }

    #[test]
    fn both_bodies_of_the_sentinel_bearing_datagram_is_the_packed_pass() {
        let both = journal_dialling(&["203.0.113.70:5004", "203.0.113.80:5006"]);
        assert_eq!(judge_packed(&observation(&both, Vec::new(), "")), "PASS");
    }

    #[test]
    fn no_dial_at_either_datagrams_first_body_is_an_absence() {
        assert_eq!(
            judge_packed(&observation("logins = 1", Vec::new(), "")),
            "ABSENT"
        );
    }

    /// A control that fired while the sentinel-bearing datagram drew nothing at
    /// all cannot be read either way, and says so rather than picking a side.
    #[test]
    fn a_result_the_control_cannot_explain_is_inconclusive() {
        let only_control = journal_dialling(&["203.0.113.90:5007", "203.0.113.100:5008"]);
        assert_eq!(
            judge_packed(&observation(&only_control, Vec::new(), "")),
            "INCONCLUSIVE"
        );
    }
}
