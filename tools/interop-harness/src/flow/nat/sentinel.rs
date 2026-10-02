//! `sentinel-sources-legacy` (ADR-0092): a **Sentinel Source**-bearing
//! source list is handed to a *stock aMule 2.3.3* and to rmule, and the flow
//! asserts the legacy body reads it without desyncing while rmule parses it.
//!
//! The flow carries the ADR-0092 sentinel row's two claims as two independent legs.
//!
//! **rmule's half — the reader gate.** `--sentinel-reader-probe` names a
//! command that must succeed for the sentinel-safe reader (`d76636b`,
//! `crates/rmule-ed2k/src/source_record.rs` +
//! `crates/rmule-primitives/src/source/sentinel.rs`) to count as present;
//! `READER_READINESS_MARKER` is the one this repository ships. No probe (or a
//! probe that fails) writes a documented `SKIPPED`, never a silent pass.
//!
//! **aMule's half — the legacy leg.** ADR-0092 originally named `ed2ksrv` as
//! the body that would emit the sentinel row, but the pinned `ed2ksrv` is
//! v4-only and has no config surface for emitting one, so
//! that row could not be driven by its own named bodies. The claim it protects
//! — *does a stock 2.3.3 desync on the shape?* — does not need `ed2ksrv` at
//! all: rmule owns the encoders, so rmule emits the list as **Stimulus** and
//! aMule's reaction is the evidence (the Kad Stimulus Node and the Registrant are the same
//! posture). `--drive-legacy` runs that leg; without
//! it the flow is the gate alone, and says so.

pub(crate) mod legacy;
pub(crate) mod plan;
pub(crate) mod verdict;

use std::ffi::OsString;
use std::fs;
use std::process::{Command, Stdio};

use anyhow::{Context, Result, bail};

use crate::artifacts::RunLayout;

pub use self::legacy::LegacyDrive;
use self::legacy::LegacyObservation;
use self::plan::{
    CONTROL_FIRST_RECORDS, CONTROL_SECOND_RECORDS, PACKED_FIRST_RECORDS, PACKED_SECOND_RECORDS,
    TCP_RECORDS,
};
use self::verdict::{SentinelVerdict, SinkDialRow, WireRow, judge_legacy, judge_packed};

/// The flow's name in every artifact it writes.
const FLOW: &str = "sentinel-sources-legacy";

/// The readiness marker: decodes ed2k-server#12's documented sentinel-source
/// payload through the probed binary's own compiled reader and asserts a clean
/// read. Point `--sentinel-reader-probe` at a built `rmule-tools` binary's
/// **absolute path** followed by `ed2k sentinel-probe`, e.g.
/// `--sentinel-reader-probe /path/to/target/debug/rmule-tools ed2k
/// sentinel-probe`. `num_args = 1..` stops collecting at the first token that
/// starts with `-`, so a form with embedded flags (`cargo run -p rmule-tools --
/// ed2k sentinel-probe`) is parsed wrong — that `-p` reads as a new,
/// unrecognised flag on this subcommand, not as part of the probe.
pub const READER_READINESS_MARKER: &str = "rmule-tools ed2k sentinel-probe";

/// What a gate-only run does and does not measure.
const GATE_ONLY_NOTE: &str = "this verdict covers only whether rmule's sentinel-safe reader \
     (ADR-0085) is wired end to end in the probed binary, via `sentinel-reader-probe`. \
     The legacy leg was NOT run, so nothing here says what a stock aMule 2.3.3 does with a \
     sentinel-bearing list — pass `--drive-legacy` for that half.";

/// What a run with the legacy leg measures.
const BOTH_LEGS_NOTE: &str = "two independent claims. rmule's half: the sentinel-safe reader \
     (ADR-0085) decoded a sentinel-bearing payload through the probed binary \
     (`sentinel_reader_present`). aMule's half: a STOCK aMule 2.3.3 was handed the same shape on \
     the wire by an rmule-authored stimulus and judged solely on its own behaviour — which \
     endpoints it dialled (`legacy_sink_dial`, `legacy_wire_row`), what its own log said \
     (`amule_log_lines`), and whether its session survived. The emit side is an `rmule-only` row \
     (ADR-0045 as amended) and is never evidence; aMule's reaction is captured evidence. \
     `ed2ksrv` emits no sentinel row at any pin the repo carries, so the ADR-0092 sentinel row's \
     server half is deferred to `ipv6-server-sentinel`.";

/// The flow's inputs.
pub struct SentinelSourcesLegacyOptions<'a> {
    /// The run dir.
    pub layout: &'a RunLayout,
    /// The container runtime the legacy leg drives, recorded either way.
    pub container_runtime: &'a str,
    /// The command that proves rmule carries the sentinel-safe reader — split
    /// into argv, e.g. `["rmule-tools", "ed2k", "sentinel-probe"]`. Empty means
    /// "not configured", which reads as absent exactly like a probe that fails.
    pub sentinel_reader_probe: &'a [String],
    /// The live legacy leg's bench, or `None` to run the reader gate alone.
    pub legacy: Option<LegacyDrive<'a>>,
}

/// Run both legs (or just the gate) and record what each found.
///
/// # Errors
/// If the verdict cannot be written, if the legacy leg's bench cannot be stood
/// up, or if the legacy leg measured a **desync** — which is a real finding
/// about the sentinel design, reported as a failure after the verdict is on
/// disk.
pub fn run_sentinel_sources_legacy(options: SentinelSourcesLegacyOptions<'_>) -> Result<()> {
    let (present, detail) = probe_reader(options.sentinel_reader_probe);
    let (gate_label, skip_reason) = gate(present, &detail);

    let observation = match (&options.legacy, present) {
        (Some(drive), true) => Some(legacy::drive(
            options.layout,
            options.container_runtime,
            drive,
        )?),
        // A legacy leg run without rmule's own reader would record "rmule did
        // not parse the sentinel" for a reason that is not interop; the gate
        // exists to stop exactly that.
        (Some(_), false) | (None, _) => None,
    };

    let verdict = assemble(
        options.container_runtime,
        options.sentinel_reader_probe,
        gate_label,
        skip_reason,
        observation,
    );
    announce(&verdict);
    write_verdict(options.layout, &verdict)?;
    if verdict.legacy_leg == "DESYNC" {
        bail!(
            "sentinel-sources-legacy: the legacy body desynced — {}",
            verdict.legacy_detail
        );
    }
    Ok(())
}

/// Fold both legs into one verdict. The overall label is the weaker of the two:
/// a gate that did not lift skips, a legacy leg that did not fire downgrades a
/// `PASS` to `OBSERVED`, and a desync fails.
fn assemble(
    container_runtime: &str,
    reader_probe: &[String],
    gate_label: &'static str,
    skip_reason: Option<String>,
    observation: Option<LegacyObservation>,
) -> SentinelVerdict {
    let present = skip_reason.is_none();
    let Some(observation) = observation else {
        return SentinelVerdict {
            flow: FLOW,
            verdict: gate_label,
            skip_reason,
            note: GATE_ONLY_NOTE,
            sentinel_reader_present: present,
            container_runtime: container_runtime.to_owned(),
            legacy_leg: "NOT-RUN",
            legacy_detail: "the legacy leg was not requested (`--drive-legacy`)".to_owned(),
            legacy_logins: 0,
            legacy_emitted: false,
            legacy_emit_trigger: String::new(),
            legacy_session_survived: false,
            amule_dialled_before_sentinel: false,
            amule_dialled_after_sentinel: false,
            amule_dialled_sentinel_port: -1,
            amule_dialled_broadcast_id: -1,
            amule_dialled_packed_first: false,
            amule_dialled_packed_second: false,
            amule_dialled_control_first: false,
            amule_dialled_control_second: false,
            packed_leg: "NOT-RUN",
            amule_status: String::new(),
            sentinel_reader_probe: reader_probe.to_vec(),
            amule_log_lines: Vec::new(),
            legacy_sink_dial: Vec::new(),
            legacy_wire_row: Vec::new(),
        };
    };

    let judged = judge_legacy(&observation);
    let overall = match judged.label {
        "PASS" => "PASS",
        "DESYNC" => "FAIL",
        _ => "OBSERVED",
    };
    SentinelVerdict {
        flow: FLOW,
        verdict: overall,
        skip_reason: None,
        note: BOTH_LEGS_NOTE,
        sentinel_reader_present: present,
        container_runtime: container_runtime.to_owned(),
        legacy_leg: judged.label,
        legacy_detail: judged.detail,
        legacy_logins: observation.logins,
        legacy_emitted: observation.emitted,
        legacy_emit_trigger: observation.emit_trigger.clone(),
        legacy_session_survived: observation.session_survived,
        amule_dialled_before_sentinel: observation.was_dialled(TCP_RECORDS[0].label),
        amule_dialled_after_sentinel: observation.was_dialled(TCP_RECORDS[2].label),
        amule_dialled_sentinel_port: observation
            .wire_row_recorded(&format!("syn_{}", TCP_RECORDS[1].label)),
        amule_dialled_broadcast_id: observation.wire_row_recorded("syn_broadcast_id"),
        amule_dialled_packed_first: observation.was_dialled(PACKED_FIRST_RECORDS[0].label),
        amule_dialled_packed_second: observation.was_dialled(PACKED_SECOND_RECORDS[0].label),
        amule_dialled_control_first: observation.was_dialled(CONTROL_FIRST_RECORDS[0].label),
        amule_dialled_control_second: observation.was_dialled(CONTROL_SECOND_RECORDS[0].label),
        packed_leg: judge_packed(&observation),
        amule_status: observation.amule_status.clone(),
        sentinel_reader_probe: reader_probe.to_vec(),
        amule_log_lines: observation.amule_log_lines.clone(),
        legacy_sink_dial: observation
            .sink_dials
            .iter()
            .map(|dial| SinkDialRow {
                local: dial.local.clone(),
                peer: dial.peer.clone(),
                bytes: dial.bytes.clone(),
            })
            .collect(),
        legacy_wire_row: observation
            .wire_rows
            .iter()
            .map(|(name, count)| WireRow {
                name: name.clone(),
                count: *count,
            })
            .collect(),
    }
}

fn announce(verdict: &SentinelVerdict) {
    match &verdict.skip_reason {
        Some(reason) => eprintln!("sentinel-sources-legacy skipped: {reason}"),
        None => eprintln!(
            "sentinel-sources-legacy: {} (reader gate {}, legacy leg {} — see the verdict's \
             `note` for exact scope)",
            verdict.verdict,
            if verdict.sentinel_reader_present {
                "lifted"
            } else {
                "shut"
            },
            verdict.legacy_leg,
        ),
    }
}

/// The gate's whole decision, pulled out of the I/O so it is unit-testable
/// without a [`RunLayout`]: `present` (already measured by [`probe_reader`])
/// picks `PASS` with no skip reason, or `SKIPPED` naming `detail`.
fn gate(present: bool, detail: &str) -> (&'static str, Option<String>) {
    if present {
        return ("PASS", None);
    }
    (
        "SKIPPED",
        Some(format!(
            "the sentinel-safe reader could not be confirmed present: {detail}. Standing the \
             topology up without it would record 'rmule did not parse the sentinel' for a \
             reason that is not interop, which ADR-0045 forbids. Point --sentinel-reader-probe \
             at a built `{READER_READINESS_MARKER}` (e.g. `--sentinel-reader-probe \
             /path/to/target/debug/rmule-tools ed2k sentinel-probe` — a binary's absolute \
             path, no embedded flags, since `num_args = 1..` stops at the first `-`-prefixed \
             token) and this flow lifts with no further change here."
        )),
    )
}

/// Run the configured probe, if any. Never an error: a probe that fails IS the
/// answer.
fn probe_reader(argv: &[String]) -> (bool, String) {
    let Some((program, args)) = argv.split_first() else {
        return (
            false,
            "no --sentinel-reader-probe configured on this branch".to_owned(),
        );
    };
    let status = Command::new(OsString::from(program))
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    match status {
        Ok(status) if status.success() => (true, format!("`{}` succeeded", argv.join(" "))),
        Ok(status) => (false, format!("`{}` exited {status}", argv.join(" "))),
        Err(error) => (
            false,
            format!("`{}` could not run: {error}", argv.join(" ")),
        ),
    }
}

fn write_verdict(layout: &RunLayout, verdict: &SentinelVerdict) -> Result<()> {
    let text = toml::to_string_pretty(verdict).context("serialize sentinel verdict")?;
    let path = layout.root().join("sentinel-sources-legacy-verdict.toml");
    println!("{text}");
    fs::write(&path, text).with_context(|| format!("write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_present_reader_passes_the_gate_with_no_skip_reason() {
        let (verdict, skip_reason) = gate(true, "`rmule-tools ed2k sentinel-probe` succeeded");
        assert_eq!(verdict, "PASS");
        assert!(skip_reason.is_none(), "a PASS names no skip reason");
    }

    #[test]
    fn an_absent_reader_is_skipped_and_names_the_probes_own_detail() {
        let (verdict, skip_reason) = gate(
            false,
            "no --sentinel-reader-probe configured on this branch",
        );
        assert_eq!(verdict, "SKIPPED");
        let reason = skip_reason.expect("an absent reader must name why");
        assert!(
            reason.contains("no --sentinel-reader-probe configured on this branch"),
            "{reason}"
        );
    }

    #[test]
    fn an_unconfigured_probe_reads_as_absent() {
        let (present, detail) = probe_reader(&[]);
        assert!(!present);
        assert_eq!(
            detail,
            "no --sentinel-reader-probe configured on this branch"
        );
    }

    #[test]
    fn a_succeeding_probe_command_reads_as_present() {
        let argv = vec!["true".to_owned()];
        let (present, detail) = probe_reader(&argv);
        assert!(present, "{detail}");
    }

    #[test]
    fn a_failing_probe_command_reads_as_absent() {
        let argv = vec!["false".to_owned()];
        let (present, detail) = probe_reader(&argv);
        assert!(!present);
        assert!(detail.contains("exited"), "{detail}");
    }

    /// A gate-only run must never read as the whole sentinel-row claim: its note says
    /// the legacy leg did not run, and the leg's own field says `NOT-RUN`.
    #[test]
    fn a_gate_only_verdict_says_the_legacy_leg_did_not_run() {
        let probe = vec!["true".to_owned()];
        let verdict = assemble("docker", &probe, "PASS", None, None);
        assert_eq!(verdict.verdict, "PASS");
        assert_eq!(verdict.legacy_leg, "NOT-RUN");
        assert!(
            verdict.note.contains("legacy leg was NOT run"),
            "{}",
            verdict.note
        );
        let text = toml::to_string_pretty(&verdict).expect("the verdict serialises");
        assert!(text.contains("legacy_leg = \"NOT-RUN\""), "{text}");
    }
}
