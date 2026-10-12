//! Unit tests for transfer-rate synthesis from core's byte levels.

use rmule_core::DownloadMetadata;
use rmule_core::diagnostics::{
    DownloadDiagnostics, SessionCounters, UploadDiagnostics, WorkerEntry,
};
use rmule_primitives::FileHash;

use super::*;
use crate::fixture::part_map;
use crate::fixture::peer_endpoint;

const KIB100: u64 = 100 * 1024;

fn download_id() -> DownloadId {
    DownloadId::from_u64(7)
}

fn slot(index: usize) -> WorkerSlot {
    WorkerSlot::from_usize(index)
}

fn receiving(part_index: u32, bytes_received: u64) -> WorkerPhase {
    WorkerPhase::ReceivingPart {
        part_index,
        bytes_received,
    }
}

/// A snapshot carrying one download that has taken `received_bytes` with
/// its slots in the given phases. The session's down total tracks the row,
/// the way core advances the two together.
fn downloading(received_bytes: u64, slots: &[(usize, WorkerPhase)]) -> DiagnosticsSnapshot {
    let workers = slots
        .iter()
        .map(|(index, phase)| {
            let mut entry = WorkerEntry::new(slot(*index));
            entry.transition(phase.clone());
            (slot(*index), entry)
        })
        .collect();
    let mut downloads = BTreeMap::new();
    downloads.insert(
        download_id(),
        DownloadDiagnostics {
            download_id: download_id(),
            file_hash: FileHash::from_bytes([0; 16]),
            metadata: DownloadMetadata::unnamed(0),
            started_at: Instant::now(),
            parts: part_map("IMMMMMMMMMM"),
            retired_peers: 0,
            workers,
            received_bytes,
            known_sources: 0,
            dials_ended: 0,
            dial_ends: Default::default(),
            reask_replies_ignored: 0,
        },
    );
    DiagnosticsSnapshot {
        downloads,
        session: SessionCounters {
            down_bytes_total: received_bytes,
            up_bytes_total: 0,
            ..SessionCounters::default()
        },
        ..DiagnosticsSnapshot::default()
    }
}

/// A snapshot carrying one upload row per `(peer octet, bytes_sent)`, with
/// the session's up total summing them.
fn uploading(rows: &[(u8, u64)]) -> DiagnosticsSnapshot {
    let uploads = rows
        .iter()
        .map(|(octet, bytes_sent)| {
            (
                peer_endpoint(*octet),
                UploadDiagnostics {
                    peer: peer_endpoint(*octet),
                    file_hash: FileHash::from_bytes([1; 16]),
                    started_at: Instant::now(),
                    bytes_sent: *bytes_sent,
                },
            )
        })
        .collect();
    DiagnosticsSnapshot {
        uploads,
        session: SessionCounters {
            down_bytes_total: 0,
            up_bytes_total: rows.iter().map(|(_, sent)| *sent).sum(),
            ..SessionCounters::default()
        },
        ..DiagnosticsSnapshot::default()
    }
}

#[test]
fn steady_stream_converges_on_the_true_rate() {
    let mut synth = RateSynthesizer::new(Duration::from_secs(4));
    let t0 = Instant::now();

    let first = synth.observe(&downloading(0, &[(0, receiving(0, 0))]), t0);
    assert_eq!(first.down_total_bps, 0.0, "no interval exists yet");

    let mut last = 0.0;
    for tick in 1..=30_u64 {
        let snap = downloading(tick * KIB100, &[(0, receiving(0, tick * KIB100))]);
        last = synth
            .observe(&snap, t0 + Duration::from_secs(tick))
            .down_total_bps;
    }
    let expected = KIB100 as f64;
    assert!(
        (last - expected).abs() < expected * 0.01,
        "EMA should converge within 1% of {expected} B/s, got {last}"
    );
}

/// 30 s at 100 KiB/s, then 10 KiB/s: the window holds the burst for a full
/// minute and forgets it after, while the Speed meter follows within seconds.
#[test]
fn the_eta_average_spans_the_last_minute_of_the_run() {
    const KIB10: u64 = 10 * 1024;
    let mut synth = RateSynthesizer::new(Duration::from_secs(4));
    let t0 = Instant::now();
    let first = synth.observe(&downloading(0, &[]), t0);
    assert!(
        first.download_avg_bps.is_empty(),
        "no interval exists yet, so no average"
    );

    let mut avg_at = BTreeMap::new();
    let mut meter_at = BTreeMap::new();
    for tick in 1..=150_u64 {
        let level = tick.min(30) * KIB100 + tick.saturating_sub(30) * KIB10;
        let rates = synth.observe(&downloading(level, &[]), t0 + Duration::from_secs(tick));
        avg_at.insert(tick, rates.download_avg_bps[&download_id()]);
        meter_at.insert(tick, rates.download_bps[&download_id()]);
    }
    let (kib100, kib10) = (KIB100 as f64, KIB10 as f64);
    assert_eq!(
        avg_at[&10], kib100,
        "a run younger than the window averages over itself"
    );
    assert_eq!(
        avg_at[&60],
        (30.0 * kib100 + 30.0 * kib10) / 60.0,
        "30 s of each rate over the 60 s window"
    );
    assert!(
        (meter_at[&60] - kib10).abs() < kib10 * 0.01,
        "the Speed meter has already followed the step down"
    );
    assert_eq!(
        avg_at[&75],
        (15.0 * kib100 + 45.0 * kib10) / 60.0,
        "15 s of the burst left in the window"
    );
    assert_eq!(avg_at[&90], kib10, "the burst has left the window");
}

/// A burst, then silence: the Speed meter reads 0 once one time constant
/// passes with no bytes, not after a long tail, and the ETA's average reads
/// 0 with it instead of draining the burst out over a minute.
#[test]
fn a_burst_then_silence_reads_zero_after_one_meter_window() {
    let tau = Duration::from_secs(4);
    let mut synth = RateSynthesizer::new(tau);
    let t0 = Instant::now();
    synth.observe(&downloading(0, &[]), t0);
    for tick in 1..=10_u64 {
        synth.observe(
            &downloading(tick * KIB100, &[]),
            t0 + Duration::from_secs(tick),
        );
    }
    let quiet = |synth: &mut RateSynthesizer, secs: u64| {
        synth.observe(
            &downloading(10 * KIB100, &[]),
            t0 + Duration::from_secs(10 + secs),
        )
    };
    let early = quiet(&mut synth, 3);
    assert!(
        early.download_bps[&download_id()] > 0.0,
        "inside the window the meter still falls"
    );
    assert!(early.download_avg_bps[&download_id()] > 0.0);
    let settled = quiet(&mut synth, 4);
    assert_eq!(settled.download_bps[&download_id()], 0.0);
    assert_eq!(settled.down_total_bps, 0.0, "the status bar's meter too");
    assert_eq!(
        settled.download_avg_bps[&download_id()],
        0.0,
        "a stopped run estimates nothing, however much the minute still holds"
    );
}

#[test]
fn smoothing_covers_about_two_thirds_of_a_step_per_tau() {
    let mut synth = RateSynthesizer::new(Duration::from_secs(4));
    let t0 = Instant::now();
    synth.observe(&downloading(0, &[(0, receiving(0, 0))]), t0);
    // One observation a full tau later: alpha = 1 - e^-1 ≈ 0.632.
    let rate = synth
        .observe(
            &downloading(4 * KIB100, &[(0, receiving(0, 4 * KIB100))]),
            t0 + Duration::from_secs(4),
        )
        .down_total_bps;
    let step = KIB100 as f64; // instantaneous rate of the interval
    let ratio = rate / step;
    assert!(
        (ratio - 0.632).abs() < 0.01,
        "one tau should cover ~63.2% of the step, covered {ratio}"
    );
}

/// The download's own total is what the Speed column follows, so a part
/// boundary — where the worker's level restarts — must not dent it.
#[test]
fn a_downloads_rate_rides_its_own_total_across_a_part_boundary() {
    let mut synth = RateSynthesizer::new(Duration::from_secs(4));
    let t0 = Instant::now();
    synth.observe(&downloading(0, &[(0, receiving(4, 0))]), t0);
    for tick in 1..=20_u64 {
        // The worker restarts its level every 4 ticks; the download's
        // monotonic total never does.
        let phase = receiving(4 + (tick / 4) as u32, (tick % 4) * KIB100);
        synth.observe(
            &downloading(tick * KIB100, &[(0, phase)]),
            t0 + Duration::from_secs(tick),
        );
    }
    let last = synth.observe(
        &downloading(21 * KIB100, &[(0, receiving(9, KIB100))]),
        t0 + Duration::from_secs(21),
    );
    let expected = KIB100 as f64;
    let bps = last.download_bps[&download_id()];
    assert!(
        (bps - expected).abs() < expected * 0.05,
        "part boundaries must not dent the download's rate: {bps} vs {expected}"
    );
}

#[test]
fn a_source_slot_counts_only_the_bytes_into_its_new_part() {
    let mut synth = RateSynthesizer::new(Duration::from_secs(4));
    let t0 = Instant::now();
    synth.observe(&downloading(9_000_000, &[(0, receiving(5, 9_000_000))]), t0);
    let rates = synth.observe(
        &downloading(9_050_000, &[(0, receiving(6, 50_000))]),
        t0 + Duration::from_secs(1),
    );
    let ema = rates.source_bps[&(download_id(), slot(0))];
    assert!(ema > 0.0, "new-part bytes must count, got {ema}");
    // alpha(1s, tau 4s) ≈ 0.221 of the 50 kB/s instantaneous rate — far
    // below anything a (9 MB → 50 kB) naive difference would produce.
    assert!(
        ema < 50_000.0,
        "rollover must never spike past the new part's own bytes, got {ema}"
    );
}

#[test]
fn a_slot_that_stops_receiving_decays_toward_zero() {
    let mut synth = RateSynthesizer::new(Duration::from_secs(4));
    let t0 = Instant::now();
    let key = (download_id(), slot(0));
    synth.observe(&downloading(0, &[(0, receiving(0, 0))]), t0);
    let busy = synth
        .observe(
            &downloading(KIB100, &[(0, receiving(0, KIB100))]),
            t0 + Duration::from_secs(1),
        )
        .source_bps[&key];
    let idle = synth
        .observe(
            &downloading(KIB100, &[(0, WorkerPhase::VerifyingPart { part_index: 0 })]),
            t0 + Duration::from_secs(2),
        )
        .source_bps[&key];
    assert!(idle < busy, "no bytes ⇒ decay ({idle} < {busy})");
    assert!(idle > 0.0, "the EMA decays, it does not snap to zero");
}

#[test]
fn zero_elapsed_time_changes_nothing() {
    let mut synth = RateSynthesizer::new(Duration::from_secs(4));
    let t0 = Instant::now();
    synth.observe(&downloading(0, &[(0, receiving(0, 0))]), t0);
    synth.observe(
        &downloading(KIB100, &[(0, receiving(0, KIB100))]),
        t0 + Duration::from_secs(1),
    );
    let before = synth.observe(
        &downloading(2 * KIB100, &[(0, receiving(0, 2 * KIB100))]),
        t0 + Duration::from_secs(2),
    );
    // The same instant again with a wildly different level: a no-op.
    let again = synth.observe(
        &downloading(9 * KIB100, &[(0, receiving(0, 9 * KIB100))]),
        t0 + Duration::from_secs(2),
    );
    assert_eq!(before, again);
}

#[test]
fn a_download_gone_from_the_snapshot_starts_fresh_when_it_returns() {
    let mut synth = RateSynthesizer::new(Duration::from_secs(4));
    let t0 = Instant::now();
    synth.observe(&downloading(0, &[(0, receiving(0, 0))]), t0);
    synth.observe(
        &downloading(KIB100, &[(0, receiving(0, KIB100))]),
        t0 + Duration::from_secs(1),
    );

    let empty = DiagnosticsSnapshot::default();
    let rates = synth.observe(&empty, t0 + Duration::from_secs(2));
    assert!(rates.download_bps.is_empty());
    assert!(rates.source_bps.is_empty());

    // Re-appearing is a first sighting again: rate 0, no stale delta.
    let rates = synth.observe(
        &downloading(50 * KIB100, &[(0, receiving(0, 50 * KIB100))]),
        t0 + Duration::from_secs(3),
    );
    assert_eq!(rates.download_bps[&download_id()], 0.0);
}

#[test]
fn the_up_meters_converge_on_the_served_byte_rate() {
    let mut synth = RateSynthesizer::new(Duration::from_secs(4));
    let t0 = Instant::now();
    let first = synth.observe(&uploading(&[(1, 0), (2, 0)]), t0);
    assert_eq!(first.up_total_bps, 0.0, "no interval exists yet");

    let mut last = TransferRates::default();
    for tick in 1..=30_u64 {
        // Peer 1 is served twice as fast as peer 2.
        last = synth.observe(
            &uploading(&[(1, tick * 2 * KIB100), (2, tick * KIB100)]),
            t0 + Duration::from_secs(tick),
        );
    }
    let per_peer = KIB100 as f64;
    assert!(
        (last.upload_bps[&peer_endpoint(1)] - 2.0 * per_peer).abs() < per_peer * 0.01,
        "peer 1 rate {}",
        last.upload_bps[&peer_endpoint(1)]
    );
    assert!(
        (last.upload_bps[&peer_endpoint(2)] - per_peer).abs() < per_peer * 0.01,
        "peer 2 rate {}",
        last.upload_bps[&peer_endpoint(2)]
    );
    assert!(
        (last.up_total_bps - 3.0 * per_peer).abs() < per_peer * 0.02,
        "▲ totals every served byte: {}",
        last.up_total_bps
    );
}

#[test]
fn an_upload_row_retiring_drops_its_meter_and_a_regrant_starts_fresh() {
    let mut synth = RateSynthesizer::new(Duration::from_secs(4));
    let t0 = Instant::now();
    synth.observe(&uploading(&[(1, 0)]), t0);
    let serving = synth.observe(&uploading(&[(1, KIB100)]), t0 + Duration::from_secs(1));
    assert!(serving.upload_bps[&peer_endpoint(1)] > 0.0);

    // Slot released: the row leaves, and so does its meter.
    let released = synth.observe(&uploading(&[]), t0 + Duration::from_secs(2));
    assert!(
        released.upload_bps.is_empty(),
        "a retired row reports nothing"
    );

    // A re-grant is a first sighting: the peer's carried-over total must
    // not land as one tick's worth of bytes.
    let regranted = synth.observe(&uploading(&[(1, 50 * KIB100)]), t0 + Duration::from_secs(3));
    assert_eq!(regranted.upload_bps[&peer_endpoint(1)], 0.0);
}

/// The design reason the totals difference `SessionCounters` instead of
/// summing the rows: bytes that land as a transfer tears down still meter.
#[test]
fn session_totals_keep_metering_after_every_row_is_gone() {
    let mut synth = RateSynthesizer::new(Duration::from_secs(4));
    let t0 = Instant::now();
    let with_row = |bytes: u64| downloading(bytes, &[(0, receiving(0, bytes))]);
    synth.observe(&with_row(0), t0);
    synth.observe(&with_row(KIB100), t0 + Duration::from_secs(1));

    // The row is torn down, but core counted the tail it delivered.
    let orphaned = DiagnosticsSnapshot {
        session: SessionCounters {
            down_bytes_total: 2 * KIB100,
            up_bytes_total: 0,
            ..SessionCounters::default()
        },
        ..DiagnosticsSnapshot::default()
    };
    let rates = synth.observe(&orphaned, t0 + Duration::from_secs(2));
    assert!(
        rates.download_bps.is_empty(),
        "no row, so no per-download rate"
    );
    assert!(
        rates.down_total_bps > 0.0,
        "▼ still meters the bytes that landed: {}",
        rates.down_total_bps
    );
}

/// The Kad totals ride the snapshot, so their meters difference tick to
/// tick, and a node that stops takes its meters with it.
#[test]
fn kad_rates_difference_tick_to_tick_and_a_stopped_node_drops_them() {
    use rmule_core::diagnostics::{
        KadFirewallCheck, KadFirewallVerdict, KadTraffic, KadUdpVerdict,
    };
    let snapshot = |datagrams_in, bytes_in, datagrams_out, bytes_out| DiagnosticsSnapshot {
        kad: Some(KadRuntimeDiagnostics {
            contact_responded: true,
            contacts: 1,
            keywords_stored: 0,
            node_id: rmule_core::KadId::from_bytes([1; 16]),
            firewall: KadFirewallVerdict::Firewalled,
            firewall_check: KadFirewallCheck::NotYetRun,
            udp: KadUdpVerdict::Unverified,
            traffic: KadTraffic {
                datagrams_in,
                bytes_in,
                datagrams_out,
                bytes_out,
            },
        }),
        ..DiagnosticsSnapshot::default()
    };
    let t0 = Instant::now();
    let mut synth = RateSynthesizer::new(Duration::from_secs(4));
    assert_eq!(
        synth.observe(&snapshot(1, 1_000, 1, 500), t0).kad,
        Some(KadRates::default()),
        "a first sighting meters nothing"
    );

    // Five seconds on: 10 KiB / 20 datagrams in, 5 KiB / 10 datagrams out.
    let later = t0 + Duration::from_secs(5);
    let rates = synth
        .observe(
            &snapshot(1 + 20, 1_000 + 10_240, 1 + 10, 500 + 5_120),
            later,
        )
        .kad
        .expect("a running node has rates");
    let alpha = 1.0 - (-5.0f64 / 4.0).exp();
    assert!((rates.in_bps - alpha * 2_048.0).abs() < 1e-6, "{rates:?}");
    assert!((rates.out_bps - alpha * 1_024.0).abs() < 1e-6, "{rates:?}");
    assert!(
        (rates.dgrams_in_bps - alpha * 4.0).abs() < 1e-6,
        "{rates:?}"
    );
    assert!(
        (rates.dgrams_out_bps - alpha * 2.0).abs() < 1e-6,
        "{rates:?}"
    );

    assert_eq!(
        synth
            .observe(
                &DiagnosticsSnapshot::default(),
                later + Duration::from_secs(1)
            )
            .kad,
        None
    );
}

#[test]
fn rate_text_is_kb_per_second_at_one_decimal() {
    assert_eq!(format_rate(0.0), "0.0 KB/s");
    assert_eq!(format_rate(123.4 * 1024.0), "123.4 KB/s");
}
