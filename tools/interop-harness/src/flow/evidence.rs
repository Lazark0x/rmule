//! Reading recorded bytes back out for the verdicts to judge (ADR-0045).
//!
//! Three recording surfaces land here: rmule's own datagram tap
//! (`datagrams.toml` rows paired with `datagrams.bin` frames), the passive
//! tcpdump pcap a capture sidecar writes, and the golden files an aMule authors
//! on a clean shutdown — plus the one byte-for-byte check a deterministic
//! synthetic file makes a real assertion. This module only *reads* and decodes;
//! which bytes count as counterparty evidence is each flow's verdict to decide.
//! Recorded bytes are never synthesised or repaired here — an absent frame is
//! reported as absent.

use std::ffi::OsString;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::artifacts::RunLayout;
use crate::docker::Docker;
use crate::flow::bench::{amulecmd_command, run_checked};
use crate::flow::wire_filter::{WireFilter, capture_ed2k_frames, refuse_segment_payload};

/// Read a node's own retained trail — its stdout/stderr log or its events log —
/// for a verdict to scan for markers.
///
/// Every read error propagates, absence included. These files are written
/// before any verdict runs (log collection drains the container; the rmule
/// runner creates its events log when it starts), so a file that will not open
/// means the run lost its record, not that the node stayed quiet. Defaulting to
/// an empty string here would turn "nobody could read the log" into
/// `tcp_firewall_installed = false` — the fabricated row ADR-0045 forbids, and
/// the same swallow [`count_pcap_rows`] refuses for a rejected BPF expression.
pub(crate) fn read_verdict_log(path: &Path) -> Result<String> {
    fs::read_to_string(path).with_context(|| format!("read {}", path.display()))
}

/// One `rmule-obfuscation-flip` marker line an rmule printed
/// (`--peer-crypt-flip`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FlipMarker {
    /// Seconds after the run's login was asked for.
    pub(crate) after_secs: u64,
    /// The policy word put in force: `off`, `supported`, `requested` or
    /// `required`.
    pub(crate) policy: String,
    /// The wall clock the policy took effect at, in Unix milliseconds — the
    /// clock the bench's taps stamp packets with. Absent from markers printed
    /// before the tools carried it.
    pub(crate) at_unix_ms: Option<u64>,
}

/// The obfuscation flips an rmule marked, in the order they fired: what a
/// verdict splits rmule's taps on, since every surface reads the policy as
/// it decides (ADR-0046). A flip the log does not hold is a flip that did
/// not fire, never one assumed.
pub(crate) fn flip_markers(log: &str) -> Vec<FlipMarker> {
    log.lines()
        .filter_map(|line| {
            let marker = line.split("rmule-obfuscation-flip ").nth(1)?;
            let field = |key: &str| {
                marker
                    .split_whitespace()
                    .find_map(|word| word.strip_prefix(key))
            };
            Some(FlipMarker {
                after_secs: field("after_secs=")?.parse().ok()?,
                policy: field("policy=")?.to_owned(),
                at_unix_ms: field("at_unix_ms=").and_then(|ms| ms.parse().ok()),
            })
        })
        .collect()
}

/// [`flip_markers`], each as `<secs>:<policy>` — the form a flow's result
/// line prints.
pub(crate) fn obfuscation_flips(log: &str) -> Vec<String> {
    flip_markers(log)
        .into_iter()
        .map(|flip| format!("{}:{}", flip.after_secs, flip.policy))
        .collect()
}

/// `items` as a TOML array of strings.
pub(crate) fn toml_strings(items: &[String]) -> String {
    let quoted: Vec<String> = items.iter().map(|item| format!("\"{item}\"")).collect();
    format!("[{}]", quoted.join(", "))
}

/// Read a golden a [`flush_golden_files`] run lifted out, where **absence is
/// the observation**: the counterparty authored no such file, so `docker cp`
/// copied nothing and the verdict records a zero-byte golden.
///
/// Only `NotFound` reads as absence. Every other error propagates, because a
/// golden that exists but cannot be read is a broken run dir, and reporting it
/// as `server_met_bytes = 0` would be a measurement nobody made.
pub(crate) fn read_flushed_golden(path: &Path) -> Result<Vec<u8>> {
    match fs::read(path) {
        Ok(bytes) => Ok(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error).with_context(|| format!("read {}", path.display())),
    }
}

/// Kad opcodes the source-capture verdict keys on (second byte after the 0xE4
/// protocol byte, as recorded in the tap's `opcode` field).
pub(crate) const KAD2_SEARCH_SOURCE_REQ: i64 = 0x34;
pub(crate) const KAD2_SEARCH_RES: i64 = 0x3B;
pub(crate) const KAD2_PUBLISH_SOURCE_REQ: i64 = 0x44;
pub(crate) const KAD2_PUBLISH_RES: i64 = 0x4B;

/// Kad keyword opcodes the inverted verdict keys on (the second byte after the
/// `0xE4` protocol byte, as the tap's `opcode` field records it).
pub(crate) const KAD2_SEARCH_KEY_REQ: i64 = 0x33;
pub(crate) const KAD2_PUBLISH_KEY_REQ: i64 = 0x43;

/// The `[u32 LE length][bytes]` frames of a `datagrams.bin`, in arrival order.
/// A truncated trailing frame ends the walk — it is never returned partially.
pub(crate) fn frames(data: &[u8]) -> impl Iterator<Item = &[u8]> {
    let mut offset = 0usize;
    std::iter::from_fn(move || {
        let len_bytes: [u8; 4] = data.get(offset..offset + 4)?.try_into().ok()?;
        let len = u32::from_le_bytes(len_bytes) as usize;
        let frame = data.get(offset + 4..offset + 4 + len)?;
        offset += 4 + len;
        Some(frame)
    })
}

/// Read the `seq`-th frame from a `datagrams.bin` capture file (frames are in
/// arrival order, seq starts at 0).
pub(crate) fn read_capture_frame(bin: &Path, seq: usize) -> Result<Vec<u8>> {
    let data = fs::read(bin).with_context(|| format!("read {}", bin.display()))?;
    frames(&data)
        .nth(seq)
        .map(<[u8]>::to_vec)
        .with_context(|| format!("frame seq {seq} not found in {}", bin.display()))
}

/// One row of the tap's `datagrams.toml`: rmule's own account of a datagram —
/// its arrival index (the `datagrams.bin` frame index), direction, remote
/// endpoint and the opcode byte after the protocol byte.
pub(crate) struct TapRow {
    pub(crate) seq: usize,
    pub(crate) direction: String,
    pub(crate) remote: String,
    pub(crate) opcode: i64,
}

impl TapRow {
    /// Whether this row is a datagram in `direction` (`"in"` / `"out"`)
    /// carrying `opcode`.
    pub(crate) fn is(&self, direction: &str, opcode: i64) -> bool {
        self.direction == direction && self.opcode == opcode
    }
}

/// Read the tap's rows. A tap that was never finalized — the node was killed
/// before its shutdown wrote `datagrams.toml` — is an inconclusive run and
/// bails naming the `.partial` frames; a tap that never existed bails too.
pub(crate) fn read_tap_rows(tap_dir: &Path) -> Result<Vec<TapRow>> {
    let rows_path = tap_dir.join("datagrams.toml");
    if !rows_path.exists() {
        let partial = tap_dir.join("datagrams.bin.partial");
        if partial.exists() {
            bail!(
                "rmule node did not finalize its capture: {} missing but {} exists (killed \
                 before shutdown). Inspect the .partial frames; the run is inconclusive.",
                rows_path.display(),
                partial.display()
            );
        }
        bail!("rmule node produced no capture at {}", rows_path.display());
    }
    let text = fs::read_to_string(&rows_path)
        .with_context(|| format!("read rmule tap {}", rows_path.display()))?;
    let value: toml::Value = toml::from_str(&text).context("parse rmule tap datagrams.toml")?;
    let empty = Vec::new();
    let rows = value
        .get("frame")
        .and_then(|frame| frame.as_array())
        .unwrap_or(&empty);
    Ok(rows
        .iter()
        .map(|row| TapRow {
            seq: row
                .get("seq")
                .and_then(toml::Value::as_integer)
                .and_then(|seq| usize::try_from(seq).ok())
                .unwrap_or(usize::MAX),
            direction: row
                .get("direction")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned(),
            remote: row
                .get("remote")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_owned(),
            opcode: row
                .get("opcode")
                .and_then(toml::Value::as_integer)
                .unwrap_or(-1),
        })
        .collect())
}

/// One tap frame, paired with the raw bytes `datagrams.bin` holds for it.
pub(crate) struct TapFrame {
    pub(crate) direction: String,
    pub(crate) remote: String,
    pub(crate) bytes: Vec<u8>,
}

/// Pair `datagrams.toml`'s rows with `datagrams.bin`'s frames (row `seq` is the
/// frame index — the capture writes both in arrival order).
pub(crate) fn read_tap_frames(tap_dir: &Path) -> Result<Vec<TapFrame>> {
    let rows = read_tap_rows(tap_dir)?;
    let bin_path = tap_dir.join("datagrams.bin");
    let data = fs::read(&bin_path).with_context(|| format!("read {}", bin_path.display()))?;
    let raw: Vec<&[u8]> = frames(&data).collect();
    Ok(rows
        .into_iter()
        .filter_map(|row| {
            Some(TapFrame {
                bytes: raw.get(row.seq)?.to_vec(),
                direction: row.direction,
                remote: row.remote,
            })
        })
        .collect())
}

/// The Kad protocol byte every Kad2 envelope opens with.
pub(crate) const KAD_PROTOCOL: u8 = 0xE4;
/// `KADEMLIA2_HELLO_REQ` — the hello whose *responder* role is the only one that
/// can ask for a `0x22` (rmule answers it with the ACK-request bit).
pub(crate) const KAD2_HELLO_REQ: u8 = rmule_kad::opcode::KADEMLIA2_HELLO_REQ;
/// `KADEMLIA2_HELLO_RES`.
pub(crate) const KAD2_HELLO_RES: u8 = rmule_kad::opcode::KADEMLIA2_HELLO_RES;
/// `KADEMLIA2_HELLO_RES_ACK` — the three-way handshake's third leg (ADR-0064).
pub(crate) const KAD2_HELLO_RES_ACK: u8 = rmule_kad::opcode::KADEMLIA2_HELLO_RES_ACK;

/// One Kad datagram off the tap, reduced to what the verify-key verdict judges:
/// its opcode and — for an obfuscated one — the crypt facts that carried it.
pub(crate) struct KadFrameFacts {
    pub(crate) opcode: u8,
    pub(crate) payload: Vec<u8>,
    /// `None` for a plaintext datagram; else the on-wire marker byte.
    pub(crate) marker: Option<u8>,
    pub(crate) receiver_verify_key: Option<u32>,
    pub(crate) sender_verify_key: Option<u32>,
}

/// Read one tap frame as a Kad datagram: plaintext when it opens with the `0xE4`
/// protocol byte, else decrypted with the keys the reader holds. `None` when it
/// is neither (a datagram keyed to something we do not hold).
pub(crate) fn kad_frame_facts(
    bytes: &[u8],
    keys: &rmule_primitives::ClientDecryptKeys<'_>,
) -> Option<KadFrameFacts> {
    if bytes.first() == Some(&KAD_PROTOCOL) {
        return Some(KadFrameFacts {
            opcode: *bytes.get(1)?,
            payload: bytes.to_vec(),
            marker: None,
            receiver_verify_key: None,
            sender_verify_key: None,
        });
    }
    let decrypted = rmule_primitives::decrypt_datagram_client(bytes, keys)?;
    if decrypted.payload.first() != Some(&KAD_PROTOCOL) {
        return None;
    }
    Some(KadFrameFacts {
        opcode: *decrypted.payload.get(1)?,
        payload: decrypted.payload,
        marker: Some(bytes[0]),
        receiver_verify_key: decrypted.receiver_verify_key,
        sender_verify_key: decrypted.sender_verify_key,
    })
}

/// The one byte-for-byte check: `copy` (a downloader's output file) must equal
/// the synthetic file. The synthetic file is deterministic, so this is a real
/// assertion rather than a summary; `who` names the downloader in the failure.
pub(crate) fn verify_bytes(layout: &RunLayout, copy: &Path, who: &str) -> Result<()> {
    let expected = fs::read(layout.synthetic_shared_file())
        .with_context(|| format!("read {}", layout.synthetic_shared_file().display()))?;
    let actual = fs::read(copy).with_context(|| format!("read {}", copy.display()))?;
    if expected != actual {
        bail!(
            "{who} output mismatch: expected {} bytes, got {} bytes",
            expected.len(),
            actual.len()
        );
    }
    Ok(())
}

/// Golden-author flush: cleanly shut an aMule node down so it writes
/// `server.met` + `nodes.dat`, then copy those out of the container into
/// `dest_dir`. The golden-authoring flow (flow H) calls this; the files it
/// produces stay provenance-tracked under the run dir and are never
/// auto-promoted into `tests/fixtures/`.
///
/// A file the node never authored is skipped (not an error), so a Kad-only or
/// server-only node still yields whatever it flushed. A copy that fails for any
/// *other* reason — a vanished container, an unwritable destination, a runtime
/// that will not spawn — is an error: reading it as an absence would let a run
/// that could not reach its artifacts pass for one whose counterparty wrote
/// nothing. Returns the paths actually copied.
pub fn flush_golden_files(
    docker: &Docker,
    container: &str,
    config_dir: &str,
    dest_dir: &Path,
) -> Result<Vec<std::path::PathBuf>> {
    // A clean `amulecmd Shutdown` triggers SaveServerMet + CRoutingZone::WriteFile
    // — the deterministic flush of both goldens.
    run_checked(
        docker.exec(container.to_owned(), amulecmd_command("Shutdown")),
        "amulecmd Shutdown for golden flush",
    )?;
    // Block until amuled actually exits: aMule persists via CFile::write_safe
    // (temp file + rename), so the `docker cp` below must not race the rename.
    // Without this wait the cp lifts the pre-shutdown file — a seeded 15-byte
    // server.met instead of aMule's full 21-tag SaveServerMet output.
    // Best-effort: a wait failure (container already gone) still lets the cp try.
    let _ = run_checked(
        docker.wait(container.to_owned()),
        "docker wait for amuled clean shutdown",
    );
    fs::create_dir_all(dest_dir).with_context(|| format!("create {}", dest_dir.display()))?;
    let mut copied = Vec::new();
    for file in ["server.met", "nodes.dat"] {
        let dest = dest_dir.join(file);
        let source = format!("{config_dir}/{file}");
        if copy_golden(docker, container, &source, &dest)? == GoldenCopy::Copied {
            copied.push(dest);
        }
    }
    Ok(copied)
}

/// What one golden's `docker cp` did.
#[derive(Clone, Copy, PartialEq, Eq)]
enum GoldenCopy {
    /// The file is now in the run dir.
    Copied,
    /// The container holds no such file — the node authored none.
    NeverAuthored,
}

/// `docker cp` one golden out of `container`. A source the container does not
/// hold is [`GoldenCopy::NeverAuthored`]; every other failure is an error
/// carrying the runtime's own stderr (see [`flush_golden_files`]).
fn copy_golden(docker: &Docker, container: &str, source: &str, dest: &Path) -> Result<GoldenCopy> {
    let output = docker
        .copy_from_container(container, source, dest.as_os_str())
        .to_command()
        .output()
        .with_context(|| format!("docker cp golden {source}: failed to spawn container runtime"))?;
    if output.status.success() {
        return Ok(GoldenCopy::Copied);
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !names_a_missing_source(&stderr) {
        bail!(
            "docker cp golden {source} -> {}: container runtime exited unsuccessfully: {stderr}",
            dest.display()
        );
    }
    println!("golden flush: {container} authored no {source} — skipped");
    Ok(GoldenCopy::NeverAuthored)
}

/// Whether a failed `docker cp`'s stderr says the *source path* is simply not
/// in the container, which each runtime phrases its own way (docker: "Could not
/// find the file … in container", or the older "No such container:path:";
/// podman: "could not be found on container … No such file or directory").
///
/// Deliberately generous: an unrecognised phrasing costs a hard error on a
/// legitimately absent golden, which is loud and fixable, whereas classifying a
/// daemon failure as an absence is the silent drop this whole check exists to
/// stop. "No such container" is not matched — a container that vanished before
/// the flush is a failure, not an absence.
fn names_a_missing_source(stderr: &str) -> bool {
    let stderr = stderr.to_lowercase();
    stderr.contains("could not find the file")
        || stderr.contains("could not be found on container")
        || stderr.contains("no such container:path:")
        || stderr.contains("no such file or directory")
}

/// Count the pcap packets matching `filter` inside a running capture sidecar
/// (the only place tcpdump and the file are both present); `wc -l` counts
/// tcpdump's per-packet lines.
///
/// The pcap is read while the sidecar is still appending to it, so a half-written
/// trailing record ("truncated dump file") is expected and tolerated — but every
/// OTHER tcpdump failure must surface, above all a BPF expression this image's
/// libpcap rejects. Swallowing that would report the row as 0 forever and
/// degrade a promoted verdict with a fabricated-looking zero, so tcpdump's own
/// exit status and stderr are propagated, and a non-numeric count bails too.
///
/// A [`WireFilter::Ed2kFrames`] row counts eD2k frames out of the link's
/// reassembled streams instead; a [`WireFilter::Packets`] BPF that reads a TCP
/// segment's payload offset is refused.
pub(crate) fn count_pcap_rows(
    docker: &Docker,
    capture_container: &str,
    pcap: &str,
    filter: impl Into<WireFilter>,
) -> Result<u64> {
    let filter = match filter.into() {
        WireFilter::Packets(bpf) => bpf.into_owned(),
        frames @ WireFilter::Ed2kFrames { .. } => {
            let counted = capture_ed2k_frames(docker, capture_container, pcap, &frames)?;
            return Ok(counted.len() as u64);
        }
    };
    refuse_segment_payload(&filter)?;
    let script = format!(
        "tcpdump -nr {pcap} '{filter}' >/tmp/wire-row.out 2>/tmp/wire-row.err; rc=$?; \
         if [ \"$rc\" -ne 0 ] && ! grep -q 'truncated dump file' /tmp/wire-row.err; then \
         cat /tmp/wire-row.err >&2; exit \"$rc\"; fi; wc -l </tmp/wire-row.out"
    );
    let counted = run_checked(
        docker.exec(
            capture_container.to_owned(),
            [
                OsString::from("sh"),
                OsString::from("-c"),
                OsString::from(script),
            ],
        ),
        "count wire row",
    )?;
    counted.trim().parse::<u64>().with_context(|| {
        format!("count wire row: non-numeric count {counted:?} for filter `{filter}`")
    })
}

/// Write the **first** datagram matching `filter` to `out_name` beside the
/// pcap, inside the capture container (the only place tcpdump and the capture
/// both are). The capture directory is bind-mounted, so the host reads the
/// result back with [`crate::flow::pcap::first_udp_payload`].
///
/// A filter that matches nothing still produces a (record-less) pcap, which
/// reads back as `None` — an absence, never a fabrication (ADR-0045).
///
/// # Errors
/// If tcpdump cannot be run in the capture container.
pub(crate) fn write_pcap_first_match(
    docker: &Docker,
    capture_container: &str,
    pcap: &str,
    filter: &str,
    out_name: &str,
) -> Result<()> {
    write_pcap_matches(docker, capture_container, (pcap, filter), out_name, Some(1))
}

/// Write **every** packet matching `filter` to `out_name`, as
/// [`write_pcap_first_match`] writes the first; the host reads them back with
/// [`crate::flow::pcap::udp_payloads`], or — a TCP link's segments —
/// [`crate::flow::pcap::tcp_streams`].
///
/// # Errors
/// If tcpdump cannot be run in the capture container.
pub(crate) fn write_pcap_all_matches(
    docker: &Docker,
    capture_container: &str,
    pcap: &str,
    filter: &str,
    out_name: &str,
) -> Result<()> {
    write_pcap_matches(docker, capture_container, (pcap, filter), out_name, None)
}

fn write_pcap_matches(
    docker: &Docker,
    capture_container: &str,
    (pcap, filter): (&str, &str),
    out_name: &str,
    limit: Option<u32>,
) -> Result<()> {
    refuse_segment_payload(filter)?;
    let out = format!("{}/{out_name}", crate::flow::bench::CAPTURE_MOUNT);
    let limit = limit
        .map(|count| format!(" -c {count}"))
        .unwrap_or_default();
    // `-c` stops at the limit; a `truncated dump file` on the *input* is the
    // sidecar's still-open handle and is not an error here either.
    let script = format!(
        "tcpdump -nr {pcap} -w {out}{limit} '{filter}' 2>/tmp/body.err; rc=$?; \
         if [ \"$rc\" -ne 0 ] && ! grep -q 'truncated dump file' /tmp/body.err; then \
         cat /tmp/body.err >&2; exit \"$rc\"; fi; \
         [ -f {out} ] || : > {out}; echo ok"
    );
    run_checked(
        docker.exec(
            capture_container.to_owned(),
            [
                OsString::from("sh"),
                OsString::from("-c"),
                OsString::from(script),
            ],
        ),
        "extract wire body",
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{flip_markers, frames, names_a_missing_source, obfuscation_flips, toml_strings};

    /// The flips are read off rmule's own marker lines, in the order they
    /// fired, and nothing else in the log reads as one.
    #[test]
    fn the_flips_are_the_marker_lines_rmule_printed() {
        let log = "rmule-kad-crypt-armed\n\
                   rmule-obfuscation-flip after_secs=60 policy=off\n\
                   INFO run_log: obfuscation policy changed policy=off\n\
                   rmule-obfuscation-flip after_secs=180 policy=requested at_unix_ms=1791428597250\n";
        let flips = obfuscation_flips(log);
        assert_eq!(flips, ["60:off", "180:requested"]);
        assert_eq!(toml_strings(&flips), r#"["60:off", "180:requested"]"#);
        let clocks: Vec<_> = flip_markers(log).iter().map(|m| m.at_unix_ms).collect();
        assert_eq!(clocks, [None, Some(1_791_428_597_250)]);
        assert!(obfuscation_flips("no markers here\n").is_empty());
    }

    /// The golden flush may only skip a golden the node never authored. A
    /// vanished container, a denied destination or a dead daemon must stay
    /// errors, or the flush turns a broken run into "the counterparty wrote
    /// nothing".
    #[test]
    fn only_a_missing_source_path_reads_as_an_unauthored_golden() {
        for absent in [
            "Error response from daemon: Could not find the file /root/.aMule/nodes.dat in \
             container amule-x",
            "Error: No such container:path: amule-x:/root/.aMule/nodes.dat",
            "Error: \"/root/.aMule/nodes.dat\" could not be found on container amule-x: No such \
             file or directory",
        ] {
            assert!(names_a_missing_source(absent), "absent golden: {absent}");
        }
        for failure in [
            "Error response from daemon: No such container: amule-x",
            "Error: open /runs/2026/nodes.dat: permission denied",
            "Cannot connect to the Docker daemon at unix:///var/run/docker.sock",
        ] {
            assert!(!names_a_missing_source(failure), "copy failure: {failure}");
        }
    }

    #[test]
    fn frame_walk_stops_at_a_truncated_trailer() {
        // Two whole frames then a length prefix promising more bytes than remain:
        // the walk yields the two and never a partial third.
        let mut data = Vec::new();
        data.extend_from_slice(&2u32.to_le_bytes());
        data.extend_from_slice(&[0xE4, 0x21]);
        data.extend_from_slice(&1u32.to_le_bytes());
        data.push(0x29);
        data.extend_from_slice(&9u32.to_le_bytes());
        data.push(0xFF);
        let walked: Vec<&[u8]> = frames(&data).collect();
        assert_eq!(walked, vec![&[0xE4, 0x21][..], &[0x29][..]]);
    }
}
