//! The Core-pumped stimulus's own per-frame tap.
//!
//! `--kad-capture-dir` wires flow M's stimulus to write the same
//! `[u32 LE length][bytes]` + `datagrams.toml` format `kad join-node
//! --capture-dir` writes (ADR-0022), so the `--kad-crypt` leg's verdict can
//! be judged from decrypted bytes — an `assert_kad_verify_keys`-style
//! per-frame check — instead of trusted from rmule's own disposition trail
//! alone. The tap is optional (only present under `--kad-crypt`): reading it
//! for a run that never armed it is an honest "no tap", not a failure.
//!
//! The format finalizes only on the Kad node's own clean shutdown (ADR-0022):
//! `ed2k serve start` now runs that shutdown from its SIGTERM handler,
//! and `run_kad_core_buddy` runs a clean `docker stop` — never a kill
//! — strictly *before* it calls [`crate::flow::kad_buddy::core_verdict::assert_kad_core_buddy`],
//! which reads this tap, so a `--kad-crypt` run now reads
//! [`TapReadout::Finalized`] with real per-frame decode counts instead of
//! the [`TapReadout::Unfinalized`] it used to read.

use std::path::Path;

use anyhow::{Context, Result};

use crate::flow::evidence::{TapFrame, kad_frame_facts, read_tap_frames};

/// How many of the Core's tap frames to/from the counterparty decoded under
/// the negotiated keys, split by direction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct CoreTapCounts {
    /// Frames to/from the named remote, decoded or not.
    pub(crate) total: u32,
    /// Of those, how many inbound frames decoded under `inbound_keys`.
    pub(crate) decoded_in: u32,
    /// Of those, how many outbound frames decoded under `outbound_keys`.
    pub(crate) decoded_out: u32,
}

/// Count how many of `frames` addressed to/from `remote` decode under
/// `inbound_keys`/`outbound_keys` — the per-frame proof
/// `verify_keys::assert_kad_verify_keys` runs for flow K, generalized to
/// whichever two keys a caller holds for its own exchange.
pub(crate) fn count_core_tap_frames(
    frames: &[TapFrame],
    remote: &str,
    inbound_keys: &rmule_primitives::ClientDecryptKeys<'_>,
    outbound_keys: &rmule_primitives::ClientDecryptKeys<'_>,
) -> CoreTapCounts {
    let mut counts = CoreTapCounts::default();
    for frame in frames {
        if frame.remote != remote {
            continue;
        }
        counts.total += 1;
        let inbound = frame.direction == "in";
        let keys = if inbound { inbound_keys } else { outbound_keys };
        if kad_frame_facts(&frame.bytes, keys).is_some() {
            if inbound {
                counts.decoded_in += 1;
            } else {
                counts.decoded_out += 1;
            }
        }
    }
    counts
}

/// What reading the Core's tap at verdict time found. The tap only finalizes
/// into `datagrams.toml`/`datagrams.bin` on the Kad node's own clean shutdown
/// (ADR-0022's `.partial`-staging contract) — and flow M reads it *before*
/// tearing the stimulus container down, so a live run reads
/// [`Unfinalized`](Self::Unfinalized) even while the tap is actively
/// recording. Never fabricated as a zero count either way (ADR-0045).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TapReadout {
    /// No `--kad-capture-dir` was wired for this run.
    Absent,
    /// The tap is (or was) recording, but the Kad node never reached a clean
    /// shutdown before this read — only the `.partial` staging file exists,
    /// which ADR-0022 documents as non-authoritative. `bytes` is its size:
    /// nonzero proves the tap is live even though it cannot yet be decoded.
    Unfinalized { bytes: u64 },
    /// A clean finalize renamed the `.partial` files into place: the counts
    /// are real per-frame decode results.
    Finalized(CoreTapCounts),
}

/// Read the Core's tap at `tap_dir` and report what state it is in.
pub(crate) fn read_core_tap(
    tap_dir: &Path,
    remote: &str,
    inbound_keys: &rmule_primitives::ClientDecryptKeys<'_>,
    outbound_keys: &rmule_primitives::ClientDecryptKeys<'_>,
) -> Result<TapReadout> {
    if tap_dir.join("datagrams.toml").exists() {
        let frames = read_tap_frames(tap_dir)?;
        return Ok(TapReadout::Finalized(count_core_tap_frames(
            &frames,
            remote,
            inbound_keys,
            outbound_keys,
        )));
    }
    let partial = tap_dir.join("datagrams.bin.partial");
    match std::fs::metadata(&partial) {
        Ok(meta) => Ok(TapReadout::Unfinalized { bytes: meta.len() }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(TapReadout::Absent),
        Err(error) => Err(error).with_context(|| format!("stat {}", partial.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(direction: &str, remote: &str, bytes: Vec<u8>) -> TapFrame {
        TapFrame {
            direction: direction.to_owned(),
            remote: remote.to_owned(),
            bytes,
        }
    }

    /// The filter (only the named remote), the direction dispatch (inbound
    /// keys vs. outbound keys), and the decode gate (plaintext `0xE4` decodes
    /// with no keys at all; unrecognizable bytes do not) — the three things
    /// `assert_kad_core_buddy`'s tap check trusts this function for.
    #[test]
    fn counts_only_the_named_remote_split_by_direction_and_decode() {
        let remote = "203.0.113.9:4672";
        let other = "203.0.113.10:4672";
        let keys = rmule_primitives::ClientDecryptKeys::default();
        let frames = vec![
            frame("in", remote, vec![0xE4, 0x01]),
            frame("out", remote, vec![0xE4, 0x02]),
            frame("in", remote, vec![0x13, 0x37]),
            frame("in", other, vec![0xE4, 0x03]),
        ];

        let counts = count_core_tap_frames(&frames, remote, &keys, &keys);

        assert_eq!(
            counts,
            CoreTapCounts {
                total: 3,
                decoded_in: 1,
                decoded_out: 1,
            }
        );
    }

    /// The three states `read_core_tap` must distinguish: no directory at
    /// all (the knob was never passed), a live-recording `.partial` (real
    /// bytes, not yet decodable), and a clean finalize (real counts). Run
    /// `1790145260` hit the middle case: 1332 tap bytes, no
    /// `datagrams.toml` — the Core-pumped container was still running at
    /// verdict time.
    #[test]
    fn distinguishes_absent_unfinalized_and_finalized() {
        let keys = rmule_primitives::ClientDecryptKeys::default();
        let dir = tempfile::tempdir().expect("tempdir");

        assert_eq!(
            read_core_tap(dir.path(), "203.0.113.9:4672", &keys, &keys).unwrap(),
            TapReadout::Absent
        );

        std::fs::write(dir.path().join("datagrams.bin.partial"), [0u8; 7]).unwrap();
        assert_eq!(
            read_core_tap(dir.path(), "203.0.113.9:4672", &keys, &keys).unwrap(),
            TapReadout::Unfinalized { bytes: 7 }
        );

        std::fs::write(dir.path().join("datagrams.toml"), "").unwrap();
        std::fs::rename(
            dir.path().join("datagrams.bin.partial"),
            dir.path().join("datagrams.bin"),
        )
        .unwrap();
        assert_eq!(
            read_core_tap(dir.path(), "203.0.113.9:4672", &keys, &keys).unwrap(),
            TapReadout::Finalized(CoreTapCounts::default())
        );
    }

    /// The stop-then-read ordering, pinned against the exact two real calls
    /// `run_kad_core_buddy` makes around `assert_kad_core_buddy`: a clean
    /// `docker stop`, then the tap read. The fake runtime's `stop`
    /// subcommand performs the ADR-0022 finalize as a side effect — what a
    /// container's own SIGTERM handler does for real — so this only reads
    /// `Finalized` because the stop ran first; reversed, it would still see
    /// the `.partial` file and read `Unfinalized`.
    /// Unix only: the fake runtime is a `/bin/sh` script.
    #[cfg(unix)]
    #[test]
    fn a_clean_stop_before_the_read_sees_a_finalized_tap() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let tap_dir = tmp.path().join("tap");
        std::fs::create_dir_all(&tap_dir).unwrap();
        std::fs::write(tap_dir.join("datagrams.bin.partial"), [0u8; 5]).unwrap();

        let script_path = tmp.path().join("fake-docker.sh");
        std::fs::write(
            &script_path,
            format!(
                "#!/bin/sh\nset -eu\ncase \"$1\" in\n  stop) touch \"{tap}/datagrams.toml\"; mv \"{tap}/datagrams.bin.partial\" \"{tap}/datagrams.bin\" ;;\nesac\nexit 0\n",
                tap = tap_dir.display(),
            ),
        )
        .unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&script_path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&script_path, perms).unwrap();
        }

        let docker = crate::docker::Docker::new(script_path.as_os_str());
        crate::flow::bench::run_checked(docker.stop_container("fake-rmule", 15), "stop")
            .expect("fake docker stop succeeds");

        let keys = rmule_primitives::ClientDecryptKeys::default();
        let readout = read_core_tap(&tap_dir, "203.0.113.9:4672", &keys, &keys).unwrap();

        assert_eq!(readout, TapReadout::Finalized(CoreTapCounts::default()));
    }
}
