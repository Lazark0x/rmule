//! What a wire row selects in a capture: packets a BPF names by their headers,
//! or eD2k frames read out of reassembled TCP streams.
//!
//! A BPF runs per packet, and a TCP packet is not an eD2k frame: a sender packs
//! two frames into one segment and splits a long one across several, so a
//! predicate on a segment's first payload byte (`tcp[((tcp[12]&0xf0)>>2)]`)
//! misses every frame that does not open its segment. A row about an eD2k
//! opcode on a TCP link is therefore [`WireFilter::Ed2kFrames`]: the BPF only
//! chooses the link by address and port, tcpdump hands those segments over
//! whole, and [`crate::flow::pcap::tcp_streams_in`] walks the frames. A
//! [`WireFilter::Packets`] BPF that still reads a segment's payload offset is
//! refused before tcpdump runs.

use std::borrow::Cow;
use std::ffi::OsString;
use std::fmt;

use anyhow::{Context, Result, bail};

use crate::docker::Docker;
use crate::flow::pcap::{Ed2kFrame, TcpStream, tcp_streams_in};

/// `OP_EDONKEYPROT`, the protocol byte of a plain eDonkey frame.
pub(crate) const OP_EDONKEYPROT: u8 = 0xE3;
/// `OP_EMULEPROT`, the protocol byte of an eMule extension frame.
pub(crate) const OP_EMULEPROT: u8 = 0xC5;

/// One wire row's selection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum WireFilter {
    /// Every packet the BPF selects. Header predicates only: a predicate on a
    /// TCP segment's payload offset is refused.
    Packets(Cow<'static, str>),
    /// Every eD2k frame with `opcode` under one of `protocols` in the TCP
    /// segments `link` selects, after reassembly.
    Ed2kFrames {
        /// The BPF choosing the link's segments by address and port; `tcp and`
        /// is prefixed when it runs.
        link: Cow<'static, str>,
        /// The protocol bytes that count.
        protocols: &'static [u8],
        /// The opcode that counts.
        opcode: u8,
    },
}

impl WireFilter {
    /// Every `opcode` frame under one of `protocols` on the TCP segments `link`
    /// selects.
    pub(crate) fn ed2k(
        link: impl Into<Cow<'static, str>>,
        protocols: &'static [u8],
        opcode: u8,
    ) -> Self {
        Self::Ed2kFrames {
            link: link.into(),
            protocols,
            opcode,
        }
    }

    /// [`ed2k`](Self::ed2k) for a row table: a fixed link template.
    pub(crate) const fn ed2k_static(
        link: &'static str,
        protocols: &'static [u8],
        opcode: u8,
    ) -> Self {
        Self::Ed2kFrames {
            link: Cow::Borrowed(link),
            protocols,
            opcode,
        }
    }

    /// A packet row for a row table: a fixed BPF template.
    pub(crate) const fn packets_static(bpf: &'static str) -> Self {
        Self::Packets(Cow::Borrowed(bpf))
    }

    /// The same selection with `substitute` applied to its BPF.
    pub(crate) fn map_bpf(&self, substitute: impl Fn(&str) -> String) -> Self {
        match self {
            Self::Packets(bpf) => Self::Packets(substitute(bpf).into()),
            Self::Ed2kFrames {
                link,
                protocols,
                opcode,
            } => Self::Ed2kFrames {
                link: substitute(link).into(),
                protocols,
                opcode: *opcode,
            },
        }
    }

    /// Whether `frame` is one this row counts.
    pub(crate) fn matches(&self, frame: &Ed2kFrame) -> bool {
        match self {
            Self::Packets(_) => false,
            Self::Ed2kFrames {
                protocols, opcode, ..
            } => protocols.contains(&frame.protocol) && frame.opcode == *opcode,
        }
    }
}

impl From<&str> for WireFilter {
    fn from(bpf: &str) -> Self {
        Self::Packets(Cow::Owned(bpf.to_owned()))
    }
}

impl From<String> for WireFilter {
    fn from(bpf: String) -> Self {
        Self::Packets(Cow::Owned(bpf))
    }
}

impl From<&String> for WireFilter {
    fn from(bpf: &String) -> Self {
        Self::Packets(Cow::Owned(bpf.clone()))
    }
}

impl From<&Self> for WireFilter {
    fn from(filter: &Self) -> Self {
        filter.clone()
    }
}

impl fmt::Display for WireFilter {
    /// As a verdict names it: the BPF, or the link plus the frame it reads.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Packets(bpf) => f.write_str(bpf),
            Self::Ed2kFrames {
                link,
                protocols,
                opcode,
            } => {
                let protocols: Vec<String> =
                    protocols.iter().map(|p| format!("{p:#04x}")).collect();
                write!(
                    f,
                    "tcp and {link}, reassembled; eD2k frames {}/{opcode:#04x}",
                    protocols.join("|")
                )
            }
        }
    }
}

/// Whether `bpf` reads a TCP segment's payload by its data offset — the
/// predicate that assumes a frame opens its segment.
pub(crate) fn reads_segment_payload(bpf: &str) -> bool {
    let squashed: String = bpf.chars().filter(|c| !c.is_whitespace()).collect();
    squashed.contains("tcp[((tcp[12]&0xf0)>>2)")
}

/// Refuse `bpf` when it reads a segment's payload offset.
///
/// # Errors
/// Always, for such a BPF.
pub(crate) fn refuse_segment_payload(bpf: &str) -> Result<()> {
    if reads_segment_payload(bpf) {
        bail!(
            "the filter `{bpf}` reads a TCP segment's first payload bytes, which misses \
             an eD2k frame sharing a segment with the one before it; select the link by \
             address and port and read its frames with WireFilter::Ed2kFrames"
        );
    }
    Ok(())
}

/// Every TCP direction on the segments `link` selects in the capture sidecar's
/// `pcap`, reassembled. tcpdump writes the selected segments to stdout as a
/// pcap; the walk runs here.
///
/// # Errors
/// If tcpdump fails (a truncated tail on a pcap still being written is not a
/// failure) or its output is not a pcap.
pub(crate) fn capture_tcp_streams(
    docker: &Docker,
    capture_container: &str,
    pcap: &str,
    link: &str,
) -> Result<Vec<TcpStream>> {
    let output = docker
        .exec(
            capture_container.to_owned(),
            [
                OsString::from("sh"),
                OsString::from("-c"),
                OsString::from(link_script(pcap, link)?),
            ],
        )
        .to_command()
        .output()
        .context("read a TCP link: failed to spawn container runtime")?;
    streams_from(&output, &format!("{capture_container}:{pcap}"), link)
}

/// The `sh -c` script that writes the segments `link` selects in `pcap` to
/// stdout as a pcap, for [`streams_from`] to walk.
///
/// # Errors
/// If `link` reads a segment's payload offset.
pub(crate) fn link_script(pcap: &str, link: &str) -> Result<String> {
    refuse_segment_payload(link)?;
    Ok(format!(
        "tcpdump -nr {pcap} -w - 'tcp and ({link})' 2>/tmp/tcp-walk.err; rc=$?; \
         if [ \"$rc\" -ne 0 ] && ! grep -q 'truncated dump file' /tmp/tcp-walk.err; then \
         cat /tmp/tcp-walk.err >&2; exit \"$rc\"; fi"
    ))
}

/// The streams in the pcap a [`link_script`] run wrote to stdout.
///
/// # Errors
/// If the run failed or its stdout is not a pcap.
pub(crate) fn streams_from(
    output: &std::process::Output,
    source: &str,
    link: &str,
) -> Result<Vec<TcpStream>> {
    if !output.status.success() {
        bail!(
            "read a TCP link: tcpdump exited unsuccessfully for `{link}`: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    tcp_streams_in(&output.stdout, source)
}

/// Every eD2k frame `filter` selects in the capture sidecar's `pcap`, in
/// capture order of the segment that completed it.
///
/// # Errors
/// As [`capture_tcp_streams`]; a [`WireFilter::Packets`] is an error here.
pub(crate) fn capture_ed2k_frames(
    docker: &Docker,
    capture_container: &str,
    pcap: &str,
    filter: &WireFilter,
) -> Result<Vec<Ed2kFrame>> {
    let WireFilter::Ed2kFrames { link, .. } = filter else {
        bail!("`{filter}` selects packets, not eD2k frames");
    };
    let mut frames: Vec<Ed2kFrame> = capture_tcp_streams(docker, capture_container, pcap, link)?
        .iter()
        .flat_map(TcpStream::ed2k_frames)
        .filter(|frame| filter.matches(frame))
        .collect();
    frames.sort_by(|a, b| a.at.total_cmp(&b.at));
    Ok(frames)
}

/// [`capture_ed2k_frames`], also writing the link's segments to `out_name`
/// beside the pcap, so the frames stay re-readable from the run's archive.
///
/// # Errors
/// As [`capture_ed2k_frames`], or if the segments cannot be written.
pub(crate) fn lift_ed2k_frames(
    docker: &Docker,
    capture_container: &str,
    pcap: &str,
    filter: &WireFilter,
    out_name: &str,
) -> Result<Vec<Ed2kFrame>> {
    let WireFilter::Ed2kFrames { link, .. } = filter else {
        bail!("`{filter}` selects packets, not eD2k frames");
    };
    crate::flow::evidence::write_pcap_all_matches(
        docker,
        capture_container,
        pcap,
        &format!("tcp and ({link})"),
        out_name,
    )?;
    capture_ed2k_frames(docker, capture_container, pcap, filter)
}

#[cfg(test)]
mod tests {
    use super::reads_segment_payload;

    /// Both spellings the harness carried are caught; a header predicate and
    /// the payload-length idiom (which reads no payload byte) are not.
    #[test]
    fn a_segment_payload_predicate_is_recognised_in_either_spelling() {
        assert!(reads_segment_payload(
            "tcp and tcp[((tcp[12] & 0xf0) >> 2)] = 0xc5"
        ));
        assert!(reads_segment_payload("tcp[((tcp[12]&0xf0)>>2)+5] = 0x84"));
        assert!(!reads_segment_payload(
            "tcp and src host 45.55.200.6 and tcp[tcpflags] & tcp-syn != 0"
        ));
        assert!(!reads_segment_payload(
            "(ip[2:2] - ((ip[0] & 0xf) << 2) - ((tcp[12] & 0xf0) >> 2)) > 0"
        ));
    }
}
