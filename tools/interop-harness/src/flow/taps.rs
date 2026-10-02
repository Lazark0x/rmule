//! **Per-Attachment Taps**: one **Capture Sidecar** per network a container is
//! attached to, and the per-tap verdict row they grow.
//!
//! A single-homed container has one attachment and the old one-sidecar-per-flow
//! shape was exactly right for it. A **NAT Gateway** has two, and the whole
//! point of a NAT flow is what changes *between* them: the WAN tap holds the
//! counterparty's bytes after translation (the evidence), the LAN tap holds the
//! same datagram before it (part of the **NAT Type Proof**). One sidecar would
//! leave the translation itself unobserved, which is the one thing the flow is
//! there to witness.
//!
//! Both sidecars share the gateway's network namespace and differ only by
//! `-i <interface>`, so the two pcaps are the same capture discipline (`-s 0`,
//! `-U`) applied at two points on one path.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Serialize;

use crate::docker::Docker;
use crate::flow::bench::{Bench, CaptureSidecar};
use crate::flow::evidence::count_pcap_rows;
use crate::flow::gate::wait_for_container_log;

/// What a tap's bytes are allowed to prove.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum TapRole {
    /// Outside the translation: counterparty bytes as the world saw them. This
    /// is the tap a verdict may cite as evidence.
    Evidence,
    /// Inside the translation: the client's own datagram before the gateway
    /// rewrote it. Corroborates the NAT Type Proof; never evidence on its own,
    /// because these are the client's bytes.
    Corroboration,
}

/// One declared attachment to tap.
pub(crate) struct Attachment<'a> {
    /// The tap's short name (`wan`, `lan`) — the pcap and the row are named for
    /// it.
    pub(crate) name: &'a str,
    /// The interface inside the tapped container's namespace.
    pub(crate) interface: &'a str,
    /// What the bytes on this side may prove.
    pub(crate) role: TapRole,
    /// The tcpdump filter.
    pub(crate) bpf: &'a str,
}

/// One tap's verdict row.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct TapRow {
    /// The attachment's name.
    pub(crate) attachment: String,
    /// The interface tapped.
    pub(crate) interface: String,
    /// The pcap's file name in the leg's directory.
    pub(crate) pcap: String,
    /// What this side's bytes may prove.
    pub(crate) role: TapRole,
    /// Packets matching the tap's own filter — a measurement, and a zero here
    /// is a **Documented Absence**, never a silent skip.
    pub(crate) packets: u64,
}

/// The taps a flow declared on one container, held for counting and teardown.
pub(crate) struct PerAttachmentTaps {
    /// `(attachment name, interface, sidecar container, pcap file, role)`.
    started: Vec<(String, String, String, String, TapRole)>,
}

impl PerAttachmentTaps {
    /// Start one sidecar per `attachments` entry on `target_container`, each
    /// writing into `host_dir`, own them all for teardown on the bench, and
    /// hold until each tcpdump reports it is listening.
    ///
    /// The readiness gate is load-bearing, not tidiness. libpcap takes tens of
    /// milliseconds to attach, and a flow whose exchange is *fast* — a gateway
    /// leg where every probe test answers at once — otherwise finishes before
    /// the tap is live and writes a 24-byte pcap holding only its file header.
    /// That reads as a **Documented Absence** when it is really a lost capture.
    /// tcpdump's own `listening on <iface>` line is the signal.
    ///
    /// Names are `<prefix>-<attachment>`, so a run dir's container ids stay
    /// readable when four gateway legs run in sequence.
    ///
    /// # Errors
    /// If any sidecar fails to start or never reports listening. Earlier
    /// sidecars are already owned by the bench, so a mid-way failure still
    /// tears down.
    pub(crate) fn start(
        bench: &mut Bench,
        capture_image: &str,
        target_container: &str,
        name_prefix: &str,
        host_dir: &Path,
        attachments: &[Attachment<'_>],
        timeout: Duration,
    ) -> Result<Self> {
        let mut started = Vec::with_capacity(attachments.len());
        for attachment in attachments {
            let container = format!("{name_prefix}-{}", attachment.name);
            let pcap_file = format!("tap-{}.pcap", attachment.name);
            let sidecar = CaptureSidecar {
                image: capture_image,
                name: &container,
                target_container,
                interface: attachment.interface,
                host_dir: host_dir.to_path_buf(),
                pcap_file: &pcap_file,
                bpf: attachment.bpf,
            };
            bench.start_extra(
                &container,
                sidecar.container(),
                &format!("run {} tap sidecar", attachment.name),
            )?;
            wait_for_container_log(&bench.docker, &container, "listening on", timeout)?;
            started.push((
                attachment.name.to_owned(),
                attachment.interface.to_owned(),
                container,
                pcap_file,
                attachment.role,
            ));
        }
        Ok(Self { started })
    }

    /// Count every tap's packets with `filter` and return the rows, in
    /// declaration order. Counted while the sidecars still run, which is the
    /// only moment tcpdump and the pcap are in the same namespace.
    ///
    /// # Errors
    /// If a count fails — a rejected BPF expression must surface rather than
    /// degrade every row to zero.
    pub(crate) fn rows(
        &self,
        docker: &Docker,
        filter: impl Into<crate::flow::wire_filter::WireFilter>,
    ) -> Result<Vec<TapRow>> {
        let filter = filter.into();
        self.started
            .iter()
            .map(|(attachment, interface, container, pcap_file, role)| {
                let packets =
                    count_pcap_rows(docker, container, &format!("/capture/{pcap_file}"), &filter)?;
                Ok(TapRow {
                    attachment: attachment.clone(),
                    interface: interface.clone(),
                    pcap: pcap_file.clone(),
                    role: *role,
                    packets,
                })
            })
            .collect()
    }

    /// Write every packet of `attachment`'s tap that matches `filter` to
    /// `out_name` in the tap's host directory, for the host to read back with
    /// [`crate::flow::pcap`]. Taken while the sidecar still runs, like
    /// [`rows`](Self::rows).
    ///
    /// # Errors
    /// If no tap was declared for `attachment`, or tcpdump cannot run.
    pub(crate) fn lift(
        &self,
        docker: &Docker,
        attachment: &str,
        filter: &str,
        out_name: &str,
    ) -> Result<()> {
        let (_, _, container, pcap_file, _) = self
            .started
            .iter()
            .find(|(name, ..)| name == attachment)
            .with_context(|| format!("no tap declared on attachment {attachment}"))?;
        crate::flow::evidence::write_pcap_all_matches(
            docker,
            container,
            &format!("/capture/{pcap_file}"),
            filter,
            out_name,
        )
    }
}

/// The `taps.toml` a flow leg writes beside its pcaps.
#[derive(Debug, Serialize)]
pub(crate) struct TapsRecord {
    /// The flow that wrote this.
    #[serde(rename = "scenario")]
    pub(crate) flow: &'static str,
    /// The container whose attachments were tapped.
    pub(crate) tapped_container: String,
    /// The filter every row was counted with.
    pub(crate) filter: String,
    /// One row per attachment.
    #[serde(rename = "tap")]
    pub(crate) taps: Vec<TapRow>,
}

/// Write `record` as `taps.toml` under `dir`.
///
/// # Errors
/// If the record cannot be serialised or the file cannot be written.
pub(crate) fn write_taps_record(dir: &std::path::Path, record: &TapsRecord) -> Result<()> {
    let text = toml::to_string_pretty(record)?;
    let path = dir.join("taps.toml");
    std::fs::write(&path, text)
        .map_err(|error| anyhow::anyhow!("write {}: {error}", path.display()))
}
