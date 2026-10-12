//! The self-check target's hello **after** its UDP verdict reads open:
//! the hello that carries `MiscOptions2` bit 12, the direct-UDP-callback
//! advert aMule writes once Kad is TCP-firewalled with UDP verified open
//! (`BaseClient.cpp:1131-1132`, rmule's `hello_direct_udp_callback`).
//!
//! The target's only other hellos are the `OP_FWCHECKUDPREQ` dials to its
//! helpers, and they leave *before* the verdict they ask for, so they carry the
//! bit clear by construction. A hello after the verdict needs a reason to dial,
//! and the one the bit advertises is the right one: an open rmule **requester**
//! on the WAN sends `OP_DIRECTCALLBACKREQ` (`0x95`, ADR-0061 route 2) to the
//! target's public Kad UDP port, the target accepts it (firewalled, UDP open)
//! and dials the requester back — its `OP_HELLO` crosses the gateway's WAN tap.
//! The requester is told the target's user hash and Kad UDP endpoint out of
//! band, as Stimulus: the facts a type-6 source row would carry.
//!
//! The requester runs Kad with `--assume-open` only so its own half of the
//! route tree reads reachable; without it the selector would read LowID→LowID
//! and never pick route 2.

use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};
use rmule_primitives::{Tag, TagValue};

use super::super::{PLACEHOLDER_SHARE, READY_TIMEOUT_SECS, absent_server, common_args, mesh};
use crate::docker::RunContainer;
use crate::flow::bench::Bench;
use crate::flow::gate::wait_for_container_log;
use crate::flow::nat::claims::{Claim, Evidence};
use crate::flow::nat::natt::bench::NattOptions;
use crate::flow::taps::PerAttachmentTaps;

/// The requester's WAN host index: the second gateway's slot, which this
/// one-gateway topology leaves free.
pub(super) const HOST_REQUESTER: usize = 1;

const HASH_REQUESTER: &str = "47474747474747474747474747474747";
const REQUESTER_KAD_ID: [u8; 16] = [0xCC; 16];

/// How long the requester holds after its `0x95` — the dial-back's window.
const REQUESTER_WINDOW_SECS: u64 = 30;

/// The peer TCP port every body listens on.
const PEER_TCP_PORT: u16 = 4662;

const OP_EDONKEYPROT: u8 = 0xE3;
const OP_HELLO: u8 = 0x01;
const CT_EMULE_MISCOPTIONS2: u8 = 0xFE;

/// `MiscOptions2` bit 12: `SupportsDirectUDPCallback`.
const DIRECT_UDP_CALLBACK_BIT: u32 = 1 << 12;

/// The two lifted pcaps, in the target's leg directory.
const LIFTED_BEFORE: &str = "target-hello-to-helpers.pcap";
const LIFTED_AFTER: &str = "target-hello-direct-callback.pcap";

/// Start the requester, wait for it to bind, then hand it the target. The
/// target file is written after readiness so the `ReachPeer` finds the client
/// UDP socket bound.
///
/// # Errors
/// If the container cannot start, never reports ready, or the file cannot be
/// written.
#[allow(clippy::too_many_arguments)]
pub(super) fn start_requester(
    bench: &mut Bench,
    options: &NattOptions<'_>,
    suffix: &str,
    wan: &str,
    requester_v4: &str,
    dir: &Path,
    root_v4: &str,
    target_kad_udp: &str,
) -> Result<String> {
    let name = format!("rmule-interop-nattdcbreq-{suffix}");
    let mut container = RunContainer::new(options.rmule_tools_image)
        .detach()
        .name(&name)
        .network(wan)
        .ip(requester_v4)
        .cap_add("NET_ADMIN")
        .env("RMULE_LOG", "info,rmule_core=debug")
        .volume(dir, "/out");
    for arg in common_args(
        "requester",
        HASH_REQUESTER,
        requester_v4,
        REQUESTER_WINDOW_SECS,
        &absent_server(),
        PLACEHOLDER_SHARE,
    ) {
        container = container.arg(arg);
    }
    for arg in [
        "--kad-id".to_owned(),
        mesh::hex(&REQUESTER_KAD_ID),
        "--assume-open".to_owned(),
        "--kad-contact".to_owned(),
        mesh::seed_operand(&mesh::hex(&mesh::BUDDY_KAD_ID), root_v4),
        "--target-file".to_owned(),
        "/out/target.toml".to_owned(),
        "--target-timeout".to_owned(),
        "120".to_owned(),
    ] {
        container = container.arg(arg);
    }
    bench.start_extra(&name, container, "run the direct-callback requester")?;
    wait_for_container_log(
        &bench.docker,
        &name,
        "rmule-natt-buddy-ready",
        Duration::from_secs(READY_TIMEOUT_SECS),
    )?;
    let path = dir.join("target.toml");
    std::fs::write(
        &path,
        format!(
            "user_hash={}\nkad_udp={target_kad_udp}\n",
            super::HASH_TARGET
        ),
    )
    .with_context(|| format!("write {}", path.display()))?;
    Ok(name)
}

/// The target's `MiscOptions2` before and after the verdict, read off the
/// gateway's WAN tap: its first `OP_HELLO` to a helper, and its first to the
/// requester.
pub(super) struct Hellos {
    before: Option<u32>,
    after: Option<u32>,
}

/// Lift both hellos.
///
/// # Errors
/// If the tap cannot be lifted or a lifted pcap read back.
pub(super) fn lift(
    bench: &Bench,
    taps: &PerAttachmentTaps,
    gateway_wan: &str,
    requester_v4: &str,
    target_dir: &Path,
) -> Result<Hellos> {
    let read = |filter: String, lifted: &str| -> Result<Option<u32>> {
        taps.lift(&bench.docker, "wan", &filter, lifted)?;
        let mut hellos: Vec<_> = crate::flow::pcap::tcp_streams(&target_dir.join(lifted))?
            .iter()
            .flat_map(crate::flow::pcap::TcpStream::ed2k_frames)
            .filter(|frame| (frame.protocol, frame.opcode) == (OP_EDONKEYPROT, OP_HELLO))
            .collect();
        hellos.sort_by(|a, b| a.at.total_cmp(&b.at));
        Ok(hellos
            .first()
            .and_then(|hello| hello_misc_options2(&hello.bytes)))
    };
    let outbound = format!("tcp and src host {gateway_wan} and tcp dst port {PEER_TCP_PORT}");
    Ok(Hellos {
        before: read(
            format!("{outbound} and not dst host {requester_v4}"),
            LIFTED_BEFORE,
        )?,
        after: read(
            format!("{outbound} and dst host {requester_v4}"),
            LIFTED_AFTER,
        )?,
    })
}

/// The claim: the dial-back's hello lights bit 12.
pub(super) fn claim(hellos: &Hellos, routed: &str) -> Claim {
    let bit = |value: Option<u32>| value.map(|value| value & DIRECT_UDP_CALLBACK_BIT != 0);
    let show = |value: Option<u32>| {
        value.map_or_else(|| "no hello".to_owned(), |value| format!("{value:#010x}"))
    };
    Claim::about(
        "the-targets-post-verdict-hello-lights-misc-options2-bit-12",
        bit(hellos.after) == Some(true),
        Evidence::RmuleOnly,
        format!(
            "the requester's route: {routed:?}; the target's OP_HELLO dialling back the 0x95 \
             carried MiscOptions2 {} (bit 12 {}); its OP_HELLO to a helper before the verdict \
             carried {} (bit 12 {}) — aMule lights the bit only once Kad is TCP-firewalled \
             with UDP verified open (BaseClient.cpp:1131-1132)",
            show(hellos.after),
            state(bit(hellos.after)),
            show(hellos.before),
            state(bit(hellos.before)),
        ),
    )
}

fn state(bit: Option<bool>) -> &'static str {
    match bit {
        Some(true) => "set",
        Some(false) => "clear",
        None => "unread",
    }
}

/// `MiscOptions2` of one whole `OP_HELLO` frame, when it carries one.
fn hello_misc_options2(hello: &[u8]) -> Option<u32> {
    // `<header 6><size 1><hash 16><id 4><port 2><count 4><tags>`.
    let body = hello.get(6..)?;
    let count = u32::from_le_bytes(body.get(23..27)?.try_into().ok()?);
    let mut at = 27;
    for _ in 0..count {
        let (tag, used) = Tag::decode_prefix(body.get(at..)?).ok()?;
        at += used;
        if let (Some(CT_EMULE_MISCOPTIONS2), TagValue::U32(value)) = (tag.name().id(), tag.value())
        {
            return Some(*value);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `OP_HELLO` `natt-udp-selfcheck-remapped` run `1790128546`
    /// lifted off the gateway's WAN tap (the target's dial to helper
    /// `45.55.200.7`, before its verdict read open): `MiscOptions2`
    /// `0x420`, bit 12 clear.
    #[test]
    fn a_pre_verdict_hello_reads_misc_options2_without_bit_12() {
        let hello = [
            0xE3, 0x56, 0x00, 0x00, 0x00, 0x01, 0x10, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
            0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x00, 0x00, 0x00, 0x00, 0x36,
            0x12, 0x06, 0x00, 0x00, 0x00, 0x02, 0x01, 0x00, 0x01, 0x0A, 0x00, 0x72, 0x6D, 0x75,
            0x6C, 0x65, 0x2D, 0x6E, 0x61, 0x74, 0x74, 0x03, 0x01, 0x00, 0x11, 0x3C, 0x00, 0x00,
            0x00, 0x83, 0xFA, 0x02, 0x30, 0x10, 0x20, 0x83, 0xFE, 0x20, 0x04, 0x00, 0x00, 0x03,
            0x01, 0x00, 0xFB, 0x80, 0x0D, 0x04, 0x03, 0x03, 0x01, 0x00, 0xAA, 0x27, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        assert_eq!(hello_misc_options2(&hello), Some(0x420));
    }
}
