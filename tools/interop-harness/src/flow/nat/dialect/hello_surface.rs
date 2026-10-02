//! `peer-hello-surface`: the hello each bench client sends rmule, and how
//! each takes rmule's.
//!
//! Every client body this bench holds — stock aMule 2.3.3, kno's aMule
//! `ab483654`, emule-qt `73fff714` — stands up logged in to `ed2ksrv`, sharing
//! one multi-part **Synthetic File** (`B`) and tapped on its own attachment
//! before anything dials. Then, in one run:
//!
//! 1. **rmule dials each** (`rmule-tools ipv6 hello`, over IPv4, last): its
//!    `OP_HELLOANSWER` retained and named by rmule's strict reader, and its
//!    reaction to rmule's hello — which ends in `CT_MOD_VERSION` —
//!    read off the wire: an `OP_EMULEINFO` would mean it took rmule for a
//!    pre-0.42 mule, a hang-up during the hold that it objected.
//! 2. **Each dials rmule**: a real serving `Core` shares a one-part file (`A`)
//!    and every client downloads it, so each opens a connection to rmule with
//!    its own `OP_HELLO` — cut from the client's tap as the capture candidate —
//!    runs Secure User Identification, and pulls the part.
//! 3. **rmule downloads from each**: one downloading `Core` per client pulls that
//!    client's own file, so each serves rmule a part.
//! 4. **rmule meets rmule**: a second downloading `Core` pulls `A` from the
//!    serving one, and each names the other in its own log.
//! 5. **After meeting** (`after_meeting`): each client, holding the link
//!    rmule's dial left, learns rmule as a source for a new file — what it
//!    does then is the dial-back claim; and kno, its IPv6 verified, answers
//!    stock aMule and a downloading rmule with an over-counted hello; then
//!    (`kno_dials`) kno dials a serving rmule it has not met, and rmule reads
//!    kno's `OP_HELLO` on the inbound road; last (`kno_dials_emuleqt`), kno
//!    dials a fresh emule-qt with the same hello, and emule-qt's answer or
//!    hang-up is read off kno's tap.
//!
//! Each client's own log is kept beside the rows; a line naming rmule's
//! software is quoted when the client writes one.

mod after_meeting;
mod kno_dials;
mod kno_dials_emuleqt;
mod transfer;

use std::time::Duration;

use anyhow::{Context, Result};

use crate::docker::RunContainer;
use crate::flow::bench::Bench;
use crate::flow::ed2ksrv::Ed2ksrvImage;
use crate::flow::gate::wait_for_container_log;
use crate::flow::nat::dialect::bench::{
    HOST_AMULE_KNO, HOST_ED2KSRV, HOST_EMULEQT, HOST_LEGACY_AMULE, Ipv6DialectOptions, Stage,
    body_log,
};
use crate::flow::nat::dialect::legs::hello_leg;
use crate::flow::nat::dialect::verdict::{Body, Claim, DriverRow, Evidence};
use crate::flow::nat::dialect::{BODY_PEER_TCP_PORT, ED2KSRV_TCP_PORT};
use crate::flow::nat::synthetic::write_hashed;
use crate::flow::taps::{Attachment, PerAttachmentTaps, TapRole};

/// The size of each client's own shared file: four parts.
const SHARED_B_BYTES: u64 = 3 * 9_728_000 + (1 << 20);

/// Readiness of the stock scenario script, which kno's image also runs.
const AMULE_READY: &str = "rmule-amule-ready";
/// emule-qt's readiness once logged in to the server, and once it hashed `B`.
const EMULEQT_READY: &str = "rmule-emuleqt-ready";
const EMULEQT_HASHED: &str = "Hashed OK";

/// One client body.
pub(super) struct Client {
    /// Its name in claims and artifacts.
    pub(super) name: &'static str,
    /// Its host slot on the WAN.
    pub(super) host: usize,
    /// Its container role (`rmule-interop-<role>-<suffix>`).
    pub(super) role: &'static str,
    /// The image option it runs.
    kind: Kind,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Amule,
    AmuleKno,
    EmuleQt,
}

pub(super) const CLIENTS: [Client; 3] = [
    Client {
        name: "amule-233",
        host: HOST_LEGACY_AMULE,
        role: "hsamule",
        kind: Kind::Amule,
    },
    Client {
        name: "amule-kno",
        host: HOST_AMULE_KNO,
        role: "hskno",
        kind: Kind::AmuleKno,
    },
    Client {
        name: "emuleqt",
        host: HOST_EMULEQT,
        role: "hsqt",
        kind: Kind::EmuleQt,
    },
];

/// The tap sidecars' name prefix; each is `<prefix>-<client>`.
pub(super) fn tap_prefix(suffix: &str) -> String {
    format!("rmule-interop-hstap-{suffix}")
}

/// Stand up the server and the three clients, each logged in, sharing `B` from
/// a directory of its own and tapped before any driver runs. Returns no body
/// for the bench's own tap: this flow keeps one per client.
///
/// # Errors
/// If a body cannot start, never becomes ready, or its tap never listens.
pub(super) fn start(
    bench: &mut Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &mut Stage,
    suffix: &str,
    timeout: Duration,
) -> Result<Option<String>> {
    let server_v4 = stage.v4(HOST_ED2KSRV).to_owned();
    let server = format!("rmule-interop-v6srv-{suffix}");
    let ed2ksrv = Ed2ksrvImage::check(&bench.docker, options.ed2ksrv_image)?;
    bench.start_extra(
        &server,
        ed2ksrv
            .container()
            .detach()
            .name(&server)
            .network(&stage.network)
            .ip(&server_v4)
            .ip6(stage.v6(HOST_ED2KSRV))
            .cap_add("NET_ADMIN"),
        "run the ed2k-server every body logs in to",
    )?;
    stage.bodies.push(Body {
        name: "ed2ksrv".to_owned(),
        image: options.ed2ksrv_image.to_owned(),
        pin: ed2ksrv.pin(),
        address_v4: server_v4.clone(),
        address_v6: String::new(),
    });

    let mut shared_b = None;
    for (index, client) in (0u64..).zip(&CLIENTS) {
        let dir = stage.leg_dir.join(format!("{}-incoming", client.name));
        std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        // A file of its own per client (sizes differ, so hashes do): the
        // downloader that asks it for a part has no other source to prefer.
        let file = write_hashed(&dir, SHARED_B_BYTES + index * 4096)?;
        std::fs::write(
            stage.leg_dir.join(format!("{}-b.link", client.name)),
            &file.link,
        )
        .context("keep the client's file link")?;
        shared_b = Some(file);
        let name = format!("rmule-interop-{}-{suffix}", client.role);
        let (image, pin) = match client.kind {
            Kind::Amule => (options.amule_image, "aMule 2.3.3, Ubuntu 24.04 package"),
            Kind::AmuleKno => (
                options.amule_kno_image,
                "kno/amule integration/network-parity ab483654",
            ),
            Kind::EmuleQt => (options.emuleqt_image, "ModderMule/emule-qt 73fff714"),
        };
        let container = RunContainer::new(image)
            .detach()
            .name(&name)
            .network(&stage.network)
            .ip(stage.v4(client.host))
            .ip6(stage.v6(client.host))
            .cap_add("NET_ADMIN")
            .volume(&dir, "/incoming");
        let container = match client.kind {
            Kind::EmuleQt => container
                .env("EMULEQT_SCENARIO_MODE", "ed2k-server")
                .env("ED2K_SERVER_HOST", &server_v4)
                .env("ED2K_SERVER_PORT", ED2KSRV_TCP_PORT.to_string()),
            // A debug-built aMule logs how it treats a source and a peer's
            // close; a release build ignores the knob.
            Kind::Amule => container
                .env("AMULE_DEBUG_SOURCE_CATEGORIES", "1")
                .env("AMULE_SCENARIO_MODE", "ed2k-server")
                .env("AMULE_SHARED_DIR", "/incoming")
                .env("ED2K_SERVER_HOST", &server_v4)
                .env("ED2K_SERVER_PORT", ED2KSRV_TCP_PORT.to_string()),
            Kind::AmuleKno => container
                .env("AMULE_SCENARIO_MODE", "ed2k-server")
                .env("AMULE_SHARED_DIR", "/incoming")
                .env("ED2K_SERVER_HOST", &server_v4)
                .env("ED2K_SERVER_PORT", ED2KSRV_TCP_PORT.to_string()),
        };
        bench.start_extra(&name, container, &format!("run {}", client.name))?;
        let ready = if client.kind == Kind::EmuleQt {
            EMULEQT_READY
        } else {
            AMULE_READY
        };
        wait_for_container_log(&bench.docker, &name, ready, timeout)?;
        if client.kind == Kind::EmuleQt {
            wait_for_container_log(&bench.docker, &name, EMULEQT_HASHED, timeout)?;
        }
        PerAttachmentTaps::start(
            bench,
            options.capture_image,
            &name,
            &tap_prefix(suffix),
            &stage.leg_dir,
            &[Attachment {
                name: client.name,
                interface: crate::flow::bench::DEFAULT_TAP_INTERFACE,
                role: TapRole::Evidence,
                bpf: "ip",
            }],
            timeout,
        )?;
        stage.bodies.push(Body {
            name: client.name.to_owned(),
            image: image.to_owned(),
            pin: pin.to_owned(),
            address_v4: stage.v4(client.host).to_owned(),
            address_v6: stage.v6(client.host).to_owned(),
        });
    }
    stage.shared = shared_b;
    Ok(None)
}

/// Drive the flow and return its claims plus the standing note.
///
/// # Errors
/// If a driver container cannot run or its row cannot be read.
pub(super) fn drive(
    bench: &mut Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
) -> Result<(Vec<Claim>, String)> {
    // The byte-moving legs go first: a client that already holds rmule's
    // user hash from a dial of ours meets the serving rmule as a known client,
    // not as a fresh source, and the first run (1790611214) saw stock aMule
    // never dial a source it had met that way.
    let mut claims = transfer::drive(bench, options, stage)?;
    for client in &CLIENTS {
        let leg = format!("hello-surface-{}", client.name);
        let peer = format!("{}:{BODY_PEER_TCP_PORT}", stage.v4(client.host));
        let row = hello_leg(bench, options, stage, &leg, &peer, None)?;
        claims.extend(dial_claims(client.name, &row));
    }
    // Only now, with every client holding the link a dial of ours left: the
    // order the first run hit, and kno's IPv6 verified last so nothing
    // before it meets kno's over-counted answer.
    claims.extend(after_meeting::drive(bench, options, stage)?);
    Ok((
        claims,
        "Each client's OP_HELLO is cut from its own tap into `op-hello-<client>.bin`; \
         its OP_HELLOANSWER is `hello-surface-<client>-capture/helloanswer.bin`."
            .to_owned(),
    ))
}

/// What rmule's dial of one client settles.
fn dial_claims(name: &str, row: &DriverRow) -> Vec<Claim> {
    vec![
        Claim::about(
            format!("{name}-hello-read-by-the-strict-reader"),
            row.flag("identified") && row.int("hello_answer_bytes") > 0,
            Evidence::Captured,
            format!(
                "OP_HELLOANSWER {} bytes ({}), {} of {} declared tags whole; rmule read it as \
                 {}; failure={:?}",
                row.int("hello_answer_bytes"),
                row.text("hello_answer_file"),
                row.int("answer_tags_read"),
                row.int("answer_tags_declared"),
                row.text("peer_software"),
                row.text("failure"),
            ),
        ),
        Claim::about(
            format!("{name}-took-rmule-for-a-mule"),
            row.flag("identified") && !row.flag("peer_sent_emule_info"),
            Evidence::DocumentedAbsence,
            format!(
                "no OP_EMULEINFO in the client's inbound stream: it read rmule's CT_EMULE_VERSION \
                 and skipped the pre-0.42 exchange (aMule ClientTCPSocket.cpp:347-349); \
                 peer_sent_emule_info={}",
                row.flag("peer_sent_emule_info"),
            ),
        ),
        Claim::about(
            format!("{name}-held-the-link-after-rmule-named-itself"),
            row.flag("identified") && !row.flag("peer_closed_during_hold"),
            Evidence::Captured,
            format!(
                "the link stayed up through the hold after a hello ending in CT_MOD_VERSION; \
                 events: {:?}",
                row.list("events_during_hold"),
            ),
        ),
    ]
}

/// The first line of `log` that names rmule, if the client wrote one.
pub(super) fn line_naming_rmule(log: &str) -> Option<&str> {
    log.lines()
        .find(|line| line.contains("rmule 0.") || line.contains("rmule v"))
        .map(str::trim)
}

/// Keep a body's log in the leg dir and return it.
pub(super) fn keep_log(bench: &Bench, stage: &Stage, container: &str, leg: &str) -> String {
    body_log(bench, stage, container, leg).unwrap_or_default()
}
