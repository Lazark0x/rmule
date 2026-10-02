//! `ipv6-extsx`: ExtSX admitted as the IPv6 carrier in source exchange.
//!
//! Three rmule bodies around one emule-qt `73fff714`, which shares a one-part
//! **Synthetic File**:
//!
//! 1. a hello from the driver host, for emule-qt's claim bits;
//! 2. the **queued requester** at [`HOST_QUEUED`], which names its own IPv6 in
//!    its hello, asks for the file and holds the upload slot emule-qt grants;
//! 3. the **asker** at the driver host, which asks for sources inside the
//!    `0xA4` bundle while the queued requester still holds its slot.
//!
//! Why this shape, from emule-qt's own source: a source ask for a *complete*
//! shared file is answered out of the clients that file is being served to
//! (`KnownFile::createSrcInfoPacket`, `KnownFile.cpp:761`, eligible when
//! `Uploading` or `OnUploadQueue`); the ExtSX path keeps a Low-ID client that
//! latched a reachable IPv6 from its hello (`UpDownClient.cpp:1007`,
//! `KnownFile.cpp:849`) and writes that address as `CT_MOD_IP_V6`
//! (`KnownFile.cpp:937`). No partfile and no download are needed: the queue
//! *is* the source list. What is scored is emule-qt's answer — its own bytes
//! about a source it was told of — and the queued requester's hello is the
//! Stimulus that told it.

use anyhow::Result;

use crate::flow::bench::Bench;
use crate::flow::nat::dialect::BODY_PEER_TCP_PORT;
use crate::flow::nat::dialect::bench::{
    HOST_DRIVER, HOST_EMULEQT, HOST_QUEUED, Ipv6DialectOptions, Stage, body_log, container_name,
    out, run_driver, start_detached_driver, wait_for_exit,
};
use crate::flow::nat::dialect::legs::{RMULE_USER_HASH, hello_leg};
use crate::flow::nat::dialect::verdict::{Claim, DriverRow, Evidence};

/// The queued requester's user hash — distinct from the asker's, since
/// emule-qt keys its client list by hash and one client cannot be its own
/// source.
pub(super) const QUEUED_USER_HASH: &str = "51515151515151515151515151515151";

/// How long the queued requester holds its slot: the asker's whole exchange
/// has to land inside it.
pub(super) const HOLD_SECS: u64 = 40;

/// The line the queued requester prints once emule-qt granted or queued it.
pub(super) const SLOT_MARKER: &str = "rmule-ipv6-hold-slot-open";

/// Drive the flow and return its claims plus the standing note.
///
/// # Errors
/// If a driver container cannot run or its row cannot be read.
pub(super) fn drive(
    bench: &mut Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
) -> Result<(Vec<Claim>, String)> {
    let qt_v6 = stage.v6(HOST_EMULEQT).to_owned();
    let qt_peer = format!("[{qt_v6}]:{BODY_PEER_TCP_PORT}");
    let hello = hello_leg(
        bench,
        options,
        stage,
        "extsx-hello-emuleqt",
        &qt_peer,
        Some(&qt_v6),
    )?;
    let mut claims = vec![
        Claim::about(
            "emuleqt-claims-extsx",
            hello.flag("claims_extsx"),
            Evidence::Captured,
            format!(
                "CT_MOD_MISCOPTIONS word 0x{:04X} bits {:?} — rmule emits an ExtSX record only \
                 to a peer that claimed this bit",
                hello.int("mod_misc_word"),
                hello.text("mod_misc_bits")
            ),
        ),
        Claim::about(
            "emuleqt-claims-extsx-skiptags",
            hello.flag("claims_extsx_skiptags"),
            Evidence::Captured,
            "the skip-unknown-tags variant: USERHASH/CONOPTS tags are emitted only to a peer \
             claiming it"
                .to_owned(),
        ),
    ];

    let Some(shared) = &stage.shared else {
        anyhow::bail!("ipv6-extsx stands up emule-qt with a shared file");
    };
    let queued_v6 = stage.v6(HOST_QUEUED).to_owned();
    let body_args = |leg: &str, v6: &str, hash: &str| {
        vec![
            "--peer".to_owned(),
            qt_peer.clone(),
            "--file".to_owned(),
            shared.link.clone(),
            "--advertise-ipv6".to_owned(),
            v6.to_owned(),
            "--user-hash".to_owned(),
            hash.to_owned(),
            "--capture".to_owned(),
            out(&format!("{leg}-capture")),
            "--out".to_owned(),
            out(&format!("{leg}.toml")),
        ]
    };
    let mut hold = vec!["ipv6".to_owned(), "hold-slot".to_owned()];
    hold.extend(body_args("extsx-queued", &queued_v6, QUEUED_USER_HASH));
    hold.extend(["--hold-secs".to_owned(), HOLD_SECS.to_string()]);
    // The queued requester holds nothing. Claiming extended requests it would
    // say so, and the answerer lists a source only when it holds a part the
    // asker lacks or reports no status at all (aMule `CreateSrcInfoPacket`,
    // emule-qt `sourceHasNeededPart`) — so it claims `0`, as every rmule body
    // did when this flow was measured.
    hold.extend(["--extended-requests".to_owned(), "0".to_owned()]);
    let (queued_container, slot_open) = start_detached_driver(
        bench,
        options,
        stage,
        "v6queued",
        HOST_QUEUED,
        &hold,
        SLOT_MARKER,
    )?;

    if !slot_open {
        wait_for_exit(bench, &queued_container)?;
        let queued = DriverRow::read(&stage.leg_dir.join("extsx-queued.toml"))?;
        body_log(bench, stage, &queued_container, "extsx-queued-driver")?;
        body_log(
            bench,
            stage,
            &container_name(options.layout, "v6qt")?,
            "emuleqt-body",
        )?;
        claims.push(Claim::about(
            "a-queued-requester-named-its-ipv6-and-holds-a-slot",
            false,
            Evidence::Captured,
            format!(
                "emule-qt never granted or queued the requester at [{queued_v6}]: identified={} \
                 failure={:?}",
                queued.flag("identified"),
                queued.text("failure"),
            ),
        ));
        return Ok((claims, String::new()));
    }
    let mut ask = vec!["ipv6".to_owned(), "sx-ask".to_owned()];
    ask.extend(body_args(
        "extsx-ask",
        stage.v6(HOST_DRIVER),
        RMULE_USER_HASH,
    ));
    run_driver(bench, options, stage, "extsx-ask", &ask)?;
    wait_for_exit(bench, &queued_container)?;
    let queued = DriverRow::read(&stage.leg_dir.join("extsx-queued.toml"))?;
    let asked = DriverRow::read(&stage.leg_dir.join("extsx-ask.toml"))?;
    body_log(bench, stage, &queued_container, "extsx-queued-driver")?;
    body_log(
        bench,
        stage,
        &container_name(options.layout, "v6qt")?,
        "emuleqt-body",
    )?;

    let ipv6_sources = asked.list("ipv6_sources");
    let carried = ipv6_sources
        .iter()
        .any(|endpoint| endpoint.contains(&queued_v6));
    claims.extend([
        Claim::about(
            "a-queued-requester-named-its-ipv6-and-holds-a-slot",
            !queued.text("slot").is_empty(),
            Evidence::Captured,
            format!(
                "the queued requester at [{queued_v6}] advertised CT_MOD_IP_V6 and emule-qt \
                 answered its OP_STARTUPLOADREQ with slot={:?} ({} bytes served); failure={:?}",
                queued.text("slot"),
                queued.int("bytes_received"),
                queued.text("failure"),
            ),
        ),
        Claim::about(
            "emuleqt-answered-the-bundled-source-ask",
            asked.int("answer_bytes") > 0 && asked.int("sx_version") == 1,
            Evidence::Captured,
            format!(
                "rmule's bundle {} drew OP_ANSWERSOURCES2 ({} bytes, {}), version byte {} — \
                 ExtSX pins it at 1",
                asked.text("bundle_hex"),
                asked.int("answer_bytes"),
                asked.text("answer_protocol"),
                asked.int("sx_version"),
            ),
        ),
        Claim::about(
            "an-extsx-record-carrying-a-v6-source",
            carried && asked.text("decode_error").is_empty(),
            Evidence::Captured,
            format!(
                "{} record(s) {:?}; rmule's ExtSX reader decoded them ({:?}) and the IPv6 half \
                 names the queued requester's [{queued_v6}]. Answer bytes: {}",
                asked.int("record_count"),
                asked.list("records"),
                asked.text("decode_error"),
                asked.text("answer_hex"),
            ),
        ),
        // rmule's own consume of the same frame: Stimulus about rmule, kept
        // beside the capture because the first run of this flow is what showed
        // admission dropping the record's IPv6 half.
        Claim::about(
            "rmule-surfaces-the-extsx-ipv6-source",
            asked
                .list("session_sources")
                .iter()
                .any(|endpoint| endpoint.contains(&queued_v6)),
            Evidence::RmuleOnly,
            format!(
                "the session's SourcesReceived carried {:?}",
                asked.list("session_sources")
            ),
        ),
    ]);
    Ok((claims, String::new()))
}
