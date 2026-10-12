//! The legs of `peer-hello-surface` that move bytes: each client dials a
//! serving rmule and pulls a part, rmule pulls a part from each client, and one
//! rmule pulls from another. Everything a claim reads comes off the clients'
//! own taps or the bodies' own logs.

use std::ffi::OsString;
use std::time::Duration;

use anyhow::{Context, Result};

use super::{CLIENTS, Client, Kind, keep_log, line_naming_rmule, tap_prefix};
use crate::flow::bench::{Bench, CAPTURE_MOUNT, amulecmd_command, run_checked};
use crate::flow::evidence::write_pcap_all_matches;
use crate::flow::nat::dialect::bench::{
    HOST_DRIVER, HOST_ED2KSRV, Ipv6DialectOptions, Stage, container_name, start_detached_driver,
    wait_for_exit,
};
use crate::flow::nat::dialect::legs::RMULE_USER_HASH;
use crate::flow::nat::dialect::verdict::{Claim, Evidence};
use crate::flow::nat::dialect::{BODY_PEER_TCP_PORT, ED2KSRV_TCP_PORT};
use crate::flow::nat::synthetic::write_hashed;
use crate::flow::pcap::{TcpStream, tcp_streams};

/// The one-part file the serving rmule shares.
const SERVED_A_BYTES: u64 = 3 << 20;
/// The downloading rmule (`B`, from the clients) and the second rmule (`A`,
/// from the first): hosts, roles and hashes of their own.
const DOWNLOADERS: [(usize, &str); 3] = [
    (5, "43434343434343434343434343434343"),
    (7, "45454545454545454545454545454545"),
    (8, "46464646464646464646464646464646"),
];
const PEER_RMULE_HOST: usize = 6;
const PEER_RMULE_ROLE: &str = "hspeer";
const PEER_RMULE_HASH: &str = "44444444444444444444444444444444";
const SERVE_ROLE: &str = "hsserve";

/// The serving rmule's run, and the downloaders' bounded runs inside it.
const SERVE_SECS: u64 = 300;
const DOWNLOAD_SECS: u64 = 150;

const ANNOUNCED: &str = "serve.files_announced";
/// `OP_OFFERFILES`, plain or packed.
const OP_OFFERFILES: u8 = 0x15;
/// How long the server gets to take the serving rmule's offer.
const OFFER_SETTLE_SECS: u64 = 20;
const DOWNLOAD_STARTED: &str = "download";

/// emule-qt's IPC, which `--add-link` talks to.
const EMULEQT_CONFIG_DIR: &str = "/config";
const EMULEQT_IPC_PORT: &str = "4712";

/// `(protocol, opcode)` of the frames a claim counts.
const OP_HELLO: (u8, u8) = (0xE3, 0x01);
const OP_EMULEINFO: (u8, u8) = (0xC5, 0x01);
const OP_SENDINGPART: (u8, u8) = (0xE3, 0x46);
const OP_COMPRESSEDPART: (u8, u8) = (0xC5, 0x40);
const OP_SENDINGPART_I64: (u8, u8) = (0xC5, 0xA2);
const OP_SECIDENTSTATE: (u8, u8) = (0xC5, 0x87);
const OP_PUBLICKEY: (u8, u8) = (0xC5, 0x85);
const OP_SIGNATURE: (u8, u8) = (0xC5, 0x86);

/// Run the byte-moving legs and return their claims.
///
/// # Errors
/// If a driver cannot start or a body cannot be told to download.
pub(super) fn drive(
    bench: &mut Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
) -> Result<Vec<Claim>> {
    let a_dir = stage.leg_dir.join("serve-a");
    std::fs::create_dir_all(&a_dir).with_context(|| format!("create {}", a_dir.display()))?;
    let shared_a = write_hashed(&a_dir, SERVED_A_BYTES)?;
    let server = format!("{}:{ED2KSRV_TCP_PORT}", stage.v4(HOST_ED2KSRV));
    let serve_v4 = stage.v4(HOST_DRIVER).to_owned();

    let serve_args = [
        "ed2k",
        "serve",
        "start",
        "--file",
        "/out/serve-a/shared.bin",
        "--server",
        &server,
        "--listen",
        &format!("0.0.0.0:{BODY_PEER_TCP_PORT}"),
        "--own-ip",
        &serve_v4,
        "--user-hash",
        RMULE_USER_HASH,
        "--max-seconds",
        &SERVE_SECS.to_string(),
    ]
    .map(str::to_owned);
    let (serve, announced) = start_detached_driver(
        bench,
        options,
        stage,
        SERVE_ROLE,
        HOST_DRIVER,
        &serve_args,
        ANNOUNCED,
    )?;
    if !announced {
        let log = keep_log(bench, stage, &serve, "rmule-serve");
        anyhow::bail!(
            "the serving rmule never announced its file: {}",
            log.lines().last().unwrap_or_default()
        );
    }
    // A client asks the server for a new file's sources once, when it adds it,
    // and not again for a quarter hour: the server has to hold the serving
    // rmule's offer by then.
    std::thread::sleep(Duration::from_secs(OFFER_SETTLE_SECS));

    for client in &CLIENTS {
        add_download(bench, options, stage, client, &shared_a.link)?;
    }
    let download = |data: &str, file: &str, out: &str, hash: &str| {
        [
            "ed2k",
            "download",
            "start",
            "--data-dir",
            data,
            "--server",
            &server,
            "--file",
            file,
            "--out",
            out,
            "--user-hash",
            hash,
            "--max-seconds",
            &DOWNLOAD_SECS.to_string(),
        ]
        .map(str::to_owned)
    };
    let (peer_rmule, _) = start_detached_driver(
        bench,
        options,
        stage,
        PEER_RMULE_ROLE,
        PEER_RMULE_HOST,
        &download(
            "/out/hs-peer-data",
            &shared_a.link,
            "/out/dl/hs-peer-a.bin",
            PEER_RMULE_HASH,
        ),
        DOWNLOAD_STARTED,
    )?;
    // One downloading rmule per client, each after that client's own file, so
    // every client is asked for a part whatever the others' speed.
    let mut downloaders = Vec::new();
    for (client, (host, hash)) in CLIENTS.iter().zip(DOWNLOADERS) {
        wait_for_offer(stage, client, Duration::from_secs(options.timeout_secs))?;
        let link = std::fs::read_to_string(stage.leg_dir.join(format!("{}-b.link", client.name)))
            .context("read the client's own file link")?;
        let (container, _) = start_detached_driver(
            bench,
            options,
            stage,
            &format!("hsdl-{}", client.name),
            host,
            &download(
                &format!("/out/hs-dl-{}-data", client.name),
                link.trim(),
                &format!("/out/dl/hs-dl-{}.bin", client.name),
                hash,
            ),
            DOWNLOAD_STARTED,
        )?;
        downloaders.push((container, stage.v4(host).to_owned()));
    }
    for (container, _) in &downloaders {
        wait_for_exit(bench, container)?;
    }
    wait_for_exit(bench, &peer_rmule)?;
    for client in &CLIENTS {
        keep_download_list(bench, options, stage, client);
    }

    let serve_log = keep_log(bench, stage, &serve, "rmule-serve");
    // The dial legs that follow run from the serving rmule's address.
    run_checked(
        bench.docker.stop_container(serve.clone(), 10),
        "stop the serving rmule",
    )?;
    let peer_log = keep_log(bench, stage, &peer_rmule, "rmule-peer");
    let peer_v4 = stage.v4(PEER_RMULE_HOST).to_owned();

    let mut claims = Vec::new();
    for (client, (downloader, downloader_v4)) in CLIENTS.iter().zip(&downloaders) {
        let downloader_log = keep_log(
            bench,
            stage,
            downloader,
            &format!("rmule-downloader-{}", client.name),
        );
        claims.extend(client_claims(
            bench,
            options,
            stage,
            client,
            &serve_v4,
            downloader_v4,
            &serve_log,
            &downloader_log,
        )?);
    }

    let serve_names_peer = first_line(&serve_log, "upload_slot_granted", &peer_v4);
    let peer_names_serve = rmule_line(&peer_log);
    claims.extend([
        Claim::about(
            "serving-rmule-names-the-downloading-rmule",
            serve_names_peer.contains("software=\"rmule"),
            Evidence::RmuleOnly,
            serve_names_peer,
        ),
        Claim::about(
            "downloading-rmule-names-the-serving-rmule",
            peer_names_serve.contains("Rmule"),
            Evidence::RmuleOnly,
            peer_names_serve,
        ),
    ]);
    Ok(claims)
}

/// Everything one client's tap and the two rmule logs settle about it.
#[allow(clippy::too_many_arguments)]
fn client_claims(
    bench: &Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
    client: &Client,
    serve_v4: &str,
    downloader_v4: &str,
    serve_log: &str,
    downloader_log: &str,
) -> Result<Vec<Claim>> {
    let name = client.name;
    let client_v4 = stage.v4(client.host).to_owned();
    let container = container_name(options.layout, client.role)?;
    let log = keep_log(bench, stage, &container, &format!("{name}-body"));
    let lift = |from: &str, to: &str, port_side: &str, out: &str| {
        lift_frames(bench, options, stage, name, from, to, port_side, out)
    };
    let to_serve = lift(
        &client_v4,
        serve_v4,
        "dst",
        &format!("{name}-to-serve.pcap"),
    )?;
    let from_serve = lift(
        serve_v4,
        &client_v4,
        "src",
        &format!("{name}-from-serve.pcap"),
    )?;
    let to_downloader = lift(
        &client_v4,
        downloader_v4,
        "src",
        &format!("{name}-to-downloader.pcap"),
    )?;
    let from_downloader = lift(
        downloader_v4,
        &client_v4,
        "dst",
        &format!("{name}-from-downloader.pcap"),
    )?;

    let hello = to_serve.iter().find(|f| (f.0, f.1) == OP_HELLO);
    let hello_file = stage.leg_dir.join(format!("op-hello-{name}.bin"));
    if let Some(frame) = hello {
        std::fs::write(&hello_file, &frame.2)
            .with_context(|| format!("write {}", hello_file.display()))?;
    }
    let count = |frames: &[Frame], ops: &[(u8, u8)]| {
        frames.iter().filter(|f| ops.contains(&(f.0, f.1))).count()
    };
    let sui = [OP_SECIDENTSTATE, OP_PUBLICKEY, OP_SIGNATURE];
    let sui_serve = (count(&to_serve, &sui), count(&from_serve, &sui));
    let sui_download = (count(&to_downloader, &sui), count(&from_downloader, &sui));
    let parts = [OP_SENDINGPART, OP_COMPRESSEDPART, OP_SENDINGPART_I64];
    let pulled = count(&from_serve, &parts);
    let served = count(&to_downloader, &parts);
    let emule_info = count(&to_serve, &[OP_EMULEINFO]) + count(&to_downloader, &[OP_EMULEINFO]);
    let queue_line = serve_log
        .lines()
        .find(|l| {
            (l.contains("upload_slot_granted") || l.contains("peer_queued"))
                && l.contains(&client_v4)
        })
        .unwrap_or_default()
        .trim()
        .to_owned();

    Ok(vec![
        Claim::about(
            format!("{name}-sends-its-op-hello-to-rmule"),
            hello.is_some(),
            Evidence::Captured,
            format!(
                "{} ({} bytes), the first OP_HELLO on {name}'s own tap toward the serving rmule",
                hello_file.display(),
                hello.map_or(0, |f| f.2.len()),
            ),
        ),
        Claim::about(
            format!("{name}-runs-secure-identification-with-rmule"),
            sui_serve.0 > 0 && sui_serve.1 > 0 && sui_download.0 > 0 && sui_download.1 > 0,
            Evidence::Captured,
            format!(
                "SUI frames (state/key/signature) {name}->serve {}, serve->{name} {}, \
                 {name}->downloader {}, downloader->{name} {}",
                sui_serve.0, sui_serve.1, sui_download.0, sui_download.1
            ),
        ),
        Claim::about(
            format!("{name}-pulls-a-part-from-rmule"),
            pulled > 0,
            Evidence::Captured,
            format!("{pulled} part frames serve->{name}"),
        ),
        Claim::about(
            format!("{name}-serves-rmule-a-part"),
            served > 0,
            Evidence::Captured,
            format!("{served} part frames {name}->its downloader"),
        ),
        Claim::absence(
            format!("{name}-sends-rmule-no-emule-info"),
            i64::try_from(emule_info).unwrap_or(-1),
            format!(
                "{emule_info} OP_EMULEINFO frames from {name} on either link: it read rmule's \
                 hello as a mule's, as a client newer than 0.42 does"
            ),
        ),
        match line_naming_rmule(&log) {
            Some(line) => Claim::about(
                format!("{name}-log-names-rmule"),
                true,
                Evidence::Captured,
                format!("{name}'s own line: {line:?}"),
            ),
            None => Claim::blocked(
                format!("{name}-log-names-rmule"),
                format!(
                    "no line of {name}'s own log names a peer's software; its client list is \
                     not reachable from the bench"
                ),
            ),
        },
        Claim::about(
            format!("{name}-queued-or-granted-by-the-serving-rmule"),
            !queue_line.is_empty(),
            Evidence::RmuleOnly,
            queue_line,
        ),
        Claim::about(
            format!("{name}-named-by-its-downloader"),
            downloader_log.contains("worker identified"),
            Evidence::RmuleOnly,
            downloader_log
                .lines()
                .find(|l| l.contains("worker identified"))
                .unwrap_or_default()
                .trim()
                .to_owned(),
        ),
    ])
}

/// Tell one client to download `link`.
/// Hold until `client`'s own tap shows it offered the server its files: a
/// body that is still hashing its file is logged in but not yet a source, and
/// a download started before its `OP_OFFERFILES` is told no sources (runs
/// `1790783373` and `1790791303`, kno's fork hashing its 30 MB file).
///
/// # Errors
/// If the tap cannot be read or no offer arrives within `timeout`.
fn wait_for_offer(stage: &Stage, client: &Client, timeout: Duration) -> Result<()> {
    let tap = stage.leg_dir.join(format!("tap-{}.pcap", client.name));
    let server_port = ED2KSRV_TCP_PORT;
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let offered = tcp_streams(&tap)?.iter().any(|stream| {
            stream.destination.port() == server_port
                && stream
                    .ed2k_frames()
                    .iter()
                    .any(|frame| frame.opcode == OP_OFFERFILES)
        });
        if offered {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!(
                "{} offered the server nothing within {} s",
                client.name,
                timeout.as_secs()
            );
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

pub(super) fn add_download(
    bench: &Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
    client: &Client,
    link: &str,
) -> Result<()> {
    let container = container_name(options.layout, client.role)?;
    let argv: Vec<OsString> = match client.kind {
        Kind::EmuleQt => [
            "emulecored",
            "--config",
            EMULEQT_CONFIG_DIR,
            "--port",
            EMULEQT_IPC_PORT,
            "--add-link",
            link,
        ]
        .map(OsString::from)
        .to_vec(),
        Kind::Amule | Kind::AmuleKno => amulecmd_command(&format!("Add {link}")).to_vec(),
    };
    let said = run_checked(
        bench.docker.exec(container, argv),
        &format!("add the download to {}", client.name),
    )?;
    std::fs::write(
        stage
            .leg_dir
            .join(format!("{}-add-download.log", client.name)),
        said,
    )
    .context("keep the add-download answer")
}

/// What an aMule's own download list says, kept beside its log.
fn keep_download_list(
    bench: &Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
    client: &Client,
) {
    if client.kind == Kind::EmuleQt {
        return;
    }
    let Ok(container) = container_name(options.layout, client.role) else {
        return;
    };
    let said = run_checked(
        bench
            .docker
            .exec(container, amulecmd_command("Show dl").to_vec()),
        "list the aMule's downloads",
    )
    .unwrap_or_else(|error| error.to_string());
    let _ = std::fs::write(
        stage.leg_dir.join(format!("{}-show-dl.log", client.name)),
        said,
    );
}

/// One eMule frame: protocol, opcode, the whole frame's bytes.
type Frame = (u8, u8, Vec<u8>);

/// The frames of one direction of every TCP link between `from` and `to`
/// through the client's own tap, each link reassembled on its own. `port_side` names which end holds the peer
/// port 4662: `dst` when `to` listens, `src` when `from` does.
#[allow(clippy::too_many_arguments)]
fn lift_frames(
    bench: &Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
    client: &str,
    from: &str,
    to: &str,
    port_side: &str,
    out_name: &str,
) -> Result<Vec<Frame>> {
    let suffix = options
        .layout
        .root()
        .file_name()
        .and_then(|n| n.to_str())
        .context("run dir name")?
        .to_owned();
    let tap = format!("{}-{client}", tap_prefix(&suffix));
    write_pcap_all_matches(
        &bench.docker,
        &tap,
        &format!("{CAPTURE_MOUNT}/tap-{client}.pcap"),
        &format!(
            "tcp and src host {from} and dst host {to} and {port_side} port {BODY_PEER_TCP_PORT}"
        ),
        out_name,
    )?;
    Ok(tcp_streams(&stage.leg_dir.join(out_name))?
        .iter()
        .flat_map(TcpStream::ed2k_frames)
        .map(|frame| (frame.protocol, frame.opcode, frame.bytes))
        .collect())
}

fn first_line(log: &str, marker: &str, peer: &str) -> String {
    log.lines()
        .find(|l| l.contains(marker) && l.contains(peer))
        .unwrap_or_default()
        .trim()
        .to_owned()
}

fn rmule_line(log: &str) -> String {
    log.lines()
        .find(|l| l.contains("worker identified") && l.contains("Rmule"))
        .unwrap_or_default()
        .trim()
        .to_owned()
}
