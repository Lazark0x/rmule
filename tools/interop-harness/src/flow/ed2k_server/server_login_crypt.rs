//! The server-login-crypt leg: whether rmule's server login opens its link
//! as the Obfuscation Policy says (ADR-0042), and whether the bench's server
//! serves it — stock Lugdunum, or ed2k-server at its pin.
//!
//! rmule serves under `--peer-crypt <policy>` (none for `off`) and logs in to
//! the server by address. That first login meets a server it knows nothing of,
//! so it goes plain whatever the policy, as aMule's does (`ServerSocket.cpp:
//! 786-795`). The Status Ping Sweep's first-contact answer then names the
//! server's obfuscation TCP port and flags, and a timed switch back to the
//! same server re-makes the session: the login under test. A tap in
//! the server's namespace (`tcp portrange 4661-4700`) records which port each
//! connection reached and the first byte rmule sent on it; rmule's own
//! records say which link each dial chose and whether its login was
//! answered. The login connection is found by its first frame, never by its
//! place in the capture. The bench network is a documentation range rmule counts as
//! public (`198.51.100.0/24`, or ed2k-server's `203.0.113.0/24`, where its
//! config pins its address), so the login is High ID and the sweep pings.

use std::fs;
use std::net::IpAddr;
use std::time::Duration;

use anyhow::{Context, Result, bail};

use crate::artifacts::RunLayout;
use crate::docker::RunContainer;
use crate::flow::bench::{
    Bench, CaptureSidecar, DEFAULT_TAP_INTERFACE, ED2K_SERVER_PORT, run_checked,
};
use crate::flow::ed2k_server::search_wire::server_tap::OP_IDCHANGE;
use crate::flow::ed2k_server::search_wire::{ED2KSRV_IP, SUBNET as ED2KSRV_SUBNET, start_ed2ksrv};
use crate::flow::pcap::{ED2K_PROTOCOLS, tcp_streams};

const SUBNET: &str = "198.51.100.0/24";
/// Past the first-contact status answer (5 s after start, 20 s grace).
const SWITCH_AFTER_SECS: u64 = 25;
/// By name there is no status-sweep answer to wait for, so the switch comes
/// once the first login is answered.
const BY_NAME_SWITCH_AFTER_SECS: u64 = 10;
/// Past the second login's answer.
const WATCH_SECS: u64 = 45;
const SHARE_BYTES: usize = 300_001;
const PCAP: &str = "lugdunum-tcp.pcap";
/// rmule's listen port, where the server's High-ID port test lands.
const LISTEN_PORT: u16 = 4662;

/// Options for the server-login-crypt leg.
pub struct ServerLoginCryptOptions<'a> {
    /// The run dir every artifact is written under.
    pub layout: &'a RunLayout,
    /// The Docker-compatible CLI to invoke.
    pub container_runtime: &'a str,
    /// Leave the containers and network running after the run.
    pub keep_containers: bool,
    /// Per-step readiness budget, in seconds.
    pub timeout_secs: u64,
    /// The Lugdunum eserver image.
    pub server_image: &'a str,
    /// Extra `KEY=VALUE` environment for the eserver container.
    pub server_env: &'a [String],
    /// The `rmule-tools` image, built from the tip under test.
    pub rmule_tools_image: &'a str,
    /// The tcpdump capture-sidecar image.
    pub capture_image: &'a str,
    /// rmule's policy: `off`, `supported`, `requested` or `required`.
    pub policy: &'a str,
    /// The ed2k-server image and bench config to log in to instead of
    /// Lugdunum; `None` runs against Lugdunum.
    pub ed2ksrv: Option<(&'a str, &'a std::path::Path)>,
    /// Dial the server by its container DNS name, not its address, and switch
    /// without waiting for the Status Ping Sweep. A server known only by name
    /// is not pinged, so the status answer cannot teach the obfuscation port:
    /// only the login's `OP_IDCHANGE` extension can.
    pub by_name: bool,
}

/// Run the leg and write `server-login-crypt/verdict.txt`.
pub fn run_server_login_crypt(options: ServerLoginCryptOptions<'_>) -> Result<()> {
    let initiates = match options.policy {
        "off" | "supported" => false,
        "requested" | "required" => true,
        other => bail!("unknown policy {other}: off, supported, requested or required"),
    };
    if options.by_name && !initiates {
        bail!("--by-name proves the second login obfuscated: use policy requested or required");
    }
    let mut bench = Bench::new(
        options.container_runtime,
        options.layout,
        options.keep_containers,
    )?;
    let timeout = Duration::from_secs(options.timeout_secs);
    let root = options.layout.root().join("server-login-crypt");
    fs::create_dir_all(&root).with_context(|| format!("create {}", root.display()))?;
    let share: Vec<u8> = (0..SHARE_BYTES)
        .map(|index| (index.wrapping_mul(131) ^ (index >> 7)) as u8)
        .collect();
    fs::write(root.join("login-crypt.bin"), share).context("write the shared file")?;

    let result = (|| -> Result<String> {
        let server = match options.ed2ksrv {
            Some((image, config)) => {
                bench.create_network(options.layout, Some(ED2KSRV_SUBNET))?;
                start_ed2ksrv(&mut bench, image, config, &root, timeout)?
            }
            None => {
                bench.create_network(options.layout, Some(SUBNET))?;
                bench.start_eserver_in_network(
                    options.layout,
                    options.server_image,
                    options.server_env,
                    timeout,
                )?;
                bench.names.server_container_name.clone()
            }
        };
        let tap = format!("{server}-tap");
        let sidecar = CaptureSidecar {
            image: options.capture_image,
            name: &tap,
            target_container: &server,
            interface: DEFAULT_TAP_INTERFACE,
            host_dir: root.clone(),
            pcap_file: PCAP,
            bpf: "tcp portrange 4661-4700",
        };
        bench.start_extra(&tap, sidecar.container(), "run the server tap")?;
        std::thread::sleep(Duration::from_secs(2));

        let rmule = format!("{server}-login-rmule");
        // By address: the sweep walks past a DNS-named row, so a container
        // name would never learn the server's obfuscation port.
        let server_ip = match options.ed2ksrv {
            Some(_) => ED2KSRV_IP.to_owned(),
            None => run_checked(bench.docker.container_ip(server.clone()), "server address")?,
        };
        // By name the sweep walks past the row, so the second login can only
        // learn the port from the first login's answer.
        let host = if options.by_name { &server } else { &server_ip };
        let endpoint = format!("{host}:{ED2K_SERVER_PORT}");
        let switch_after = if options.by_name {
            BY_NAME_SWITCH_AFTER_SECS
        } else {
            SWITCH_AFTER_SECS
        };
        let mut serve = vec![
            "ed2k".to_owned(),
            "serve".to_owned(),
            "start".to_owned(),
            "--file".to_owned(),
            "/w/login-crypt.bin".to_owned(),
            "--server".to_owned(),
            endpoint.clone(),
            "--switch-to".to_owned(),
            endpoint,
            "--switch-after".to_owned(),
            switch_after.to_string(),
            "--listen".to_owned(),
            format!("0.0.0.0:{LISTEN_PORT}"),
            "--tcp-port".to_owned(),
            LISTEN_PORT.to_string(),
            "--user-hash".to_owned(),
            "6B1E39C4A0D27F5813E9C64B0A7D2E91".to_owned(),
            "--nickname".to_owned(),
            "server-login-crypt".to_owned(),
            "--max-seconds".to_owned(),
            WATCH_SECS.to_string(),
        ];
        if options.policy != "off" {
            serve.extend(["--peer-crypt".to_owned(), options.policy.to_owned()]);
        }
        let container = serve.iter().fold(
            RunContainer::new(options.rmule_tools_image.to_owned())
                .detach()
                .name(&rmule)
                .network(bench.names.network_name.clone())
                .env("RMULE_LOG", "info")
                .volume(&root, "/w"),
            |container, arg| container.arg(arg),
        );
        bench.start_extra(&rmule, container, "run the serving rmule")?;
        // The driver exits on its own `--max-seconds`.
        run_checked(
            bench.docker.wait(rmule.clone()),
            "wait for the serving rmule",
        )?;
        let logs = run_checked(bench.docker.logs(rmule.clone()), "rmule logs")?;
        fs::write(root.join("rmule.log"), format!("{logs}\n")).context("write rmule.log")?;
        // The server's own account of each connection, kept beside rmule's.
        let server_logs = run_checked(bench.docker.logs(server.clone()), "server logs")?;
        fs::write(root.join("server.log"), format!("{server_logs}\n"))
            .context("write server.log")?;
        bench.stop_extra(&rmule);
        bench.stop_extra(&tap);
        let server_ip: IpAddr = server_ip
            .trim()
            .parse()
            .with_context(|| format!("parse the server address {server_ip}"))?;
        verdict(
            options.policy,
            initiates,
            options.by_name,
            &logs,
            &root.join(PCAP),
            server_ip,
        )
    })();

    if result.is_err() {
        bench.collect_failure_logs(options.layout);
    }
    bench.cleanup_best_effort();
    let verdict = result?;
    fs::write(root.join("verdict.txt"), format!("{verdict}\n")).context("write verdict")?;
    println!("{verdict}");
    Ok(())
}

/// One dial as rmule's records state it: the link it chose, and whether the
/// login on it was answered before the next dial.
struct Dial {
    link: String,
    answered: bool,
}

/// rmule's dials, in order, off its `server.login` records.
fn dials(logs: &str) -> Vec<Dial> {
    let mut dials: Vec<Dial> = Vec::new();
    for line in logs.lines().filter(|line| line.contains("server.login ")) {
        if let Some(at) = line.find("step=link_chosen ") {
            let link = line[at + "step=link_chosen ".len()..].trim().to_owned();
            dials.push(Dial {
                link,
                answered: false,
            });
        } else if line.contains("step=answered ")
            && let Some(last) = dials.last_mut()
        {
            last.answered = true;
        }
    }
    dials
}

/// Whether the first dial was the plain one a server known to nothing gets,
/// and a later dial followed it: the by-name proof needs both links.
fn first_dial_was_plain_unknown(dials: &[Dial]) -> bool {
    dials.len() >= 2
        && dials[0].link == "link=plain why=server_not_known_to_obfuscate"
        && dials[0].answered
}

/// What a connection rmule opened to the server began with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LoginKind {
    /// An `OP_LOGINREQUEST` frame in the clear.
    Plain,
    /// Not an eD2k frame at all: the opening of the Obfuscated Handshake,
    /// whose first byte is a random marker and whose rest is the DH value.
    Obfuscated,
}

/// The smallest obfuscated opening: marker, the 4-byte semi-random word and
/// the 96-byte `G^A`.
const OBFUSCATED_OPENING_MIN: usize = 1 + 4 + 96;
/// `OP_LOGINREQUEST`.
const OP_LOGINREQUEST: u8 = 0x01;

impl LoginKind {
    /// Tell a login from the bytes its connection opened with: a plain login
    /// opens with an eD2k protocol byte, a length and opcode `0x01`; an
    /// obfuscated one opens with a byte that is no protocol byte and runs on
    /// past the handshake's smallest opening. Any other eD2k frame, or a
    /// stub too short to be either, is no login.
    fn of(opening: &[u8]) -> Option<Self> {
        let first = *opening.first()?;
        if ED2K_PROTOCOLS.contains(&first) {
            (opening.get(5) == Some(&OP_LOGINREQUEST)).then_some(Self::Plain)
        } else {
            (opening.len() >= OBFUSCATED_OPENING_MIN).then_some(Self::Obfuscated)
        }
    }

    fn word(self) -> &'static str {
        match self {
            Self::Plain => "plain",
            Self::Obfuscated => "obfuscated",
        }
    }
}

/// One login connection as the tap saw it.
struct Login {
    kind: LoginKind,
    port: u16,
    first_byte: Option<u8>,
    /// Bytes the server sent back on it.
    replied: usize,
    /// The payload size of the `OP_IDCHANGE` the server answered a plain
    /// login with; `None` when none was read (an obfuscated answer is
    /// encrypted, so only a plain login can show it).
    id_change_payload: Option<usize>,
}

/// The payload size that carries the reported IP and the obfuscation port
/// (`rmule_ed2k::id_change`).
const ID_CHANGE_EXTENDED: usize = 20;

/// The payload size of the first `OP_IDCHANGE` in a server's plain byte
/// stream, walking its frames (`[protocol][u32 length][opcode][payload]`)
/// until the bytes stop being eD2k frames.
fn id_change_payload_len(mut bytes: &[u8]) -> Option<usize> {
    while let [protocol, l0, l1, l2, l3, opcode, ..] = bytes {
        if !ED2K_PROTOCOLS.contains(protocol) {
            return None;
        }
        let length = u32::from_le_bytes([*l0, *l1, *l2, *l3]) as usize;
        if length == 0 {
            return None;
        }
        if *opcode == OP_IDCHANGE && *protocol == 0xE3 {
            return Some(length - 1);
        }
        bytes = bytes.get(5 + length..)?;
    }
    None
}

/// Read rmule's dials against the tap: each login connection to the server
/// (told by its first frame, on a destination port in the tap's range), the
/// port it reached, the first byte rmule sent on it and how many bytes the
/// server answered with; and
/// the first byte of each port test the server dialed back to rmule's
/// listener, which shows whether the server tests a crypt-capable client
/// obfuscated.
fn verdict(
    policy: &str,
    initiates: bool,
    by_name: bool,
    logs: &str,
    pcap: &std::path::Path,
    server: IpAddr,
) -> Result<String> {
    let dials = dials(logs);
    let streams = tcp_streams(pcap)?;
    let reply_to = |stream: &crate::flow::pcap::TcpStream| {
        streams
            .iter()
            .find(|back| back.source == stream.destination && back.destination == stream.source)
    };
    // Every connection rmule opened to the server's ports, told apart by what
    // it opened with. Order says nothing: the port test the server runs is a
    // connection too, and a login may follow or precede other traffic.
    let logins: Vec<Login> = streams
        .iter()
        .filter(|stream| {
            stream.destination.ip() == server
                && (ED2K_SERVER_PORT..=4700).contains(&stream.destination.port())
        })
        .filter_map(|stream| {
            let kind = LoginKind::of(&stream.bytes)?;
            let reply = reply_to(stream);
            Some(Login {
                kind,
                port: stream.destination.port(),
                first_byte: stream.bytes.first().copied(),
                replied: reply.map_or(0, |back| back.bytes.len()),
                id_change_payload: reply
                    .filter(|_| kind == LoginKind::Plain)
                    .and_then(|back| id_change_payload_len(&back.bytes)),
            })
        })
        .collect();
    let port_tests: Vec<Option<u8>> = streams
        .iter()
        .filter(|stream| stream.source.ip() == server && stream.destination.port() == LISTEN_PORT)
        .map(|stream| stream.bytes.first().copied())
        .collect();
    let Some(last) = dials.last() else {
        bail!("rmule stated no link: no login was dialed");
    };
    // The login under test is the last one of the kind the last dial chose.
    let of_kind = |kind: LoginKind| logins.iter().rfind(|login| login.kind == kind);
    let outcome = match (
        initiates,
        of_kind(LoginKind::Obfuscated),
        of_kind(LoginKind::Plain),
    ) {
        (true, Some(login), _)
            if (!by_name || first_dial_was_plain_unknown(&dials))
                && last.link == format!("link=obfuscated port={}", login.port)
                && login.replied > 0
                && last.answered =>
        {
            "OBFUSCATED-LOGIN-ANSWERED"
        }
        (false, _, Some(login))
            if login.port == ED2K_SERVER_PORT
                && last.link.starts_with("link=plain ")
                && login.replied > 0
                && last.answered =>
        {
            "PLAIN-LOGIN-ANSWERED"
        }
        _ => "FAIL",
    };
    let byte_words =
        |byte: Option<u8>| byte.map_or_else(|| "none".to_owned(), |byte| format!("{byte:02x}"));
    let dial_words: Vec<String> = dials
        .iter()
        .map(|dial| {
            format!(
                "[{} answered={}]",
                dial.link.replace(' ', ","),
                if dial.answered { "yes" } else { "no" }
            )
        })
        .collect();
    let login_words: Vec<String> = logins
        .iter()
        .map(|login| {
            let id_change = login
                .id_change_payload
                .map_or_else(|| "unread".to_owned(), |size| size.to_string());
            format!(
                "[{},port={},first_byte={},server_bytes={},id_change_payload={}]",
                login.kind.word(),
                login.port,
                byte_words(login.first_byte),
                login.replied,
                id_change
            )
        })
        .collect();
    let test_words: Vec<String> = port_tests.iter().map(|byte| byte_words(*byte)).collect();
    let extension = match logins.iter().find_map(|login| login.id_change_payload) {
        Some(size) if size >= ID_CHANGE_EXTENDED => "yes",
        Some(_) => "no",
        None => "unread",
    };
    Ok(format!(
        "verdict={outcome} policy={policy} by_name={by_name} id_change_size20={extension} dials={} logins={} port_test_first_bytes=[{}]",
        dial_words.join(""),
        login_words.join(""),
        test_words.join(",")
    ))
}

#[cfg(test)]
mod tests;
