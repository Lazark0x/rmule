//! The `ed2k server probe` command: log in to a live server and report the
//! compression and UDP-obfuscation capabilities it actually honours, as
//! `key: value` lines that double as the bench's evidence file.

use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Args;
use rmule_ed2k::{Ed2kEvent, GlobServStatRes, ServerTcpFlags};
use rmule_net::ed2k::{ConnectOptions, Connection};
use rmule_primitives::{ClientId, ClientIdentity, Ed2kText, ServerEndpoint, UserHash};

use crate::capture::write_new;
use crate::ed2k::server_udp::{
    PingOutcome, SERVER_UDP_CRYPT_OFFSET, SERVER_UDP_PLAIN_OFFSET, StatusReply, crypt_status_ping,
    plain_status_ping, resolve_server_ipv4,
};
use crate::operand::parse_user_hash;

/// Server capability probe (the bench wire smoke): log in and read the IDCHANGE
/// `SRV_TCPFLG` word (compression advert), then status-ping the server's UDP
/// surfaces (plain `0x96` and the obfuscated crypt-ping) and read the `0x97`
/// `SRV_UDPFLG` word (UDP-obfuscation advert).
/// Primarily an advert probe reporting wire facts; with `--out` it also lays
/// down each reply's raw datagram, which is what a fixture promotion needs.
#[derive(Debug, Args)]
pub(crate) struct ServerProbeArgs {
    /// Server endpoint as `host:port` (the eD2k TCP port, e.g. `4661`). The UDP
    /// probes derive the server's plain-status port (TCP+4) and crypt-ping port
    /// (TCP+12) from it, per rmule-core's `adapters.rs` offsets.
    endpoint: String,
    /// Optional directory to write a `probe.txt` summary into, plus each UDP
    /// reply's raw datagram as `<label>.bin` (`plain_ping_0x97.bin`;
    /// `crypt_ping_0x97_raw.bin` + `crypt_ping_0x97_plain.bin` for the
    /// obfuscated leg) — the counterparty's exact bytes, ready to promote.
    #[arg(long)]
    out: Option<PathBuf>,
    /// Client nickname tag value.
    #[arg(long, default_value = "rmule-tools")]
    nickname: String,
    /// 16-byte user hash as upper-case hex (32 chars).
    #[arg(long, default_value = "42424242424242424242424242424242")]
    user_hash: String,
    /// Local TCP port advertised in the login packet.
    #[arg(long, default_value_t = 4662)]
    tcp_port: u16,
    /// CT_VERSION value (eDonkey protocol version constant).
    #[arg(long, default_value_t = 60)]
    protocol_version: u32,
    /// Per-step network timeout, seconds (login wait and each UDP reply wait).
    /// The eserver runs amd64-emulated, so keep this generous.
    #[arg(long, default_value_t = 15)]
    timeout: u64,
    /// Ride `CT_EMULE_UDPPORTS` (`0xF9`, ADR-0091) on the login, naming this
    /// client-UDP port with Kad off. A running core sends the tag on every
    /// login, so this is how a server body is asked whether it still accepts
    /// one — no socket is bound, the port is only a value.
    #[arg(long)]
    udp_ports_advert: Option<u16>,
}

/// Accumulates the probe's `key: value` lines: each is printed live (so it
/// shows in the container logs the harness collects) and retained for the
/// optional `probe.txt` written to the run dir.
struct ProbeReport {
    lines: Vec<String>,
}

impl ProbeReport {
    fn new(endpoint: String) -> Self {
        let mut report = Self { lines: Vec::new() };
        report.line(format!("probe_endpoint: {endpoint}"));
        report
    }

    fn line(&mut self, line: String) {
        println!("{line}");
        self.lines.push(line);
    }

    fn write(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        let path = dir.join("probe.txt");
        let mut body = self.lines.join("\n");
        body.push('\n');
        std::fs::write(&path, body).with_context(|| format!("write {}", path.display()))
    }
}

/// Probe a server's advertised compression and UDP-obfuscation capabilities.
/// Reports wire facts as `PASS/FAIL`-shaped `key: value` lines; with `--out`
/// each UDP reply's raw datagram lands beside `probe.txt` as well, ready for
/// fixture promotion.
pub(crate) async fn server_probe(args: ServerProbeArgs) -> Result<()> {
    let endpoint = ServerEndpoint::parse_host_port(&args.endpoint)
        .with_context(|| format!("parse endpoint {}", args.endpoint))?;
    let tcp_port = endpoint.port();
    let server_ip = resolve_server_ipv4(&args.endpoint).await?;
    let per_step = Duration::from_secs(args.timeout);
    let mut report = ProbeReport::new(format!("{server_ip}:{tcp_port}"));
    // Fail on an unusable --out before spending a login on it.
    if let Some(dir) = &args.out {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    }

    // 1. Compression advert — a TCP login, read from the IDCHANGE SRV_TCPFLG word.
    probe_compression(&args, endpoint, per_step, &mut report).await?;

    // 2. UDP-obfuscation advert — the 0x97 SRV_UDPFLG word. Learned from either a
    //    plain 0x96 status ping or the obfuscated crypt-ping; track the best
    //    answer so the final verdict reflects whichever surface replied.
    let mut udpobf_advert: Option<bool> = None;
    let mut obf_ports_nonzero = false;

    for offset in [SERVER_UDP_PLAIN_OFFSET, 0] {
        let Some(port) = tcp_port.checked_add(offset) else {
            continue;
        };
        let label = format!("plain_ping[tcp+{offset}={port}]");
        let outcome = match plain_status_ping(server_ip, port, per_step).await {
            Ok(outcome) => outcome,
            Err(error) => {
                report.line(format!("{label}: error {error:#}"));
                continue;
            }
        };
        if let Some(dir) = &args.out {
            dump_reply_bytes(dir, &plain_ping_stem(offset), &outcome, &mut report)?;
        }
        match outcome.reply {
            StatusReply::Ok(res) => {
                record_status_reply(
                    &label,
                    &res,
                    &mut report,
                    &mut udpobf_advert,
                    &mut obf_ports_nonzero,
                );
                // Got the advert — no need to spend another timeout on the next
                // candidate port.
                break;
            }
            StatusReply::NoReply => report.line(format!("{label}: no-reply")),
            StatusReply::NotStatus(why) => report.line(format!("{label}: not-status ({why})")),
        }
    }

    // 3. Crypt-ping (raw challenge + padding to TCP+12); the reply is RC4-keyed
    //    on the challenge (ADR-0046).
    let mut crypt_answered = false;
    if let Some(port) = tcp_port.checked_add(SERVER_UDP_CRYPT_OFFSET) {
        let label = format!("crypt_ping[tcp+{SERVER_UDP_CRYPT_OFFSET}={port}]");
        match crypt_status_ping(server_ip, port, per_step).await {
            Ok(outcome) => {
                if let Some(dir) = &args.out {
                    dump_reply_bytes(dir, CRYPT_PING_FIXTURE_STEM, &outcome, &mut report)?;
                }
                match outcome.reply {
                    StatusReply::Ok(res) => {
                        crypt_answered = true;
                        report.line(format!("{label}: decrypted"));
                        record_status_reply(
                            &label,
                            &res,
                            &mut report,
                            &mut udpobf_advert,
                            &mut obf_ports_nonzero,
                        );
                    }
                    StatusReply::NoReply => report.line(format!("{label}: no-reply")),
                    StatusReply::NotStatus(why) => {
                        report.line(format!("{label}: not-status ({why})"));
                    }
                }
            }
            Err(error) => report.line(format!("{label}: error {error:#}")),
        }
    }

    // 4. Headline UDP-obfuscation verdict: the crypt advert is YES only when
    //    a 0x97 set SRV_UDPFLG_UDPOBFUSCATION; NO when a 0x97 arrived without it;
    //    UNSUPPORTED when no 0x97 reached us at all (nothing to read the bit from).
    let crypt_advert = match udpobf_advert {
        Some(true) => "YES",
        Some(false) => "NO",
        None => "UNSUPPORTED",
    };
    report.line(format!("crypt_ping_answered: {crypt_answered}"));
    report.line(format!("obf_ports_nonzero: {obf_ports_nonzero}"));
    report.line(format!("crypt_advert: {crypt_advert}"));

    if let Some(dir) = &args.out {
        report.write(dir)?;
    }
    Ok(())
}

/// Fixture stem for the obfuscated leg's datagrams.
const CRYPT_PING_FIXTURE_STEM: &str = "crypt_ping_0x97";

/// Fixture stem for one plain-ping leg: the canonical server-UDP port (TCP+4)
/// keeps the bare name a promotion expects, while the same-as-TCP fallback port
/// is suffixed so two legs can never write over each other's evidence.
fn plain_ping_stem(offset: u16) -> String {
    if offset == SERVER_UDP_PLAIN_OFFSET {
        "plain_ping_0x97".to_owned()
    } else {
        format!("plain_ping_tcp{offset}_0x97")
    }
}

/// Write one leg's datagram(s) under `--out` so a fixture promotion holds the
/// counterparty's exact bytes: `<stem>.bin` for a reply that arrived in the
/// clear, or `<stem>_raw.bin` (ciphertext, as received) plus `<stem>_plain.bin`
/// (decrypted payload) when the crypt leg decrypted. Only the server's own
/// bytes are written — the probe never re-encodes what it claims to have
/// observed (ADR-0045 point 2). Refuses to overwrite: a pre-existing file means
/// the run dir already holds a capture, which is an error, not a merge.
fn dump_reply_bytes(
    dir: &Path,
    stem: &str,
    outcome: &PingOutcome,
    report: &mut ProbeReport,
) -> Result<()> {
    let Some(raw) = &outcome.raw else {
        return Ok(());
    };
    match &outcome.plain {
        Some(plain) => {
            write_new(&dir.join(format!("{stem}_raw.bin")), raw)?;
            write_new(&dir.join(format!("{stem}_plain.bin")), plain)?;
            report.line(format!(
                "{stem}: wrote {stem}_raw.bin ({} bytes) + {stem}_plain.bin ({} bytes)",
                raw.len(),
                plain.len()
            ));
        }
        None => {
            write_new(&dir.join(format!("{stem}.bin")), raw)?;
            report.line(format!("{stem}: wrote {stem}.bin ({} bytes)", raw.len()));
        }
    }
    Ok(())
}

/// Record one valid `0x97`'s capability fields and fold its UDP-obfuscation bit
/// into the running verdict.
fn record_status_reply(
    label: &str,
    res: &GlobServStatRes,
    report: &mut ProbeReport,
    udpobf_advert: &mut Option<bool>,
    obf_ports_nonzero: &mut bool,
) {
    report.line(format!(
        "{label}: answered users={} files={}",
        res.users(),
        res.files()
    ));
    match res.udp_flags() {
        Some(flags) => {
            report.line(format!("{label}: udp_flags=0x{:08X}", flags.bits()));
            report.line(format!(
                "{label}: srv_udpflg_udpobfuscation={}",
                flags.supports_udp_obfuscation()
            ));
            // Any positive advert wins; a bare-boned reply never clears a prior YES.
            *udpobf_advert =
                Some(udpobf_advert.unwrap_or(false) || flags.supports_udp_obfuscation());
        }
        None => report.line(format!("{label}: udp_flags=none (reply body < 28 bytes)")),
    }
    if let (Some(udp), Some(tcp)) = (res.obfuscation_udp_port(), res.obfuscation_tcp_port()) {
        report.line(format!("{label}: obf_udp_port={udp} obf_tcp_port={tcp}"));
        if udp != 0 || tcp != 0 {
            *obf_ports_nonzero = true;
        }
    }
}

/// A TCP login to read the IDCHANGE `SRV_TCPFLG` word (compression advert). A
/// failed/absent login is reported, not fatal — the UDP probes stand alone.
async fn probe_compression(
    args: &ServerProbeArgs,
    endpoint: ServerEndpoint,
    per_step: Duration,
    report: &mut ProbeReport,
) -> Result<()> {
    // Answer the server's High-ID port-check for the login's duration.
    let listener = match spawn_hello_answering_listener(probe_identity(args)?, &endpoint).await {
        Ok(task) => {
            report.line(format!(
                "highid_listener: bound 0.0.0.0:{} (hello-answering)",
                args.tcp_port
            ));
            Some(task)
        }
        Err(error) => {
            report.line(format!(
                "highid_listener: bind failed ({error:#}); login may be Low-ID"
            ));
            None
        }
    };

    let outcome = probe_login(args, endpoint, per_step, report).await;
    if let Some(task) = listener {
        task.abort();
    }
    outcome
}

/// The identity the probe logs in with.
fn probe_identity(args: &ServerProbeArgs) -> Result<ClientIdentity> {
    Ok(ClientIdentity::new(
        UserHash::from_bytes(parse_user_hash(&args.user_hash)?),
        Ed2kText::from_utf8(&args.nickname),
        args.tcp_port,
        args.protocol_version,
    ))
}

/// Bind `identity`'s TCP port and answer the server's High-ID port-check on
/// it until the task is aborted.
///
/// Lugdunum's check is a protocol exchange, not a bare TCP connect: the server
/// back-connects the advertised port during the login and sends `OP_HELLO`;
/// only an `OP_HELLOANSWER` within its window earns High-ID (a mute accept draws
/// "WARNING : No answer from your `<port>` port" and a Low ID — and this build
/// drops Low-ID logins before sending `OP_IDCHANGE` in multi-client topologies,
/// ADR-0040). `PeerListener` accepts drive the real inbound handshake, which
/// replies the moment the hello lands. The context carries the same user hash
/// and port the login does (the server verifies the answering client is the
/// logging-in one), client id 0 (not yet assigned mid-login), and the server as
/// `connected_server` when its host is an IPv4 literal.
pub(super) async fn spawn_hello_answering_listener(
    identity: ClientIdentity,
    endpoint: &ServerEndpoint,
) -> Result<tokio::task::JoinHandle<()>> {
    let listener = rmule_net::peer::PeerListener::bind(std::net::SocketAddrV4::new(
        Ipv4Addr::UNSPECIFIED,
        identity.tcp_port(),
    ))
    .await
    .context("bind the High-ID listener")?;
    let connected_server = endpoint
        .host()
        .parse::<Ipv4Addr>()
        .ok()
        .map(|ip| rmule_primitives::Ipv4Endpoint::new(ip, endpoint.port()));
    let ctx = rmule_peer::PeerHandshakeContext {
        identity,
        client_id: ClientId::from_u32(0),
        connected_server,
    };
    Ok(tokio::spawn(async move {
        loop {
            let Ok(mut conn) = listener
                .accept(ctx.clone(), rmule_net::peer::ConnectOptions::default())
                .await
            else {
                continue;
            };
            // The driver answers the hello; drain events until the server
            // closes its check connection.
            tokio::spawn(async move { while conn.next_event().await.is_some() {} });
        }
    }))
}

/// The login half of the compression probe, factored out so the High-ID
/// listener can be torn down whatever the outcome.
async fn probe_login(
    args: &ServerProbeArgs,
    endpoint: ServerEndpoint,
    per_step: Duration,
    report: &mut ProbeReport,
) -> Result<()> {
    let identity = probe_identity(args)?;
    let options = ConnectOptions {
        capture_dir: None,
        connect_timeout: per_step,
        login_timeout: per_step,
        obfuscation: None,
        advertised_ipv6: None,
        udp_ports: args
            .udp_ports_advert
            .map(|client_udp| rmule_ed2k::UdpPortsAdvert {
                kad_udp: 0,
                client_udp,
            }),
    };
    if let Some(advert) = options.udp_ports {
        report.line(format!("udp_ports_advert: 0x{:08X}", advert.word()));
    }
    match Connection::connect_with_options(endpoint, identity, options).await {
        Ok(mut conn) => {
            match await_login(&mut conn, per_step).await {
                Some((client_id, tcp_flags)) => {
                    report.line(format!(
                        "login_accepted: true client_id={}",
                        client_id.as_u32()
                    ));
                    report.line(format!("high_id: {}", client_id.is_high_id()));
                    match tcp_flags {
                        Some(flags) => {
                            report.line(format!("tcp_flags: 0x{:08X}", flags.bits()));
                            report.line(format!(
                                "srv_tcpflg_compression: {}",
                                flags.supports_compression()
                            ));
                            report.line(format!(
                                "srv_tcpflg_tcpobfuscation: {}",
                                flags.supports_tcp_obfuscation()
                            ));
                            report.line(format!(
                                "compression_advert: {}",
                                if flags.supports_compression() {
                                    "YES"
                                } else {
                                    "NO"
                                }
                            ));
                        }
                        None => {
                            // A bare 4-byte IDCHANGE carries no flags word — aMule
                            // treats that as "no grants" (ADR-0047).
                            report.line("tcp_flags: none".to_owned());
                            report.line("compression_advert: NO".to_owned());
                        }
                    }
                }
                None => {
                    report.line("login_accepted: false".to_owned());
                    report.line("compression_advert: UNKNOWN".to_owned());
                }
            }
            let _ = conn.shutdown().await;
        }
        Err(error) => {
            report.line(format!("login_accepted: false connect_error={error}"));
            report.line("compression_advert: UNKNOWN".to_owned());
        }
    }
    Ok(())
}

/// Drain events until the login resolves (accepted → its flags word; rejected /
/// disconnected / timeout → `None`).
pub(super) async fn await_login(
    conn: &mut Connection,
    dur: Duration,
) -> Option<(ClientId, Option<ServerTcpFlags>)> {
    let deadline = tokio::time::Instant::now() + dur;
    loop {
        match tokio::time::timeout_at(deadline, conn.next_event()).await {
            Ok(Some(Ed2kEvent::LoginAccepted {
                client_id,
                tcp_flags,
                ..
            })) => return Some((client_id, tcp_flags)),
            Ok(Some(Ed2kEvent::LoginRejected))
            | Ok(Some(Ed2kEvent::Disconnected { .. }))
            | Ok(None) => return None,
            // Pre-login chatter (server message, status): keep waiting.
            Ok(Some(_)) => continue,
            Err(_timeout) => return None,
        }
    }
}
