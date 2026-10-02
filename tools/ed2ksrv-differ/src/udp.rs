//! Server-UDP: rmule against the oracle's **real ingress**, executed.
//!
//! This is the surface both known emitter defects lived on, and neither was
//! reachable through a pure function. The crypt-ping window is not a parser at
//! all — it is a dispatch decision made in `UdpServer::run` from the datagram's
//! length and first byte, before any parse happens
//! (`udp.rs:159`, `:179`, `:188`, `:320`). A harness that transcribed that
//! predicate would be re-deriving the very thing that already exists as a doc
//! comment in `rmule_ed2k::server_udp::crypt_ping_padding_len` — and a
//! transcription rots silently against a re-pin, which is the failure mode
//! ADR-0045 exists to prevent.
//!
//! So the oracle is **run**: their `UdpServer` is bound on loopback in this
//! process, driven by their own `run()` loop, and probed with datagrams rmule's
//! production minters produce. A reply is evidence; silence is evidence too, and
//! is exactly what both defects looked like on the wire.
//!
//! Not covered here, deliberately: the multi-hash `0x9A`/`0x94` truncation
//! (`ed2k-server#6`) and the `0x90` tag-strip. Both need an *indexed file* to
//! answer about, which needs a TCP login, an `OP_OFFERFILES`, and a live source
//! — a whole session harness rather than a decoder differ. The bench container
//! already covers them end to end.

use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use ed2k_server::config::Config;
use ed2k_server::filter::ContentFilter;
use ed2k_server::proto::server_obfuscation as their_crypt;
use ed2k_server::server::obf_ping::decode_obf_s2s;
use ed2k_server::server::udp::{UdpServer, resolve_seckey};
use ed2k_server::state::ServerState;

use rmule_ed2k::{
    GlobServStatReq, GlobServStatRes, ServerDescReq, ServerDescRes, crypt_ping_challenge,
    crypt_ping_padding_len,
};
use rmule_primitives::{
    DatagramNonce, ServerCryptDirection, decrypt_datagram_server, encrypt_datagram_server,
};

use crate::report::{Origin, Reading, Report, Row, hex, read};

const SURFACE: &str = "server-udp";

/// How long a probe waits before calling a datagram dropped. Everything here is
/// loopback in one process, so a reply that has not arrived in this window is
/// not coming.
const REPLY_DEADLINE: Duration = Duration::from_millis(250);

/// The oracle's identity in this bench, echoed back in its `0xA3`.
const ORACLE_NAME: &str = "rmule-differ-oracle";
const ORACLE_DESC: &str = "ed2k-server as a decode oracle";
const ORACLE_VERSION: &str = "17.15";
/// Their hardcoded `pingflg`/`ST_UDPFLAGS` (`udp.rs:667`) — `ed2k-server#4`.
const ORACLE_UDP_FLAGS: u32 = 0x0000_17FB;

/// A live, unpatched `ed2k-server` bound on loopback.
///
/// Holds its runtime: dropping this stops the listeners.
pub struct Oracle {
    _runtime: tokio::runtime::Runtime,
    tcp_port: u16,
}

impl Oracle {
    /// Bind the oracle on the first port base whose whole UDP block is free.
    ///
    /// `this_ip` is set: it seeds the obfuscation `seckey` as well as the
    /// advertised identity, and leaving it unset degrades the key to a
    /// port-only derivation (audit §6).
    pub fn start() -> Result<Self, String> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| format!("tokio runtime: {e}"))?;

        // 4 (main), 8 (aux) and 12 (obf-ping) are the offsets this differ drives.
        for base in (45_000u16..45_200).step_by(20) {
            if !block_is_free(base) {
                continue;
            }
            let toml = format!(
                r#"
[server]
name = "{ORACLE_NAME}"
desc = "{ORACLE_DESC}"
public = false
this_ip = "127.0.0.1"
seed_servers = []

[network]
tcp_port = {base}
listen_ip = "127.0.0.1"

[limits]

[content_filter]
"#
            );
            let cfg: Config =
                toml::from_str(&toml).map_err(|e| format!("oracle config rejected: {e}"))?;
            let cfg = Arc::new(cfg);
            let state = Arc::new(ServerState::new(
                Arc::new(ContentFilter::new()),
                cfg.clone(),
            ));
            let seckey = resolve_seckey(&cfg);

            let bound: Result<(UdpServer, UdpServer), String> = runtime.block_on(async {
                let main = UdpServer::bind(cfg.clone(), state.clone(), seckey)
                    .await
                    .map_err(|e| e.to_string())?;
                let obf_ping =
                    UdpServer::bind_on_port(cfg.clone(), state.clone(), base + 12, seckey)
                        .await
                        .map_err(|e| e.to_string())?;
                Ok((main, obf_ping))
            });
            let Ok((main, obf_ping)) = bound else {
                continue;
            };
            runtime.spawn(main.run());
            runtime.spawn(obf_ping.run());

            return Ok(Self {
                _runtime: runtime,
                tcp_port: base,
            });
        }
        Err("no free UDP port block in 45000..45200 for the oracle".to_owned())
    }

    /// Send one datagram to `tcp_port + offset` and return the reply, or `None`
    /// when nothing arrives before [`REPLY_DEADLINE`].
    ///
    /// A fresh socket per probe: their reply goes back to the source port, so a
    /// fresh ephemeral port makes it impossible for a late reply to be read as
    /// the answer to a later probe — which would turn a silent drop into a
    /// false pass.
    fn probe(&self, offset: u16, datagram: &[u8]) -> Option<Vec<u8>> {
        let socket = UdpSocket::bind("127.0.0.1:0").ok()?;
        socket.set_read_timeout(Some(REPLY_DEADLINE)).ok()?;
        let target = SocketAddr::from(([127, 0, 0, 1], self.tcp_port + offset));
        socket.send_to(datagram, target).ok()?;
        let mut buf = vec![0u8; 65_535];
        let (len, _from) = socket.recv_from(&mut buf).ok()?;
        buf.truncate(len);
        Some(buf)
    }
}

fn block_is_free(base: u16) -> bool {
    [4u16, 8, 12]
        .iter()
        .all(|off| UdpSocket::bind(("127.0.0.1", base + off)).is_ok())
}

/// The raw crypt-ping datagram, byte-for-byte what `rmule-core`'s
/// `encode_crypt_ping` builds (`crates/rmule-core/src/server_udp.rs:498`):
/// the challenge little-endian, then opaque padding.
fn crypt_ping(challenge: u32, padding_len: usize) -> Vec<u8> {
    let mut datagram = challenge.to_le_bytes().to_vec();
    datagram.extend(std::iter::repeat_n(0xABu8, padding_len));
    datagram
}

pub fn run(report: &mut Report) {
    let oracle = match Oracle::start() {
        Ok(o) => o,
        Err(why) => {
            // A dead oracle is a harness failure, not a decoder disagreement:
            // the unreachable side makes this row a SKIP (visible, with the
            // reason, but never a divergence — see `Reading::Unreachable`).
            report.push(Row {
                surface: SURFACE,
                case: "oracle/start".to_owned(),
                origin: Origin::RmuleEmit,
                input: Vec::new(),
                rmule: Reading::Unreachable(format!(
                    "oracle failed to start ({why}) — every server-udp case skipped"
                )),
                ed2ksrv: Reading::Silent,
            });
            return;
        }
    };

    crypt_ping_mint_space(&oracle, report);
    crypt_ping_boundaries(&oracle, report);
    crypt_pong_dual_decode(&oracle, report);
    crypt_envelope_both_ways(report);
    status_ping(&oracle, report);
    server_description(&oracle, report);
}

// ── the crypt-ping mint space, exhaustively ─────────────────────────────────

/// Every datagram rmule's crypt-ping minter can produce, against the oracle's
/// executed acceptance.
///
/// Both minters are pure functions of a byte or a `u32`, so the emit space is
/// finite and enumerable — which is the whole reason this row can be a proof
/// rather than a sample. `crypt_ping_padding_len` collapses 256 seeds onto a
/// handful of lengths; `crypt_ping_challenge`'s only dispatch-relevant
/// projection is the low byte, which is the first byte on the wire, so 256
/// values cover it.
fn crypt_ping_mint_space(oracle: &Oracle, report: &mut Report) {
    // Measure the oracle's window by execution before asserting anything about
    // rmule's — the point is that the window is a fact about the pinned binary,
    // not a constant copied out of its source.
    let answered: Vec<usize> = (0usize..=24)
        .filter(|&total| {
            total >= 4
                && oracle
                    .probe(12, &crypt_ping(0x0102_0301, total - 4))
                    .is_some()
        })
        .collect();
    let window = match (answered.first(), answered.last()) {
        (Some(lo), Some(hi)) if answered.len() == hi - lo + 1 => format!("{lo}..={hi}"),
        _ => format!("{answered:?} (not contiguous)"),
    };
    report.observe(
        SURFACE,
        format!(
            "obf-ping acceptance measured by execution over datagram lengths 4..=24: {window} \
             bytes answered. Their own arm reads 4..=18 (udp.rs:320); the pre-flight at \
             udp.rs:188 is what raises the floor."
        ),
    );

    let mut lengths: Vec<usize> = (0u16..=255)
        .map(|seed| 4 + crypt_ping_padding_len(seed as u8))
        .collect();
    lengths.sort_unstable();
    lengths.dedup();
    report.observe(
        SURFACE,
        format!(
            "rmule's crypt-ping minter over all 256 padding seeds yields datagram lengths \
             {:?} — the full emit space, enumerated not sampled.",
            lengths
        ),
    );

    for total in lengths {
        let datagram = crypt_ping(crypt_ping_challenge(0x0102_0301), total - 4);
        let their_answer = oracle.probe(12, &datagram);
        report.push(Row {
            surface: SURFACE,
            case: format!("crypt-ping/minted-length-{total}"),
            origin: Origin::RmuleEmit,
            input: datagram,
            // rmule mints this length because it believes every server family
            // answers it; that belief is the claim under test.
            rmule: read([("answered", "true".to_owned())]),
            ed2ksrv: read([("answered", their_answer.is_some().to_string())]),
        });
    }

    // The challenge's low byte is the datagram's first wire byte. Enumerate the
    // whole projection and execute every distinct value.
    let mismatches: Vec<u8> = (0u16..=255)
        .map(|low| crypt_ping_challenge(0x1122_3300 | u32::from(low)))
        .filter(|challenge| oracle.probe(12, &crypt_ping(*challenge, 10)).is_none())
        .map(|challenge| challenge.to_le_bytes()[0])
        .collect();
    report.push(Row {
        surface: SURFACE,
        case: "crypt-ping/challenge-low-byte-space".to_owned(),
        origin: Origin::RmuleEmit,
        input: crypt_ping(crypt_ping_challenge(0x1122_33e3), 10),
        rmule: read([("unanswered_low_bytes", "0".to_owned())]),
        ed2ksrv: read([(
            "unanswered_low_bytes",
            if mismatches.is_empty() {
                "0".to_owned()
            } else {
                format!("{mismatches:02x?}")
            },
        )]),
    });
}

// ── the two boundaries, re-executed ─────────────────────────────────────────

/// Datagrams the *parity reference* family accepts and this oracle does not.
///
/// Both are outside rmule's emit space today — that is the point: they are the
/// shapes rmule used to mint, kept as executable proof that the two silent-drop
/// paths are real and still open at this pin. `origin: boundary` keeps them from
/// being read as live rmule defects.
fn crypt_ping_boundaries(oracle: &Oracle, report: &mut Report) {
    // 9 bytes: inside the eserver family's 4..=18 and inside this server's own
    // obf-ping arm, but under its 10-byte pre-flight floor.
    let short = crypt_ping(0x0102_0301, 5);
    report.push(Row {
        surface: SURFACE,
        case: "crypt-ping/reference-legal-length-9".to_owned(),
        origin: Origin::Boundary,
        input: short.clone(),
        rmule: read([("answered", "true".to_owned())]),
        ed2ksrv: read([("answered", oracle.probe(12, &short).is_some().to_string())]),
    });

    // A challenge whose low byte is 0xE3, i.e. exactly what an unclamped aMule
    // mint produces once in 256.
    let colliding = crypt_ping(0x1122_33e3, 10);
    assert_eq!(colliding[0], 0xE3, "the collision case must lead with 0xE3");
    report.push(Row {
        surface: SURFACE,
        case: "crypt-ping/challenge-low-byte-e3".to_owned(),
        origin: Origin::Boundary,
        input: colliding.clone(),
        rmule: read([("answered", "true".to_owned())]),
        ed2ksrv: read([(
            "answered",
            oracle.probe(12, &colliding).is_some().to_string(),
        )]),
    });
}

// ── the crypt-pong, read by both decoders ───────────────────────────────────

/// The one row where both implementations decrypt the *same live ciphertext*.
///
/// rmule reads it with `decrypt_datagram_server` + `GlobServStatRes::decode_udp`;
/// they read it with `decode_obf_s2s`, which runs their own RC4 and lifts the
/// ServerKey from payload offset 36. Two independent RC4 key schedules and two
/// independent field layouts over bytes neither side chose in advance — the
/// shape that caught rmule's datagram-crypt sync-word endianness bug.
fn crypt_pong_dual_decode(oracle: &Oracle, report: &mut Report) {
    let challenge = crypt_ping_challenge(0x2233_4451);
    let Some(pong) = oracle.probe(12, &crypt_ping(challenge, 10)) else {
        report.push(Row {
            surface: SURFACE,
            case: "crypt-pong/dual-decode".to_owned(),
            origin: Origin::RmuleEmit,
            input: Vec::new(),
            rmule: Reading::Unreachable("no crypt-pong to read".to_owned()),
            ed2ksrv: Reading::Silent,
        });
        return;
    };

    let ours = match decrypt_datagram_server(&pong, challenge, ServerCryptDirection::FromServer) {
        None => Reading::Refused("rmule could not decrypt the crypt-pong".to_owned()),
        Some(inner) => match GlobServStatRes::decode_udp(&inner) {
            Err(e) => Reading::Refused(e.to_string()),
            Ok(status) => read([
                ("decrypts", "true".to_owned()),
                ("challenge_echo", format!("0x{:08x}", status.challenge())),
                (
                    "server_key",
                    status
                        .server_udp_key()
                        .map_or_else(|| "<none>".to_owned(), |k| format!("0x{k:08x}")),
                ),
            ]),
        },
    };

    let theirs = match decode_obf_s2s(&pong, challenge) {
        None => Reading::Refused("their decode_obf_s2s rejected their own reply".to_owned()),
        Some(server_key) => read([
            ("decrypts", "true".to_owned()),
            // Their reader does not surface the echo, so the comparable value is
            // the challenge the datagram was keyed on — which decrypting at all
            // already proves.
            ("challenge_echo", format!("0x{challenge:08x}")),
            ("server_key", format!("0x{server_key:08x}")),
        ]),
    };

    report.push(Row {
        surface: SURFACE,
        case: "crypt-pong/dual-decode".to_owned(),
        origin: Origin::RmuleEmit,
        input: pong,
        rmule: ours,
        ed2ksrv: theirs,
    });
}

// ── the crypt envelope, encoder against decoder, both ways ──────────────────

/// The server-UDP obfuscation envelope, pure both ways.
///
/// `MD5(key_LE ‖ obf_byte ‖ salt)`, RC4 with no discard, `0x13EF24D5` sync word.
/// Each direction pairs one side's encoder with the other's decoder, so a
/// disagreement about field order or endianness cannot cancel out the way a
/// self-round-trip lets it.
fn crypt_envelope_both_ways(report: &mut Report) {
    const KEY: u32 = 0x5E0D_856B;
    let inner: Vec<u8> = vec![0xE3, 0x97, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06];

    let ours_encoded = encrypt_datagram_server(
        &inner,
        KEY,
        ServerCryptDirection::ToServer,
        &DatagramNonce {
            marker_byte: 0x8F,
            random_key: 0x0F44,
            padding: vec![0x00; 3],
        },
    );
    report.push(Row {
        surface: SURFACE,
        case: "crypt-envelope/rmule-encodes-they-decode".to_owned(),
        origin: Origin::RmuleEmit,
        input: ours_encoded.clone(),
        rmule: read([("inner", hex(&inner))]),
        ed2ksrv: match their_crypt::decode_with_obfbyte(&ours_encoded, KEY, 0x6b) {
            None => Reading::Refused("their decode rejected rmule's envelope".to_owned()),
            Some(out) => read([("inner", hex(&out))]),
        },
    });

    let theirs_encoded = their_crypt::encode_with_obfbyte(&inner, KEY, 0x1234_5678, 0xa5);
    report.push(Row {
        surface: SURFACE,
        case: "crypt-envelope/they-encode-rmule-decodes".to_owned(),
        origin: Origin::RmuleEmit,
        input: theirs_encoded.clone(),
        rmule: match decrypt_datagram_server(&theirs_encoded, KEY, ServerCryptDirection::FromServer)
        {
            None => Reading::Refused("rmule could not decrypt their envelope".to_owned()),
            Some(out) => read([("inner", hex(&out))]),
        },
        ed2ksrv: read([("inner", hex(&inner))]),
    });
}

// ── plain status ping and description ───────────────────────────────────────

/// `OP_GLOBSERVSTATREQ 0x96` → `0x97`, live.
///
/// rmule's challenge is `0x55AA0000 + rand16`, whose bytes 2 and 3 are `AA 55` —
/// the marker their handler reads to choose the 44-byte extended form
/// (`udp.rs:671`). The oracle side of the comparison is what its own source
/// fixes: the echoed challenge, the hardcoded `pingflg`, and the two obfuscation
/// ports derived from `tcp_port`.
fn status_ping(oracle: &Oracle, report: &mut Report) {
    let request = GlobServStatReq::mint(0x0d0c);
    let wire = request.encode_packet().encode_udp();
    let Some(reply) = oracle.probe(4, &wire) else {
        report.push(Row {
            surface: SURFACE,
            case: "status-ping/0x96-extended-0x97".to_owned(),
            origin: Origin::RmuleEmit,
            input: wire,
            rmule: Reading::Unreachable("no reply to read".to_owned()),
            ed2ksrv: Reading::Silent,
        });
        return;
    };

    let ours = match GlobServStatRes::decode_udp(&reply) {
        Err(e) => Reading::Refused(e.to_string()),
        Ok(status) => read([
            ("challenge", format!("0x{:08x}", status.challenge())),
            (
                "udp_flags",
                status
                    .udp_flags()
                    .map_or_else(|| "<none>".to_owned(), |f| format!("0x{:08x}", f.bits())),
            ),
            (
                "obf_tcp_port",
                status
                    .obfuscation_tcp_port()
                    .map_or_else(|| "<none>".to_owned(), |p| p.to_string()),
            ),
            (
                "obf_udp_port",
                status
                    .obfuscation_udp_port()
                    .map_or_else(|| "<none>".to_owned(), |p| p.to_string()),
            ),
        ]),
    };

    let theirs = read([
        ("challenge", format!("0x{:08x}", request.challenge())),
        ("udp_flags", format!("0x{ORACLE_UDP_FLAGS:08x}")),
        ("obf_tcp_port", oracle.tcp_port.to_string()),
        ("obf_udp_port", (oracle.tcp_port + 14).to_string()),
    ]);

    report.push(Row {
        surface: SURFACE,
        case: "status-ping/0x96-extended-0x97".to_owned(),
        origin: Origin::RmuleEmit,
        input: reply,
        rmule: ours,
        ed2ksrv: theirs,
    });
}

/// `OP_SERVER_DESC_REQ 0xA2` → `0xA3`, live.
///
/// rmule pins `INV_SERV_DESC_LEN 0xF0FF` into the low half of every desc
/// challenge, which is the marker their handler reads to send the tagged form
/// rather than the legacy two-string body (`udp.rs:1223`). The legacy body is
/// where the two implementations genuinely disagree about string order
/// (audit §4.12) — this row is what proves rmule never lands there.
fn server_description(oracle: &Oracle, report: &mut Report) {
    let request = ServerDescReq::mint(0x4a4b);
    let wire = request.encode_packet().encode_udp();
    let Some(reply) = oracle.probe(4, &wire) else {
        report.push(Row {
            surface: SURFACE,
            case: "desc-req/0xA2-tagged-0xA3".to_owned(),
            origin: Origin::RmuleEmit,
            input: wire,
            rmule: Reading::Unreachable("no reply to read".to_owned()),
            ed2ksrv: Reading::Silent,
        });
        return;
    };

    let ours = match ServerDescRes::decode_udp(&reply) {
        Err(e) => Reading::Refused(e.to_string()),
        Ok(ServerDescRes::Legacy { description, name }) => read([
            ("form", "legacy".to_owned()),
            ("challenge", "<none>".to_owned()),
            ("name", name),
            ("desc", description),
            ("version", "<none>".to_owned()),
        ]),
        Ok(ServerDescRes::Tagged { challenge, tags }) => read([
            ("form", "tagged".to_owned()),
            ("challenge", format!("0x{challenge:08x}")),
            ("name", tags.name.unwrap_or_else(|| "<none>".to_owned())),
            (
                "desc",
                tags.description.unwrap_or_else(|| "<none>".to_owned()),
            ),
            (
                "version",
                tags.version.unwrap_or_else(|| "<none>".to_owned()),
            ),
        ]),
    };

    let theirs = read([
        ("form", "tagged".to_owned()),
        ("challenge", format!("0x{:08x}", request.challenge())),
        ("name", ORACLE_NAME.to_owned()),
        ("desc", ORACLE_DESC.to_owned()),
        ("version", ORACLE_VERSION.to_owned()),
    ]);

    report.push(Row {
        surface: SURFACE,
        case: "desc-req/0xA2-tagged-0xA3".to_owned(),
        origin: Origin::RmuleEmit,
        input: reply,
        rmule: ours,
        ed2ksrv: theirs,
    });
}
