//! The flow-L emit verdict: byte checks over the retained tap on rmule's
//! namespace, where rmule is the queued downloader and a stock aMule the
//! sharer it must reask.
//!
//! rmule's `0x90` is judged in the mode its policy held at that datagram:
//! the run's aMules request obfuscation, so an armed rmule must send it
//! obfuscated. It opens under the sharer's User Hash with rmule's address
//! mixed in, and the sharer's answer under rmule's hash with the sharer's
//! address. A key is taken only from plaintext the same tap carries — a
//! hello on a plain link, rmule's login to the eserver, or the eserver's
//! `OP_FOUNDSOURCES_OBFU` row naming the sharer — and never from rmule's
//! log. The sharer's `0x91` is the counterparty's own word that it took the
//! ping; what rmule sent is stimulus (ADR-0045).

use std::fs;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;

use anyhow::{Context, Result};
use rmule_primitives::UserHash;
use serde::Serialize;

use crate::flow::identity::{hex_lower, parse_ed2k_file_hash};
use crate::flow::nat::claims::{Claim, Evidence, label};
use crate::flow::pcap::{TcpStream, Udp4Datagram, records, tcp_streams, udp4_datagrams};
use crate::flow::peer::udp_reask::tap::{
    EMULE_PROTOCOL, Flip, OP_HELLO, OP_HELLOANSWER, OP_REASKACK, crypt_at, hello_hash,
    is_obfuscated, open, ping_shape,
};
use crate::flow::wire_filter::OP_EDONKEYPROT;

/// The eserver's TCP port on the bench.
const ESERVER_TCP_PORT: u16 = 4661;
/// `OP_LOGINREQUEST`, a client to its server: the user hash first.
const OP_LOGINREQUEST: u8 = 0x01;
/// `OP_FOUNDSOURCES_OBFU`: the file hash, a one-byte count, then per source
/// `[id 4][port 2][crypt 1]` and, iff the crypt byte's top bit is set, the
/// source's user hash.
const OP_FOUNDSOURCES_OBFU: u8 = 0x44;
/// The crypt-byte bit that says a user hash follows.
const HAS_USER_HASH: u8 = 0x80;
/// The id of a sentinel source, whose address follows inline; no bench
/// eserver writes one, so a walk stops there.
const SENTINEL_ID: [u8; 4] = [0xFF; 4];

/// What a retained emit run is scored from.
pub(crate) struct EmitRun<'a> {
    /// The `tcp or udp` tap on rmule's namespace.
    pub(crate) pcap: &'a Path,
    /// The downloading rmule's address.
    pub(crate) rmule: Ipv4Addr,
    /// The sharer aMule's address.
    pub(crate) sharer: Ipv4Addr,
    /// The shared file's ED2K hash.
    pub(crate) file_hash: [u8; 16],
    /// The shared file's size in bytes.
    pub(crate) file_size: u64,
    /// Whether rmule started with its peer obfuscation armed.
    pub(crate) crypt: bool,
    /// The obfuscation flips rmule's marker lines recorded, in order.
    pub(crate) flips: Vec<Flip>,
}

/// The flow's verdict file.
#[derive(Debug, Serialize)]
struct EmitVerdict<'a> {
    #[serde(rename = "scenario")]
    flow: &'static str,
    verdict: &'static str,
    detail: String,
    crypt: bool,
    /// Seconds after rmule's login of each obfuscation flip the run recorded.
    flips: Vec<u64>,
    /// Each user hash the datagrams were opened under, and the plaintext it
    /// was read off.
    keys: Vec<String>,
    /// Each TCP link rmule opened to the sharer: when, how it opened, and the
    /// policy in force at that moment.
    dials: Vec<String>,
    claim: &'a [Claim],
}

/// A user hash and the plaintext it was read off.
#[derive(Clone, Copy)]
struct Key {
    hash: UserHash,
    from: &'static str,
}

/// The user hashes rmule's and the sharer's datagrams open under.
struct Keys {
    rmule: Option<Key>,
    sharer: Option<Key>,
}

impl Keys {
    /// Every key the tap's plaintext carries; a hello outranks the eserver
    /// leg, which is read only when the peer link opened obfuscated.
    fn read(run: &EmitRun<'_>, streams: &[TcpStream]) -> Self {
        let (mut rmule_hello, mut sharer_hello) = (None, None);
        let (mut rmule_login, mut sharer_row) = (None, None);
        for stream in streams {
            let (SocketAddr::V4(from), SocketAddr::V4(to)) = (stream.source, stream.destination)
            else {
                continue;
            };
            for frame in stream
                .ed2k_frames()
                .into_iter()
                .filter(|frame| frame.protocol == OP_EDONKEYPROT)
            {
                let rmule_sent = *from.ip() == run.rmule;
                if rmule_sent && *to.ip() == run.sharer && frame.opcode == OP_HELLO {
                    rmule_hello = rmule_hello.or_else(|| hello_hash(&frame));
                } else if *from.ip() == run.sharer
                    && *to.ip() == run.rmule
                    && frame.opcode == OP_HELLOANSWER
                {
                    sharer_hello = sharer_hello.or_else(|| hello_hash(&frame));
                } else if rmule_sent
                    && to.port() == ESERVER_TCP_PORT
                    && frame.opcode == OP_LOGINREQUEST
                {
                    rmule_login = rmule_login.or_else(|| user_hash_at(frame.payload(), 0));
                } else if from.port() == ESERVER_TCP_PORT
                    && *to.ip() == run.rmule
                    && frame.opcode == OP_FOUNDSOURCES_OBFU
                {
                    sharer_row =
                        sharer_row.or_else(|| sharer_row_hash(frame.payload(), run.sharer));
                }
            }
        }
        let key = |hash: Option<UserHash>, from| hash.map(|hash| Key { hash, from });
        Self {
            rmule: key(rmule_hello, "rmule's hello to the sharer")
                .or_else(|| key(rmule_login, "rmule's login to the eserver")),
            sharer: key(sharer_hello, "the sharer's hello answer")
                .or_else(|| key(sharer_row, "the eserver's 0x44 row for the sharer")),
        }
    }

    fn describe(&self) -> Vec<String> {
        [("rmule", self.rmule), ("sharer", self.sharer)]
            .into_iter()
            .map(|(whose, key)| match key {
                Some(key) => format!(
                    "{whose} {} from {}",
                    hex_lower(key.hash.as_bytes()),
                    key.from
                ),
                None => format!("{whose}: no plaintext on the tap carried its user hash"),
            })
            .collect()
    }
}

/// The 16 bytes at `at` as a user hash.
fn user_hash_at(payload: &[u8], at: usize) -> Option<UserHash> {
    let bytes: [u8; 16] = payload.get(at..at + 16)?.try_into().ok()?;
    Some(UserHash::from_bytes(bytes))
}

/// The user hash an `OP_FOUNDSOURCES_OBFU` body names for the High-ID source
/// at `sharer` (its id is the address's octets in wire order).
fn sharer_row_hash(payload: &[u8], sharer: Ipv4Addr) -> Option<UserHash> {
    let count = *payload.get(16)?;
    let mut at = 17;
    for _ in 0..count {
        let id = payload.get(at..at + 4)?;
        let crypt = *payload.get(at + 6)?;
        at += 7;
        let hash = if crypt & HAS_USER_HASH != 0 {
            at += 16;
            user_hash_at(payload, at - 16)
        } else {
            None
        };
        if id == SENTINEL_ID {
            return None;
        }
        if id == sharer.octets() {
            return hash;
        }
    }
    None
}

/// The scored claims and the context the verdict file carries beside them.
struct Scored {
    claims: Vec<Claim>,
    keys: Vec<String>,
    dials: Vec<String>,
}

/// The flow-L emit claims for a retained run.
///
/// # Errors
/// If the pcap cannot be read.
fn score(run: &EmitRun<'_>) -> Result<Scored> {
    let datagrams = udp4_datagrams(run.pcap)?;
    let streams = tcp_streams(run.pcap)?;
    let started = records(run.pcap)?.first().map_or(0.0, |r| r.at);
    let armed = |at: f64| crypt_at(run.crypt, &run.flips, started, at);
    let keys = Keys::read(run, &streams);

    let toward_sharer =
        |d: &&Udp4Datagram| *d.source.ip() == run.rmule && *d.destination.ip() == run.sharer;
    let toward_rmule =
        |d: &&Udp4Datagram| *d.source.ip() == run.sharer && *d.destination.ip() == run.rmule;
    let ping = datagrams.iter().find(toward_sharer);
    let ack = ping.and_then(|ping| {
        datagrams
            .iter()
            .filter(toward_rmule)
            .find(|d| d.at >= ping.at)
    });
    let opened_ping = ping.and_then(|d| {
        open(
            &d.payload,
            is_obfuscated(&d.payload),
            keys.sharer.as_ref().map(|key| &key.hash),
            run.rmule,
        )
    });
    let opened_ack = ack.and_then(|d| {
        open(
            &d.payload,
            is_obfuscated(&d.payload),
            keys.rmule.as_ref().map(|key| &key.hash),
            run.sharer,
        )
    });
    let ping_armed = ping.is_some_and(|d| armed(d.at));
    let wire = |d: &Udp4Datagram| {
        if is_obfuscated(&d.payload) {
            format!("{} bytes, obfuscated", d.payload.len())
        } else {
            format!("{} bytes, plain", d.payload.len())
        }
    };

    let mut claims = vec![Claim::about(
        "rmule-reasked-the-sharer-with-a-0x90-for-the-file",
        opened_ping
            .as_deref()
            .is_some_and(|bytes| ping_shape(bytes, &run.file_hash, run.file_size)),
        Evidence::RmuleOnly,
        match (ping, &opened_ping) {
            (None, _) => "rmule sent the sharer no datagram".to_owned(),
            (Some(d), Some(bytes)) => format!(
                "{} at +{:.1} s, opened to {}",
                wire(d),
                d.at - started,
                hex_lower(bytes)
            ),
            (Some(d), None) => format!(
                "{} did not open under the sharer's user hash and rmule's address",
                wire(d)
            ),
        },
    )];

    if ping_armed {
        let to_sharer: Vec<&Udp4Datagram> = datagrams
            .iter()
            .filter(toward_sharer)
            .filter(|d| armed(d.at))
            .collect();
        let plain = to_sharer
            .iter()
            .filter(|d| d.payload.first() == Some(&EMULE_PROTOCOL))
            .count();
        claims.push(Claim::about(
            "the-reask-left-obfuscated",
            ping.is_some_and(|d| is_obfuscated(&d.payload)) && plain == 0,
            Evidence::RmuleOnly,
            format!(
                "marker byte {:#04x}; {plain} of {} datagrams to the sharer while armed \
                 opened with the plain 0xc5",
                ping.and_then(|d| d.payload.first().copied()).unwrap_or(0),
                to_sharer.len()
            ),
        ));
    } else {
        claims.push(Claim::about(
            "the-reask-left-plain",
            ping.is_some_and(|d| !is_obfuscated(&d.payload)),
            Evidence::RmuleOnly,
            ping.map_or_else(|| "no reask".to_owned(), &wire),
        ));
    }

    claims.push(Claim::about(
        "the-sharer-answered-with-a-0x91",
        opened_ack
            .as_deref()
            .is_some_and(|bytes| bytes.starts_with(&[EMULE_PROTOCOL, OP_REASKACK])),
        Evidence::Captured,
        match (ack, &opened_ack) {
            (None, _) => "the sharer sent rmule no datagram after the ping".to_owned(),
            (Some(d), Some(bytes)) => format!(
                "{} {:.1} ms after the ping, opened to {}",
                wire(d),
                ping.map_or(0.0, |ping| (d.at - ping.at) * 1000.0),
                hex_lower(bytes)
            ),
            (Some(d), None) => format!(
                "{} did not open under rmule's user hash and the sharer's address",
                wire(d)
            ),
        },
    ));

    let to_sharer_links: Vec<&TcpStream> = streams
        .iter()
        .filter(|s| {
            matches!((s.source, s.destination),
                (SocketAddr::V4(from), SocketAddr::V4(to))
                if *from.ip() == run.rmule && *to.ip() == run.sharer)
        })
        .collect();
    claims.push(match ack.map(|d| d.at) {
        Some(at) => {
            let after = to_sharer_links
                .iter()
                .filter(|s| s.opened_at() > at)
                .count();
            let end = records(run.pcap)?.iter().map(|r| r.at).fold(at, f64::max);
            Claim::absence(
                "rmule-dialed-the-sharer-no-more-after-the-ack",
                i64::try_from(after).unwrap_or(i64::MAX),
                format!(
                    "{after} TCP links from rmule to the sharer in the {:.0} s after the ack",
                    end - at
                ),
            )
        }
        None => Claim::absence(
            "rmule-dialed-the-sharer-no-more-after-the-ack",
            -1,
            "no ack came back, so there is no moment to count from",
        ),
    });

    let dials = to_sharer_links
        .iter()
        .map(|s| {
            let at = s.opened_at();
            format!(
                "+{:.1} s {} under {}",
                at - started,
                if s.opens_plain() {
                    "plain"
                } else {
                    "obfuscated"
                },
                if armed(at) { "an armed policy" } else { "off" }
            )
        })
        .collect();
    Ok(Scored {
        claims,
        keys: keys.describe(),
        dials,
    })
}

/// Score `run` and write `peer-udp-reask-emit-verdict.toml` under `root`,
/// printing the label.
///
/// # Errors
/// If the pcap cannot be read or the verdict cannot be written.
pub(crate) fn write(root: &Path, run: &EmitRun<'_>) -> Result<&'static str> {
    let scored = score(run)?;
    let (verdict, detail) = label(&scored.claims);
    let text = toml::to_string_pretty(&EmitVerdict {
        flow: "peer-udp-reask-emit",
        verdict,
        detail,
        crypt: run.crypt,
        flips: run.flips.iter().map(|f| f.after_secs).collect(),
        keys: scored.keys,
        dials: scored.dials,
        claim: &scored.claims,
    })
    .context("serialize the peer-udp-reask-emit verdict")?;
    let path = root.join("peer-udp-reask-emit-verdict.toml");
    fs::write(&path, &text).with_context(|| format!("write {}", path.display()))?;
    println!("peer_udp_reask_emit verdict={verdict}");
    Ok(verdict)
}

/// Score the run dir a finished emit flow (or an archive) left behind; a
/// two-download run's standing verdict is re-taken beside it.
///
/// # Errors
/// If an artifact cannot be read or the verdict cannot be written.
pub fn score_run_dir(
    root: &Path,
    rmule: Ipv4Addr,
    sharer: Ipv4Addr,
    crypt: bool,
) -> Result<&'static str> {
    let link = fs::read_to_string(root.join("synthetic/shared.ed2k.txt"))
        .context("read synthetic/shared.ed2k.txt")?;
    let file_size = fs::metadata(root.join("synthetic/shared.bin"))
        .context("stat synthetic/shared.bin")?
        .len();
    let pcap = root.join("emit-reask-capture/emit-reask.pcap");
    if root.join("synthetic").join(super::SECOND_LINK).exists() {
        super::standing::write(
            root,
            &super::standing::StandingRun {
                pcap: &pcap,
                rmule,
                sharer,
            },
        )?;
    }
    write(
        root,
        &EmitRun {
            pcap: &pcap,
            rmule,
            sharer,
            file_hash: parse_ed2k_file_hash(link.trim())?,
            file_size,
            crypt,
            flips: Flip::read_run_dir(root),
        },
    )
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::sharer_row_hash;

    /// The sharer's hash is the one on its own row, past a row without a
    /// hash and a row with another's; a row whose crypt byte lacks the hash
    /// bit names none.
    #[test]
    fn the_sharers_hash_is_read_off_its_own_row() {
        let sharer = Ipv4Addr::new(203, 0, 113, 6);
        let mut body = vec![0xAB; 16];
        body.push(3);
        body.extend([203, 0, 113, 4, 0x36, 0x12, 0x01]);
        body.extend([203, 0, 113, 5, 0x36, 0x12, 0x83]);
        body.extend([0x11; 16]);
        body.extend([203, 0, 113, 6, 0x36, 0x12, 0x83]);
        body.extend([0x22; 16]);
        assert_eq!(
            sharer_row_hash(&body, sharer).map(|hash| *hash.as_bytes()),
            Some([0x22; 16])
        );
        body[17 + 7 + 7 + 16 + 6] = 0x03;
        assert!(sharer_row_hash(&body[..body.len() - 16], sharer).is_none());
    }
}
