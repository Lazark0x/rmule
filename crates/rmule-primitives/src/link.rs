//! `ed2k://` URIs: the file, server and server-list link forms, parsed from
//! their pipe-delimited text and printed back in the canonical spelling
//! byte-for-byte.

use std::{fmt, str::FromStr};

use percent_encoding::percent_decode_str;

mod sources;

pub use sources::{LinkPeer, LinkPeerHost, LinkSourceExpiry, LinkSources};

use crate::{
    AichRootHash, Ed2kText, FileHash, Ipv6Endpoint, PartHash, PartHashSet, PrimitiveError, Result,
    ServerEndpoint, is_usable_tag_identity,
};

/// The eD2k listen port an `s6=` entry means when it names none — the
/// dialect's stated default (ADR-0089 §6.2), not a rmule convention.
const S6_DEFAULT_PORT: u16 = 4662;

/// The most source hints one link carries, across all of its source tokens
/// combined — `s6=` and `sources,` alike — emule-qt's `kMaxLinkSources`
/// (`src/core/protocol/ED2KLink.h:29` @ `73fff714`; `ipv6-spec.md` §6.1). The
/// rest are dropped, never fatal.
const MAX_LINK_SOURCES: usize = 64;

/// An `ed2k://` link in one of its three forms.
///
/// The kind segment decides which: nothing else about a link's text is
/// interpretable until it is known.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ed2kLink {
    /// A file to download.
    File(Ed2kFileLink),
    /// A server to connect to.
    Server(Ed2kServerLink),
    /// A URL to fetch a server list from.
    ServerList(Ed2kServerListLink),
}

/// A file link: everything needed to start a download without contacting
/// anyone first.
///
/// The two optional fields are what make a link *verifiable* rather than
/// merely resolvable — with a part hash set or an AICH root, corrupt parts are
/// detectable before the whole file finishes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ed2kFileLink {
    /// File name as wire-faithful bytes. Real-world ED2K links carry
    /// legacy Windows-1252 / mojibake names that pre-cleanup were
    /// rejected by the strict UTF-8 percent-decoder; modelling as
    /// [`Ed2kText`] (per ADR-0019) preserves the original bytes through
    /// parse → display round trips. UI-side rendering uses
    /// `Ed2kText::to_display_string` for a lossy UTF-8 projection.
    pub name: Ed2kText,
    /// The file's size in bytes — the second half of its identity, since a
    /// hash alone does not decide part geometry.
    pub size: u64,
    /// The eD2k file hash.
    pub file_hash: FileHash,
    /// The part hash set, when the link's optional `p=` field carried one
    /// that is the file hash's own — parsing drops one that is not.
    pub part_hash_set: Option<PartHashSet>,
    /// The AICH root hash, when the link's optional `h=` field carried one.
    pub aich_root: Option<AichRootHash>,
    /// IPv6 source hints from the link's `s6=` token(s) (ADR-0089 §6.2), in
    /// the order they were written.
    ///
    /// Hints, not identity: a link is complete without them, and an entry that
    /// did not parse was skipped rather than costing the rest of the list.
    pub ipv6_sources: Vec<Ipv6Endpoint>,
    /// The classic hints (ADR-0089): the `sources,` tokens'
    /// peers and the `s=` web sources. Hints like `ipv6_sources`: a
    /// download's first candidates, never part of the file's identity.
    pub sources: LinkSources,
}

/// A link as read, with the fields it carried that no client reads.
///
/// eMule and aMule both skip a file link field they do not know and read the
/// rest (emule-qt `srchybrid/ED2KLink.cpp:216-217`, `default: ASSERT(0)`,
/// compiled out of a release build; aMule `src/ED2KLink.cpp:188-270`, an
/// `if`/`else if` chain with no `else`), so rmule does too, and says which.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkRead {
    /// The link, with every field rmule reads.
    pub link: Ed2kLink,
    /// The name of each field skipped, in link order: the text before its
    /// `=`, or the whole field when it has none.
    pub skipped_fields: Vec<String>,
}

/// A link naming one server to connect to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ed2kServerLink {
    /// Where that server is reached.
    pub endpoint: ServerEndpoint,
}

/// A link naming a URL to fetch a server list from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ed2kServerListLink {
    /// The URL, kept as written — this crate does not fetch, so it does not
    /// interpret it either.
    pub address: String,
}

impl Ed2kLink {
    /// Parse link text.
    ///
    /// # Errors
    /// [`PrimitiveError::InvalidLink`] on malformed text,
    /// [`PrimitiveError::UnsupportedLinkKind`] on an unmodelled kind,
    /// [`PrimitiveError::FileSizeAboveLimit`] and [`PrimitiveError::FileSizeZero`]
    /// on a file size aMule refuses (`ED2KLink.cpp:179`), plus the hash and
    /// endpoint errors the fields themselves raise.
    pub fn parse(input: &str) -> Result<Self> {
        input.parse()
    }

    /// Parse link text, and say which fields no client reads were skipped.
    ///
    /// # Errors
    /// As [`parse`](Self::parse).
    pub fn read(input: &str) -> Result<LinkRead> {
        if input.trim() != input {
            return Err(PrimitiveError::InvalidLink {
                reason: "surrounding whitespace",
            });
        }
        let Some(rest) = strip_prefix_ignore_ascii_case(input, "ed2k://") else {
            return Err(PrimitiveError::InvalidLink {
                reason: "missing ed2k scheme",
            });
        };
        let Some(body) = rest.strip_suffix("|/") else {
            return Err(PrimitiveError::InvalidLink {
                reason: "missing final delimiter",
            });
        };
        let Some(body) = body.strip_prefix('|') else {
            return Err(PrimitiveError::InvalidLink {
                reason: "missing link type delimiter",
            });
        };
        // No `body.contains("|/|")` pre-check: the substring has false
        // positives on legitimate file names.

        let fields = body.split('|').collect::<Vec<_>>();
        let Some(kind) = fields.first() else {
            return Err(PrimitiveError::InvalidLink {
                reason: "missing link type",
            });
        };

        let mut skipped_fields = Vec::new();
        let link = match kind.to_ascii_lowercase().as_str() {
            "file" => parse_file_link(&fields, &mut skipped_fields),
            "server" => parse_server_link(&fields),
            "serverlist" => parse_server_list_link(&fields),
            _ => Err(PrimitiveError::UnsupportedLinkKind),
        }?;
        Ok(LinkRead {
            link,
            skipped_fields,
        })
    }

    /// The kind segment, as it is spelled in the link text.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::File(_) => "file",
            Self::Server(_) => "server",
            Self::ServerList(_) => "serverlist",
        }
    }
}

impl FromStr for Ed2kLink {
    type Err = PrimitiveError;

    fn from_str(input: &str) -> Result<Self> {
        Self::read(input).map(|read| read.link)
    }
}

impl fmt::Display for Ed2kLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File(link) => {
                write!(
                    f,
                    "ed2k://|file|{}|{}|{}|",
                    encode_file_name(link.name.as_bytes()),
                    link.size,
                    link.file_hash.to_hex_upper()
                )?;
                if let Some(part_hash_set) = &link.part_hash_set {
                    write!(f, "p=")?;
                    for (index, hash) in part_hash_set.hashes().iter().enumerate() {
                        if index > 0 {
                            write!(f, ":")?;
                        }
                        write!(f, "{}", hash.to_hex_upper())?;
                    }
                    write!(f, "|")?;
                }
                if let Some(aich_root) = link.aich_root {
                    write!(f, "h={}|", aich_root.to_base32_upper())?;
                }
                // eMule reads `s=` only in the parameter section, before the
                // `/` that closes it.
                for url in link.sources.web() {
                    write!(f, "s={url}|")?;
                }
                // The lone `/` closes the parameter section and is emitted
                // unconditionally — stock eMule's tokenizer stops at the first
                // empty token, so a source block must never follow an empty
                // field. `s6=` then sits *after* it and *before* any
                // `|sources,` token: stock's parameter switch asserts on an
                // unknown parameter, and its source scan starts at the first
                // occurrence of the substring "sources" and reads to the end
                // of the link, so anything earlier stays invisible to it. The
                // classic peers come last, as eMule's own writer puts them
                // (`AbstractFile.cpp:439-443`).
                write!(f, "/")?;
                if link.ipv6_sources.is_empty() && link.sources.peers().is_empty() {
                    return Ok(());
                }
                if !link.ipv6_sources.is_empty() {
                    write!(f, "|s6=")?;
                    for (index, endpoint) in link.ipv6_sources.iter().enumerate() {
                        if index > 0 {
                            write!(f, ",")?;
                        }
                        // Emission always brackets and always names the port,
                        // even when it is the default: the tolerant forms exist
                        // for ingest only.
                        write!(f, "{endpoint}")?;
                    }
                }
                let mut peers = String::new();
                sources::write_sources_tokens(&mut peers, link.sources.peers());
                write!(f, "{peers}|/")
            }
            Self::Server(link) => {
                // An IPv6 literal is **always** bracketed on emission
                // (ADR-0087 §6.4): the bracket is what makes a legacy client
                // fail its `inet_addr()` and degrade to treating the string as
                // an unresolvable dynIP hostname, rather than deciding it has
                // understood something.
                let host = link.endpoint.host();
                if host.parse::<std::net::Ipv6Addr>().is_ok() {
                    write!(f, "ed2k://|server|[{host}]|{}|/", link.endpoint.port())
                } else {
                    write!(f, "ed2k://|server|{host}|{}|/", link.endpoint.port())
                }
            }
            Self::ServerList(link) => {
                write!(f, "ed2k://|serverlist|{}|/", link.address)
            }
        }
    }
}

/// Read a file link's fields; each one no client reads is named in `skipped`.
fn parse_file_link(fields: &[&str], skipped: &mut Vec<String>) -> Result<Ed2kLink> {
    if fields.len() < 4 {
        return Err(PrimitiveError::InvalidLink {
            reason: "file link has too few fields",
        });
    }

    let name = decode_file_name(fields[1])?;
    let size = parse_u64(fields[2], "invalid file size")?;
    if size > crate::MAX_ED2K_FILE_SIZE {
        return Err(PrimitiveError::FileSizeAboveLimit { file_size: size });
    }
    if size == 0 {
        return Err(PrimitiveError::FileSizeZero);
    }
    let file_hash = FileHash::from_hex(fields[3])?;
    let mut part_hash_set = None;
    let mut aich_root = None;
    let mut ipv6_sources = Vec::new();
    let mut peers = Vec::new();
    let mut web = Vec::new();
    let hints = |ipv6: &Vec<Ipv6Endpoint>, peers: &Vec<LinkPeer>| {
        MAX_LINK_SOURCES.saturating_sub(ipv6.len() + peers.len())
    };

    for field in &fields[4..] {
        if let Some(value) = field.strip_prefix("p=") {
            if part_hash_set.is_some() {
                return Err(PrimitiveError::DuplicateLinkField { field: "p" });
            }
            let hashes = parse_part_hashes(value)?;
            part_hash_set = Some(PartHashSet::from_hashes(size, hashes)?);
        } else if let Some(value) = field.strip_prefix("h=") {
            if aich_root.is_some() {
                return Err(PrimitiveError::DuplicateLinkField { field: "h" });
            }
            aich_root = Some(AichRootHash::from_base32(value)?);
        } else if let Some(value) = field.strip_prefix("s6=") {
            // Several `s6=` tokens accumulate rather than collide: the
            // dialect's own cap is "sources across all source tokens
            // combined", so they are one list written in pieces, not a
            // duplicate field — and the cap holds across all of them.
            let room = hints(&ipv6_sources, &peers);
            ipv6_sources.extend(parse_ipv6_sources(value).take(room));
        } else if starts_with_ignore_ascii_case(field, "sources,")
            || starts_with_ignore_ascii_case(field, "sources@")
        {
            // aMule reads every `sources,` field wherever it sits
            // (`ED2KLink.cpp:191`); eMule reads the first, after the `/`
            // (`ED2KLink.cpp:228-321`). Several accumulate under the one cap.
            let room = hints(&ipv6_sources, &peers);
            sources::read_sources_token(field, room, &mut peers);
        } else if starts_with_ignore_ascii_case(field, "kadsources,") {
            // eMule writes it (`Emule.cpp:825`) for a firewalled node's buddy
            // ask, and no reference reads a source out of it: accepted, and
            // nothing taken.
        } else if let Some(value) = field.strip_prefix("s=") {
            // A web source eMule takes (`ED2KLink.cpp:140-173`); one it would
            // not crack is skipped, as eMule's release build skips it.
            web.extend(sources::read_web_source(value));
        } else if *field == "/" {
            // The parameter section's terminator, which a link carrying a
            // source block emits as a field of its own. Nothing to read; its
            // whole job is to stop stock eMule's parameter switch before the
            // sources.
        } else if field.is_empty() {
            return Err(PrimitiveError::InvalidLink {
                reason: "empty file link field",
            });
        } else {
            // Skipped, as both references skip it; a field whose name cannot
            // be told from its value is malformed, not unknown.
            let name = field.split_once('=').map_or(*field, |(name, _)| name);
            if name.is_empty() {
                return Err(PrimitiveError::InvalidLink {
                    reason: "file link field with no name",
                });
            }
            skipped.push(name.to_string());
        }
    }

    // A set that is not the file hash's own is dropped, the link kept: the
    // hash identifies the file, and a peer's set proven against it verifies
    // the parts instead (aMule `CPartFile::CPartFile(const CED2KFileLink*)`,
    // `src/PartFile.cpp:248-251` at `4e8f2b3c`, loads it with `checkhash`).
    let part_hash_set = part_hash_set.filter(|set| set.belongs_to(file_hash));

    Ok(Ed2kLink::File(Ed2kFileLink {
        name,
        size,
        file_hash,
        part_hash_set,
        aich_root,
        ipv6_sources,
        sources: LinkSources::new(peers, web),
    }))
}

/// Read one `s6=` token's comma-separated entries (ADR-0089 §6.2).
///
/// Ingest is deliberately more tolerant than emission: `[v6]:port`, a bare
/// `[v6]` at the default port, and an unbracketed literal are all accepted. A
/// malformed entry is **skipped**, never fatal — one bad hint must not cost
/// the rest of a list, and the link itself is complete without any of them.
/// So is an entry that names no dialable peer: an address
/// [`is_usable_tag_identity`] refuses (loopback, link-local, the LAN's ULA,
/// mapped, unspecified) or port 0.
fn parse_ipv6_sources(token: &str) -> impl Iterator<Item = Ipv6Endpoint> + '_ {
    token
        .split(',')
        .filter_map(parse_ipv6_source)
        .filter(|endpoint| is_usable_tag_identity(endpoint.ip) && endpoint.port != 0)
}

/// One `s6=` entry, or `None` when it names something this token cannot carry.
///
/// An unbracketed entry parses as a *whole* address and is never split at its
/// last colon: `2001:db8::1:4662` is itself a valid IPv6 literal, so splitting
/// would silently invent a different address on a different port. An IPv4
/// literal or a DNS name is refused outright — `s6=` is IPv6-only, and running
/// an IPv6 literal through a 32-bit projection is exactly the mistake the
/// separate token exists to prevent.
fn parse_ipv6_source(entry: &str) -> Option<Ipv6Endpoint> {
    if let Some(rest) = entry.strip_prefix('[') {
        return match rest.split_once(']') {
            Some((address, "")) => Some(Ipv6Endpoint::new(address.parse().ok()?, S6_DEFAULT_PORT)),
            Some((address, port)) => Some(Ipv6Endpoint::new(
                address.parse().ok()?,
                port.strip_prefix(':')?.parse().ok()?,
            )),
            None => None,
        };
    }
    Some(Ipv6Endpoint::new(entry.parse().ok()?, S6_DEFAULT_PORT))
}

fn parse_server_link(fields: &[&str]) -> Result<Ed2kLink> {
    if fields.len() != 3 {
        return Err(PrimitiveError::InvalidLink {
            reason: "server link must contain host and port",
        });
    }

    let port = parse_port(fields[2])?;
    let endpoint = ServerEndpoint::new(server_host(fields[1])?, port)?;
    Ok(Ed2kLink::Server(Ed2kServerLink { endpoint }))
}

/// The host text a server link's address field stands for (ADR-0087 §6.4).
///
/// Ingest accepts both spellings of an IPv6 literal and stores the
/// bracket-stripped form, because the brackets are link syntax and not part of
/// the address. An **unbracketed** string containing a colon is refused unless
/// the whole of it parses as an IPv6 literal — which is what rejects a
/// `host:1234` pasted into an address field, rather than storing a hostname no
/// resolver will ever answer for.
fn server_host(field: &str) -> Result<&str> {
    if let Some(inner) = field.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
        return if inner.parse::<std::net::Ipv6Addr>().is_ok() {
            Ok(inner)
        } else {
            Err(PrimitiveError::InvalidLink {
                reason: "bracketed server host is not an IPv6 literal",
            })
        };
    }
    if field.contains(':') && field.parse::<std::net::Ipv6Addr>().is_err() {
        return Err(PrimitiveError::InvalidLink {
            reason: "unbracketed server host with a colon is not an IPv6 literal",
        });
    }
    Ok(field)
}

fn parse_server_list_link(fields: &[&str]) -> Result<Ed2kLink> {
    if fields.len() != 2 {
        return Err(PrimitiveError::InvalidLink {
            reason: "server-list link must contain one address",
        });
    }
    let address = fields[1];
    if address.is_empty() || address.trim() != address {
        return Err(PrimitiveError::InvalidLink {
            reason: "invalid server-list address",
        });
    }
    Ok(Ed2kLink::ServerList(Ed2kServerListLink {
        address: address.to_owned(),
    }))
}

fn parse_part_hashes(input: &str) -> Result<Vec<PartHash>> {
    if input.is_empty() {
        return Err(PrimitiveError::InvalidLink {
            reason: "empty part hash set",
        });
    }
    input.split(':').map(PartHash::from_hex).collect()
}

/// Percent-decode the raw bytes of a file-name field. Strict UTF-8 is
/// *not* required — real ED2K links in the wild carry Windows-1252 /
/// mojibake names; the raw bytes are preserved as [`Ed2kText`] and a
/// lossy UTF-8 projection is the UI's responsibility.
fn decode_file_name(input: &str) -> Result<Ed2kText> {
    Ok(Ed2kText::from_bytes(
        percent_decode_str(input).collect::<Vec<u8>>(),
    ))
}

fn encode_file_name(input: &[u8]) -> String {
    let mut encoded = String::new();
    for byte in input {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(*byte));
        } else {
            encoded.push_str(&format!("%{byte:02X}"));
        }
    }
    encoded
}

fn parse_port(input: &str) -> Result<u16> {
    let port = parse_u64(input, "invalid server port")?;
    u16::try_from(port).map_err(|_| PrimitiveError::InvalidLink {
        reason: "invalid server port",
    })
}

fn parse_u64(input: &str, reason: &'static str) -> Result<u64> {
    if input.is_empty() {
        return Err(PrimitiveError::InvalidLink { reason });
    }
    input
        .parse::<u64>()
        .map_err(|_| PrimitiveError::InvalidLink { reason })
}

fn starts_with_ignore_ascii_case(input: &str, prefix: &str) -> bool {
    input
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix))
}

fn strip_prefix_ignore_ascii_case<'a>(input: &'a str, prefix: &str) -> Option<&'a str> {
    let candidate = input.get(..prefix.len())?;
    if candidate.eq_ignore_ascii_case(prefix) {
        input.get(prefix.len()..)
    } else {
        None
    }
}
