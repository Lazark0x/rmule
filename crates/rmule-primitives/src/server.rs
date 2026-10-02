//! Server-metadata primitives split per ADR-0017.
//!
//! `ServerIdentity` carries static-ish "who is this server" fields populated
//! by sources like `OP_SERVERIDENT` and (future) `server.met`. Each known
//! field is optional so partial population from any single source is honest;
//! `extra_tags` preserves unknown well-formed tags for forward compatibility.
//!
//! `merge` precedence: values present in `other` win. Combine an existing
//! identity with a fresher source via `existing.merge(other)`.

use std::net::Ipv6Addr;

mod flags;

pub use flags::{ServerTcpFlag, ServerTcpFlags, ServerUdpFlag, ServerUdpFlags};

use crate::{
    CT_MOD_IP_V6, CT_MOD_SVR_IP_V6, CT_MOD_YOUR_IP, Ed2kText, ST_IPV6_STATUS, ServerHash,
    ServerIpv6Status, Tag, TagValue, read_ipv6_address_tag,
};

/// Tag IDs documented in aMule `src/include/tags/ServerTags.h` and consumed by
/// `OP_SERVERIDENT` per `docs/reference/notes/ed2k-welcome-packets.md`.
pub(crate) const SERVER_TAG_NAME: u8 = 0x01;
pub(crate) const SERVER_TAG_DESCRIPTION: u8 = 0x0B;

/// Source of an `OP_SERVERIDENT`-shaped projection. Implemented by the eD2k
/// `ServerIdent` packet so the primitives crate can build a `ServerIdentity`
/// without depending on the protocol crate (ADR layering).
pub trait ServerIdentSource {
    /// The server's own hash — its identity across sessions and address
    /// changes.
    fn server_hash(&self) -> ServerHash;
    /// The identity tags as they arrived, typed and untyped alike.
    fn identity_tags(&self) -> &[Tag];
}

/// What is known about a server, accumulated from whichever sources have
/// spoken so far.
///
/// Every typed field is optional because no single source carries all of them:
/// a server.met row, an `OP_SERVERIDENT` and a status reply each fill a
/// different subset, and a partly-known server must stay representable.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServerIdentity {
    /// The server's hash, when a source has stated it.
    pub server_hash: Option<ServerHash>,
    /// The advertised name (`ST_SERVERNAME`).
    pub name: Option<Ed2kText>,
    /// The advertised description (`ST_DESCRIPTION`).
    pub description: Option<Ed2kText>,
    /// The advertised software version, when a source carries one.
    pub version: Option<Ed2kText>,
    /// The server's own public IPv6 (`CT_MOD_SVR_IP_V6`, ADR-0087 §4.3), read
    /// **id-tolerantly**.
    ///
    /// Informational: rmule logs it and keeps using the address it dialled.
    /// The tolerance is why that matters — the spec assigns `0xAF`, and the one
    /// server implementing the dialect reports emitting "`ST_IPV6` (`0xAE`)"
    /// for the same field. `0xAE` on a server→client packet is therefore read
    /// here as a fallback when no `0xAF` arrived, and **never** as a reflection
    /// of our own address: if the author instead meant the server echoing our
    /// `CT_MOD_IP_V6` back, mistaking it for the server's address costs a log
    /// line, while mistaking the server's address for ours would make rmule
    /// advertise an address it does not hold.
    pub server_ipv6: Option<Ipv6Addr>,
    /// Whether [`Self::server_ipv6`] came from the spec's `0xAF` id rather than
    /// the tolerated `0xAE` fallback — the provenance [`Self::merge`] needs so
    /// a later ident carrying only `0xAE` never replaces an `0xAF` value.
    pub server_ipv6_from_spec_id: bool,
    /// Our own public IPv6 as the server observed it (`CT_MOD_YOUR_IP` `0xAD`,
    /// **hash form only**) — the egress reflection that is tier 1 of
    /// ADR-0084's confidence ladder.
    ///
    /// A reader here does not know which family the session ran over, and a
    /// reflection received over an IPv4 session says nothing about IPv6
    /// connectivity — so the "only on a v6 session" half of the rule belongs to
    /// the consumer that knows, not to this projection.
    pub reflected_ipv6: Option<Ipv6Addr>,
    /// The server's verdict on the IPv6 we advertised (`ST_IPV6_STATUS`
    /// `0xAB`). `None` is the normal case — the tag is absent on the pre-login
    /// ident a `OP_GETSERVERLIST` draws, and on any server that publishes no
    /// IPv6 sources.
    pub ipv6_status: Option<ServerIpv6Status>,
    /// Every other well-formed tag, kept verbatim so a future rmule can type
    /// it without a re-capture (ADR-0018).
    pub extra_tags: Vec<Tag>,
}

impl ServerIdentity {
    /// Project an `OP_SERVERIDENT`-shaped source into a typed `ServerIdentity`.
    ///
    /// Per the welcome-packet notes only `ST_SERVERNAME` (`0x01`) and
    /// `ST_DESCRIPTION` (`0x0B`) are promoted to typed fields. Every other
    /// well-formed tag is preserved in `extra_tags` per ADR-0018.
    #[must_use]
    pub fn from_serverident_source(source: &impl ServerIdentSource) -> Self {
        let mut identity = Self {
            server_hash: Some(source.server_hash()),
            ..Self::default()
        };
        // `0xAF` is the spec's id for the server's own address and `0xAE` is
        // only tolerated where it left a gap, so the reader has to remember
        // *which* id filled the slot: a later `0xAF` must be able to correct an
        // `0xAE`-sourced address regardless of wire order, while a second
        // `0xAF` must not overwrite the first.
        for tag in source.identity_tags() {
            match (tag.name().id(), tag.value()) {
                (Some(SERVER_TAG_NAME), TagValue::String(text)) => {
                    identity.name = Some(text.clone());
                }
                (Some(SERVER_TAG_DESCRIPTION), TagValue::String(text)) => {
                    identity.description = Some(text.clone());
                }
                // `ST_IPV6_STATUS` SHOULD be `TAGTYPE_UINT8`; a receiver must
                // accept any integer width, so all three widths land here.
                (Some(ST_IPV6_STATUS), TagValue::U8(bits)) => {
                    identity.ipv6_status = Some(ServerIpv6Status::from_bits(u32::from(*bits)));
                }
                (Some(ST_IPV6_STATUS), TagValue::U16(bits)) => {
                    identity.ipv6_status = Some(ServerIpv6Status::from_bits(u32::from(*bits)));
                }
                (Some(ST_IPV6_STATUS), TagValue::U32(bits)) => {
                    identity.ipv6_status = Some(ServerIpv6Status::from_bits(*bits));
                }
                (Some(CT_MOD_SVR_IP_V6), TagValue::Hash(_))
                    if !identity.server_ipv6_from_spec_id =>
                {
                    if let Some(address) = read_ipv6_address_tag(tag, CT_MOD_SVR_IP_V6) {
                        identity.server_ipv6 = Some(address);
                        identity.server_ipv6_from_spec_id = true;
                    }
                }
                // The id-tolerant fallback: `0xAE` only fills the slot the
                // spec-correct id left empty, and an address no tag can
                // identify leaves that slot as it found it.
                (Some(CT_MOD_IP_V6), TagValue::Hash(_)) if identity.server_ipv6.is_none() => {
                    identity.server_ipv6 = read_ipv6_address_tag(tag, CT_MOD_IP_V6);
                }
                (Some(CT_MOD_YOUR_IP), TagValue::Hash(_)) if identity.reflected_ipv6.is_none() => {
                    identity.reflected_ipv6 = read_ipv6_address_tag(tag, CT_MOD_YOUR_IP);
                }
                _ => identity.extra_tags.push(tag.clone()),
            }
        }
        identity
    }

    /// Merge `other` into `self`, with `other`'s values winning on every
    /// typed field that's `Some` — except that a tolerated `0xAE` server
    /// address never replaces one the spec's `0xAF` id stated, the same
    /// precedence [`Self::from_serverident_source`] keeps inside one ident. `extra_tags` is unioned with dedup by
    /// `(name, value)` — re-merging the same source twice (or merging a
    /// source whose `extra_tags` already includes a tag we've now typed)
    /// does not double the unknown-tag list.
    #[must_use]
    pub fn merge(mut self, other: Self) -> Self {
        if other.server_hash.is_some() {
            self.server_hash = other.server_hash;
        }
        if other.name.is_some() {
            self.name = other.name;
        }
        if other.description.is_some() {
            self.description = other.description;
        }
        if other.version.is_some() {
            self.version = other.version;
        }
        if other.server_ipv6.is_some()
            && (other.server_ipv6_from_spec_id || !self.server_ipv6_from_spec_id)
        {
            self.server_ipv6 = other.server_ipv6;
            self.server_ipv6_from_spec_id = other.server_ipv6_from_spec_id;
        }
        if other.reflected_ipv6.is_some() {
            self.reflected_ipv6 = other.reflected_ipv6;
        }
        // A fresh ident that carries no verdict says nothing, and must not
        // silently unsuppress an advert the previous one suppressed — the
        // verdict only ends with the session, which is the consumer's clear.
        if other.ipv6_status.is_some() {
            self.ipv6_status = other.ipv6_status;
        }
        for tag in other.extra_tags {
            if !self.extra_tags.iter().any(|t| t == &tag) {
                self.extra_tags.push(tag);
            }
        }
        self
    }
}

/// The load figures a server reports: how many users it holds and how many
/// files they collectively offer.
///
/// Both are the server's own claim, unverifiable from the client side, and are
/// what a client ranks servers by.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ServerStatusReport {
    /// Users currently logged in, as the server reports them.
    pub user_count: u32,
    /// Files those users collectively offer, as the server reports them.
    pub file_count: u32,
}
