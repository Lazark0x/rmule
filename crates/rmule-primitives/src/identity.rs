//! Who a party is on the eD2k network: the server-assigned client id (High or
//! Low), the host-and-port a server is reached at, and the identity a client
//! logs in with. The bare address+port wire values live in `endpoint`.

use std::net::IpAddr;

use crate::{Ed2kText, PrimitiveError, Result, Tag, UserHash};

/// The id a server hands a client at login — the network's verdict on whether
/// that client is directly reachable.
///
/// A High ID *is* the client's IPv4 address as a little-endian `u32`, so a
/// peer can dial it. A Low ID is a small opaque number: the server could not
/// reach the client back, and every connection to it must be brokered.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClientId(u32);

impl ClientId {
    /// The boundary between Low and High IDs (`0x0100_0000`). Below it no
    /// value could be a real routable address, which is exactly why the
    /// protocol reuses the range for unreachable clients.
    pub const LOW_ID_THRESHOLD: u32 = 16_777_216;

    /// Wrap the raw id a server sent.
    #[must_use]
    pub const fn from_u32(value: u32) -> Self {
        Self(value)
    }

    /// The raw id, as it travels on the wire.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Whether this client is unreachable from outside — every peer contact
    /// has to be brokered by a server or a buddy.
    #[must_use]
    pub const fn is_low_id(self) -> bool {
        self.0 < Self::LOW_ID_THRESHOLD
    }

    /// Whether this client is directly dialable, its id being its own address.
    #[must_use]
    pub const fn is_high_id(self) -> bool {
        !self.is_low_id()
    }
}

impl ClientId {
    /// The **Placeholder Low ID** an IPv6-only source takes in a 32-bit id
    /// field (ADR-0087).
    ///
    /// Such a source has no ed2k wire form at all, and the field cannot be
    /// left out: an ExtSX record's header is fixed. Writing `0` would be read
    /// as a Low ID with no server behind it, sending the reader down a
    /// callback nobody can broker; writing a truncation of the IPv6 would be a
    /// routable address belonging to someone else. So the field takes a value
    /// in the Low-ID range that is *no* address, and the source's real
    /// endpoint rides the record's `CT_MOD_IP_V6` tag.
    ///
    /// A foreign implementation picks its own placeholder from the same range.
    /// Reading one as an ordinary Low ID costs nothing: the ADR-0061 route
    /// tree dials such a peer over IPv6 at rung 0 either way, and the callback
    /// fallback it would otherwise reach is simply never taken.
    pub const IPV6_ONLY_PLACEHOLDER: Self = Self(1);
}

/// Where a server is reached: a host *as configured* plus a port.
///
/// The host stays a string rather than an address because a server list
/// legitimately carries names, and resolution belongs to whoever dials — not
/// to a value type. Names are lower-cased on the way in so the same server
/// written two ways compares equal; IP literals are kept verbatim. Ordered
/// by host text, then port — a total order for tables to tie-break on.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct ServerEndpoint {
    host: String,
    port: u16,
}

impl ServerEndpoint {
    /// Build an endpoint from a host and port.
    ///
    /// # Errors
    /// [`PrimitiveError::InvalidServerEndpoint`] if the port is zero or the
    /// host is empty or whitespace-padded.
    pub fn new(host: impl Into<String>, port: u16) -> Result<Self> {
        if port == 0 {
            return Err(PrimitiveError::InvalidServerEndpoint {
                reason: "endpoint port must be non-zero",
            });
        }
        let host = canonical_host(&host.into())?;
        Ok(Self { host, port })
    }

    /// Parse a `host:port` (or `[ipv6]:port`) string. Uses
    /// `SocketAddr::from_str` first so bracketed IPv6 literals split
    /// correctly, then falls back to splitting on the last `:` for
    /// hostname-style inputs. Rejects empty host and zero port.
    pub fn parse_host_port(input: &str) -> Result<Self> {
        use std::net::SocketAddr;
        use std::str::FromStr;
        if let Ok(sa) = SocketAddr::from_str(input) {
            return Self::new(sa.ip().to_string(), sa.port());
        }
        let (host, port) = input
            .rsplit_once(':')
            .ok_or(PrimitiveError::InvalidServerEndpoint {
                reason: "endpoint missing ':port'",
            })?;
        if host.is_empty() {
            return Err(PrimitiveError::InvalidServerEndpoint {
                reason: "endpoint has empty host",
            });
        }
        let port: u16 = port
            .parse()
            .map_err(|_| PrimitiveError::InvalidServerEndpoint {
                reason: "endpoint port is not a valid u16",
            })?;
        Self::new(host, port)
    }

    /// The canonical host text — lower-cased for names, verbatim for IP
    /// literals.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The TCP port, always non-zero.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }
}

/// Application-layer description of who rmule is on the eD2k network.
///
/// Fields are private so the construction discipline matches every other
/// validated primitive in this crate. `new` takes the four required
/// inputs; opaque capability tags go in via [`Self::with_extra_tags`].
/// Collision filtering with known login-tag IDs happens at use-site
/// (`rmule_ed2k::LoginRequest::from_identity`) — primitives doesn't
/// know which numeric IDs the eD2k service treats as canonical.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClientIdentity {
    user_hash: UserHash,
    nickname: Ed2kText,
    tcp_port: u16,
    protocol_version: u32,
    extra_tags: Vec<Tag>,
}

impl ClientIdentity {
    /// The four facts a login must carry. Capability tags are attached
    /// separately through [`Self::with_extra_tags`].
    #[must_use]
    pub fn new(
        user_hash: UserHash,
        nickname: Ed2kText,
        tcp_port: u16,
        protocol_version: u32,
    ) -> Self {
        Self {
            user_hash,
            nickname,
            tcp_port,
            protocol_version,
            extra_tags: Vec::new(),
        }
    }

    /// Attach opaque forward-compatibility tags for capability bits not
    /// yet typed. Capability tags themselves (`CT_SERVER_FLAGS`,
    /// `CT_EMULE_VERSION`) are registry-derived (ADR-0047), never carried
    /// here; the eD2k service filters extras against its canonical login
    /// IDs at encode time, so a collider cannot reach the wire.
    #[must_use]
    pub fn with_extra_tags(mut self, extra_tags: Vec<Tag>) -> Self {
        self.extra_tags = extra_tags;
        self
    }

    /// The persistent identity peers credit and ban on — stable across
    /// sessions, unlike the client id.
    #[must_use]
    pub fn user_hash(&self) -> UserHash {
        self.user_hash
    }

    /// The display name announced to servers and peers.
    #[must_use]
    pub fn nickname(&self) -> &Ed2kText {
        &self.nickname
    }

    /// The port this client listens on for peer connections — what a server
    /// dials back to decide High or Low ID.
    #[must_use]
    pub fn tcp_port(&self) -> u16 {
        self.tcp_port
    }

    /// The eD2k protocol version advertised at login.
    #[must_use]
    pub fn protocol_version(&self) -> u32 {
        self.protocol_version
    }

    /// The opaque forward-compatibility tags, in the order they will be sent.
    #[must_use]
    pub fn extra_tags(&self) -> &[Tag] {
        &self.extra_tags
    }
}

fn canonical_host(host: &str) -> Result<String> {
    if host.is_empty() || host.trim() != host {
        return Err(PrimitiveError::InvalidServerEndpoint {
            reason: "invalid server host",
        });
    }
    if host.parse::<IpAddr>().is_ok() {
        Ok(host.to_owned())
    } else {
        Ok(host.to_ascii_lowercase())
    }
}
