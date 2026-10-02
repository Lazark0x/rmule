//! **Client Software**: which program a peer runs and at what version, read
//! off its hello — aMule's `CUpDownClient::ReGetClientSoft`
//! (`BaseClient.cpp:1771`) and eMule's `InitClientSoftwareVersion`
//! (`BaseClient.cpp:1583` @emule-qt `73fff714`).
//!
//! Only facts the peer supplied are kept: a family, version numbers as
//! numbers, and the mod string as the peer wrote it. Nothing here is a label —
//! a front end renders one. A compatible-client code no table names stays a
//! raw code, never a guessed name.
//!
//! A connection's [`SoftwareEvidence`] gathers what both references read: the
//! hello, the word MLDonkey and old eDonkey Hybrid append to it, and the legacy
//! `OP_EMULEINFO` (`0xC5 0x01`) whose "mule version" byte is the only version a
//! pre-0.42 mule sends (docs/protocol/parity/peer-tcp.md, *Hello read surface*).

mod compatible;

use std::cmp::Ordering;

use rmule_primitives::{Ed2kText, Tag, UserHash};

use crate::emule_info::LegacyMuleInfo;
use crate::hello::{HelloTrailer, PeerHelloBody, hello_int, hello_text};
use crate::hello_tag::{CT_EMULE_VERSION, CT_MOD_VERSION, CT_NAME, CT_VERSION};
use compatible::CompatibleClient;

/// A client family, in the order of the compatible-client codes aMule
/// numbers them by (`ClientSoftware.h:29`) — the rank a sort uses. Families
/// named only by a heuristic take aMule's codes past the table; a code no
/// table names ranks after all of them, by its value; no identification at all
/// ranks last.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ClientFamily {
    /// eMule, or a mod of it — compatible code `0`.
    Emule,
    /// cDonkey — code `1`.
    Cdonkey,
    /// xMule / lMule — code `2`, or an eMule hello whose mod or nickname
    /// names xMule (aMule's fake-eMule rule, `BaseClient.cpp:1794`).
    Xmule,
    /// aMule — code `3`.
    Amule,
    /// Shareaza — codes `4`, `0x28` and `0x44`.
    Shareaza,
    /// eMule Plus — code `5`.
    EmulePlus,
    /// HydraNode — code `6`.
    HydraNode,
    /// MLDonkey from its compatible code — `0x0A` or `0x98`.
    MlDonkey,
    /// lphant — code `0x14`.
    Lphant,
    /// eDonkey Hybrid, known by the `pr` tag it sends instead of
    /// `CT_EMULE_VERSION`.
    EdonkeyHybrid,
    /// eDonkey: no mule tag and no user-hash mark.
    Edonkey,
    /// An MLDonkey whose user hash carries `M`…`L` and whose hello names no
    /// compatible code.
    MlDonkeyOld,
    /// An early eMule, by its user-hash mark (`[5] = 13`, `[14] = 110`).
    EmuleOld,
    /// rmule: an aMule-coded mule hello whose `CT_MOD_VERSION` is rmule's
    /// (ADR-0047). A claim like every other hello field —
    /// rmule grants nothing on it.
    Rmule,
    /// A compatible-client code no table names, as the peer sent it.
    Compatible(u8),
    /// The hello named no user: both references stop there.
    Unknown,
}

/// Three version numbers, compared as numbers. Each family writes them in its
/// own notation; that is a front end's to render.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ClientVersion {
    /// Major.
    pub major: u32,
    /// Minor.
    pub minor: u32,
    /// Update — the letter in eMule's `v0.70b`.
    pub update: u32,
}

impl ClientVersion {
    const fn new(major: u32, minor: u32, update: u32) -> Self {
        Self {
            major,
            minor,
            update,
        }
    }
}

/// The mod a peer named in `CT_MOD_VERSION`: its text, or the number a few
/// clients send in its place.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ClientMod {
    /// The mod's name, the peer's bytes unchanged.
    Named(Ed2kText),
    /// A numeric mod id.
    Numbered(u32),
}

impl ClientMod {
    fn sort_key(&self) -> (u32, &[u8]) {
        match self {
            Self::Numbered(id) => (*id, &[]),
            Self::Named(text) => (u32::MAX, text.as_bytes()),
        }
    }
}

/// Which client a peer runs, as its hello tells it. Ordered by family rank,
/// then version, then mod — never by a rendered label.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ClientSoftware {
    family: ClientFamily,
    version: Option<ClientVersion>,
    client_mod: Option<ClientMod>,
}

impl Ord for ClientSoftware {
    fn cmp(&self, other: &Self) -> Ordering {
        self.family
            .cmp(&other.family)
            .then_with(|| self.version.cmp(&other.version))
            .then_with(|| {
                let mine = self.client_mod.as_ref().map(ClientMod::sort_key);
                mine.cmp(&other.client_mod.as_ref().map(ClientMod::sort_key))
            })
    }
}

impl PartialOrd for ClientSoftware {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl ClientSoftware {
    /// The family.
    #[must_use]
    pub const fn family(&self) -> ClientFamily {
        self.family
    }

    /// The version, or `None` when the hello carried none this family reads.
    #[must_use]
    pub const fn version(&self) -> Option<ClientVersion> {
        self.version
    }

    /// The mod the peer named, when it named one.
    #[must_use]
    pub const fn client_mod(&self) -> Option<&ClientMod> {
        self.client_mod.as_ref()
    }

    /// Identify the client behind a hello alone — no trailer, no
    /// `OP_EMULEINFO`. A session folds those in through [`SoftwareEvidence`].
    #[must_use]
    pub fn from_hello_body(body: &PeerHelloBody) -> Self {
        let mut evidence = SoftwareEvidence::default();
        evidence.hello(body, HelloTrailer::Absent);
        evidence.software()
    }

    const fn bare(family: ClientFamily, version: Option<ClientVersion>) -> Self {
        Self {
            family,
            version,
            client_mod: None,
        }
    }
}

/// What a peer has told one connection about its software: its hello, the
/// word after it, and any legacy `OP_EMULEINFO` block — in arrival order,
/// each overwriting what it names, as both references keep them in fields of
/// one client (aMule `ProcessHelloTypePacket` / `ProcessMuleInfoPacket`,
/// eMule the same names). An `OP_HELLO` starts a fresh one (their
/// `ClearHelloProperties`); an `OP_HELLOANSWER` folds into what an
/// `OP_EMULEINFO` sent before it already said.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SoftwareEvidence {
    named: bool,
    nickname: Vec<u8>,
    protocol_version: Option<u32>,
    hybrid: bool,
    mldonkey: bool,
    mark: HashMark,
    /// A `CT_EMULE_VERSION` tag or a legacy `OP_EMULEINFO` arrived: a mule
    /// (eMule's `m_bEmuleProtocol`).
    emule_protocol: bool,
    /// Both references' `m_byEmuleVersion`: `0` none, `0x99` "read the
    /// `CT_EMULE_VERSION` word", else the legacy byte.
    mule_version: u8,
    emule_word: u32,
    compatible: CompatibleClient,
    client_mod: Option<ClientMod>,
}

/// The mule-version value both references store for "the version is in the
/// `CT_EMULE_VERSION` word".
const MULE_VERSION_FROM_WORD: u8 = 0x99;

impl SoftwareEvidence {
    /// Fold in a hello and what followed its connected server.
    pub fn hello(&mut self, body: &PeerHelloBody, trailer: HelloTrailer) {
        let nickname = hello_text(&body.tags, CT_NAME);
        self.named = nickname.is_some_and(|text| !text.as_bytes().is_empty());
        self.nickname = nickname.map_or_else(Vec::new, |text| text.as_bytes().to_vec());
        self.protocol_version = hello_int(&body.tags, CT_VERSION);
        // eDonkey Hybrid 1.3 dropped the trailing word and sends a text tag
        // named `pr…` instead (eMule `BaseClient.cpp:545`).
        let pr_tag = body.tags.iter().any(|tag| {
            tag.name()
                .text_value()
                .is_some_and(|text| text.starts_with("pr"))
        });
        self.hybrid = pr_tag || matches!(trailer, HelloTrailer::Hybrid(_));
        self.mldonkey = trailer == HelloTrailer::MlDonkey;
        self.mark = HashMark::of(body.user_hash);
        if let Some(word) = hello_int(&body.tags, CT_EMULE_VERSION) {
            self.emule_protocol = true;
            self.compatible = CompatibleClient::of((word >> 24) as u8);
            self.emule_word = word;
            self.mule_version = MULE_VERSION_FROM_WORD;
        }
        if let Some(client_mod) = read_mod(&body.tags) {
            self.client_mod = Some(client_mod);
        }
    }

    /// Whether the peer speaks the eMule extended protocol: aMule's
    /// `ExtProtocolAvailable()` (`m_bEmuleProtocol`), set by a mule hello or a
    /// legacy block and cleared by a block under an unknown protocol byte.
    /// aMule asks sources and sends the queue rank only on it
    /// (`DownloadClient.cpp:191`, `UploadClient.cpp:724`).
    #[must_use]
    pub const fn ext_protocol(&self) -> bool {
        self.emule_protocol
    }

    /// Whether the hello folded last came from behind eMule's hash mark
    /// without being a mule hello — a pre-0.42 mule, which learns what we
    /// support only from an `OP_EMULEINFO`.
    #[must_use]
    pub fn wants_emule_info(&self) -> bool {
        self.mark == HashMark::Emule && !self.emule_protocol
    }

    /// Fold in a legacy `OP_EMULEINFO` / `OP_EMULEINFOANSWER` block.
    pub fn emule_info(&mut self, info: &LegacyMuleInfo) {
        self.emule_protocol = true;
        self.mule_version = info.mule_version();
        self.compatible = CompatibleClient::of(info.compatible_client());
        if let Some(client_mod) = info.client_mod() {
            self.client_mod = Some(client_mod.clone());
        }
    }

    /// Fold in an `OP_EMULEINFO` / `OP_EMULEINFOANSWER` under a protocol byte
    /// that is neither legacy nor OS info: its version is recorded, the
    /// compatible client and the mule flag are cleared, and nothing else is
    /// touched (stock aMule 2.3.3 `BaseClient.cpp:884-895`).
    pub fn unknown_emule_info(&mut self, mule_version: u8) {
        self.emule_protocol = false;
        self.mule_version = mule_version;
        self.compatible = CompatibleClient::Emule;
    }

    /// The Client Software this evidence names.
    ///
    /// A mule — `CT_EMULE_VERSION` seen, a legacy `OP_EMULEINFO` read, or a
    /// user hash with eMule's mark — is named by its compatible-client code, as
    /// eMule decides (`m_bEmuleProtocol || iHashType == SO_EMULE`); aMule tests
    /// the hash mark alone. Every other hello falls to the heuristics both
    /// references share, in their order.
    #[must_use]
    pub fn software(&self) -> ClientSoftware {
        if !self.named {
            return ClientSoftware::bare(ClientFamily::Unknown, None);
        }
        if self.emule_protocol || self.mark == HashMark::Emule {
            return self.mule();
        }
        let legacy = self.protocol_version;
        if self.hybrid {
            return ClientSoftware::bare(ClientFamily::EdonkeyHybrid, legacy.map(hybrid_version));
        }
        let family = if self.mldonkey || self.mark == HashMark::MlDonkey {
            ClientFamily::MlDonkeyOld
        } else if self.mark == HashMark::EmuleOld {
            ClientFamily::EmuleOld
        } else {
            ClientFamily::Edonkey
        };
        ClientSoftware::bare(family, legacy.map(minor_only))
    }

    /// The mule branch: the compatible code names the family; a code no table
    /// names — `0` included, as eMule reads it (`BaseClient.cpp:1615-1627`) —
    /// falls to the trailer before it is eMule or an unnamed code.
    fn mule(&self) -> ClientSoftware {
        let mut family = match self.compatible {
            CompatibleClient::Cdonkey => ClientFamily::Cdonkey,
            CompatibleClient::Xmule => ClientFamily::Xmule,
            CompatibleClient::Amule => ClientFamily::Amule,
            CompatibleClient::Shareaza => ClientFamily::Shareaza,
            CompatibleClient::EmulePlus => ClientFamily::EmulePlus,
            CompatibleClient::HydraNode => ClientFamily::HydraNode,
            CompatibleClient::MlDonkey => ClientFamily::MlDonkey,
            CompatibleClient::Lphant => ClientFamily::Lphant,
            _ if self.mldonkey => ClientFamily::MlDonkey,
            _ if self.hybrid => ClientFamily::EdonkeyHybrid,
            CompatibleClient::Emule => ClientFamily::Emule,
            CompatibleClient::Unnamed(code) => ClientFamily::Compatible(code),
        };
        if family == ClientFamily::Emule && self.names_xmule() {
            family = ClientFamily::Xmule;
        }
        let mut software = ClientSoftware {
            family,
            version: self.mule_version(),
            client_mod: self.client_mod.clone(),
        };
        if family == ClientFamily::Amule
            && let Some(ClientMod::Named(text)) = &self.client_mod
            && let Some(version) = rmule_mod_version(text.as_bytes())
        {
            software = ClientSoftware::bare(ClientFamily::Rmule, version);
        }
        software
    }

    /// The version both references show a mule: the word's 24 low bits
    /// (`8 compat | 7 major | 7 minor | 3 update | 7 build`,
    /// `BaseClient.cpp:626`; the build is read by neither), or a legacy
    /// byte's `0.<(v >> 4) * 10 + (v & 15)>` (eMule `:1636-1639`).
    fn mule_version(&self) -> Option<ClientVersion> {
        match self.mule_version {
            0 => None,
            MULE_VERSION_FROM_WORD => {
                let word = self.emule_word;
                Some(ClientVersion::new(
                    (word >> 17) & 0x7F,
                    (word >> 10) & 0x7F,
                    (word >> 7) & 0x07,
                ))
            }
            legacy => Some(minor_only(
                u32::from(legacy >> 4) * 10 + u32::from(legacy & 0x0F),
            )),
        }
    }

    fn names_xmule(&self) -> bool {
        let in_mod = matches!(&self.client_mod, Some(ClientMod::Named(text))
            if contains(&text.as_bytes().to_ascii_lowercase(), b"xmule"));
        in_mod || contains(&self.nickname, b"xmule.")
    }
}

/// The `CT_MOD_VERSION` text rmule's own hello carries: this prefix and its
/// version (ADR-0047).
const RMULE_MOD_PREFIX: &str = "rmule ";

/// The `CT_MOD_VERSION` text rmule's own hello carries.
pub(crate) const RMULE_MOD_VERSION: &str = concat!("rmule ", env!("CARGO_PKG_VERSION"));

/// `Some(version)` when `text` is rmule's mod text — the version is `None`
/// when what follows the prefix is not `major.minor.update`.
fn rmule_mod_version(text: &[u8]) -> Option<Option<ClientVersion>> {
    let rest = std::str::from_utf8(text.strip_prefix(RMULE_MOD_PREFIX.as_bytes())?).ok()?;
    let mut parts = rest.split('.').map(|part| part.parse::<u32>().ok());
    Some(
        match (
            parts.next().flatten(),
            parts.next().flatten(),
            parts.next().flatten(),
            parts.next(),
        ) {
            (Some(major), Some(minor), Some(update), None) => {
                Some(ClientVersion::new(major, minor, update))
            }
            _ => None,
        },
    )
}

fn read_mod(tags: &[Tag]) -> Option<ClientMod> {
    hello_text(tags, CT_MOD_VERSION)
        .map(|text| ClientMod::Named(text.clone()))
        .or_else(|| hello_int(tags, CT_MOD_VERSION).map(ClientMod::Numbered))
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

/// The marks eMule's user-hash generator writes into bytes 5 and 14 (both
/// references' `GetHashType`, aMule `BaseClient.cpp:1740`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum HashMark {
    EmuleOld,
    Emule,
    MlDonkey,
    #[default]
    None,
}

impl HashMark {
    fn of(hash: UserHash) -> Self {
        let bytes = hash.as_bytes();
        match (bytes[5], bytes[14]) {
            (13, 110) => Self::EmuleOld,
            (14, 111) => Self::Emule,
            (b'M', b'L') => Self::MlDonkey,
            _ => Self::None,
        }
    }
}

/// `CT_VERSION` read as eMule reads a pre-mule client's: `0.<version>`.
/// aMule multiplies an eDonkey's by ten and prints `v<x/100000>.<x/1000 % 100>`,
/// which reads the protocol version `60` as `v0.0`.
const fn minor_only(version: u32) -> ClientVersion {
    ClientVersion::new(0, version, 0)
}

/// eDonkey Hybrid's decimal `CT_VERSION` (eMule `BaseClient.cpp:1672`, the
/// superset of aMule's `:1893`: eMule adds the 1.0.x and 1.1–1.3 bands).
fn hybrid_version(v: u32) -> ClientVersion {
    if v > 100_000 {
        let whole = v / 100_000;
        ClientVersion::new(whole - 1, (v - whole * 100_000) / 100, v % 100)
    } else if (10_100..=10_309).contains(&v) {
        let whole = v / 10_000;
        ClientVersion::new(whole, (v - whole * 10_000) / 100, v % 10)
    } else if v > 10_000 {
        let whole = v / 10_000;
        ClientVersion::new(whole - 1, (v - whole * 10_000) / 10, v % 10)
    } else if (1_000..1_020).contains(&v) {
        let whole = v / 1_000;
        ClientVersion::new(whole, (v - whole * 1_000) / 10, v % 10)
    } else if v > 1_000 {
        let whole = v / 1_000;
        ClientVersion::new(whole - 1, v - whole * 1_000, 0)
    } else if v > 100 {
        let tens = v / 10;
        ClientVersion::new(0, tens, v - tens * 10)
    } else {
        ClientVersion::new(0, v, 0)
    }
}
