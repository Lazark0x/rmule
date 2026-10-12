//! The eD2k hash family and the part geometry it is derived from: the 16-byte
//! file, part, user and server hashes, the AICH root, the fixed part size every
//! file is chunked by, and the summary that folds a whole file's bytes into a
//! file hash plus its part hash set.

use data_encoding::{BASE32_NOPAD, HEXUPPER};
use ed2k::digest::Digest;

use crate::{PrimitiveError, Result};

/// The fixed part size every eD2k file is chunked by: 9,728,000 bytes
/// (9500 KiB). Not a tunable — the whole network's part indices, part hashes
/// and request ranges are expressed in multiples of it.
pub const ED2K_PART_SIZE: u64 = 9_728_000;
const ED2K_PART_SIZE_USIZE: usize = ED2K_PART_SIZE as usize;

/// The largest file eD2k addresses: 2^38 bytes, 256 GiB. aMule defines it
/// as `MAX_FILE_SIZE` (`src/include/protocol/ed2k/Constants.h:80`) and
/// refuses a link (`src/ED2KLink.cpp:179`) or a search row
/// (`src/SearchList.cpp:561-569`) naming a larger file; so does rmule, where
/// each is decoded.
pub const MAX_ED2K_FILE_SIZE: u64 = 0x40_0000_0000;

/// Number of ED2K parts that cover `file_size` bytes — `ceil(file_size / ED2K_PART_SIZE)`.
///
/// Saturates at `u32::MAX` for `file_size` values beyond what the eD2k wire
/// can address, so callers always get a valid `u32` part index ceiling.
#[must_use]
pub const fn part_count(file_size: u64) -> u32 {
    let parts = file_size.saturating_add(ED2K_PART_SIZE - 1) / ED2K_PART_SIZE;
    if parts > u32::MAX as u64 {
        u32::MAX
    } else {
        parts as u32
    }
}

/// The part count an `OP_FILESTATUS` states for a `file_size`-byte file:
/// `file_size / ED2K_PART_SIZE + 1`, and `0` for an empty file (aMule
/// `m_iED2KPartCount`, stock 2.3.3 `KnownFile.cpp:422`). An exact multiple of
/// the part size counts one phantom part past its last real one, so this is
/// one more than [`part_count`] there and equal to it everywhere else. aMule
/// refuses a status of any other non-zero count (`DownloadClient.cpp:417-425`)
/// and its uploader drops one (`UploadClient.cpp` `ProcessExtendedInfo`).
///
/// Saturates at `u32::MAX` like [`part_count`].
#[must_use]
pub const fn ed2k_status_part_count(file_size: u64) -> u32 {
    if file_size == 0 {
        return 0;
    }
    let parts = file_size / ED2K_PART_SIZE + 1;
    if parts > u32::MAX as u64 {
        u32::MAX
    } else {
        parts as u32
    }
}

/// The self-inverse per-32-bit-word byte swap between a 128-bit eD2k hash's
/// raw bytes and the order a Kad payload carries it in.
///
/// Every 128-bit field in a Kad payload is written by aMule's
/// `CFileDataIO::WriteUInt128` (`src/SafeFile.cpp:285-291`), which emits a
/// `CUInt128` as **four little-endian 32-bit chunks**; a hash enters that type
/// through `CUInt128(const uint8_t*)` → `SetValueBE`, which loads it
/// big-endian. The two together reverse each four-byte word and nothing else,
/// which is why reading the field back is the same transform.
///
/// It lives here because it is the one place two namespaces meet — a Kad
/// payload's 128-bit field and an eD2k hash — and both the Kad codecs and the
/// peer-TCP relay codecs have to cross it.
#[must_use]
pub const fn kad_wire_id(bytes: [u8; 16]) -> [u8; 16] {
    let [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p] = bytes;
    [d, c, b, a, h, g, f, e, l, k, j, i, p, o, n, m]
}

macro_rules! fixed_hash {
    ($name:ident, $len:expr, $kind:literal, $encoding:ident, $formatting:ident) => {
        #[doc = concat!("The eD2k ", $kind, " hash: ", stringify!($len), " opaque bytes.")]
        ///
        /// A value identity, never interpreted as a number. `Ord` is plain
        /// byte order so ordered containers (the TUI's `BTreeMap`
        /// projections) have a stable key.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        #[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
        pub struct $name([u8; $len]);

        impl $name {
            /// The hash's width in bytes, fixed by the protocol.
            pub const BYTE_LEN: usize = $len;

            /// Wrap bytes that are already this hash. Nothing to validate —
            /// every byte pattern of this width is a legal hash.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            /// The hash's bytes, in wire order.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }

            /// Parse the hex text form, case-insensitively.
            ///
            /// # Errors
            /// [`PrimitiveError::InvalidHashEncoding`] if the text is not
            /// hex, [`PrimitiveError::InvalidHashLength`] if it decodes to a
            /// different width.
            pub fn $encoding(input: &str) -> Result<Self> {
                decode_fixed_hex(input, $kind).map(Self)
            }

            /// The uppercase-hex text form — what an `ed2k://` link and every
            /// human-facing surface print.
            #[must_use]
            pub fn $formatting(self) -> String {
                HEXUPPER.encode(&self.0)
            }
        }
    };
}

fixed_hash!(FileHash, 16, "file", from_hex, to_hex_upper);
fixed_hash!(PartHash, 16, "part", from_hex, to_hex_upper);
fixed_hash!(UserHash, 16, "user", from_hex, to_hex_upper);
fixed_hash!(ServerHash, 16, "server", from_hex, to_hex_upper);

/// Declarative codec for an empty-payload packet — a unit struct whose wire
/// form is opcode-only (no body). Generates the `struct`, a `decode_packet`,
/// and an empty-body `encode_packet`, so the empty-payload packets across
/// `rmule-ed2k` and `rmule-peer` stop hand-rolling the identical shape. The
/// error *type* is a macro parameter, so this crate never names a concrete
/// protocol error enum. Three decode contracts match how each packet is
/// decoded:
///
/// * **self-validating** (`Name, Err, opcode, "OP_LABEL"`) — the decoder is
///   handed a raw [`Packet`](crate::Packet) and checks the protocol byte (must
///   be eDonkey), the opcode, and that the payload is empty, mapping each
///   failure onto `Err::InvalidPayload { opcode, reason }`. The error strings
///   are byte-identical to the hand-rolled originals.
/// * **self-validating, body-tolerant** — as above with a trailing
///   `, tolerate_body`, which drops the empty-payload check for a packet whose
///   body is documented as ignorable (`OP_CALLBACK_FAIL`'s "null notverified").
/// * **dispatch-validated** (`Name, Err, protocol: <p>, opcode: <o>`) — the
///   protocol/opcode were already matched by a packet dispatcher, so the
///   decoder only rejects a non-empty payload, via
///   `Err::WrongPayloadLen { expected: 0, actual }`.
#[macro_export]
macro_rules! empty_body_codec {
    // Dispatch-validated: opcode/protocol already matched upstream; the decoder
    // only rejects a non-empty body. (`protocol:`/`opcode:` disambiguate this
    // arm from the self-validating forms below.)
    (
        $(#[$meta:meta])*
        $name:ident, $err:ident, protocol: $protocol:expr, opcode: $opcode:expr $(,)?
    ) => {
        $(#[$meta])*
        pub struct $name;

        impl $name {
            /// Decode the packet, whose protocol and opcode a dispatcher has
            /// already matched.
            ///
            /// # Errors
            /// `WrongPayloadLen` if the body is not empty.
            pub fn decode_packet(packet: &$crate::Packet) -> ::core::result::Result<Self, $err> {
                let actual = packet.payload().len();
                if actual != 0 {
                    return ::core::result::Result::Err($err::WrongPayloadLen { expected: 0, actual });
                }
                ::core::result::Result::Ok(Self)
            }

            /// The packet form: this opcode with an empty body.
            #[must_use]
            pub fn encode_packet(&self) -> $crate::Packet {
                $crate::Packet::new($protocol, $opcode, ::std::vec::Vec::new())
            }
        }
    };
    // Self-validating, body-tolerant: checks protocol + opcode only.
    (
        $(#[$meta:meta])*
        $name:ident, $err:ident, $opcode:expr, $label:literal, tolerate_body $(,)?
    ) => {
        $(#[$meta])*
        pub struct $name;

        impl $name {
            /// Decode the packet, checking it is this protocol and opcode.
            ///
            /// # Errors
            /// `InvalidPayload` if the protocol byte, the opcode, or (where
            /// this codec checks it) the empty body does not match.
            pub fn decode_packet(packet: &$crate::Packet) -> ::core::result::Result<Self, $err> {
                let opcode = $opcode;
                if packet.protocol() != $crate::PacketProtocol::Edonkey {
                    return ::core::result::Result::Err($err::InvalidPayload {
                        opcode,
                        reason: "unsupported packet protocol",
                    });
                }
                if packet.opcode() != opcode {
                    return ::core::result::Result::Err($err::InvalidPayload {
                        opcode,
                        reason: ::core::concat!("wrong opcode for ", $label),
                    });
                }
                ::core::result::Result::Ok(Self)
            }

            /// The packet form: this opcode with an empty body.
            #[must_use]
            pub fn encode_packet(&self) -> $crate::Packet {
                $crate::Packet::new(
                    $crate::PacketProtocol::Edonkey,
                    $opcode,
                    ::std::vec::Vec::new(),
                )
            }
        }
    };
    // Self-validating: checks protocol + opcode + empty payload.
    (
        $(#[$meta:meta])*
        $name:ident, $err:ident, $opcode:expr, $label:literal $(,)?
    ) => {
        $(#[$meta])*
        pub struct $name;

        impl $name {
            /// Decode the packet, checking it is this protocol and opcode.
            ///
            /// # Errors
            /// `InvalidPayload` if the protocol byte, the opcode, or (where
            /// this codec checks it) the empty body does not match.
            pub fn decode_packet(packet: &$crate::Packet) -> ::core::result::Result<Self, $err> {
                let opcode = $opcode;
                if packet.protocol() != $crate::PacketProtocol::Edonkey {
                    return ::core::result::Result::Err($err::InvalidPayload {
                        opcode,
                        reason: "unsupported packet protocol",
                    });
                }
                if packet.opcode() != opcode {
                    return ::core::result::Result::Err($err::InvalidPayload {
                        opcode,
                        reason: ::core::concat!("wrong opcode for ", $label),
                    });
                }
                if !packet.payload().is_empty() {
                    return ::core::result::Result::Err($err::InvalidPayload {
                        opcode,
                        reason: ::core::concat!($label, " must have empty payload"),
                    });
                }
                ::core::result::Result::Ok(Self)
            }

            /// The packet form: this opcode with an empty body.
            #[must_use]
            pub fn encode_packet(&self) -> $crate::Packet {
                $crate::Packet::new(
                    $crate::PacketProtocol::Edonkey,
                    $opcode,
                    ::std::vec::Vec::new(),
                )
            }
        }
    };
}

/// The root of a file's AICH hash tree: 20 bytes of SHA-1, the identity a
/// peer's part-recovery data is checked against.
///
/// Wider than the eD2k hashes and written in base32 rather than hex, because
/// that is the form eMule's `ed2k://` link carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AichRootHash([u8; 20]);

impl AichRootHash {
    /// The root hash's width in bytes — SHA-1, so 20, not the eD2k 16.
    pub const BYTE_LEN: usize = 20;

    /// Wrap bytes that are already a root hash.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    /// The root hash's bytes, in wire order.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    /// Parse the unpadded base32 text form, case-insensitively — the form an
    /// `ed2k://` link's `h=` field carries.
    ///
    /// # Errors
    /// [`PrimitiveError::InvalidHashEncoding`] if the text is not base32,
    /// [`PrimitiveError::InvalidHashLength`] if it decodes to other than 20
    /// bytes.
    pub fn from_base32(input: &str) -> Result<Self> {
        let normalized = input.to_ascii_uppercase();
        let bytes = BASE32_NOPAD
            .decode(normalized.as_bytes())
            .map_err(|_| PrimitiveError::InvalidHashEncoding { kind: "AICH root" })?;
        let bytes: [u8; 20] =
            bytes
                .try_into()
                .map_err(|bytes: Vec<u8>| PrimitiveError::InvalidHashLength {
                    expected: Self::BYTE_LEN,
                    actual: bytes.len(),
                })?;
        Ok(Self(bytes))
    }

    /// The uppercase, unpadded base32 text form.
    #[must_use]
    pub fn to_base32_upper(self) -> String {
        BASE32_NOPAD.encode(&self.0)
    }
}

/// A file's complete part hash set, with the size it was derived from.
///
/// The pair is kept together because neither half is checkable alone: the
/// count of hashes a file must have follows from its size, so a set that
/// travelled without its size could be silently mismatched against a
/// different file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartHashSet {
    file_size: u64,
    hashes: Vec<PartHash>,
}

impl PartHashSet {
    /// Build a set, checking the hash count against what `file_size` implies.
    ///
    /// # Errors
    /// [`PrimitiveError::InvalidPartHashSetCount`] if the count disagrees —
    /// the set belongs to some other file.
    pub fn from_hashes(file_size: u64, hashes: Vec<PartHash>) -> Result<Self> {
        let expected = Self::expected_hash_count(file_size)?;
        let actual = hashes.len();
        if actual != expected {
            return Err(PrimitiveError::InvalidPartHashSetCount {
                file_size,
                expected,
                actual,
            });
        }
        Ok(Self { file_size, hashes })
    }

    /// How many part hashes a file of `file_size` bytes must carry.
    ///
    /// Zero below one part size — a single-part file's file hash *is* its part
    /// hash, so the wire carries no set at all. At or above it, one hash per
    /// part plus the trailing hash of the final (possibly empty) remainder.
    ///
    /// # Errors
    /// [`PrimitiveError::FileTooLarge`] if the count overflows.
    pub fn expected_hash_count(file_size: u64) -> Result<usize> {
        if file_size < ED2K_PART_SIZE {
            return Ok(0);
        }

        let count = (file_size / ED2K_PART_SIZE)
            .checked_add(1)
            .ok_or(PrimitiveError::FileTooLarge { file_size })?;
        usize::try_from(count).map_err(|_| PrimitiveError::FileTooLarge { file_size })
    }

    /// The file size this set was built against.
    #[must_use]
    pub const fn file_size(&self) -> u64 {
        self.file_size
    }

    /// The part hashes, in part order.
    #[must_use]
    pub fn hashes(&self) -> &[PartHash] {
        &self.hashes
    }

    /// Whether this is `file_hash`'s own set: the MD4 of its part hashes laid
    /// end to end is the file hash (aMule `CKnownFile::CreateHashFromHashlist`,
    /// `src/KnownFile.cpp:787-799` at `4e8f2b3c`). A single-part file's set is
    /// empty and has nothing to contradict.
    #[must_use]
    pub fn belongs_to(&self, file_hash: FileHash) -> bool {
        if self.hashes.is_empty() {
            return true;
        }
        let listed: Vec<u8> = self.hashes.iter().flat_map(|h| *h.as_bytes()).collect();
        // A 16-byte-per-part list is far below one ED2K part, where the ED2K
        // hash is the plain MD4 of its input.
        FileHash::from_bytes(ed2k::Ed2kBlue::digest(&listed).into()) == file_hash
    }
}

/// Everything hashing a file yields: its size, its eD2k file hash, and its
/// part hash set when it has one.
///
/// The three facts are produced by one pass and travel together, so a caller
/// publishing or verifying a file never has to re-read its bytes to recover
/// the missing one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileHashSummary {
    file_size: u64,
    file_hash: FileHash,
    part_hash_set: Option<PartHashSet>,
}

impl FileHashSummary {
    /// Hash a file already in memory.
    #[must_use]
    pub fn digest_bytes(bytes: &[u8]) -> Self {
        let file_size = bytes.len() as u64;
        let file_hash = FileHash::from_bytes(ed2k::Ed2kRed::digest(bytes).into());
        let part_hash_set = digest_part_hash_set(bytes, file_size);

        Self {
            file_size,
            file_hash,
            part_hash_set,
        }
    }

    /// Hash what `reader` yields, one part in memory at a time, so a file
    /// of any size costs one part's buffer. The same three facts as
    /// [`digest_bytes`](Self::digest_bytes) over the same bytes. Returns
    /// `io::Result` directly rather than going through `PrimitiveError::Io` —
    /// `PrimitiveError` is a protocol-level taxonomy and shouldn't bundle
    /// "the disk read failed" into matchers downstream of every decoder.
    pub fn digest_reader(mut reader: impl std::io::Read) -> std::io::Result<Self> {
        let mut file = ed2k::Ed2kRed::default();
        let mut part = vec![0; ED2K_PART_SIZE_USIZE];
        let mut hashes = Vec::new();
        let mut file_size = 0u64;
        loop {
            let filled = fill(&mut reader, &mut part)?;
            if filled > 0 {
                let bytes = &part[..filled];
                ed2k::digest::Update::update(&mut file, bytes);
                hashes.push(PartHash::from_bytes(ed2k::Ed2kBlue::digest(bytes).into()));
                file_size += filled as u64;
            }
            if filled < part.len() {
                break;
            }
        }
        let part_hash_set = (file_size >= ED2K_PART_SIZE).then(|| {
            if file_size.is_multiple_of(ED2K_PART_SIZE) {
                hashes.push(PartHash::from_bytes(ed2k::Ed2kBlue::digest([]).into()));
            }
            PartHashSet::from_hashes(file_size, hashes)
                .expect("one hash per part, plus the empty one on an exact multiple")
        });
        Ok(Self {
            file_size,
            file_hash: FileHash::from_bytes(file.finalize().into()),
            part_hash_set,
        })
    }

    /// The hashed file's size in bytes.
    #[must_use]
    pub const fn file_size(&self) -> u64 {
        self.file_size
    }

    /// The eD2k file hash — the file's network identity.
    #[must_use]
    pub const fn file_hash(&self) -> FileHash {
        self.file_hash
    }

    /// The part hash set, or `None` for a file below one part size, which has
    /// none.
    #[must_use]
    pub fn part_hash_set(&self) -> Option<&PartHashSet> {
        self.part_hash_set.as_ref()
    }
}

/// Read into `buf` until it is full or the reader ends; the count read.
fn fill(reader: &mut impl std::io::Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(read) => filled += read,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(filled)
}

fn digest_part_hash_set(bytes: &[u8], file_size: u64) -> Option<PartHashSet> {
    if file_size < ED2K_PART_SIZE {
        return None;
    }

    let mut hashes = bytes
        .chunks(ED2K_PART_SIZE_USIZE)
        .map(|part| PartHash::from_bytes(ed2k::Ed2kBlue::digest(part).into()))
        .collect::<Vec<_>>();

    if file_size.is_multiple_of(ED2K_PART_SIZE) {
        hashes.push(PartHash::from_bytes(ed2k::Ed2kBlue::digest([]).into()));
    }

    // The hash count produced above mirrors
    // `PartHashSet::expected_hash_count(file_size)` exactly (one entry
    // per `chunks(ED2K_PART_SIZE)` slice plus the trailing empty hash
    // on exact-multiple sizes), so the validation in `from_hashes`
    // cannot fail. The `expect` documents this dead panic path.
    Some(
        PartHashSet::from_hashes(file_size, hashes)
            .expect("digest_part_hash_set produces the exact aMule hashset count by construction"),
    )
}

fn decode_fixed_hex<const N: usize>(input: &str, kind: &'static str) -> Result<[u8; N]> {
    let normalized = input.to_ascii_uppercase();
    let bytes = HEXUPPER
        .decode(normalized.as_bytes())
        .map_err(|_| PrimitiveError::InvalidHashEncoding { kind })?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| PrimitiveError::InvalidHashLength {
            expected: N,
            actual: bytes.len(),
        })
}
