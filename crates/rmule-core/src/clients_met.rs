//! `clients.met` — the eMule/aMule **credit file** codec and its config-dir
//! persistence edge, the durable home of the ADR-0041 credit ring
//! across runs.
//!
//! aMule loads this file in `CClientCreditsList::LoadList` and writes it in
//! `SaveList` (`src/ClientCreditsList.cpp`); this module is the byte-for-byte
//! Rust twin — a pure [`decode`]/[`encode`] pair over [`CreditRecord`] (aMule's
//! `CreditStruct`), plus [`load_clients_met`]/[`save_clients_met`] as the file
//! I/O edge. The codec is clock-free, honouring the ring's explicit-time
//! discipline; the 150-day expiry and the `nLastSeen` stamp live at the edge,
//! where the wall clock is injected.
//!
//! ## Format (`CClientCreditsList`, all integers little-endian)
//!
//! `version(1) = 0x12`, `count(u32)`, then `count` fixed [`ENTRY_LEN`]-byte
//! records — aMule's `CreditStruct` in `SaveList`'s exact field order:
//!
//! | field           | width | note                                            |
//! |-----------------|-------|-------------------------------------------------|
//! | `key`           | 16    | the peer **User Hash** (`CMD4Hash`)             |
//! | `uploaded` lo   | 4     | low 32 bits of bytes we served the peer         |
//! | `downloaded` lo | 4     | low 32 bits of bytes the peer served us         |
//! | `nLastSeen`     | 4     | unix secs; drives the 150-day expiry            |
//! | `uploaded` hi   | 4     | high 32 bits (the u64 is split lo-then-hi)      |
//! | `downloaded` hi | 4     | high 32 bits                                    |
//! | `nReserved3`    | 2     | unused; preserved verbatim for byte-parity      |
//! | `nKeySize`      | 1     | secure-ident DER length; `> 80` ⇒ file corrupt  |
//! | `abySecureIdent`| 80    | the `MAXPUBKEYSIZE` public-key buffer, verbatim |
//!
//! ## Documented divergence — `nLastSeen` stamped at save, not per touch
//!
//! aMule stamps `nLastSeen` on every credit access (`GetCredit` →
//! `SetLastSeen`). rmule's credit ring is clock-free (explicit-time), so the
//! save edge stamps `nLastSeen = now` for every persisted record instead. The
//! 150-day expiry therefore keys on "not *persisted* in 150 days" rather than
//! aMule's "not *seen* in 150 days" — the same observable effect for a
//! continuously-running or normally-restarted daemon, and a record carried
//! verbatim from an aMule-written file keeps aMule's own stamp.

use std::path::Path;

use rmule_primitives::UserHash;
use thiserror::Error;

use crate::credit::PeerCredit;

/// `CREDITFILE_VERSION` (`DataFileVersion.h`): the only version this codec
/// reads or writes. Anything else is [`ClientsMetError::UnsupportedVersion`].
pub const CREDITFILE_VERSION: u8 = 0x12;

/// `MAXPUBKEYSIZE` (`ClientCredits.h`): the fixed secure-ident buffer width. A
/// stored `nKeySize` above it means the file is corrupt.
pub const MAX_PUBKEY_SIZE: usize = 80;

/// aMule's expiry horizon (`ClientCreditsList.cpp`: `time(NULL) - 12960000`):
/// 150 days in seconds. A record whose `last_seen` predates `now - EXPIRY_SECS`
/// is dropped on load.
pub const EXPIRY_SECS: u32 = 12_960_000;

/// One fixed-width `CreditStruct` record: `16 + 4·5 + 2 + 1 + 80`.
const ENTRY_LEN: usize = 16 + 20 + 2 + 1 + MAX_PUBKEY_SIZE;

/// The `clients.met` file name, in the config dir the loaders already use.
pub const CLIENTS_MET_FILE: &str = "clients.met";

/// Whole-file reasons the credit file cannot be decoded — aMule's own two
/// rejection points, surfaced as typed errors the tolerant load edge maps to
/// "start with an empty ring" (matching `LoadList`).
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ClientsMetError {
    /// The leading version byte is not [`CREDITFILE_VERSION`] — aMule's
    /// "Creditfile is outdated and will be replaced" (`LoadList` returns early,
    /// the file is later overwritten).
    #[error("clients.met version byte 0x{byte:02X} is not CREDITFILE_VERSION (0x12)")]
    UnsupportedVersion {
        /// The version byte actually read.
        byte: u8,
    },

    /// A record's `nKeySize` exceeds the 80-byte maximum — aMule's corruption
    /// tripwire (`nKeySize > MAXPUBKEYSIZE` discards the *whole* file: "we can
    /// no longer assume that any of the clients in the file are valid").
    #[error("clients.met record {index} has key size {key_size} > 80 — file is corrupt")]
    Corrupt {
        /// The zero-based record the oversized key was found in.
        index: usize,
        /// The declared key size, which exceeded the 80-byte maximum.
        key_size: u8,
    },
}

/// One credit record, the on-disk twin of aMule's `CreditStruct`. Byte-faithful
/// so a record read from an aMule-written file re-encodes verbatim: `reserved3`
/// and the full the 80-byte maximum `secure_ident` buffer (garbage past
/// `key_size` included, as aMule writes it) are preserved, not normalised.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreditRecord {
    /// The peer's User Hash — aMule's `CreditStruct::key`.
    pub key: UserHash,
    /// Lifetime bytes we served this peer.
    pub uploaded: u64,
    /// Lifetime bytes this peer served us.
    pub downloaded: u64,
    /// Unix seconds the peer was last seen (`nLastSeen`); drives expiry.
    pub last_seen: u32,
    /// aMule's unused `nReserved3`; carried for byte-parity.
    pub reserved3: u16,
    /// The secure-ident public-key DER length (`nKeySize`), `<= 80`.
    pub key_size: u8,
    /// The `MAXPUBKEYSIZE` secure-ident buffer, verbatim (`abySecureIdent`).
    pub secure_ident: [u8; MAX_PUBKEY_SIZE],
}

impl CreditRecord {
    /// Build an on-disk record from a live ring [`PeerCredit`] snapshot,
    /// stamping `last_seen = now` (see the module's divergence note). The bound
    /// SUI public key, if any, lands in the `nKeySize` + `abySecureIdent`
    /// buffer; a peer with no proven key writes a zero buffer, exactly as aMule
    /// does for an unsecured peer.
    #[must_use]
    pub fn from_peer_credit(peer: &PeerCredit, now: u32) -> Self {
        let mut secure_ident = [0u8; MAX_PUBKEY_SIZE];
        let key_size = peer.public_key.as_ref().map_or(0, |der| {
            let len = der.len().min(MAX_PUBKEY_SIZE);
            secure_ident[..len].copy_from_slice(&der[..len]);
            u8::try_from(len).expect("len <= MAX_PUBKEY_SIZE (80) fits u8")
        });
        Self {
            key: peer.key,
            uploaded: peer.totals.uploaded,
            downloaded: peer.totals.downloaded,
            last_seen: now,
            reserved3: 0,
            key_size,
            secure_ident,
        }
    }

    /// Whether this record is older than aMule's 150-day horizon relative to
    /// `now` (`nLastSeen < now - EXPIRY_SECS`) — the load-time drop condition.
    #[must_use]
    pub const fn is_expired(&self, now: u32) -> bool {
        self.last_seen < now.saturating_sub(EXPIRY_SECS)
    }

    /// The bound SUI public key, or `None` when `key_size` is zero (an
    /// unsecured peer) — the `abySecureIdent[..nKeySize]` slice.
    #[must_use]
    pub fn public_key(&self) -> Option<&[u8]> {
        if self.key_size == 0 {
            None
        } else {
            Some(&self.secure_ident[..usize::from(self.key_size)])
        }
    }
}

/// Encode credit records as a `clients.met` payload, aMule `SaveList` verbatim.
///
/// Only records with non-zero lifetime totals are written — aMule's
/// `if (GetUploadedTotal() || GetDownloadedTotal())` guard: a peer we have
/// never exchanged bytes with carries no credit worth persisting. The header
/// count is the number actually written.
#[must_use]
pub fn encode(records: &[CreditRecord]) -> Vec<u8> {
    let writable: Vec<&CreditRecord> = records
        .iter()
        .filter(|r| r.uploaded != 0 || r.downloaded != 0)
        .collect();
    let count = u32::try_from(writable.len()).unwrap_or(u32::MAX);

    let mut out = Vec::with_capacity(5 + writable.len() * ENTRY_LEN);
    out.push(CREDITFILE_VERSION);
    out.extend_from_slice(&count.to_le_bytes());
    for record in writable {
        out.extend_from_slice(record.key.as_bytes());
        // The u64 totals are split low-word-then-high-word, straddling the
        // nLastSeen field between them (aMule's exact read/write interleave).
        out.extend_from_slice(&(record.uploaded as u32).to_le_bytes());
        out.extend_from_slice(&(record.downloaded as u32).to_le_bytes());
        out.extend_from_slice(&record.last_seen.to_le_bytes());
        out.extend_from_slice(&((record.uploaded >> 32) as u32).to_le_bytes());
        out.extend_from_slice(&((record.downloaded >> 32) as u32).to_le_bytes());
        out.extend_from_slice(&record.reserved3.to_le_bytes());
        out.push(record.key_size);
        out.extend_from_slice(&record.secure_ident);
    }
    out
}

/// Decode a `clients.met` payload into its records, aMule `LoadList` verbatim
/// minus the clock-dependent expiry (the load edge applies that with `now`).
///
/// Truncation after the header keeps every whole record parsed so far — aMule's
/// whole-`try` exception boundary keeps the clients added before an I/O fault.
/// A record whose `nKeySize > 80` aborts with [`ClientsMetError::Corrupt`]
/// (aMule discards the entire file), and a wrong version byte is
/// [`ClientsMetError::UnsupportedVersion`].
pub fn decode(bytes: &[u8]) -> Result<Vec<CreditRecord>, ClientsMetError> {
    let Some((&version, rest)) = bytes.split_first() else {
        // No version byte at all: aMule's `FileExists` short-circuit — an
        // absent/empty file is simply an empty ring, not an error.
        return Ok(Vec::new());
    };
    if version != CREDITFILE_VERSION {
        return Err(ClientsMetError::UnsupportedVersion { byte: version });
    }
    let Some(count_bytes) = rest.get(..4) else {
        return Ok(Vec::new());
    };
    let count = u32::from_le_bytes(count_bytes.try_into().expect("4-byte slice"));

    let mut records = Vec::new();
    let mut offset = 4;
    for index in 0..count as usize {
        let Some(entry) = rest.get(offset..offset + ENTRY_LEN) else {
            break; // truncated: keep the records parsed so far
        };
        let record = decode_entry(entry);
        if record.key_size > MAX_PUBKEY_SIZE as u8 {
            return Err(ClientsMetError::Corrupt {
                index,
                key_size: record.key_size,
            });
        }
        records.push(record);
        offset += ENTRY_LEN;
    }
    Ok(records)
}

/// Decode one fixed-width record; the slice is exactly [`ENTRY_LEN`] bytes.
fn decode_entry(entry: &[u8]) -> CreditRecord {
    let read_u32 = |at: usize| u32::from_le_bytes(entry[at..at + 4].try_into().expect("4 bytes"));

    let key = UserHash::from_bytes(entry[0..16].try_into().expect("16-byte user hash"));
    let uploaded = u64::from(read_u32(16)) | (u64::from(read_u32(28)) << 32);
    let downloaded = u64::from(read_u32(20)) | (u64::from(read_u32(32)) << 32);
    let last_seen = read_u32(24);
    let reserved3 = u16::from_le_bytes(entry[36..38].try_into().expect("2 bytes"));
    let key_size = entry[38];
    let mut secure_ident = [0u8; MAX_PUBKEY_SIZE];
    secure_ident.copy_from_slice(&entry[39..39 + MAX_PUBKEY_SIZE]);

    CreditRecord {
        key,
        uploaded,
        downloaded,
        last_seen,
        reserved3,
        key_size,
        secure_ident,
    }
}

/// Persist the credit ring as `clients.met` in `dir`, atomically and durably
/// (temp file + fsync + rename over the target — aMule's backup-then-write
/// discipline collapsed to the crash-safe minimum; the fsync keeps a power
/// loss right after the swap from leaving a truncated new file). `snapshot` is
/// the ring's [`PeerCredit`] rows (`CreditStore::snapshot`); `now` stamps
/// `nLastSeen`.
pub fn save_clients_met(dir: &Path, snapshot: &[PeerCredit], now: u32) -> std::io::Result<()> {
    use std::io::Write;

    let records: Vec<CreditRecord> = snapshot
        .iter()
        .map(|peer| CreditRecord::from_peer_credit(peer, now))
        .collect();
    let bytes = encode(&records);

    let path = dir.join(CLIENTS_MET_FILE);
    let mut tmp = path.clone().into_os_string();
    tmp.push(".tmp");
    let staged = (|| {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, &path)
    })();
    if staged.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    staged
}

/// Replay loaded records into a live ring — the daemon's startup seed (aMule's
/// `LoadList` populating `m_mapClients`). Only peers the store has never met
/// are replayed: an empty ring takes every record, and a ring that already
/// carries a peer keeps its own totals, so the file can never double-count a
/// ring that outlived it. Returns how many records were seeded.
pub fn seed_credit_ring(
    store: &(impl crate::credit::CreditStore + ?Sized),
    records: &[CreditRecord],
) -> Result<usize, crate::CoreError> {
    let mut seeded = 0;
    for record in records {
        let known = store.totals(record.key)?;
        if known.uploaded != 0 || known.downloaded != 0 || store.public_key(record.key)?.is_some() {
            continue;
        }
        store.record_upload(record.key, record.uploaded)?;
        store.record_download(record.key, record.downloaded)?;
        if let Some(der) = record.public_key() {
            store.bind_public_key(record.key, der)?;
        }
        seeded += 1;
    }
    Ok(seeded)
}

/// Load `clients.met` from `dir`, dropping records past the 150-day expiry
/// relative to `now`.
///
/// Tolerant like aMule's `LoadList`: an absent file is an empty ring, and a
/// corrupt or wrong-version file is discarded (empty ring) rather than
/// propagated — the daemon starts fresh instead of refusing to boot. Only a
/// real filesystem read error surfaces.
pub fn load_clients_met(dir: &Path, now: u32) -> std::io::Result<Vec<CreditRecord>> {
    let path = dir.join(CLIENTS_MET_FILE);
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let records = match decode(&bytes) {
        Ok(records) => records,
        Err(error) => {
            tracing::warn!(%error, path = %path.display(), "clients.met discarded (aMule LoadList tolerance) — starting with an empty credit ring");
            return Ok(Vec::new());
        }
    };
    Ok(records
        .into_iter()
        .filter(|record| !record.is_expired(now))
        .collect())
}

#[cfg(test)]
mod tests {
    use rmule_primitives::UserHash;

    use super::*;
    use crate::credit::CreditTotals;

    fn user_hash(seed: u8) -> UserHash {
        UserHash::from_bytes([seed; UserHash::BYTE_LEN])
    }

    /// A hand-built aMule-format record, cited to `SaveList`'s field order — the
    /// deterministic golden-substitute, since no aMule-authored clients.met
    /// golden exists in-repo (unlike server.met / nodes.dat).
    fn amule_style_record(seed: u8) -> CreditRecord {
        let mut secure_ident = [0u8; MAX_PUBKEY_SIZE];
        // A plausible 59-byte 384-bit DER public key body (the SUI key width),
        // with deliberate non-zero garbage past key_size to prove the full
        // 80-byte buffer is carried verbatim, as aMule writes it.
        for (i, byte) in secure_ident.iter_mut().enumerate() {
            *byte = (i as u8).wrapping_mul(7).wrapping_add(seed);
        }
        CreditRecord {
            key: user_hash(seed),
            // A > 4 GiB total so the hi word is exercised, not just the lo word.
            uploaded: (5u64 << 32) | 0x1234_5678,
            downloaded: 0x00AB_CDEF,
            last_seen: 1_900_000_000,
            reserved3: 0,
            key_size: 59,
            secure_ident,
        }
    }

    #[test]
    fn encode_then_decode_is_a_fixed_point_over_amule_field_layout() {
        // The state round-trip (no golden exists): aMule-shaped records survive
        // encode → decode byte-identically, including the split u64 totals, the
        // reserved word, and the full 80-byte ident buffer with its garbage
        // tail.
        let records = vec![amule_style_record(0x11), amule_style_record(0x22)];
        let bytes = encode(&records);

        assert_eq!(bytes[0], CREDITFILE_VERSION);
        assert_eq!(&bytes[1..5], &2u32.to_le_bytes(), "two records written");
        assert_eq!(bytes.len(), 5 + 2 * ENTRY_LEN);

        let decoded = decode(&bytes).expect("our own clients.met decodes");
        assert_eq!(decoded, records, "every field round-trips byte-for-byte");
    }

    #[test]
    fn split_u64_totals_reconstruct_across_the_lastseen_field() {
        // Pin the exact interleave: lo(up), lo(down), lastSeen, hi(up), hi(down).
        let record = amule_style_record(0x33);
        let bytes = encode(&[record]);
        let entry = &bytes[5..];
        assert_eq!(&entry[16..20], &0x1234_5678u32.to_le_bytes(), "uploaded lo");
        assert_eq!(
            &entry[20..24],
            &0x00AB_CDEFu32.to_le_bytes(),
            "downloaded lo"
        );
        assert_eq!(&entry[24..28], &1_900_000_000u32.to_le_bytes(), "nLastSeen");
        assert_eq!(&entry[28..32], &5u32.to_le_bytes(), "uploaded hi");
        assert_eq!(&entry[32..36], &0u32.to_le_bytes(), "downloaded hi");

        assert_eq!(
            decode(&bytes).unwrap()[0].uploaded,
            (5u64 << 32) | 0x1234_5678
        );
    }

    #[test]
    fn zero_total_records_are_not_written() {
        // aMule's SaveList guard: a peer with no exchanged bytes is skipped.
        let zero = CreditRecord {
            key: user_hash(1),
            uploaded: 0,
            downloaded: 0,
            last_seen: 1_900_000_000,
            reserved3: 0,
            key_size: 0,
            secure_ident: [0u8; MAX_PUBKEY_SIZE],
        };
        let bytes = encode(&[zero, amule_style_record(2)]);
        assert_eq!(
            &bytes[1..5],
            &1u32.to_le_bytes(),
            "only the non-zero record"
        );
        assert_eq!(decode(&bytes).unwrap().len(), 1);
    }

    #[test]
    fn wrong_version_byte_is_rejected() {
        let mut bytes = encode(&[amule_style_record(1)]);
        bytes[0] = 0x11;
        assert_eq!(
            decode(&bytes),
            Err(ClientsMetError::UnsupportedVersion { byte: 0x11 })
        );
    }

    #[test]
    fn an_oversized_key_size_is_whole_file_corruption() {
        let mut bytes = encode(&[amule_style_record(1)]);
        // The nKeySize byte sits at header(5) + 38.
        bytes[5 + 38] = 81;
        assert_eq!(
            decode(&bytes),
            Err(ClientsMetError::Corrupt {
                index: 0,
                key_size: 81
            })
        );
    }

    #[test]
    fn truncation_after_the_header_keeps_prior_records() {
        let bytes = encode(&[amule_style_record(1), amule_style_record(2)]);
        // Declare 2 but cut the second record mid-way.
        let truncated = &bytes[..5 + ENTRY_LEN + 10];
        let decoded = decode(truncated).expect("valid header, short second record");
        assert_eq!(decoded.len(), 1, "the first whole record survives");
    }

    #[test]
    fn empty_or_absent_payload_is_an_empty_ring() {
        assert_eq!(decode(&[]), Ok(Vec::new()));
        assert_eq!(decode(&[CREDITFILE_VERSION]), Ok(Vec::new()));
    }

    #[test]
    fn expiry_drops_records_past_the_150_day_horizon() {
        let now = 2_000_000_000u32;
        let fresh = CreditRecord {
            last_seen: now - 1,
            ..amule_style_record(1)
        };
        let stale = CreditRecord {
            last_seen: now - EXPIRY_SECS - 1,
            ..amule_style_record(2)
        };
        assert!(!fresh.is_expired(now));
        assert!(stale.is_expired(now));
    }

    #[test]
    fn from_peer_credit_packs_the_der_key_into_the_fixed_ident_buffer() {
        // The two branches with real logic: a bound DER key lands in the
        // `nKeySize` + zero-padded `abySecureIdent` buffer and reads back
        // exactly; an unsecured peer writes a zero buffer (aMule's shape).
        let der = vec![0xDEu8; 59];
        let peer = PeerCredit {
            key: user_hash(0x44),
            totals: CreditTotals {
                uploaded: 4096,
                downloaded: 8192,
            },
            public_key: Some(der.clone()),
        };
        let record = CreditRecord::from_peer_credit(&peer, 1_777_777_777);
        assert_eq!(record.key_size, 59);
        assert_eq!(record.public_key(), Some(der.as_slice()));
        assert!(
            record.secure_ident[59..].iter().all(|&b| b == 0),
            "the buffer past key_size stays zeroed for a fresh record"
        );

        // An unsecured peer writes a zero key buffer.
        let bare = PeerCredit {
            key: user_hash(0x55),
            totals: CreditTotals {
                uploaded: 1,
                downloaded: 0,
            },
            public_key: None,
        };
        assert_eq!(CreditRecord::from_peer_credit(&bare, 0).public_key(), None);
    }
}
