//! The **Served Downloads** (ADR-0113): every download larger than one part
//! that is queued, running or paused, keyed by its file hash, and the
//! actor-written **held back** set beside them. A Served Download belongs to
//! its download and is never a Shared File Registry row; it is offered — a
//! **Partial Share** — while its **Verified Range** holds a part, its part
//! hash set is whole and it is not held back.
//!
//! One writer per entry at every instant, by a lease: the core actor holds it
//! while the download is queued or paused, hands it to the run a start or a
//! Resume spawns ([`ServedDownloads::hand_to_run`]) and takes it back once the
//! run has ended ([`ServedDownloads::take_back`]). A run writes only through
//! its [`RunLease`], and every write checks that the entry's holder is still
//! that run, so a run the actor took the lease back from writes nothing. The
//! held back set and an entry's end are the actor's alone.
//!
//! A run's write that changes whether its entry is offered bumps the **offer
//! generation**; the actor selects on it, reads what moved
//! ([`ServedDownloads::look`]) and fires its one share trigger. The actor's
//! own changes it looks at in the same step that made them.
//!
//! Serve State reads every entry afresh before each peer input and reask
//! ([`ServedDownloads::read_since`]), gated by the cell's **version**, which
//! every change moves. An asker of a running download is handed to its run
//! through the entry's inbox ([`ServedDownloads::sight`]), which the run opens
//! ([`RunLease::take_askers`]) and the actor closes when it takes the lease
//! back.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::SystemTime;

use rmule_peer::PartBitmap;
use rmule_primitives::{ED2K_PART_SIZE, Ed2kText, FileHash, PartHash, PartHashSet, SourceSighting};
use tokio::sync::{mpsc, watch};

use crate::download::RunNumber;
use crate::file_key::FileKey;
use crate::{DownloadId, DownloadLifecycle, DurableDownloadRecord, VerifiedPartRecord};

/// How many askers a running download's inbox holds before the serve side
/// drops the next one.
const ASKER_INBOX: usize = 16;

/// Why a Partial Share stopped being offered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PartialEnd {
    /// The download completed; its registry row offers the file whole.
    Completed,
    /// The download was cancelled or failed; its own event says why.
    Ended,
    /// Its destination lies under a refused entry of the Shared Directory
    /// List (ADR-0101).
    HeldBack,
    /// The part file is not the one the Verified Range named.
    Changed,
    /// The part file could not be read.
    Unreadable,
}

/// Whether a download row is a Served Download: queued, active, completing
/// or paused, and larger than one part (aMule's `GetFileSize() > PARTSIZE`).
/// A failed row's part file is in doubt; a file of one part has no part hash
/// set and is shared by its completion alone.
pub(crate) fn is_member(lifecycle: DownloadLifecycle, file_size: u64) -> bool {
    matches!(
        lifecycle,
        DownloadLifecycle::Queued
            | DownloadLifecycle::Active
            | DownloadLifecycle::Completing
            | DownloadLifecycle::Paused
    ) && file_size > ED2K_PART_SIZE
}

/// A part hash set holding every hash its file's size calls for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WholeSet(Arc<[PartHash]>);

impl WholeSet {
    /// `hashes` as the whole set of a `file_size`-byte file; `None` when they
    /// are not as many as the size calls for (none held is not a set).
    pub(crate) fn of(file_size: u64, hashes: &[PartHash]) -> Option<Self> {
        let expected = PartHashSet::expected_hash_count(file_size).ok()?;
        (expected > 0 && hashes.len() == expected).then(|| Self(hashes.into()))
    }

    /// The hashes in part order.
    pub(crate) fn hashes(&self) -> &[PartHash] {
        &self.0
    }
}

/// The parts whose recorded hash equals the whole set's at their index: the
/// only bytes the serve side reads from a part file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct VerifiedRange(BTreeSet<u32>);

impl VerifiedRange {
    /// The range `records` hold against `set`. Without a whole set no part is
    /// checked, so the range is empty.
    pub(crate) fn of_records(set: Option<&WholeSet>, records: &[VerifiedPartRecord]) -> Self {
        let Some(set) = set else {
            return Self::default();
        };
        Self(
            records
                .iter()
                .filter(|record| {
                    set.hashes().get(record.part_index as usize) == Some(&record.part_hash)
                })
                .map(|record| record.part_index)
                .collect(),
        )
    }

    /// Whether part `part_index` lies inside the range.
    pub(crate) fn holds(&self, part_index: u32) -> bool {
        self.0.contains(&part_index)
    }

    /// The status a `file_size`-byte file holding this range states: spelt by
    /// the one function the run's own status is ([`PartBitmap::downloader`]),
    /// so what the serve side says and what the run says are one set.
    pub(crate) fn status(&self, file_size: u64) -> PartBitmap {
        PartBitmap::downloader(file_size, |part| self.holds(part.value()))
    }

    /// Whether the range holds any part of the file.
    pub(crate) fn holds_a_part(&self) -> bool {
        !self.0.is_empty()
    }

    /// Whether every byte of `start..end` lies inside the range: each part
    /// it touches is held.
    pub(crate) fn covers(&self, start: u64, end: u64) -> bool {
        if end <= start {
            return true;
        }
        let part = |offset: u64| u32::try_from(offset / ED2K_PART_SIZE).ok();
        match (part(start), part(end - 1)) {
            (Some(first), Some(last)) => (first..=last).all(|part| self.holds(part)),
            _ => false,
        }
    }
}

/// The file a Served Download's verified bytes are read from, as the writer
/// that last held it read it through its handle. Memory only: every start
/// re-reads the parts it vouches for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PartFileIdentity {
    /// Which file it is.
    pub(crate) key: FileKey,
    /// Its length and modification time as the run left it; `None` while a
    /// run writes it, when only the key is compared.
    pub(crate) at_rest: Option<AtRest>,
}

/// A file's length and modification time with nobody writing it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AtRest {
    /// Its length in bytes.
    pub(crate) len: u64,
    /// When it was last written.
    pub(crate) modified: SystemTime,
}

impl PartFileIdentity {
    /// The identity of the file `key` names while a run writes it: only its
    /// key is compared.
    pub(crate) const fn while_written(key: FileKey) -> Self {
        Self { key, at_rest: None }
    }

    /// The identity of the file `meta` describes, `key` its file key, with
    /// nobody writing it: its length and time are compared too. `None` when
    /// the system keeps no modification time.
    pub(crate) fn at_rest(key: FileKey, meta: &std::fs::Metadata) -> Option<Self> {
        Some(Self {
            key,
            at_rest: Some(AtRest {
                len: meta.len(),
                modified: meta.modified().ok()?,
            }),
        })
    }

    /// Whether the file an opened handle reports — `key`, and `meta` for its
    /// length and time — is this one: the key always, the length and time
    /// only when the identity holds them, since a run moves both as it
    /// writes.
    pub(crate) fn holds(&self, key: FileKey, meta: &std::fs::Metadata) -> bool {
        self.key == key
            && self.at_rest.is_none_or(|rest| {
                rest.len == meta.len() && meta.modified().ok() == Some(rest.modified)
            })
    }
}

/// How a read of a Served Download's bytes is checked before it reads
/// (ADR-0113 §"Reading a part file"): the file it opens must be the one the
/// identity names, and a path that names nothing gives way to the other
/// once — the completion move puts the bytes at one of the two at every
/// instant.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReadCheck {
    /// The file the entry's range was read from; `None` reads nothing.
    pub(crate) identity: Option<PartFileIdentity>,
    /// The download's other path.
    pub(crate) other: PathBuf,
}

/// What a running download's source-exchange answer is drawn from
/// (ADR-0113): the sources its run downloads from or waits at whose queue is
/// not full, each with the parts it advertised — `None` when it advertised
/// none — and how many sources the run knows, which the serve throttle reads
/// as the file's rarity. Empty while the actor holds the entry: a queued or
/// paused download has no source in those states.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ExchangePool {
    /// Each source, as an answer names it, with its Advertised Parts.
    pub(crate) sources: Vec<(SourceSighting, Option<PartBitmap>)>,
    /// How many sources the run knows.
    pub(crate) known: u32,
}

/// Which of a download's two paths holds its verified bytes now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BytesAt {
    /// The part file.
    PartFile,
    /// The finished file, in place at the final path.
    FinalFile,
}

/// One Served Download as a reader sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Served {
    /// The download it belongs to.
    pub(crate) download_id: DownloadId,
    /// The file's exact size.
    pub(crate) file_size: u64,
    /// The name the file is offered under: the download's own, as its stored
    /// metadata spells it (ADR-0113), which the destination's file name may
    /// not be once a safe-filename rewrite or a free name chose that. A
    /// download whose name core never learned takes its destination's.
    pub(crate) name: Ed2kText,
    /// The part file.
    pub(crate) part_path: PathBuf,
    /// The destination.
    pub(crate) final_path: PathBuf,
    /// Which of the two holds the bytes now.
    pub(crate) bytes_at: BytesAt,
    /// The part hash set, once whole.
    pub(crate) set: Option<WholeSet>,
    /// The parts proven against the set.
    pub(crate) range: VerifiedRange,
    /// The file the range was read from, once a writer read it.
    pub(crate) identity: Option<PartFileIdentity>,
    /// What a source-exchange ask for it is answered from.
    pub(crate) pool: ExchangePool,
}

impl Served {
    /// The path that holds the bytes now, and how a read of it is checked.
    pub(crate) fn read_target(&self) -> (PathBuf, ReadCheck) {
        let (path, other) = match self.bytes_at {
            BytesAt::PartFile => (&self.part_path, &self.final_path),
            BytesAt::FinalFile => (&self.final_path, &self.part_path),
        };
        let check = ReadCheck {
            identity: self.identity,
            other: other.clone(),
        };
        (path.clone(), check)
    }
}

/// Who writes an entry now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Holder {
    /// The core actor: the download is queued or paused, or its run ended.
    Actor,
    /// The run with this number.
    Run(RunNumber),
}

struct Entry {
    served: Served,
    holder: Holder,
    /// Why a run's write withdrew the offer, until the actor looks.
    withdrawn: Option<PartialEnd>,
    /// A run's write offered the entry since the actor's last look, so an
    /// offer that ended again before the look is still said.
    offered_since_look: bool,
    /// Where the run holding the entry takes its askers; `None` while the
    /// actor holds it.
    askers: Option<mpsc::Sender<SourceSighting>>,
    /// A read found the file changed or unreadable: the range stays empty
    /// until a holder records the identity of the file it reads.
    emptied: bool,
}

/// What the actor's last look saw of a Served Download.
#[derive(Clone, Copy)]
struct Seen {
    offered: bool,
}

#[derive(Default)]
struct Book {
    entries: HashMap<FileHash, Entry>,
    held_back: HashSet<FileHash>,
    /// The entries the actor ended since its last look, and why.
    ended: HashMap<FileHash, PartialEnd>,
    /// What the actor's last look saw.
    seen: HashMap<FileHash, Seen>,
    /// Moved by every change a reader could see.
    version: u64,
}

impl Book {
    fn offered(&self, file_hash: FileHash) -> bool {
        self.entries.get(&file_hash).is_some_and(|entry| {
            entry.served.set.is_some()
                && entry.served.range.holds_a_part()
                && !self.held_back.contains(&file_hash)
        })
    }

    /// The entry `lease` writes, while its run still holds it.
    fn leased(&mut self, lease: &RunLease) -> Option<&mut Entry> {
        self.entries
            .get_mut(&lease.file_hash)
            .filter(|entry| entry.holder == Holder::Run(lease.run))
    }
}

/// One Served Download as Serve State reads it (ADR-0113 rule 5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ServedLook {
    /// The entry as it stands.
    pub(crate) served: Served,
    /// Whether it is offered now: a **Partial Share**.
    pub(crate) offered: bool,
    /// Whether a run holds it and takes its askers as sightings.
    pub(crate) takes_askers: bool,
}

/// Every Served Download as one read found it, at the cell's version then.
#[derive(Clone, Debug, Default)]
pub(crate) struct ServedRead {
    /// The version the read was made at.
    pub(crate) version: u64,
    /// Each entry, by file hash.
    pub(crate) entries: HashMap<FileHash, ServedLook>,
}

/// One change the actor's look found since the last.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OfferChange {
    /// A download became a Served Download.
    Joined(FileHash),
    /// A Served Download began to offer its parts.
    Offered(FileHash),
    /// A Partial Share stopped being offered.
    Withdrawn(FileHash, PartialEnd),
    /// A Served Download ended.
    Left(FileHash),
}

/// The cell itself — cloned into the actor and every run's lease. A plain
/// `std::sync::Mutex`: every section is a map update that never crosses an
/// `.await`.
#[derive(Clone)]
pub(crate) struct ServedDownloads {
    book: Arc<Mutex<Book>>,
    offers: Arc<watch::Sender<u64>>,
}

impl Default for ServedDownloads {
    fn default() -> Self {
        Self {
            book: Arc::default(),
            offers: Arc::new(watch::channel(0).0),
        }
    }
}

impl ServedDownloads {
    fn lock(&self) -> MutexGuard<'_, Book> {
        self.book.lock().expect("served downloads mutex")
    }

    /// The offer generation, bumped by every run's write that changes
    /// whether its entry is offered.
    pub(crate) fn offer_changes(&self) -> watch::Receiver<u64> {
        self.offers.subscribe()
    }

    /// Make `record`'s download a Served Download, held by the actor, with an
    /// empty range and no identity, and `set` as its part hash set when it is
    /// whole. `false` when the row is no member, or the file already has an
    /// entry (the store admits one live download per file).
    pub(crate) fn install(&self, record: &DurableDownloadRecord, set: &[PartHash]) -> bool {
        if !is_member(record.lifecycle(), record.file_size()) {
            return false;
        }
        let paths = record.paths();
        let known = &record.metadata().name;
        let name = if known.as_bytes().is_empty() {
            Ed2kText::from_utf8(
                paths
                    .final_path()
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_default(),
            )
        } else {
            known.clone()
        };
        let served = Served {
            download_id: record.id(),
            file_size: record.file_size(),
            name,
            part_path: paths.part_path().to_path_buf(),
            final_path: paths.final_path().to_path_buf(),
            bytes_at: BytesAt::PartFile,
            set: WholeSet::of(record.file_size(), set),
            range: VerifiedRange::default(),
            identity: None,
            pool: ExchangePool::default(),
        };
        let mut book = self.lock();
        if book.entries.contains_key(&record.file_hash()) {
            return false;
        }
        book.entries.insert(
            record.file_hash(),
            Entry {
                served,
                holder: Holder::Actor,
                withdrawn: None,
                offered_since_look: false,
                askers: None,
                emptied: false,
            },
        );
        book.version += 1;
        true
    }

    /// Hand the entry of `file_hash` to run `run`: its lease, or `None` when
    /// there is no entry or the actor does not hold it.
    pub(crate) fn hand_to_run(&self, file_hash: FileHash, run: RunNumber) -> Option<RunLease> {
        let mut book = self.lock();
        let entry = book.entries.get_mut(&file_hash)?;
        if entry.holder != Holder::Actor {
            return None;
        }
        entry.holder = Holder::Run(run);
        Some(RunLease {
            cell: self.clone(),
            file_hash,
            run,
        })
    }

    /// Take the entry of `file_hash` back from run `run`, which has ended or
    /// been told to; from here its lease writes nothing, its inbox is closed
    /// and its source-exchange pool is empty.
    pub(crate) fn take_back(&self, file_hash: FileHash, run: RunNumber) {
        let mut guard = self.lock();
        let book = &mut *guard;
        if let Some(entry) = book.entries.get_mut(&file_hash)
            && entry.holder == Holder::Run(run)
        {
            entry.holder = Holder::Actor;
            let pool = std::mem::take(&mut entry.served.pool);
            if entry.askers.take().is_some() || pool != ExchangePool::default() {
                book.version += 1;
            }
        }
    }

    /// End the Served Download of `download_id` for `cause`, which the next
    /// look reports. `false` when it has no entry or a run still holds it.
    pub(crate) fn end(&self, download_id: DownloadId, cause: PartialEnd) -> bool {
        let mut book = self.lock();
        let Some(file_hash) = book
            .entries
            .iter()
            .find(|(_, entry)| entry.served.download_id == download_id)
            .map(|(file_hash, _)| *file_hash)
        else {
            return false;
        };
        if book.entries[&file_hash].holder != Holder::Actor {
            return false;
        }
        book.entries.remove(&file_hash);
        book.held_back.remove(&file_hash);
        book.ended.insert(file_hash, cause);
        book.version += 1;
        true
    }

    /// Hold back `file_hash`'s entry, or release it.
    pub(crate) fn hold_back(&self, file_hash: FileHash, held: bool) {
        let mut book = self.lock();
        let moved = if !held {
            book.held_back.remove(&file_hash)
        } else {
            book.entries.contains_key(&file_hash) && book.held_back.insert(file_hash)
        };
        if moved {
            book.version += 1;
        }
    }

    /// Every Served Download as it stands, unless nothing changed since the
    /// read at version `seen`.
    pub(crate) fn read_since(&self, seen: u64) -> Option<ServedRead> {
        let book = self.lock();
        (book.version != seen).then(|| ServedRead {
            version: book.version,
            entries: book
                .entries
                .iter()
                .map(|(file_hash, entry)| {
                    let look = ServedLook {
                        served: entry.served.clone(),
                        offered: book.offered(*file_hash),
                        takes_askers: entry.askers.is_some(),
                    };
                    (*file_hash, look)
                })
                .collect(),
        })
    }

    /// Hand `sighting`, an asker of `file_hash`'s Served Download, to the run
    /// that holds it. `false` when no run takes it: the entry is gone, the
    /// actor holds it, or its inbox is full.
    pub(crate) fn sight(&self, file_hash: FileHash, sighting: SourceSighting) -> bool {
        self.lock()
            .entries
            .get(&file_hash)
            .and_then(|entry| entry.askers.as_ref())
            .is_some_and(|askers| askers.try_send(sighting).is_ok())
    }

    /// Every entry's destination, for the refused-folder rule.
    pub(crate) fn destinations(&self) -> Vec<(FileHash, PathBuf)> {
        self.lock()
            .entries
            .iter()
            .map(|(file_hash, entry)| (*file_hash, entry.served.final_path.clone()))
            .collect()
    }

    /// What changed since the actor's last look, each change once: the
    /// membership and the offer of every entry.
    pub(crate) fn look(&self) -> Vec<OfferChange> {
        let mut guard = self.lock();
        let book = &mut *guard;
        let mut changes = Vec::new();
        let mut seen = HashMap::with_capacity(book.entries.len());
        let mut hashes: Vec<FileHash> = book.entries.keys().copied().collect();
        hashes.sort_unstable();
        for file_hash in hashes {
            let offered = book.offered(file_hash);
            let entry = book.entries.get_mut(&file_hash).expect("listed above");
            let withdrawn = entry.withdrawn.take();
            let flickered = std::mem::take(&mut entry.offered_since_look);
            let cause = if book.held_back.contains(&file_hash) {
                PartialEnd::HeldBack
            } else {
                withdrawn.unwrap_or(PartialEnd::Changed)
            };
            let was = book.seen.get(&file_hash).map(|seen| seen.offered);
            if was.is_none() {
                changes.push(OfferChange::Joined(file_hash));
            }
            let was = was.unwrap_or(false);
            match (was, offered) {
                (false, true) => changes.push(OfferChange::Offered(file_hash)),
                (true, false) => changes.push(OfferChange::Withdrawn(file_hash, cause)),
                // Withdrawn and offered again between two looks: both said.
                (true, true) if withdrawn.is_some() => {
                    changes.push(OfferChange::Withdrawn(file_hash, cause));
                    changes.push(OfferChange::Offered(file_hash));
                }
                // Offered and withdrawn again between two looks: both said.
                (false, false) if flickered => {
                    changes.push(OfferChange::Offered(file_hash));
                    changes.push(OfferChange::Withdrawn(file_hash, cause));
                }
                _ => {}
            }
            seen.insert(file_hash, Seen { offered });
        }
        let mut left: Vec<(FileHash, Seen)> = book
            .seen
            .iter()
            .filter(|(file_hash, _)| !seen.contains_key(file_hash))
            .map(|(file_hash, was)| (*file_hash, *was))
            .collect();
        left.sort_unstable_by_key(|(file_hash, _)| *file_hash);
        for (file_hash, was) in left {
            if was.offered {
                let cause = book
                    .ended
                    .get(&file_hash)
                    .copied()
                    .unwrap_or(PartialEnd::Ended);
                changes.push(OfferChange::Withdrawn(file_hash, cause));
            }
            changes.push(OfferChange::Left(file_hash));
        }
        book.ended.clear();
        book.seen = seen;
        changes
    }

    /// The file hashes offered now, in hash order.
    pub(crate) fn offered(&self) -> Vec<FileHash> {
        let book = self.lock();
        let mut offered: Vec<FileHash> = book
            .entries
            .keys()
            .copied()
            .filter(|file_hash| book.offered(*file_hash))
            .collect();
        offered.sort_unstable();
        offered
    }

    /// The Served Download of `file_hash`, as it stands.
    pub(crate) fn served(&self, file_hash: FileHash) -> Option<Served> {
        self.lock()
            .entries
            .get(&file_hash)
            .map(|entry| entry.served.clone())
    }

    /// A read of `file_hash`'s bytes, checked against `checked`, found the
    /// file changed or could not read it, for `cause` (ADR-0113 §"Reading a
    /// part file"): whoever holds the entry, its Verified Range empties at
    /// once and stays empty until a holder records the identity of the file
    /// it reads — a run at its lease's start, the swap, the Offer Check — and
    /// the actor's next look says why. `false` when the entry is gone, or
    /// names another file than `checked` now: a swap moved it since the read
    /// was decided, and the next read is checked against the new one.
    pub(crate) fn empty_range(
        &self,
        file_hash: FileHash,
        checked: Option<PartFileIdentity>,
        cause: PartialEnd,
    ) -> bool {
        let mut guard = self.lock();
        let book = &mut *guard;
        let was = book.offered(file_hash);
        let Some(entry) = book
            .entries
            .get_mut(&file_hash)
            .filter(|entry| entry.served.identity == checked)
        else {
            return false;
        };
        entry.emptied = true;
        entry.served.range = VerifiedRange::default();
        if was {
            entry.withdrawn = Some(cause);
        }
        book.version += 1;
        drop(guard);
        if was {
            self.offers.send_modify(|generation| *generation += 1);
        }
        true
    }

    /// Whether the core actor holds the entry of `file_hash`, and it is
    /// `download_id`'s.
    pub(crate) fn held_by_actor(&self, file_hash: FileHash, download_id: DownloadId) -> bool {
        self.lock().entries.get(&file_hash).is_some_and(|entry| {
            entry.holder == Holder::Actor && entry.served.download_id == download_id
        })
    }

    /// The **Offer Check** found the parts `records` names still holding in
    /// the file `identity` names (ADR-0113 §"A paused download"): the entry
    /// the actor holds for `download_id` takes them as its range, against the
    /// set it holds, and that file as its identity. The actor looks at what
    /// this moved itself. `false` when the entry is gone, another download's,
    /// or a run holds it.
    pub(crate) fn offer_checked(
        &self,
        file_hash: FileHash,
        download_id: DownloadId,
        records: &[VerifiedPartRecord],
        identity: PartFileIdentity,
    ) -> bool {
        let mut guard = self.lock();
        let book = &mut *guard;
        let Some(entry) = book.entries.get_mut(&file_hash).filter(|entry| {
            entry.holder == Holder::Actor && entry.served.download_id == download_id
        }) else {
            return false;
        };
        entry.emptied = false;
        entry.served.range = VerifiedRange::of_records(entry.served.set.as_ref(), records);
        entry.served.identity = Some(identity);
        book.version += 1;
        true
    }

    /// Run `write` on the entry `lease` holds and bump the offer generation
    /// when it changed whether the entry is offered. `false` when the lease's
    /// run no longer holds the entry.
    fn write(&self, lease: &RunLease, write: impl FnOnce(&mut Entry)) -> bool {
        let mut guard = self.lock();
        let book = &mut *guard;
        let was = book.offered(lease.file_hash);
        let Some(entry) = book.leased(lease) else {
            return false;
        };
        write(entry);
        let now = book.offered(lease.file_hash);
        let entry = book.leased(lease).expect("written above");
        if was && !now {
            entry.withdrawn = Some(PartialEnd::Changed);
        }
        if !was && now {
            entry.offered_since_look = true;
        }
        book.version += 1;
        drop(guard);
        if was != now {
            self.offers.send_modify(|generation| *generation += 1);
        }
        true
    }
}

/// A run's lease on its download's entry: the only way a run writes it, and
/// good only while the actor has not taken it back.
pub(crate) struct RunLease {
    cell: ServedDownloads,
    file_hash: FileHash,
    run: RunNumber,
}

impl RunLease {
    /// Open the entry's inbox: the askers the serve side hands this run from
    /// now on, in place of any inbox an earlier pass of the run opened.
    /// `None` when the run no longer holds the entry.
    pub(crate) fn take_askers(&self) -> Option<mpsc::Receiver<SourceSighting>> {
        let (askers, inbox) = mpsc::channel(ASKER_INBOX);
        let mut guard = self.cell.lock();
        let book = &mut *guard;
        book.leased(self)?.askers = Some(askers);
        book.version += 1;
        Some(inbox)
    }

    /// The source-exchange pool the run's Source Book holds now; the cell's
    /// version moves only when it differs from the one held.
    pub(crate) fn record_pool(&self, pool: ExchangePool) -> bool {
        let mut guard = self.cell.lock();
        let book = &mut *guard;
        let Some(entry) = book.leased(self) else {
            return false;
        };
        if entry.served.pool != pool {
            entry.served.pool = pool;
            book.version += 1;
        }
        true
    }

    /// Rule the Verified Range from the part hash set in force and the parts
    /// the store records: `set` becomes the entry's set when it is whole.
    pub(crate) fn record_range(&self, set: &[PartHash], records: &[VerifiedPartRecord]) -> bool {
        self.cell.write(self, |entry| {
            let served = &mut entry.served;
            if let Some(whole) = WholeSet::of(served.file_size, set) {
                served.set = Some(whole);
            }
            served.range = if entry.emptied {
                VerifiedRange::default()
            } else {
                VerifiedRange::of_records(served.set.as_ref(), records)
            };
        })
    }

    /// The file the run holds, as it read it through its handle: a range a
    /// read emptied may be ruled again from here.
    pub(crate) fn record_identity(&self, identity: PartFileIdentity) -> bool {
        self.cell.write(self, |entry| {
            entry.served.identity = Some(identity);
            entry.emptied = false;
        })
    }

    /// The finished file is in place at `path`, the destination the
    /// completion move chose (ADR-0115), `identity` the file that holds the
    /// bytes now: the entry is read from there, still under the download's
    /// name.
    pub(crate) fn bytes_in_place(
        &self,
        path: &std::path::Path,
        identity: Option<PartFileIdentity>,
    ) -> bool {
        self.cell.write(self, |entry| {
            let served = &mut entry.served;
            served.final_path = path.to_path_buf();
            served.bytes_at = BytesAt::FinalFile;
            served.identity = identity;
            entry.emptied &= identity.is_none();
        })
    }
}

#[cfg(test)]
pub(crate) mod leased;
#[cfg(test)]
mod tests;
