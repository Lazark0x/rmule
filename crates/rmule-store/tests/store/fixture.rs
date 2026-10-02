//! The two backends every leg runs against and the record kinds the legs
//! share. [`Backend::Memory`] keeps its bytes behind an `Arc` and hands the
//! engine a delegating [`StorageBackend`], so a "reopen" — the ladder's and
//! the version refusal's whole subject — works in memory exactly as on disk.

use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use rmule_store::redb::backends::InMemoryBackend;
use rmule_store::{
    Indexed, Ladder, MultimapIndex, Record, Schema, StorageBackend, Store, StoreError, UniqueIndex,
};
use serde::{Deserialize, Serialize};

/// The download-shaped record the index legs exercise: one unique index on
/// the part path, one multimap index on `(file_hash, size)`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Download {
    pub name: String,
    pub size: u64,
    pub part_path: String,
    pub file_hash: [u8; 16],
}

impl Record for Download {
    const NAME: &'static str = "download";
    const VERSION: u32 = 1;
}

/// `Download`'s next shape: same name, one more field, version bumped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadV2 {
    pub name: String,
    pub size: u64,
    pub part_path: String,
    pub file_hash: [u8; 16],
    pub trail: String,
}

impl Record for DownloadV2 {
    const NAME: &'static str = "download";
    const VERSION: u32 = 2;
}

pub static PART_PATH: UniqueIndex<&'static str, u64, Download> =
    UniqueIndex::new("download.part_path", |d| d.part_path.as_str());

pub static IDENTITY: MultimapIndex<([u8; 16], u64), u64, Download> =
    MultimapIndex::new("download.identity", |d| (d.file_hash, d.size));

pub static DOWNLOADS: Indexed<u64, Download> = Indexed::new("download", &[&PART_PATH, &IDENTITY]);

pub static DOWNLOADS_V2: Indexed<u64, DownloadV2> = Indexed::new("download", &[]);

pub const V1: Ladder = Ladder::new(1, &[]);

pub fn schema_v1() -> Schema {
    Schema::new().indexed(&DOWNLOADS)
}

pub fn download(n: u64) -> Download {
    Download {
        name: format!("file-{n}"),
        size: 1000 + n,
        part_path: format!("/tmp/{n}.part"),
        file_hash: [n as u8; 16],
    }
}

/// An in-memory backend the fixture keeps hold of across reopens.
#[derive(Debug, Clone)]
pub struct SharedMemory(Arc<InMemoryBackend>);

impl StorageBackend for SharedMemory {
    fn len(&self) -> io::Result<u64> {
        self.0.len()
    }
    fn read(&self, offset: u64, out: &mut [u8]) -> io::Result<()> {
        self.0.read(offset, out)
    }
    fn set_len(&self, len: u64) -> io::Result<()> {
        self.0.set_len(len)
    }
    fn sync_data(&self) -> io::Result<()> {
        self.0.sync_data()
    }
    fn write(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        self.0.write(offset, data)
    }
}

pub enum Backend {
    File {
        _dir: tempfile::TempDir,
        path: PathBuf,
    },
    Memory(SharedMemory),
}

impl Backend {
    pub fn both() -> [Backend; 2] {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("rmule.redb");
        [
            Backend::File { _dir: dir, path },
            Backend::Memory(SharedMemory(Arc::new(InMemoryBackend::new()))),
        ]
    }

    pub fn label(&self) -> &'static str {
        match self {
            Backend::File { .. } => "file",
            Backend::Memory(_) => "memory",
        }
    }

    pub fn open(&self, schema: &Schema, ladder: &Ladder) -> Result<Store, StoreError> {
        match self {
            Backend::File { path, .. } => Store::open(path, schema, ladder),
            Backend::Memory(memory) => Store::open_backend(memory.clone(), schema, ladder),
        }
    }
}

/// Run `check` once per backend, naming the backend on failure.
pub fn on_each_backend(check: impl Fn(&Backend)) {
    for backend in Backend::both() {
        let label = backend.label();
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| check(&backend)));
        assert!(outcome.is_ok(), "failed on the {label} backend");
    }
}
