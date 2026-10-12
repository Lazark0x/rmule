//! What the legs of this binary share: the recorded frames under
//! `tests/fixtures/`, the identity a test session logs in with, and the three
//! states a session leg starts from — new, started, logged in.
//!
//! `Ed2kSession` is sans-I/O, so a leg needs no sockets, no runtime, and no
//! fakes. Anything a second crate would want lives in `rmule-testkit` instead
//! — the login identity below is that crate's `test_identity`, pinned to this
//! crate's nickname and port.

use std::fs;
use std::path::{Path, PathBuf};

use rmule_ed2k::{Ed2kEvent, Ed2kSession, Output, ServerTcpFlags};
use rmule_primitives::session::drain;
use rmule_primitives::{ClientIdentity, FileHash, Packet, PacketProtocol, ServerEndpoint};

// ---- recorded bytes ---------------------------------------------------------

/// The root every fixture path in this crate is relative to.
fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// A recorded frame under `tests/fixtures/`, by path.
pub fn bytes(path: &str) -> Vec<u8> {
    let full = fixtures().join(path);
    fs::read(&full).unwrap_or_else(|error| panic!("read fixture {}: {error}", full.display()))
}

/// One packet slice of a capture session: `tests/fixtures/server/captured/`,
/// then the dated capture directory, then the file.
pub fn captured(capture: &str, name: &str) -> Vec<u8> {
    bytes(&format!("server/captured/{capture}/{name}"))
}

/// Every `.toml` case under `tests/fixtures/<family>`, sorted by path so a
/// failure names the same case on every run.
pub fn case_paths(family: &str) -> Vec<PathBuf> {
    let root = fixtures().join(family);
    let mut entries = fs::read_dir(root)
        .unwrap_or_else(|error| panic!("{family} fixture directory: {error}"))
        .map(|entry| entry.expect("fixture entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
        .collect::<Vec<_>>();
    entries.sort();
    entries
}

/// The same cases, narrowed to one packet family by filename prefix — the
/// fixture directories hold every opcode of a direction side by side.
pub fn case_paths_named(family: &str, prefix: &str) -> Vec<PathBuf> {
    case_paths(family)
        .into_iter()
        .filter(|path| {
            path.file_stem()
                .is_some_and(|stem| stem.to_string_lossy().starts_with(prefix))
        })
        .collect()
}

/// The capture directories under `root` that hold a `marker` file — the marker
/// is what makes a directory a capture of that kind rather than a sibling note.
pub fn capture_dirs(root: &Path, marker: &str) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(root) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = entries
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| path.is_dir() && path.join(marker).is_file())
        .collect();
    out.sort();
    out
}

// ---- values a leg builds a request from -------------------------------------

/// A file hash of one repeated byte — enough to tell two files apart.
pub fn hash(byte: u8) -> FileHash {
    FileHash::from_bytes([byte; FileHash::BYTE_LEN])
}

// ---- the session under test -------------------------------------------------

/// The endpoint a test session dials. It is never resolved: the session is
/// sans-I/O, so the host only has to be a legal one.
pub fn endpoint() -> ServerEndpoint {
    ServerEndpoint::new("example.invalid", 4661).expect("test endpoint")
}

/// The identity a test session logs in with: `user_hash_byte` repeated, the
/// nickname `rmule-test`, the default eD2k TCP port, protocol version 60.
pub fn identity(user_hash_byte: u8) -> ClientIdentity {
    rmule_testkit::test_identity(user_hash_byte, "rmule-test", 4662)
}

/// A session that has not started yet — the leg drives `start` itself.
pub fn session(user_hash_byte: u8) -> Ed2kSession {
    Ed2kSession::new(endpoint(), identity(user_hash_byte))
}

/// Start a session and consume its two start outputs, asserting rather than
/// draining: `start` owes exactly a `LoginRequested` event and the login write.
/// A leg that configures the session first (capabilities, say) starts it here.
pub fn start(session: &mut Ed2kSession) {
    session.start();
    assert!(matches!(
        session.poll_output(),
        Some(Output::Event(Ed2kEvent::LoginRequested { .. }))
    ));
    assert!(matches!(session.poll_output(), Some(Output::Write(_))));
}

/// A session already started, for the legs that only care about what comes
/// after.
pub fn started_session(user_hash_byte: u8) -> Ed2kSession {
    let mut session = session(user_hash_byte);
    start(&mut session);
    session
}

/// A session that has also consumed the recorded Lugdunum `OP_IDCHANGE`, so
/// it holds a real client id and the server's TCP flags.
pub fn logged_in_session(user_hash_byte: u8) -> Ed2kSession {
    let mut session = started_session(user_hash_byte);
    session.handle_bytes(&bytes("login/id_change_with_tcp_flags.bin"));
    drain(|| session.poll_output());
    session
}

/// Log a started session in with a synthetic `OP_IDCHANGE` carrying client id
/// 1 and, optionally, the server's TCP flags extension.
pub fn login_with_flags(session: &mut Ed2kSession, flags: Option<ServerTcpFlags>) {
    login_as(session, 1, flags);
}

/// Log in holding the server-assigned `client_id`.
pub fn login_as(session: &mut Ed2kSession, client_id: u32, flags: Option<ServerTcpFlags>) {
    let mut payload = client_id.to_le_bytes().to_vec();
    if let Some(flags) = flags {
        payload.extend_from_slice(&flags.bits().to_le_bytes());
    }
    session.handle_bytes(&Packet::new(PacketProtocol::Edonkey, 0x40, payload).encode());
    assert!(matches!(
        session.poll_output(),
        Some(Output::Event(Ed2kEvent::LoginAccepted { .. }))
    ));
}
