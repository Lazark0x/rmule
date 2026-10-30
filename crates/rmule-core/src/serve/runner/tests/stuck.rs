//! The serve loop never waits on a peer or a disk (ADR-0031). A connection
//! nobody reads and a file whose open parks stand in for a stuck peer and a
//! slow disk; no test here sleeps, and each bound only fails a loop that never
//! answers.

use super::aich::{said, serving, shared};
use super::*;
use rmule_peer::PartRanges;

/// More than the link's two queues hold, so a loop that waits for room parks.
const MORE_THAN_THE_QUEUES_HOLD: usize = 40;

fn status_ask(file_hash: FileHash) -> ServeInput {
    ServeInput::Server(ServerEvent::FileIdSet { file_hash })
}

fn hello(byte: u8) -> ServeInput {
    HelloFacts::of(UserHash::from_bytes([byte; UserHash::BYTE_LEN])).identified()
}

fn first_block_ask(file_hash: FileHash, len: u64) -> ServeInput {
    ServeInput::Server(ServerEvent::PartsRequested {
        file_hash,
        ranges: PartRanges::new([(0, len), (0, 0), (0, 0)]),
    })
}

async fn a_shared_file(
    dir: &tempfile::TempDir,
    registry: &DurableSharedFileRegistry,
    byte: u8,
) -> FileHash {
    let path = dir.path().join(format!("{byte}.bin"));
    std::fs::write(&path, vec![byte; 4096]).unwrap();
    shared(registry, byte, 4096, path)
}

#[tokio::test]
async fn a_peer_that_stops_reading_holds_no_other_peer_up() {
    let dir = tempfile::tempdir().unwrap();
    let store = rmule_testkit::memory_store();
    let registry = DurableSharedFileRegistry::new(store.clone());
    let file = a_shared_file(&dir, &registry, 0x51).await;
    let rig = serving(registry, store).await;

    let (stuck, _nobody_reads) = rig.link(peer_at([198, 51, 100, 3], 4000)).await;
    let (other, mut other_rx) = rig.link(peer_at([198, 51, 100, 4], 4000)).await;
    stuck.send(hello(0x0D)).await.unwrap();
    other.send(hello(0x0E)).await.unwrap();
    tokio::spawn(async move {
        for _ in 0..MORE_THAN_THE_QUEUES_HOLD {
            if stuck.send(status_ask(file)).await.is_err() {
                return;
            }
        }
        stuck.closed().await;
    });

    // Asked as often as the stuck peer does, so these outlast whatever part of
    // its flood the loop has not reached yet.
    for _ in 0..2 * MORE_THAN_THE_QUEUES_HOLD {
        other.send(status_ask(file)).await.unwrap();
        assert!(matches!(
            said(&mut other_rx, "another peer's ask answered").await,
            ServerCommand::AnswerFileStatus { .. }
        ));
    }
    rig.stop().await;
}

/// The open of a pipe nobody writes parks, as a dead mount does, and the
/// write end this opens as it drops lets the read end the test.
#[cfg(unix)]
struct ParkedOpen(std::path::PathBuf);

#[cfg(unix)]
impl ParkedOpen {
    fn at(path: std::path::PathBuf) -> Self {
        let made = std::process::Command::new("mkfifo").arg(&path).status();
        assert!(made.unwrap().success());
        Self(path)
    }
}

#[cfg(unix)]
impl Drop for ParkedOpen {
    fn drop(&mut self) {
        let _ = std::fs::OpenOptions::new().write(true).open(&self.0);
    }
}

#[cfg(unix)]
#[tokio::test]
async fn a_read_parked_on_its_file_holds_no_other_peer_up() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("mounted.bin");
    let parked = ParkedOpen::at(path.clone());
    let store = rmule_testkit::memory_store();
    let registry = DurableSharedFileRegistry::new(store.clone());
    let slow = shared(&registry, 0x52, 4096, path);
    let ready = a_shared_file(&dir, &registry, 0x53).await;
    let rig = serving(registry, store).await;

    let (holder, mut holder_rx) = rig.link(peer_at([198, 51, 100, 3], 4000)).await;
    let (other, mut other_rx) = rig.link(peer_at([198, 51, 100, 4], 4000)).await;
    holder.send(hello(0x0D)).await.unwrap();
    other.send(hello(0x0E)).await.unwrap();
    holder
        .send(ServeInput::Server(ServerEvent::SlotRequested {
            file_hash: slow,
        }))
        .await
        .unwrap();
    assert!(matches!(
        said(&mut holder_rx, "the slot granted").await,
        ServerCommand::GrantSlot { .. }
    ));
    holder.send(first_block_ask(slow, 4096)).await.unwrap();
    // Follows the block ask into the loop: a loop in the read never gets here.
    holder.send(status_ask(ready)).await.unwrap();
    assert!(matches!(
        said(&mut holder_rx, "the holder's next ask answered").await,
        ServerCommand::AnswerFileStatus { .. }
    ));

    other.send(status_ask(ready)).await.unwrap();
    assert!(matches!(
        said(&mut other_rx, "another peer's ask answered").await,
        ServerCommand::AnswerFileStatus { .. }
    ));
    drop(parked);
    rig.stop().await;
}

/// The connection's command side filled and nobody takes from it: the link's
/// task waits on it, and what the peer says still reaches the loop, so the
/// close frees the slot.
#[tokio::test]
async fn a_link_waiting_on_its_connection_still_hears_the_peer() {
    let dir = tempfile::tempdir().unwrap();
    let store = rmule_testkit::memory_store();
    let registry = DurableSharedFileRegistry::new(store.clone());
    let file = a_shared_file(&dir, &registry, 0x54).await;
    let rig = serving(registry, store).await;

    let (stuck, mut unread) = rig.link(peer_at([198, 51, 100, 3], 4000)).await;
    let (waiter, mut waiter_rx) = rig.link(peer_at([198, 51, 100, 4], 4000)).await;
    stuck.send(hello(0x0D)).await.unwrap();
    waiter.send(hello(0x0E)).await.unwrap();
    let slot = ServeInput::Server(ServerEvent::SlotRequested { file_hash: file });
    stuck.send(slot.clone()).await.unwrap();
    assert!(matches!(
        said(&mut unread, "the slot granted").await,
        ServerCommand::GrantSlot { .. }
    ));
    waiter.send(slot).await.unwrap();
    assert!(matches!(
        said(&mut waiter_rx, "the waiter ranked").await,
        ServerCommand::SetQueueRank { .. }
    ));

    for _ in 0..MORE_THAN_THE_QUEUES_HOLD {
        stuck.send(status_ask(file)).await.unwrap();
    }
    stuck
        .send(ServeInput::Connection(
            rmule_peer::ConnectionEvent::Disconnected {
                reason: rmule_peer::PeerCloseReason::Local,
            },
        ))
        .await
        .unwrap();

    assert!(matches!(
        said(&mut waiter_rx, "the freed slot granted").await,
        ServerCommand::GrantSlot { .. }
    ));
    rig.stop().await;
}

/// A slot held over a connection that ends under a block goes to the next
/// waiter: the link says it ended though no event of the peer's reached it.
#[tokio::test]
async fn a_connection_gone_under_a_command_frees_its_slot() {
    let dir = tempfile::tempdir().unwrap();
    let store = rmule_testkit::memory_store();
    let registry = DurableSharedFileRegistry::new(store.clone());
    let file = a_shared_file(&dir, &registry, 0x55).await;
    let rig = serving(registry, store).await;

    let (holder, mut holder_rx) = rig.link(peer_at([198, 51, 100, 3], 4000)).await;
    let (waiter, mut waiter_rx) = rig.link(peer_at([198, 51, 100, 4], 4000)).await;
    holder.send(hello(0x0D)).await.unwrap();
    waiter.send(hello(0x0E)).await.unwrap();
    let slot = ServeInput::Server(ServerEvent::SlotRequested { file_hash: file });
    holder.send(slot.clone()).await.unwrap();
    assert!(matches!(
        said(&mut holder_rx, "the slot granted").await,
        ServerCommand::GrantSlot { .. }
    ));
    waiter.send(slot).await.unwrap();
    assert!(matches!(
        said(&mut waiter_rx, "the waiter ranked").await,
        ServerCommand::SetQueueRank { .. }
    ));

    // The driver is gone: both ends of the connection close, the command
    // side first, and an output finds that out.
    drop(holder_rx);
    holder.send(status_ask(file)).await.unwrap();
    tokio::task::yield_now().await;
    drop(holder);

    assert!(matches!(
        said(&mut waiter_rx, "the freed slot granted").await,
        ServerCommand::GrantSlot { .. }
    ));
    rig.stop().await;
}

/// Asks with nobody reading the answers fill the outbox, and the link ends at
/// once: the loop does not wait for the socket's bound to say so.
#[tokio::test]
async fn a_full_outbox_ends_its_link() {
    let dir = tempfile::tempdir().unwrap();
    let store = rmule_testkit::memory_store();
    let registry = DurableSharedFileRegistry::new(store.clone());
    let file = a_shared_file(&dir, &registry, 0x56).await;
    let rig = serving(registry, store).await;

    let (flooder, unread) = rig.link(peer_at([198, 51, 100, 3], 4000)).await;
    flooder.send(hello(0x0D)).await.unwrap();
    let flood = async {
        // Outbox, the waiting output and the connection's own queue, past.
        for _ in 0..200 {
            if flooder.send(status_ask(file)).await.is_err() {
                return;
            }
        }
        flooder.closed().await;
    };

    timeout(Duration::from_secs(5), flood)
        .await
        .expect("the link ended");
    drop(unread);
    rig.stop().await;
}
