//! A served block deflated by its link's own task, off the async runtime
//! (ADR-0031): it crosses as the block's stream, to a peer
//! that says it inflates, and plain to one that does not.

use super::aich::{said, serving, shared};
use super::*;
use rmule_peer::PartRanges;

/// Ask `file`'s first `len` bytes on a slot, as `hello` says, and return what
/// the block crossed as.
async fn served_as(
    hello: HelloFacts,
    file: FileHash,
    len: u64,
    rig: &aich::ServeRig,
) -> ServerCommand {
    let (conn, mut rx) = rig.link(peer_at([198, 51, 100, 9], 4000)).await;
    conn.send(hello.identified()).await.unwrap();
    conn.send(ServeInput::Server(ServerEvent::SlotRequested {
        file_hash: file,
    }))
    .await
    .unwrap();
    assert!(matches!(
        said(&mut rx, "a slot granted").await,
        ServerCommand::GrantSlot { .. }
    ));
    conn.send(ServeInput::Server(ServerEvent::PartsRequested {
        file_hash: file,
        ranges: PartRanges::new([(0, len), (0, 0), (0, 0)]),
    }))
    .await
    .unwrap();
    said(&mut rx, "the block").await
}

#[tokio::test]
async fn a_block_crosses_deflated_to_a_peer_that_inflates_and_plain_to_one_that_does_not() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("text.bin");
    let bytes = b"a served block of source text, ".repeat(600);
    std::fs::write(&path, &bytes).unwrap();
    let len = bytes.len() as u64;

    for (claim, deflated) in [(1, true), (0, false)] {
        let store = rmule_testkit::memory_store();
        let registry = DurableSharedFileRegistry::new(store.clone());
        let file = shared(&registry, 0x43, len, path.clone());
        let rig = serving(registry, store).await;
        let hello = HelloFacts {
            data_compression_version: claim,
            ..HelloFacts::of(UserHash::from_bytes([0x0F; UserHash::BYTE_LEN]))
        };

        match served_as(hello, file, len, &rig).await {
            ServerCommand::SendDeflatedBlock {
                start, end, stream, ..
            } if deflated => {
                assert_eq!((start, end), (0, len));
                assert_eq!(Some(stream), rmule_peer::deflate_block(&bytes));
            }
            ServerCommand::SendBlock { bytes: plain, .. } if !deflated => {
                assert_eq!(plain, bytes);
            }
            other => panic!("claim {claim}: {other:?}"),
        }
        rig.stop().await;
    }
}
