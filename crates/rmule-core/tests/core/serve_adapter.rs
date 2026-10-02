//! The serve adapter handle round-trips a command to the runtime and an
//! event back, exactly like `PeerWorker` on the download side.
use rmule_core::{ServeConnCommand, ServeConnEvent, ServeConnection};
use rmule_primitives::{ClientId, FileHash, PeerSource};
use tokio::sync::mpsc;

#[tokio::test]
async fn serve_connection_forwards_commands_and_yields_events() {
    let peer = PeerSource::new(ClientId::from_u32(0x0100_007F), 5000)
        .as_peer_endpoint()
        .unwrap();
    let (cmd_tx, mut cmd_rx) = mpsc::channel(4);
    let (evt_tx, evt_rx) = mpsc::channel(4);
    let mut conn = ServeConnection::new(peer, cmd_tx, evt_rx);

    let file_hash = FileHash::from_bytes([0x05; FileHash::BYTE_LEN]);
    evt_tx
        .send(ServeConnEvent::SlotRequested { file_hash })
        .await
        .unwrap();
    assert_eq!(conn.peer(), peer);
    assert_eq!(
        conn.next_event().await,
        Some(ServeConnEvent::SlotRequested { file_hash })
    );

    conn.send(ServeConnCommand::GrantSlot { file_hash })
        .await
        .unwrap();
    assert_eq!(
        cmd_rx.recv().await,
        Some(ServeConnCommand::GrantSlot { file_hash })
    );
}
