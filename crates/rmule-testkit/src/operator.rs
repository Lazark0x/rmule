//! The operator's word, as a test gives it: nothing in core dials a server
//! but the operator's connect (ADR-0095, "Connecting is the operator's act"),
//! so a leg that needs a session says so the way a front end does — list the
//! server, then connect to it; and nothing is shared but a directory the
//! operator added and confirmed (ADR-0101, "Shared Directories").

use std::path::Path;

use rmule_core::{
    ClientCredentials, Core, CoreCommand, CoreEvent, ManagedServer, ScanCommand, ScanEvent,
    ServeEvent, ServerListCommand,
};
use rmule_primitives::{FileHash, ServerEndpoint};
use tokio::time::{Duration, timeout};

/// List `server` and send the operator's `ConnectToServer` to it, as the
/// TUI's `c` does. Returns once core has both commands; the connect's trail
/// (`Connecting` → `Connected` / `ConnectFailed`) follows on the event stream,
/// and every download or search already waiting rides the session it makes.
///
/// # Panics
/// Core refused a command (it has stopped).
pub async fn connect_to(core: &Core, server: &ServerEndpoint, credentials: ClientCredentials) {
    core.send(CoreCommand::ServerList(ServerListCommand::AddServer {
        server: ManagedServer::listed(server.clone()),
    }))
    .await
    .expect("core accepts the server");
    core.send(CoreCommand::ConnectToServer {
        server: server.clone(),
        credentials,
    })
    .await
    .expect("core accepts the connect");
}

/// Share `dir` as the operator does: add it to the **Shared Directory List**,
/// answer its confirm yes, and wait for its first pass to end. Returns every
/// file the pass shared, in the order shared. Every other event met on the
/// way is dropped, so a leg shares before it starts what it watches.
///
/// # Panics
/// The add was refused, the pass did not end within 10 s, or core stopped.
pub async fn share_directory(core: &mut Core, dir: &Path) -> Vec<FileHash> {
    core.send(CoreCommand::Scan(ScanCommand::AddSharedDirectory {
        path: dir.to_path_buf(),
    }))
    .await
    .expect("core accepts the add");
    let mut shared = Vec::new();
    timeout(Duration::from_secs(10), async {
        loop {
            match core.next_event().await.expect("core event stream open") {
                CoreEvent::Scan(ScanEvent::ConsentRequested { dir, .. }) => core
                    .send(CoreCommand::Scan(ScanCommand::Answer { dir, share: true }))
                    .await
                    .expect("core accepts the answer"),
                CoreEvent::Scan(ScanEvent::DirectoryRefused { reason, .. }) => {
                    panic!("the add was refused: {reason:?}")
                }
                CoreEvent::Serve(ServeEvent::FileShared { file_hash }) => shared.push(file_hash),
                CoreEvent::Scan(ScanEvent::Finished { .. }) => return,
                _ => {}
            }
        }
    })
    .await
    .expect("the shared directory's pass ended within 10 s");
    shared
}
