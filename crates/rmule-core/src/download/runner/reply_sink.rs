//! The download's install on the shared client-UDP socket's **Reask Routes**
//! (ADR-0057, ADR-0107): the reply quartet (`0x91`/`0x92`/`0x93`) for the pings
//! this download sends reaches its runner through the sink it installs, for as
//! long as the run lives. The runner hands each reply to the brain, which reads
//! it.

use tokio::sync::mpsc;

use crate::client_udp::ClientUdpDatagram;
use crate::service::{DownloadId, SharedReaskReplySink};

/// RAII lease on one download's reply-sink install in the shared **Reask
/// Routes**: removes that install and its pings in flight — and only those —
/// on drop, so a finished download stops receiving reask replies while the
/// downloads beside it keep theirs.
pub(super) struct ReaskSinkLease {
    sink: SharedReaskReplySink,
    download_id: DownloadId,
}

impl ReaskSinkLease {
    /// Install `reply_tx` as `download_id`'s reply sink for the lease's life.
    pub(super) fn install(
        sink: SharedReaskReplySink,
        download_id: DownloadId,
        reply_tx: mpsc::Sender<ClientUdpDatagram>,
    ) -> Self {
        sink.lock()
            .expect("reask reply sink mutex")
            .install(download_id, reply_tx);
        Self { sink, download_id }
    }
}

impl Drop for ReaskSinkLease {
    fn drop(&mut self) {
        self.sink
            .lock()
            .expect("reask reply sink mutex")
            .remove(self.download_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two downloads of the **Download Set** hold installs side by side, and
    /// one ending removes only its own — the other keeps its replies.
    #[test]
    fn a_sink_lease_removes_only_its_own_install() {
        let sink = SharedReaskReplySink::default();
        let (first_tx, _first_rx) = mpsc::channel(1);
        let (second_tx, _second_rx) = mpsc::channel(1);
        let first = ReaskSinkLease::install(sink.clone(), DownloadId::from_u64(1), first_tx);
        let _second = ReaskSinkLease::install(sink.clone(), DownloadId::from_u64(2), second_tx);
        assert_eq!(sink.lock().unwrap().installed(), 2);

        drop(first);
        assert_eq!(sink.lock().unwrap().installed(), 1);
    }
}
