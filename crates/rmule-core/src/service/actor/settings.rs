//! The actor's half of **Core Settings** (ADR-0069): a live key the
//! operator changed through a running core's handle, already persisted, taken
//! up where the state it changes lives.

use crate::CoreEvent;
use crate::adapters::{
    KadRuntimeFactory, PeerTransferService, ServeRuntimeService, SourceLookupService,
};
use crate::settings::LiveSetting;

use super::CoreActor;

impl<S, P, L, K> CoreActor<S, P, L, K>
where
    S: SourceLookupService,
    P: PeerTransferService,
    L: ServeRuntimeService,
    K: KadRuntimeFactory,
{
    /// Take up one live setting.
    pub(super) async fn on_live_setting(&mut self, live: LiveSetting) {
        match live {
            LiveSetting::RememberPeers(peers) => self.remember_peers = peers,
            LiveSetting::ServerPolicy(policy) => self.on_set_server_policy(policy),
            // The confirm's yes first, so the new directory's scan asks
            // nothing more and a scan already waiting on it is released
            // (ADR-0101); then the directory moves.
            LiveSetting::DownloadDir {
                dir,
                share_confirmed,
            } => {
                if share_confirmed {
                    self.on_scan_command(crate::ScanCommand::Answer {
                        dir: dir.clone(),
                        share: true,
                    })
                    .await;
                }
                self.download_directory(dir).await;
            }
            // Downloads already placed keep the paths their rows hold; the
            // list is judged again against the new Temp Directory (ADR-0115).
            LiveSetting::TempDir(dir) => self.temp_directory_moved(dir).await,
            LiveSetting::Obfuscation(policy) => self.on_set_obfuscation(policy).await,
        }
    }

    /// Put the operator's new obfuscation policy in force (ADR-0046): the
    /// one cell every surface reads as it decides, so the next dial, accept,
    /// server login, datagram and crypt-ping follow it, and the Kad pump
    /// re-arms its node on the change. A connection that already negotiated
    /// keeps what it agreed. A change is an event, as the start value is, so
    /// the lean Run Log states it.
    async fn on_set_obfuscation(&mut self, policy: Option<rmule_net::peer::ObfuscationPolicy>) {
        if self.wiring.hello_adverts.obfuscation.set(policy) {
            super::send_event(&self.evt_tx, CoreEvent::ObfuscationPolicyChanged { policy }).await;
        }
    }
}
