//! The app's **Kad join**: assemble the start config from durable
//! identity + data dir, resolve its seeds, and send the one
//! [`CoreCommand::EnableKad`] the shipped app was missing.
//!
//! # Why the app drives this and not the core Join Sequence
//!
//! ADR-0067's [`run_join_sequence`](rmule_core::run_join_sequence) is the same
//! orchestration, and the Kad leg here is deliberately its
//! [`acquire_kad_seeds`] call verbatim — one seed policy, not two. What the app
//! cannot reuse is the *whole* sequence: its eD2k leg writes the managed
//! server list through a `&dyn ServerListStore`, and once [`attach`](crate::attach) has
//! handed that seam to `CoreBuilder::server_list` the actor is the list's only
//! writer (ADR-0080) — the front-end's own clone of the handle is for reading
//! preferences, not for writing beside the actor. The Kad leg needs no store
//! at all, so it runs here, through the same [`CoreClient`] door every other
//! UI command uses.
//!
//! # Kad starts on the first eD2k connect, or on the operator's `K`
//!
//! The join waits on its start lane. The app sends on it once for the run's
//! first [`ServerConnectionEvent::Connected`] edge — the sequencing an
//! hands-on run asked for, hung on the *login* rather than on the keystroke —
//! and again each time the operator presses `K` in Networks while Kad reads
//! off. Kad has its own switch because the two networks are separate: in aMule
//! each connects and disconnects on its own (ADR-0093, "Kad after a
//! disconnect"), so leaving the server leaves Kad running, and an operator can
//! run Kad without ever connecting to a server.
//!
//! - **Nothing unattended reaches Kad.** The app is the single
//!   consumer that flips `BootstrapConfig::auto_fetch_nodes_dat` on (ADR-0067).
//!   Behind the start lane that opt-in can only run after
//!   the operator has said "connect me" or "start Kad", which is aMule's
//!   posture for `UpdateNotesDat` — user-triggered only.
//! - **The first login starts Kad once.** A reconnect, a server switch or a
//!   second login finds the first-login start spent, and so does a login
//!   after the operator's own `K`: a Kad the operator stopped stays stopped.
//!   A duplicate start while a node runs is ignored by core.
//!
//! Networks' `c` is the eD2k dial and nothing else; `K` is Kad's. The Networks panel
//! reports core's Kad state throughout (`DiagnosticsSnapshot::kad_state`).
//!
//! [`ServerConnectionEvent::Connected`]: rmule_core::ServerConnectionEvent::Connected

use rmule_bootstrap::{BootstrapConfig, Fetcher};
use rmule_core::{
    ClientCredentials, CoreCommand, KadEnableConfig, KadIdentity, KadSeedOutcome, acquire_kad_seeds,
};

use crate::client::{CoreClient, CoreClientError};

/// The app's half of the Kad start lane: the [`App`] sends on it
/// for the run's first eD2k login and for each `K` the operator presses while
/// Kad is off.
///
/// [`App`]: crate::app::App
pub type KadStarter = tokio::sync::mpsc::UnboundedSender<()>;

/// The join task's half of the start lane; see [`start_lane`].
pub type KadStarts = tokio::sync::mpsc::UnboundedReceiver<()>;

/// The lane that sequences each join behind a start request. Dropping the
/// [`KadStarter`] — the app quitting — ends [`join_on_next_start`] having
/// touched nothing.
#[must_use]
pub fn start_lane() -> (KadStarter, KadStarts) {
    tokio::sync::mpsc::unbounded_channel()
}

/// Assemble the Kad start config from what startup already loaded: the TUI
/// installs no shutdown lever
/// of its own — the core's quit stops Kad through the activity's own lever —
/// so `kad_shutdown` stays `None` here, unlike `ed2k serve start`'s `--kad`
/// flag, whose lever confirms the tap finalized.
///
/// Front-end-owned config (ADR-0069): the durable [`KadIdentity`], the
/// **Kad UDP Key** and the Client Identity come from the app's store, the
/// persisted routing table from its data dir. Seeds are left empty — [`join`]
/// resolves them.
#[must_use]
pub fn enable_config(
    data_dir: &std::path::Path,
    kad: KadIdentity,
    kad_udp_key: u32,
    credentials: &ClientCredentials,
) -> KadEnableConfig {
    KadEnableConfig {
        kad_id: kad.id,
        // Their port is the one peers are told to dial for the eD2k half of a
        // Kad answer — the same one the Client Identity advertises everywhere
        // else, carried once.
        peer_credentials: credentials.clone(),
        bootstrap: Vec::new(),
        contacts: Vec::new(),
        // Beside `rmule.redb` / `clients.met` (ADR-0069, ADR-0083): the
        // running node writes its routing table here, and the next start reads
        // it back as seeds.
        nodes_dat_path: Some(data_dir.join("nodes.dat")),
        // A deployment keeps the live ADR-0058 verdicts: a genuinely firewalled
        // node must not claim openness it has not proven.
        assume_open_reachability: false,
        // Generate-once (`AppConfigStore::ensure_kad_udp_key`): the verify
        // keys the network learned for this node hold across a restart.
        kad_udp_key,
        // No TUI knob: the per-frame tap is a bench diagnostic
        // opt-in (`ed2k serve start --kad-capture-dir`), not a deployment one.
        kad_capture_dir: None,
        // No lever of its own: the core's quit stops Kad.
        kad_shutdown: None,
    }
}

/// Resolve `config`'s seeds and join Kad.
///
/// Returns what the seed resolution found — the caller's honest trail line. The
/// join is sent **whatever** that outcome is, including a stranded one: an
/// empty-table node is what arms the ed2k→Kad handoff (ADR-0067), so
/// withholding the start on "no contacts" would quietly disable the very route
/// that recovers from it.
///
/// # Errors
/// [`CoreClientError::CoreStopped`] if the core is gone; the bus carries its
/// own `CoreClosed` in that case, so a caller has nothing to add.
pub async fn join<C, F>(
    client: &C,
    mut config: KadEnableConfig,
    bootstrap: &BootstrapConfig,
    fetcher: &F,
) -> Result<KadSeedOutcome, CoreClientError>
where
    C: CoreClient,
    F: Fetcher + Sync,
{
    let outcome = acquire_kad_seeds(&mut config, bootstrap, fetcher).await;
    client.send(CoreCommand::EnableKad(config)).await?;
    Ok(outcome)
}

/// Wait for the next start request, then [`join`] with a fresh copy of
/// `config`. `None` once the app has dropped its [`KadStarter`].
pub async fn join_on_next_start<C, F>(
    starts: &mut KadStarts,
    client: &C,
    config: &KadEnableConfig,
    bootstrap: &BootstrapConfig,
    fetcher: &F,
) -> Option<Result<KadSeedOutcome, CoreClientError>>
where
    C: CoreClient,
    F: Fetcher + Sync,
{
    starts.recv().await?;
    Some(join(client, config.clone(), bootstrap, fetcher).await)
}

#[cfg(test)]
mod tests {
    use std::future::Future;
    use std::sync::Mutex;

    use rmule_bootstrap::FetchError;
    use rmule_core::KadId;
    use rmule_primitives::{ClientIdentity, Ed2kText, UserHash};

    use super::*;

    /// Records what reached the core, so the assertion is on the command the
    /// app actually sends — the thing whose absence was the bug.
    #[derive(Default)]
    struct RecordingClient {
        sent: Mutex<Vec<CoreCommand>>,
    }

    impl CoreClient for RecordingClient {
        fn send(
            &self,
            command: CoreCommand,
        ) -> impl Future<Output = Result<(), CoreClientError>> + Send {
            self.sent.lock().unwrap().push(command);
            async { Ok(()) }
        }
    }

    impl RecordingClient {
        fn kad_join(&self) -> KadEnableConfig {
            let sent = self.sent.lock().unwrap();
            match sent.iter().find_map(|c| match c {
                CoreCommand::EnableKad(config) => Some(config.clone()),
                _ => None,
            }) {
                Some(config) => config,
                None => panic!("the app sent no Kad join: {sent:?}"),
            }
        }
    }

    struct FakeFetcher {
        result: Result<Vec<u8>, FetchError>,
        calls: Mutex<usize>,
    }

    impl Fetcher for FakeFetcher {
        fn get(
            &self,
            _url: &str,
            _max_bytes: usize,
        ) -> impl Future<Output = Result<Vec<u8>, FetchError>> + Send {
            *self.calls.lock().unwrap() += 1;
            let result = self.result.clone();
            async move { result }
        }
    }

    fn refusing_fetcher() -> FakeFetcher {
        FakeFetcher {
            result: Err(FetchError::Timeout {
                url: "http://mirror".to_owned(),
            }),
            calls: Mutex::new(0),
        }
    }

    fn credentials() -> ClientCredentials {
        ClientIdentity::new(
            UserHash::from_bytes([0x42; UserHash::BYTE_LEN]),
            Ed2kText::from_utf8("rmule"),
            4662,
            0x3C,
        )
        .into()
    }

    fn kad_identity() -> KadIdentity {
        KadIdentity {
            id: KadId::from_bytes([0x11; KadId::BYTE_LEN]),
            udp_port: 4672,
        }
    }

    fn nodes_dat_v2(count: u8) -> Vec<u8> {
        let contacts: Vec<_> = (1..=count)
            .map(|n| {
                rmule_core::KadContact::new(
                    KadId::from_bytes([n; KadId::BYTE_LEN]),
                    rmule_kad::KadNodeEndpoint::new(std::net::Ipv4Addr::new(203, 0, 113, n), 4672),
                    4662,
                    8,
                )
            })
            .collect();
        rmule_kad::NodesDat::encode_v2(&contacts)
    }

    /// The startup config the app hands core: the durable Kad identity, the
    /// Client Identity's advertised port and hash, and the data-dir file the
    /// running node persists its table to.
    #[test]
    fn the_start_config_carries_the_durable_identity_and_the_data_dir_file() {
        let config = enable_config(
            std::path::Path::new("/data/rmule"),
            kad_identity(),
            0,
            &credentials(),
        );
        assert_eq!(config.kad_id, kad_identity().id);
        assert_eq!(
            config.peer_credentials.tcp_port(),
            4662,
            "the advertised eD2k port peers dial"
        );
        assert_eq!(
            config.nodes_dat_path.as_deref(),
            Some(std::path::Path::new("/data/rmule/nodes.dat"))
        );
        assert!(
            !config.assume_open_reachability,
            "a deployment proves openness"
        );
    }

    /// The warm restart the app is meant to give a returning user: the table
    /// the last run persisted rides the join, and nothing is fetched.
    #[tokio::test]
    async fn a_saved_table_rides_the_join_and_suppresses_the_fetch() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("nodes.dat"), nodes_dat_v2(4)).unwrap();
        let client = RecordingClient::default();
        let fetcher = refusing_fetcher();

        let outcome = join(
            &client,
            enable_config(dir.path(), kad_identity(), 0, &credentials()),
            &BootstrapConfig {
                auto_fetch_nodes_dat: true,
                ..BootstrapConfig::default()
            },
            &fetcher,
        )
        .await
        .unwrap();

        assert_eq!(
            outcome,
            KadSeedOutcome::Persisted {
                contacts: 4,
                candidates: 0
            }
        );
        assert_eq!(*fetcher.calls.lock().unwrap(), 0);
        assert_eq!(client.kad_join().contacts.len(), 4);
    }

    /// The honest degrade: nothing saved and the acquisition failed, so the
    /// trail line says *why* — and Kad is joined anyway, because an
    /// empty-table node is what the ed2k→Kad handoff bootstraps.
    #[tokio::test]
    async fn a_stranded_cold_start_still_joins_and_says_why() {
        let dir = tempfile::tempdir().unwrap();
        let client = RecordingClient::default();

        let outcome = join(
            &client,
            enable_config(dir.path(), kad_identity(), 0, &credentials()),
            &BootstrapConfig {
                auto_fetch_nodes_dat: true,
                ..BootstrapConfig::default()
            },
            &refusing_fetcher(),
        )
        .await
        .unwrap();

        assert!(matches!(outcome, KadSeedOutcome::AcquireFailed(_)));
        let words = crate::words::kad::seed_outcome_words(&outcome);
        assert!(
            words.contains("fetch failed"),
            "the flash line must name the failure: {words}"
        );
        assert!(
            client.kad_join().contacts.is_empty(),
            "the join still fires — that is what arms the peer handoff"
        );
    }

    /// The sequencing: a run that never connects to a server and
    /// never presses `K` never joins — and, because the acquisition sits
    /// behind the same lane, never reaches for the network either. Both
    /// switches are on here, so only the lane can be what holds it back. Each
    /// start that does come joins with its own copy of the config.
    #[tokio::test]
    async fn only_a_start_request_joins_and_each_one_joins_again() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("nodes.dat"), nodes_dat_v2(4)).unwrap();
        let client = RecordingClient::default();
        let fetcher = refusing_fetcher();
        let bootstrap = BootstrapConfig {
            auto_fetch_nodes_dat: true,
            ..BootstrapConfig::default()
        };
        let config = enable_config(dir.path(), kad_identity(), 0, &credentials());
        let (start, mut starts) = start_lane();

        start.send(()).unwrap();
        start.send(()).unwrap();
        for _ in 0..2 {
            assert!(
                join_on_next_start(&mut starts, &client, &config, &bootstrap, &fetcher)
                    .await
                    .is_some_and(|joined| joined.is_ok())
            );
        }
        assert_eq!(
            client.sent.lock().unwrap().len(),
            2,
            "one EnableKad per start"
        );

        drop(start); // the app quit
        assert!(
            join_on_next_start(&mut starts, &client, &config, &bootstrap, &fetcher)
                .await
                .is_none(),
            "no start, no join"
        );
        assert_eq!(*fetcher.calls.lock().unwrap(), 0);
        assert_eq!(client.sent.lock().unwrap().len(), 2);
    }
}
