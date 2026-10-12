//! **Core Settings** on a running core (ADR-0069): a live key set through
//! `Core::settings()` is persisted and taken up at once, a start-shaped one
//! waits for the next start, and a core that has stopped takes nothing up.

use rmule_core::{
    AppConfigStore, Core, CoreCommand, CoreConfig, CoreEvent, CoreSettings, DurableAppConfig,
    ManagedServer, ServerHealth, ServerListStore, Setting, TakesEffect,
};
use rmule_primitives::ServerEndpoint;
use rmule_testkit::HANG_GUARD;
use tokio::time::{Duration, timeout};

fn core(store: std::sync::Arc<rmule_core::DurableStore>) -> Core {
    Core::builder(CoreConfig::default(), store)
        .settings(CoreSettings::default())
        .build()
}

/// The Dead Server Limit is live: a server two failures in is failing under
/// the default of three and dead the moment the operator lowers it to two.
#[tokio::test]
async fn a_running_core_judges_every_server_again_under_a_new_limit() {
    let store = rmule_testkit::memory_store();
    let listed = ServerEndpoint::new("192.0.2.7", 4661).unwrap();
    let rows = DurableAppConfig::new(store.clone());
    rows.merge_server(ManagedServer::listed(listed.clone()))
        .unwrap();
    rows.set_server_fail_count(&listed, 2).unwrap();
    let core = core(store);
    let health = |core: &Core| {
        core.diagnostics_snapshot()
            .servers
            .iter()
            .find(|row| row.server.endpoint == listed)
            .map(|row| row.health)
    };
    let until = |wanted: ServerHealth| {
        let core = &core;
        async move {
            timeout(HANG_GUARD, async {
                while health(core) != Some(wanted) {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .is_ok()
        }
    };
    assert!(until(ServerHealth::Failing).await, "failing under three");

    assert_eq!(
        core.settings().set(Setting::DeadServerRetries(2)),
        Ok(TakesEffect::Now)
    );
    assert!(until(ServerHealth::Dead).await, "dead under two");
    assert_eq!(
        core.settings().read().unwrap().server_policy.dead_after,
        2,
        "and the limit is the store's"
    );
}

/// A live set and the command sent after it are taken in that order: a
/// diagnostics dump asked for straight after each change to the Dead Server
/// Limit already judges the server under it. Many rounds, because two
/// separate inboxes would let the dump overtake the change about half the
/// time.
#[tokio::test]
async fn a_command_sent_after_a_live_set_runs_under_it() {
    let store = rmule_testkit::memory_store();
    let listed = ServerEndpoint::new("192.0.2.7", 4661).unwrap();
    let rows = DurableAppConfig::new(store.clone());
    rows.merge_server(ManagedServer::listed(listed.clone()))
        .unwrap();
    rows.set_server_fail_count(&listed, 2).unwrap();
    let mut core = core(store);
    let settings = core.settings();
    for (limit, judged) in [(2, ServerHealth::Dead), (3, ServerHealth::Failing)].repeat(16) {
        assert_eq!(
            settings.set(Setting::DeadServerRetries(limit)),
            Ok(TakesEffect::Now)
        );
        core.send(CoreCommand::DumpDiagnostics).await.unwrap();
        let snapshot = timeout(HANG_GUARD, async {
            loop {
                if let Some(CoreEvent::DiagnosticsSnapshot { snapshot }) = core.next_event().await {
                    return snapshot;
                }
            }
        })
        .await
        .expect("the dump answers");
        let health = snapshot
            .servers
            .iter()
            .find(|row| row.server.endpoint == listed)
            .map(|row| row.health);
        assert_eq!(health, Some(judged), "judged under a limit of {limit}");
    }
    core.shutdown().await;
}

/// A start-shaped key on a running core is persisted for the next start, and
/// once the core has stopped even a live key waits for one.
#[tokio::test]
async fn what_a_running_core_cannot_take_up_waits_for_the_next_start() {
    let store = rmule_testkit::memory_store();
    let core = core(store.clone());
    let settings = core.settings();
    assert_eq!(
        settings.set(Setting::UdpPort(4999)),
        Ok(TakesEffect::NextStart)
    );
    core.shutdown().await;
    assert_eq!(
        settings.set(Setting::DeadServerRetries(5)),
        Ok(TakesEffect::NextStart)
    );
    let stored = DurableAppConfig::new(store);
    assert_eq!(stored.ensure_kad_identity().unwrap().udp_port, 4999);
    assert_eq!(settings.read().unwrap().server_policy.dead_after, 5);
}

/// The Obfuscation Policy is our own posture, so it reaches the lean Run Log
/// as events: once as the core starts, and again at each live change that
/// changes it — a set to the value in force says nothing.
#[tokio::test]
async fn the_obfuscation_policy_is_stated_at_start_and_at_each_change() {
    use rmule_core::ObfuscationPolicy;
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .settings(CoreSettings {
            obfuscation: Some(ObfuscationPolicy::Required),
            ..CoreSettings::default()
        })
        .build();
    let next_policy = async |core: &mut Core| {
        timeout(HANG_GUARD, async {
            loop {
                match core.next_event().await.expect("the core runs") {
                    CoreEvent::ObfuscationPolicyAtStart { policy } => return (false, policy),
                    CoreEvent::ObfuscationPolicyChanged { policy } => return (true, policy),
                    _ => {}
                }
            }
        })
        .await
        .expect("a policy event")
    };

    assert_eq!(
        next_policy(&mut core).await,
        (false, Some(ObfuscationPolicy::Required))
    );
    let settings = core.settings();
    assert_eq!(
        settings.set(Setting::Obfuscation(Some(ObfuscationPolicy::Required))),
        Ok(TakesEffect::Now)
    );
    assert_eq!(
        settings.set(Setting::Obfuscation(None)),
        Ok(TakesEffect::Now)
    );
    assert_eq!(
        next_policy(&mut core).await,
        (true, None),
        "the unchanged set is silent; the change to off is stated"
    );
}
