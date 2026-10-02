//! The `kad_ended` bump inside the discovery task is cooperative
//! code that runs only after `discovery.run()` returns cleanly — a panic
//! mid-`await` never reaches it, so before the watchdog this leg would never
//! see `CoreEvent::KadStopped` and Kad would read as running forever. This
//! kills the pump by panicking `next_sources` — the same effect an abort has
//! on the task's `JoinHandle` — and proves the reaper's second wake source
//! (a poll of the same handle's `AbortHandle`) flips the flag with
//! `KadStopReason::TaskFailed`.

use rmule_core::{
    ClientUdpBind, Core, CoreCommand, CoreConfig, CoreError, CoreEvent, KadEnableConfig,
    KadReachLevel, KadRuntimeFactory, KadSource, KadSourceChannel, KadStopReason,
};
use rmule_primitives::{FileHash, SourceLookupTarget};
use tokio::time::{Duration, timeout};

use crate::fixture::kad_enable_config;

/// A Kad seam whose `next_sources` panics on its first call — the discovery
/// task dies mid-`await`, never reaching the cooperative `kad_ended` bump at
/// the bottom of its loop.
struct PanickingChannel;

impl KadSourceChannel for PanickingChannel {
    async fn search_sources(&self, _target: SourceLookupTarget) {}
    async fn publish_source(&self, _target: SourceLookupTarget) {}
    async fn next_sources(&self) -> Option<(FileHash, Vec<KadSource>)> {
        panic!("simulate a pump task dying mid-await");
    }
}

struct PanickingKad {
    channel: Option<PanickingChannel>,
}

impl KadRuntimeFactory for PanickingKad {
    type Channel = PanickingChannel;

    fn kad_reach(&self) -> KadReachLevel {
        KadReachLevel::fixed(true)
    }

    async fn start(
        &mut self,
        _config: &KadEnableConfig,
        _bind: ClientUdpBind,
    ) -> Result<PanickingChannel, CoreError> {
        Ok(self.channel.take().expect("kad started once"))
    }
}

#[tokio::test]
async fn a_panicked_pump_flips_kad_active_through_the_watchdog() {
    let mut core = Core::builder(CoreConfig::default(), rmule_testkit::memory_store())
        .kad(PanickingKad {
            channel: Some(PanickingChannel),
        })
        .build();

    core.send(CoreCommand::EnableKad(kad_enable_config()))
        .await
        .expect("kad enabled");

    let stopped = timeout(Duration::from_secs(5), async {
        loop {
            if let CoreEvent::KadStopped { reason } =
                core.next_event().await.expect("core still running")
            {
                return reason;
            }
        }
    })
    .await
    .expect("KadStopped fires once the watchdog notices the panicked pump");

    assert_eq!(
        stopped,
        KadStopReason::TaskFailed,
        "a panic mid-await is not a clean close"
    );
}
