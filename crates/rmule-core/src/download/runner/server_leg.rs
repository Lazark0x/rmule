//! A running download's server leg (ADR-0093, "A download's sources are
//! independent"): each server session that comes up while the run is
//! running is asked for the file's sources, as aMule asks the server it has
//! just connected to for every file in its queue. A run that started on Kad
//! alone gains the server's sources when the operator connects, and a
//! re-made session is asked again. The leg never dials: it rides the session
//! the **Session Generation** announces.

use std::future::Future;
use std::pin::Pin;

use rmule_primitives::{ExchangedSource, SourceLookupTarget};
use tokio::sync::watch;

use super::RunnerContext;
use crate::adapters::SourceLookupService;

/// One ask in flight, kept across the fleet loop's turns so another arm
/// firing never drops it half-way.
/// Its output carries the generation of the session the ask rode.
type Asking<'a> = Pin<Box<dyn Future<Output = (u64, Vec<ExchangedSource>)> + Send + 'a>>;

/// The run's subscription to new sessions and the ask each one gets.
pub(in crate::download) struct ServerLeg<'a> {
    sessions: watch::Receiver<u64>,
    asking: Option<Asking<'a>>,
    target: SourceLookupTarget,
    /// The newest session generation this run asked: one ask per file per
    /// session, the first lookup's own login counting as that session
    /// (ADR-0097, "The Source Ask Budget").
    asked: u64,
}

impl<'a> ServerLeg<'a> {
    /// Subscribed before the run's first lookup, so a session that comes up
    /// after it is a wake, not a miss.
    pub(in crate::download) fn new(
        mut sessions: watch::Receiver<u64>,
        target: SourceLookupTarget,
    ) -> Self {
        sessions.borrow_and_update();
        Self {
            sessions,
            asking: None,
            target,
            asked: 0,
        }
    }

    /// The run asked the session of `generation` for the file: that session
    /// is not asked again.
    pub(in crate::download) fn rode(&mut self, generation: u64) {
        self.asked = self.asked.max(generation);
    }

    /// Ask the live session now, if one is up, rather than wait for the next
    /// one: a run fed by its seeds starts before its first lookup, which this
    /// ask is (ADR-0109, "Source Seeds"). With no session the leg waits for
    /// one as it always does.
    pub(in crate::download) fn ask_first<S, P>(&mut self, runner: &'a RunnerContext<S, P>)
    where
        S: SourceLookupService,
        P: Send,
    {
        if runner.reach.session().is_some() {
            tracing::info!("the run starts from its seeds: asking the live session for sources");
            self.asking = Some(Box::pin(ask(runner, self.target)));
        }
    }

    /// The sources the next session answered — empty when it said nothing
    /// inside the lookup bound or ended first. Cancel-safe: an ask in flight
    /// survives this future being dropped.
    pub(in crate::download) async fn next_answer<S, P>(
        &mut self,
        runner: &'a RunnerContext<S, P>,
    ) -> Vec<ExchangedSource>
    where
        S: SourceLookupService,
        P: Send,
    {
        loop {
            if let Some(asking) = self.asking.as_mut() {
                let (generation, sources) = asking.await;
                self.asking = None;
                self.rode(generation);
                return sources;
            }
            if self.sessions.changed().await.is_err() {
                return std::future::pending().await;
            }
            if *self.sessions.borrow_and_update() <= self.asked {
                continue;
            }
            tracing::info!("a server session came up: asking it for sources");
            self.asking = Some(Box::pin(ask(runner, self.target)));
        }
    }
}

async fn ask<S, P>(
    runner: &RunnerContext<S, P>,
    target: SourceLookupTarget,
) -> (u64, Vec<ExchangedSource>)
where
    S: SourceLookupService,
    P: Send,
{
    // Side by side with every other run's lookups (ADR-0107): the budget is
    // the only wait, and the bound starts once the ask is admitted.
    let generation = super::lookup::budget_admits(runner).await;
    let mut lookup = runner.source_lookup.lock().await.clone();
    let sources =
        match tokio::time::timeout(runner.source_lookup_timeout, lookup.lookup_sources(target))
            .await
        {
            Ok(Ok(outcome)) => outcome.sources,
            Ok(Err(error)) => {
                tracing::info!(%error, "the new session answered no sources");
                Vec::new()
            }
            Err(_) => {
                tracing::info!("the new session stayed silent on the source lookup");
                Vec::new()
            }
        };
    (generation, sources)
}
