//! The Kad seam stubbed for the legs that run with Kad enabled and no socket:
//! one channel that records the keyword walks it was asked for, answers them
//! with scripted rows when it has any, and answers source lookups with
//! scripted sources when it has any. And the wait the legs that run a real
//! node share: until its routing table holds a contact.

use std::sync::{Arc, Mutex};

use rmule_core::{
    ClientUdpBind, Core, CoreError, KadEnableConfig, KadKeywordSink, KadRuntimeFactory,
    KadSourceChannel,
};
use rmule_primitives::{FileHash, KeywordQuery, SearchResult, SourceLookupTarget, SourceSighting};
use rmule_testkit::HANG_GUARD;
use tokio::sync::mpsc;
use tokio::time::{Duration, timeout};

type SourceAnswer = (FileHash, Vec<SourceSighting>);

/// A Kad node that is both the factory and the channel it starts. A keyword
/// walk with no scripted rows ends without sending; a source lookup with no
/// scripted sources is never answered.
#[derive(Clone)]
pub struct StubKad {
    walks: Arc<Mutex<Vec<String>>>,
    keyword_rows: Option<Vec<SearchResult>>,
    sources: Option<Vec<SourceSighting>>,
    answers_tx: mpsc::Sender<SourceAnswer>,
    answers_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<SourceAnswer>>>,
}

impl StubKad {
    /// A node that answers nothing and records every keyword walk.
    pub fn new() -> Self {
        let (answers_tx, answers_rx) = mpsc::channel(8);
        Self {
            walks: Arc::default(),
            keyword_rows: None,
            sources: None,
            answers_tx,
            answers_rx: Arc::new(tokio::sync::Mutex::new(answers_rx)),
        }
    }

    /// Answer every keyword walk with `rows`, sent as one batch.
    pub fn answering_keywords(mut self, rows: Vec<SearchResult>) -> Self {
        self.keyword_rows = Some(rows);
        self
    }

    /// Answer every source lookup with `sources`.
    pub fn answering_sources(mut self, sources: Vec<SourceSighting>) -> Self {
        self.sources = Some(sources);
        self
    }

    /// The phrase of each keyword walk asked for, in order.
    pub fn walks(&self) -> Arc<Mutex<Vec<String>>> {
        Arc::clone(&self.walks)
    }
}

impl KadSourceChannel for StubKad {
    async fn search_sources(&self, target: SourceLookupTarget) {
        if let Some(sources) = &self.sources {
            let _ = self
                .answers_tx
                .send((target.file_hash(), sources.clone()))
                .await;
        }
    }

    async fn publish_source(&self, _target: SourceLookupTarget) {}

    async fn next_sources(&self) -> Option<SourceAnswer> {
        self.answers_rx.lock().await.recv().await
    }

    async fn search_keyword(&self, query: KeywordQuery, results: KadKeywordSink) {
        self.walks
            .lock()
            .unwrap()
            .push(query.phrase().to_display_string());
        if let Some(rows) = &self.keyword_rows {
            let _ = results.send(rows.clone()).await;
        }
    }
}

impl KadRuntimeFactory for StubKad {
    type Channel = Self;

    async fn start(
        &mut self,
        _config: &KadEnableConfig,
        _node: &rmule_core::KadNodeIdentity,
        _bind: ClientUdpBind,
        _cells: &rmule_core::KadCells,
    ) -> Result<Self, CoreError> {
        Ok(self.clone())
    }
}

/// Wait until the running Kad node's routing table holds a contact — the moment
/// a publish that fires once, on the share, has somewhere to walk to. The
/// table is the diagnostics snapshot's live reading, so nothing is guessed:
/// the wait ends when the bootstrap answer lands, however long the host takes.
pub async fn until_kad_holds_a_contact(core: &Core) {
    timeout(HANG_GUARD, async {
        while !core
            .diagnostics_snapshot()
            .kad
            .is_some_and(|kad| kad.contacts > 0)
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the Kad node met a contact");
}
