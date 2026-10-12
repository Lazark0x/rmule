//! The Kad seam stubbed for the legs that run with Kad enabled and no socket:
//! one channel that records the keyword walks it was asked for, answers them
//! with scripted rows when it has any, and answers source lookups with
//! scripted sources when it has any.

use std::sync::{Arc, Mutex};

use rmule_core::{
    ClientUdpBind, CoreError, KadEnableConfig, KadKeywordSink, KadRuntimeFactory, KadSourceChannel,
};
use rmule_primitives::{FileHash, KeywordQuery, SearchResult, SourceLookupTarget, SourceSighting};
use tokio::sync::mpsc;

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
