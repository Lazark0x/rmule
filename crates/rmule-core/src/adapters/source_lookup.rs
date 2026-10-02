//! The source-lookup seam (ADR-0031): asking *where* a file's sources are.
//! The trait the core actor drives, and the production implementation that
//! rides the node's live server session and never opens one (ADR-0095,
//! "Connecting is the operator's act").

use std::future::Future;

use rmule_primitives::{ClientId, ExchangedSource, SourceLookupTarget};

use crate::DownloadFailure;
use crate::server_session::SharedServerSession;

/// What one server source lookup produced: who the server says we are, and
/// who else has the file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceLookupOutcome {
    /// The id the server assigned us on this session. High-ID means peers can
    /// dial us; Low-ID means they cannot, which gates callback capability.
    pub client_id: ClientId,
    /// Server-lookup sources as candidates carrying the optional `(user_hash,
    /// crypt_options)` provenance an `OP_FOUNDSOURCES_OBFU` (`0x44`) reply
    /// delivers (ADR-0046). A plain `0x42` reply yields
    /// [`ExchangedSource::plain`] entries — plaintext-dial only.
    pub sources: Vec<ExchangedSource>,
}

/// The source-lookup seam (ADR-0031): how core asks a server who has a file
/// without owning the session or the socket. The production adapter rides the
/// shared server session; a test adapter answers from a script.
///
/// A cheap handle (ADR-0107): the **Download Set** shares one, and each ask
/// runs on a clone of its own, so one download's lookup never waits on
/// another's. The production adapter attributes each answer by the file hash
/// `OP_FOUNDSOURCES` carries, which is what makes asks side by side exact.
pub trait SourceLookupService: Clone + Send + 'static {
    /// Ask for `target`'s sources. One call, one answer — the streaming
    /// `OP_FOUNDSOURCES` batches are folded by the adapter, so core sees a
    /// single outcome.
    ///
    /// The production adapter asks the node's live session, whichever server
    /// it is on, dials nothing, and answers
    /// [`DownloadFailure::ServerDisconnected`] when there is no session —
    /// which the run reads as "wait for a connection" (it names no
    /// server, since it could reach none but the session's).
    fn lookup_sources(
        &mut self,
        target: SourceLookupTarget,
    ) -> impl Future<Output = Result<SourceLookupOutcome, DownloadFailure>> + Send;

    /// Adopt the builder's one set of `AdapterCells`
    /// `Core::builder` weaves its own lookup through this and
    /// `CoreBuilder::source_lookup` calls it on the lookup it installs, so an
    /// injected lookup rides the node's one server session (ADR-0032).
    /// Default no-op: a scripted fake rides none.
    fn adopt_cells(&mut self, _cells: &super::AdapterCells) {}
}

/// The production [`SourceLookupService`]: the node's one live eD2k server
/// session, the operator's, shared with every other activity.
#[derive(Clone, Default)]
pub struct RuntimeSourceLookupService {
    session: SharedServerSession,
}

impl SourceLookupService for RuntimeSourceLookupService {
    fn adopt_cells(&mut self, cells: &super::AdapterCells) {
        self.session = cells.session.clone();
    }

    async fn lookup_sources(
        &mut self,
        target: SourceLookupTarget,
    ) -> Result<SourceLookupOutcome, DownloadFailure> {
        let handle = self
            .session
            .live_session()
            .await
            .ok_or(DownloadFailure::ServerDisconnected)?;
        handle.lookup_sources(target).await
    }
}
