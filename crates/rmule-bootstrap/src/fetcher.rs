//! The single I/O seam of `rmule-bootstrap`.
//!
//! Every acquisition pipeline is generic over [`Fetcher`], so the fetch is
//! the only corner that ever touches a socket. [`FetchError`] is deliberately
//! free of any HTTP-client type: the pipeline logic sees these variants, never
//! a `reqwest` error, which is what keeps the machinery testable against a
//! canned-bytes fake and portable across fetch backends.

use thiserror::Error;

/// Why a bounded fetch failed. HTTP-client-agnostic on purpose (see the
/// module docs): a `reqwest` error is mapped onto one of these at the seam so
/// it never leaks past [`Fetcher::get`].
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum FetchError {
    /// The request never produced a complete response (connection refused,
    /// DNS failure, TLS handshake failure, a truncated body, …).
    #[error("fetch of {url} failed before a complete response: {detail}")]
    Transport {
        /// The URL that was requested.
        url: String,
        /// The backend's own words for the failure, already flattened to a
        /// string so no HTTP-client type crosses the seam.
        detail: String,
    },

    /// The server answered, but with a non-success status. A poisoned or
    /// misconfigured mirror answering `404`/`500` must reject the payload,
    /// not be parsed as a server list.
    #[error("fetch of {url} answered HTTP {status}")]
    Status {
        /// The URL that was requested.
        url: String,
        /// The non-2xx status code the mirror answered with.
        status: u16,
    },

    /// The response body reached the size cap before completing. Enforced
    /// while streaming so a hostile mirror cannot exhaust memory by
    /// advertising a small (or no) `Content-Length` and then sending forever.
    #[error("response body exceeded the {cap}-byte cap")]
    TooLarge {
        /// The byte cap the body was measured against, as passed to
        /// [`Fetcher::get`].
        cap: usize,
    },

    /// The request exceeded its deadline.
    #[error("fetch of {url} timed out")]
    Timeout {
        /// The URL that was requested.
        url: String,
    },
}

/// Fetch a URL to bounded bytes — the crate's sole I/O seam.
///
/// Both acquisition pipelines — server.met and nodes.dat — are generic over
/// this. [`ReqwestFetcher`](crate::ReqwestFetcher) is the only
/// production implementation (rustls, redirect/size/timeout caps) and the
/// crate's only I/O corner; unit tests drive the pipelines with a fake that
/// returns canned bytes, so no socket opens in the deterministic tier.
///
/// The `-> impl Future + Send` shape (RPITIT, not `async_trait`) matches the
/// repo's other async seams (`rmule_core::adapters`), keeping the fetch on
/// static dispatch with no boxing.
pub trait Fetcher {
    /// `GET url`, returning up to `max_bytes` of response body.
    ///
    /// A response that *would* exceed `max_bytes` fails with
    /// [`FetchError::TooLarge`] rather than buffering unboundedly. A non-2xx
    /// status fails with [`FetchError::Status`] — the caller must not parse a
    /// mirror's error page as a server list.
    fn get(
        &self,
        url: &str,
        max_bytes: usize,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, FetchError>> + Send;
}
