//! The single I/O seam of `rmule-bootstrap`.
//!
//! Every acquisition pipeline is generic over [`Fetcher`], so the fetch is
//! the only corner that ever touches a socket. [`FetchError`] is deliberately
//! free of any HTTP-client type: the pipeline logic sees these variants, never
//! a `reqwest` error, which is what keeps the machinery testable against a
//! canned-bytes fake and portable across fetch backends.

use std::future::Future;
use std::pin::Pin;

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

/// What [`Fetcher::get`] returns: a boxed future, so `dyn Fetcher` exists.
pub type FetchFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<u8>, FetchError>> + Send + 'a>>;

/// Fetch a URL to bounded bytes — the crate's sole I/O seam.
///
/// Both acquisition pipelines — server.met and nodes.dat — run over a
/// `&dyn Fetcher`. [`ReqwestFetcher`](crate::ReqwestFetcher) is the only
/// production implementation (rustls, redirect/size/timeout caps) and the
/// crate's only I/O corner; unit tests drive the pipelines with a fake that
/// returns canned bytes, so no socket opens in the deterministic tier.
///
/// One GET a session is not worth a type parameter on every holder: the actor
/// keeps its capability as `Arc<dyn Fetcher>`, which is why the future is boxed.
pub trait Fetcher: Send + Sync {
    /// `GET url`, returning up to `max_bytes` of response body.
    ///
    /// A response that *would* exceed `max_bytes` fails with
    /// [`FetchError::TooLarge`] rather than buffering unboundedly. A non-2xx
    /// status fails with [`FetchError::Status`] — the caller must not parse a
    /// mirror's error page as a server list.
    fn get<'a>(&'a self, url: &'a str, max_bytes: usize) -> FetchFuture<'a>;
}
