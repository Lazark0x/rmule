//! The production [`Fetcher`]: reqwest with rustls, confined to this module.
//!
//! This is the crate's only I/O corner and the only place a `reqwest` type
//! appears — the [`FetchError`] mapping below is the boundary past which no
//! HTTP type leaks. rustls (never native-tls) is a security-improving,
//! wire-compatible divergence from aMule's TLS-incapable wxHTTP client: the
//! GET and payload are identical, the transport hardens when the mirror
//! offers `https` (ADR-0065, "Dependency").
//!
//! The redirect, timeout, and size caps together bound a hostile mirror: a
//! redirect loop, a hung connection, and an unbounded body each fail closed
//! rather than tying up or exhausting the client.

use std::time::Duration;

use crate::config::BootstrapConfig;
use crate::fetcher::{FetchError, Fetcher};

/// A reqwest-backed [`Fetcher`] with redirect + timeout caps baked into the
/// client and the body cap enforced per-request while streaming.
///
/// `Clone` is reqwest's own: the client is an `Arc` over one connection pool,
/// so an app that injects the capability into more than one consumer (rmule
/// hands one to core for `UpdateServerList` and keeps one for the Kad seed
/// acquisition) shares a pool instead of standing up a second TLS stack.
#[derive(Clone)]
pub struct ReqwestFetcher {
    client: reqwest::Client,
}

impl ReqwestFetcher {
    /// Build a fetcher whose client follows at most `max_redirects` redirects
    /// and times out each request after `request_timeout`.
    ///
    /// # Errors
    /// Returns [`FetchError::Transport`] if the underlying TLS/HTTP client
    /// cannot be constructed (e.g. no usable rustls backend).
    pub fn new(max_redirects: usize, request_timeout: Duration) -> Result<Self, FetchError> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::limited(max_redirects))
            .timeout(request_timeout)
            .build()
            .map_err(|error| FetchError::Transport {
                url: String::new(),
                detail: format!("HTTP client construction failed: {error}"),
            })?;
        Ok(Self { client })
    }

    /// Build a fetcher from a [`BootstrapConfig`]'s redirect and timeout caps.
    ///
    /// # Errors
    /// As [`ReqwestFetcher::new`].
    pub fn from_config(config: &BootstrapConfig) -> Result<Self, FetchError> {
        Self::new(config.max_redirects, config.request_timeout)
    }
}

/// Map a `reqwest` error onto the seam's HTTP-type-free vocabulary.
fn map_error(url: &str, error: &reqwest::Error) -> FetchError {
    if error.is_timeout() {
        FetchError::Timeout {
            url: url.to_owned(),
        }
    } else {
        FetchError::Transport {
            url: url.to_owned(),
            detail: error.to_string(),
        }
    }
}

impl Fetcher for ReqwestFetcher {
    fn get(
        &self,
        url: &str,
        max_bytes: usize,
    ) -> impl std::future::Future<Output = Result<Vec<u8>, FetchError>> + Send {
        // Own the request inputs so the returned future does not borrow `self`
        // or `url` — it can be awaited freely by an actor that moved on.
        let client = self.client.clone();
        let url = url.to_owned();
        async move {
            let mut response = client
                .get(&url)
                .send()
                .await
                .map_err(|error| map_error(&url, &error))?;

            let status = response.status();
            if !status.is_success() {
                // A mirror's 404/500 error page must reject, never parse as a
                // server list.
                return Err(FetchError::Status {
                    url,
                    status: status.as_u16(),
                });
            }

            // Stream the body so the cap is enforced regardless of any
            // (absent or lying) Content-Length header.
            let mut body = Vec::new();
            while let Some(chunk) = response
                .chunk()
                .await
                .map_err(|error| map_error(&url, &error))?
            {
                if body.len() + chunk.len() > max_bytes {
                    return Err(FetchError::TooLarge { cap: max_bytes });
                }
                body.extend_from_slice(&chunk);
            }
            Ok(body)
        }
    }
}
