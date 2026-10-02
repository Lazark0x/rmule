//! **Readiness Gates**: the waits that hold a flow until a counterparty is
//! genuinely up, so a drive step never races a container that is still booting.
//! Every gate is bounded and fails with what it was waiting for — a timeout here
//! is a real finding about the counterparty, never something to paper over with
//! a longer sleep.

use std::net::{SocketAddr, TcpStream};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Result, anyhow, bail};

const CONNECT_TIMEOUT: Duration = Duration::from_millis(50);
const RETRY_INTERVAL: Duration = Duration::from_millis(25);

/// Hold until `addr` accepts a TCP connection or `timeout` elapses.
pub fn wait_for_tcp_ready(addr: SocketAddr, timeout: Duration) -> Result<()> {
    let deadline = Instant::now() + timeout;
    loop {
        let now = Instant::now();
        if now >= deadline {
            bail!(
                "server readiness timed out after {} ms waiting for {addr}",
                timeout.as_millis()
            );
        }

        let remaining = deadline.saturating_duration_since(now);
        match TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT.min(remaining)) {
            Ok(_) => return Ok(()),
            Err(_) if Instant::now() >= deadline => {
                bail!(
                    "server readiness timed out after {} ms waiting for {addr}",
                    timeout.as_millis()
                );
            }
            Err(_) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                thread::sleep(RETRY_INTERVAL.min(remaining));
            }
        }
    }
}

/// Retry a fallible operation up to `max_attempts` times, sleeping `backoff`
/// between tries (the harness drives counterparties — e.g. the
/// Lugdunum eserver login that gates a detached rmule serve container's
/// `files_announced` readiness — that are intermittently unreliable, so one
/// failed attempt does not yet mean the counterparty is genuinely down).
///
/// `attempt_fn` receives the 1-based attempt number, so a caller whose
/// operation leaves state behind on failure (a stalled container) can tear it
/// down before the next try. The first attempt runs immediately, with no
/// backoff before it. Returns the first `Ok`, or the last `Err` once every
/// attempt is exhausted — a genuinely broken operation still fails clearly,
/// it just takes `max_attempts` tries to say so rather than retrying forever
/// or masking the failure as a pass.
pub fn retry_with_backoff<T>(
    max_attempts: u32,
    backoff: Duration,
    mut attempt_fn: impl FnMut(u32) -> Result<T>,
) -> Result<T> {
    let mut last_error = None;
    for attempt in 1..=max_attempts {
        if attempt > 1 {
            thread::sleep(backoff);
        }
        match attempt_fn(attempt) {
            Ok(value) => return Ok(value),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow!("retry_with_backoff called with max_attempts=0")))
}
