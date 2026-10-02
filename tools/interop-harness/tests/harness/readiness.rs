//! The bounded waits: TCP readiness against a deadline and the retry-with-backoff
//! the eserver-login gate rides — every one terminates, and says why.

use std::cell::Cell;
use std::net::{SocketAddr, TcpListener};
use std::time::Duration;

use rmule_interop_harness::readiness::{retry_with_backoff, wait_for_tcp_ready};

#[test]
fn tcp_readiness_succeeds_when_port_accepts_connections() -> anyhow::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let addr = listener.local_addr()?;

    wait_for_tcp_ready(addr, Duration::from_secs(1))?;

    Ok(())
}

#[test]
fn tcp_readiness_times_out_for_unused_port() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);

    let error = wait_for_tcp_ready(addr, Duration::from_millis(30)).unwrap_err();

    assert!(
        error.to_string().contains("server readiness timed out"),
        "{error:?}"
    );
}

#[test]
fn tcp_readiness_rejects_zero_timeout() {
    let addr = SocketAddr::from(([127, 0, 0, 1], 4661));

    let error = wait_for_tcp_ready(addr, Duration::ZERO).unwrap_err();

    assert!(
        error.to_string().contains("server readiness timed out"),
        "{error:?}"
    );
}

#[test]
fn retry_with_backoff_succeeds_without_retrying_on_an_immediate_success() {
    let calls = Cell::new(0u32);

    let result = retry_with_backoff(3, Duration::ZERO, |_attempt| {
        calls.set(calls.get() + 1);
        Ok::<_, anyhow::Error>(42)
    });

    assert_eq!(result.unwrap(), 42);
    assert_eq!(calls.get(), 1, "a first-try success must not retry");
}

#[test]
fn retry_with_backoff_self_heals_after_transient_failures() {
    let calls = Cell::new(0u32);

    // The first two attempts fail like a flaky login; the third lands, the
    // way a transient eserver-login flake is expected to clear.
    let result = retry_with_backoff(3, Duration::from_millis(1), |attempt| {
        calls.set(calls.get() + 1);
        if attempt < 3 {
            anyhow::bail!("transient failure on attempt {attempt}");
        }
        Ok(attempt)
    });

    assert_eq!(result.unwrap(), 3, "recovers on the attempt that succeeds");
    assert_eq!(calls.get(), 3);
}

#[test]
fn retry_with_backoff_gives_up_after_max_attempts_with_the_last_error() {
    let calls = Cell::new(0u32);

    // A genuinely-down counterparty: every attempt fails, so the retry must
    // still terminate — bounded, not an infinite loop — and surface the last
    // attempt's error rather than a generic/opaque failure.
    let result = retry_with_backoff::<()>(3, Duration::from_millis(1), |attempt| {
        calls.set(calls.get() + 1);
        anyhow::bail!("persistent failure on attempt {attempt}")
    });

    let error = result.unwrap_err();
    assert_eq!(calls.get(), 3, "gives up after exactly max_attempts tries");
    assert!(
        error
            .to_string()
            .contains("persistent failure on attempt 3"),
        "{error:?}"
    );
}
