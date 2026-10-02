//! Per-test tracing installation. Library crates never install a tracing
//! subscriber in production code (ADR-0027); this helper exists for
//! integration tests that want a failing run to dump structured trace output
//! through cargo's per-test writer.

use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt;

/// Returned by [`init_tracing`]. Drop unsets the per-test subscriber so a
/// later test in the same binary can install its own.
#[must_use = "dropping the guard immediately removes the subscriber"]
pub struct TracingGuard {
    _inner: tracing::subscriber::DefaultGuard,
}

/// Install a tracing subscriber for the lifetime of the returned guard.
///
/// Filter is read from `RMULE_LOG` if set; otherwise defaults to
/// `rmule_core=info,rmule_net::peer=info,rmule_net::ed2k=info,warn`. The
/// subscriber routes through cargo's per-test writer so passing tests stay
/// silent and failing tests dump only their own trace.
pub fn init_tracing() -> TracingGuard {
    let filter = EnvFilter::try_from_env("RMULE_LOG").unwrap_or_else(|_| {
        EnvFilter::new("rmule_core=info,rmule_net::peer=info,rmule_net::ed2k=info,warn")
    });
    let subscriber = fmt::Subscriber::builder()
        .with_env_filter(filter)
        .with_test_writer()
        .finish();
    TracingGuard {
        _inner: tracing::subscriber::set_default(subscriber),
    }
}

/// Every line a test's subscriber wrote, held for the test to read back — how
/// a test proves a `tracing` line fired, and under which spans.
#[derive(Clone, Default)]
pub struct CapturedLog(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

impl CapturedLog {
    /// Everything captured so far, as text.
    #[must_use]
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.0.lock().expect("captured-log mutex poisoned")).into_owned()
    }
}

impl std::io::Write for CapturedLog {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("captured-log mutex poisoned")
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'w> fmt::MakeWriter<'w> for CapturedLog {
    type Writer = Self;

    fn make_writer(&'w self) -> Self::Writer {
        self.clone()
    }
}

/// Install, for the returned guard's lifetime, a subscriber that writes every
/// event at `max_level` or above — with its span context, unlike the per-test
/// writer — into the returned [`CapturedLog`]. The subscriber is the calling
/// thread's default, so a test on a current-thread runtime sees every task it
/// spawns.
pub fn capture_tracing(max_level: tracing::Level) -> (CapturedLog, TracingGuard) {
    let log = CapturedLog::default();
    let subscriber = fmt::Subscriber::builder()
        .with_writer(log.clone())
        .with_max_level(max_level)
        .with_ansi(false)
        .finish();
    let guard = TracingGuard {
        _inner: tracing::subscriber::set_default(subscriber),
    };
    (log, guard)
}
