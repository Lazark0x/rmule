//! The OS asking a run to stop (ADR-0118): every signal a front end turns into
//! a Quit, in one place. SIGTERM, SIGHUP and SIGINT on Unix; Ctrl-C,
//! Ctrl-Break and the console's close on Windows. Installed once, ahead of
//! whatever waits on it, so a request that lands between two turns of a loop
//! is held, not lost.

/// The installed handlers.
#[cfg(unix)]
#[derive(Debug)]
pub struct StopRequest {
    terminate: tokio::signal::unix::Signal,
    hangup: tokio::signal::unix::Signal,
    interrupt: tokio::signal::unix::Signal,
}

#[cfg(unix)]
impl StopRequest {
    /// Install the handlers, on a Tokio runtime.
    ///
    /// # Errors
    ///
    /// The OS refused a handler.
    pub fn install() -> std::io::Result<Self> {
        use tokio::signal::unix::{SignalKind, signal};
        Ok(Self {
            terminate: signal(SignalKind::terminate())?,
            hangup: signal(SignalKind::hangup())?,
            interrupt: signal(SignalKind::interrupt())?,
        })
    }

    /// Wait for the next request.
    pub async fn recv(&mut self) {
        tokio::select! {
            _ = self.terminate.recv() => {}
            _ = self.hangup.recv() => {}
            _ = self.interrupt.recv() => {}
        }
    }
}

/// The installed handlers.
#[cfg(windows)]
#[derive(Debug)]
pub struct StopRequest {
    ctrl_c: tokio::signal::windows::CtrlC,
    ctrl_break: tokio::signal::windows::CtrlBreak,
    ctrl_close: tokio::signal::windows::CtrlClose,
}

#[cfg(windows)]
impl StopRequest {
    /// Install the handlers, on a Tokio runtime.
    ///
    /// # Errors
    ///
    /// The OS refused a handler.
    pub fn install() -> std::io::Result<Self> {
        use tokio::signal::windows::{ctrl_break, ctrl_c, ctrl_close};
        Ok(Self {
            ctrl_c: ctrl_c()?,
            ctrl_break: ctrl_break()?,
            ctrl_close: ctrl_close()?,
        })
    }

    /// Wait for the next request.
    pub async fn recv(&mut self) {
        tokio::select! {
            _ = self.ctrl_c.recv() => {}
            _ = self.ctrl_break.recv() => {}
            _ = self.ctrl_close.recv() => {}
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use std::time::Duration;

    use super::StopRequest;

    /// `rustix` sends the process its own hangup, which an installed handler
    /// must take where the default would end the test binary.
    #[tokio::test]
    async fn a_hangup_is_a_stop_request() {
        let mut stop = StopRequest::install().expect("handlers");
        rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::HUP)
            .expect("the process signals itself");
        tokio::time::timeout(Duration::from_secs(5), stop.recv())
            .await
            .expect("the hangup arrives as a request");
    }
}
