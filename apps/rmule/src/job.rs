//! The shell's job control heard as actions on the bus (ADR-0118): a SIGTSTP
//! from outside is Ctrl-Z, and a SIGCONT is the run going again, whoever
//! stopped it. A system with no job control has nothing to hear.

use std::io;

use tokio::sync::mpsc;

use crate::action::Action;

/// Hear the stop and the continue for the rest of the run, on a Tokio runtime.
///
/// # Errors
///
/// The OS refused a handler.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub fn listen(actions: mpsc::Sender<Action>) -> io::Result<()> {
    use tokio::signal::unix::{SignalKind, signal};

    let (stop, cont) = rmule_os::terminal::job_signals();
    let mut stop = signal(SignalKind::from_raw(stop))?;
    let mut cont = signal(SignalKind::from_raw(cont))?;
    tokio::spawn(async move {
        loop {
            let action = tokio::select! {
                _ = stop.recv() => Action::Suspend,
                _ = cont.recv() => Action::Continued,
            };
            if actions.send(action).await.is_err() {
                return;
            }
        }
    });
    Ok(())
}

/// Hear nothing: this system has no such signals.
///
/// # Errors
///
/// Never.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub fn listen(_actions: mpsc::Sender<Action>) -> io::Result<()> {
    Ok(())
}
