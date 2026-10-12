//! The timed server switch of `ed2k serve start`: at the switch, the files
//! named for it join the shared directory, then the driver hangs up on the
//! first server and connects to the second, as the operator does from the
//! Servers tab. What each server is told of the share set on the way is the
//! announce-on-switch proof's evidence (ADR-0099).

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use rmule_core::run_log::Level;
use rmule_core::{Core, CoreCommand, CoreEvent, ServeEvent, ServerConnectionEvent};
use rmule_primitives::ServerEndpoint;

use crate::share::ScratchShare;

/// The longest the added files' hashing or the hang-up may take.
const STEP_BUDGET: Duration = Duration::from_secs(120);

/// What the switch does, and when.
pub(super) struct Switch {
    /// The second server.
    pub(super) to: ServerEndpoint,
    /// The second server as the command line spelled it.
    pub(super) to_text: String,
    /// Seconds after the first login was asked for.
    pub(super) after: Duration,
    /// Files placed in the shared directory before the hang-up.
    pub(super) add: Vec<PathBuf>,
}

/// Run the switch: share `switch.add`, wait until each is shared, hang up,
/// wait for the hang-up, then list and connect to `switch.to`. Prints
/// `rmule-serve-switch` markers a flow keys its taps on.
///
/// # Errors
/// A file cannot be placed or is not shared in time, the hang-up is not
/// seen in time, the stream ends, or a command cannot be sent.
pub(super) async fn run(core: &mut Core, share: &ScratchShare, switch: &Switch) -> Result<()> {
    for file in &switch.add {
        share.add(file)?;
    }
    let mut waiting = switch.add.len();
    if waiting > 0 {
        until(core, "the added files shared", |event| {
            if matches!(event, CoreEvent::Serve(ServeEvent::FileShared { .. })) {
                waiting -= 1;
            }
            waiting == 0
        })
        .await?;
    }
    println!("rmule-serve-switch added={}", switch.add.len());
    core.send(CoreCommand::DisconnectFromServer).await?;
    until(core, "the hang-up", |event| {
        matches!(
            event,
            CoreEvent::ServerConnection(ServerConnectionEvent::Disconnected { .. })
        )
    })
    .await?;
    println!("rmule-serve-switch disconnected");
    crate::node::connect(core, &switch.to)
        .await
        .with_context(|| format!("connect to {}", switch.to_text))?;
    println!("rmule-serve-switch connecting to={}", switch.to_text);
    Ok(())
}

/// Print every event until `done` says so, within [`STEP_BUDGET`].
async fn until(
    core: &mut Core,
    what: &str,
    mut done: impl FnMut(&CoreEvent) -> bool,
) -> Result<()> {
    let deadline = tokio::time::Instant::now() + STEP_BUDGET;
    loop {
        let Ok(event) = tokio::time::timeout_at(deadline, core.next_event()).await else {
            bail!("{what} not seen within {}s", STEP_BUDGET.as_secs());
        };
        let Some(event) = event else {
            bail!("the event stream ended before {what}");
        };
        println!("{}", event.record().render(Level::Full));
        if done(&event) {
            return Ok(());
        }
    }
}
