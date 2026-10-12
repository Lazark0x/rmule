//! The player lane (ADR-0114, "A launch"): the reducer hands each launch to a
//! task on the app's runtime, which starts the player through
//! `tokio::process` and awaits its exit, then tells the operator how it
//! ended. It never waits through `spawn_blocking`: the runtime's drop waits
//! for blocking tasks, and an open player would hold the TUI's exit. Nothing
//! is tracked beyond the exit: a second launch is a second process.

use std::ffi::OsString;
use std::process::Stdio;

use tokio::sync::mpsc;

use crate::action::Action;
use crate::words::player as words;

/// One player to start: its arguments, program first, and the name of the
/// download it previews, captured at launch so its notes name it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Launch {
    /// The program, then its arguments, the download's path among them.
    pub argv: Vec<OsString>,
    /// The download's name as the operator reads it.
    pub name: String,
}

/// The app's half of the player lane: the reducer sends one [`Launch`] per
/// Preview.
pub type PlayerLauncher = mpsc::UnboundedSender<Launch>;

/// The lane task's half; see [`play_each`].
pub type PlayerLaunches = mpsc::UnboundedReceiver<Launch>;

/// The lane between the reducer and [`play_each`]. Dropping the
/// [`PlayerLauncher`] — the app quitting — ends the task; a player already
/// open stays open.
#[must_use]
pub fn lane() -> (PlayerLauncher, PlayerLaunches) {
    mpsc::unbounded_channel()
}

/// Start each launch the lane carries, each awaited on a task of its own,
/// until the app drops its half. How each player ended is posted on
/// `actions`.
pub async fn play_each(mut launches: PlayerLaunches, actions: mpsc::Sender<Action>) {
    while let Some(launch) = launches.recv().await {
        tokio::spawn(play(launch, actions.clone()));
    }
}

/// Start one player with standard input, output and error null — the
/// terminal holds the TUI — await its exit, and post what the operator is
/// owed: nothing for a clean exit.
async fn play(launch: Launch, actions: mpsc::Sender<Action>) {
    let Some((program, args)) = launch.argv.split_first() else {
        return;
    };
    let mut command = tokio::process::Command::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        // Quitting the TUI leaves the player open.
        .kill_on_drop(false);
    // A process group of its own, so the terminal closing does not reach it.
    #[cfg(unix)]
    command.process_group(0);
    let told = match command.spawn() {
        Ok(mut child) => match child.wait().await {
            Ok(status) => words::exit_note(&launch.name, status).map(Action::Note),
            Err(error) => Some(Action::Note(words::unwatched(&launch.name, error.kind()))),
        },
        Err(error) => {
            let refused = words::spawn_refused(&launch.name, error.kind());
            Some(Action::Actions(vec![
                Action::Flash(refused.clone()),
                Action::Note(refused),
            ]))
        }
    };
    if let Some(action) = told {
        // A closed bus means the app has quit; the player outlives it.
        let _ = actions.send(action).await;
    }
}
