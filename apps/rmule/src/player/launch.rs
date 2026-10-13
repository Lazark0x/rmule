//! The player lane (ADR-0114, "A launch"): the reducer hands each launch to a
//! task on the app's runtime, which looks the Default App up when no Player
//! Command is set, starts the player through `tokio::process` and awaits its
//! exit, then tells the operator how it ended. The lookup, a short read of
//! the system's answer, runs through `spawn_blocking`; the wait for the
//! player never does: the runtime's drop waits for blocking tasks, and an
//! open player would hold the TUI's exit. Nothing is tracked beyond the
//! exit: a second launch is a second process.

use std::ffi::OsString;
use std::io::ErrorKind;
use std::path::PathBuf;
use std::process::Stdio;

use tokio::sync::mpsc;

use super::default_app::{self, DefaultApp};
use crate::action::Action;
use crate::words::{Sentence, player as words};

/// One player to start, and the name of the download it previews, captured
/// at launch so its notes name it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Launch {
    /// What starts.
    pub start: Start,
    /// The download's name as the operator reads it.
    pub name: String,
}

/// What a launch starts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Start {
    /// The Player Command's program, then its arguments, the download's path
    /// among them.
    Command(Vec<OsString>),
    /// The Default App for `extension`, looked up on the lane, started on
    /// `file`.
    DefaultApp {
        /// The extension of the download's name.
        extension: String,
        /// Where the download's bytes lie, as core published it.
        file: PathBuf,
    },
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

/// Start one player, await its exit, and post what the operator is owed:
/// nothing for a clean exit.
async fn play(launch: Launch, actions: mpsc::Sender<Action>) {
    let told = match arguments(launch.start, &launch.name).await {
        Ok(argv) => run(&argv, &launch.name).await,
        Err(refused) => Some(flashed(refused)),
    };
    if let Some(action) = told {
        // A closed bus means the app has quit; the player outlives it.
        let _ = actions.send(action).await;
    }
}

/// The arguments `start` runs, program first, or why no player starts.
async fn arguments(start: Start, name: &str) -> Result<Vec<OsString>, Sentence> {
    let (extension, file) = match start {
        Start::Command(argv) => return Ok(argv),
        Start::DefaultApp { extension, file } => (extension, file),
    };
    match find(extension.clone()).await {
        Ok(Some(app)) => Ok(app.argv(&file)),
        Ok(None) => Err(words::no_app(name, &extension)),
        Err(kind) => Err(words::lookup_failed(name, &extension, kind)),
    }
}

/// The Default App for `extension`, looked up off the runtime's workers. A
/// lookup that panics reads as one the system refused for no named reason.
async fn find(extension: String) -> Result<Option<DefaultApp>, ErrorKind> {
    tokio::task::spawn_blocking(move || default_app::lookup(&extension))
        .await
        .map_err(|_| ErrorKind::Other)?
        .map_err(|error| error.kind())
}

/// A refusal the operator sees at once and finds again in the log.
fn flashed(refused: Sentence) -> Action {
    Action::Actions(vec![Action::Flash(refused.clone()), Action::Note(refused)])
}

/// Run `argv` with standard input, output and error null — the terminal
/// holds the TUI — await its exit, and say how it ended: nothing for a clean
/// exit.
async fn run(argv: &[OsString], name: &str) -> Option<Action> {
    let (program, args) = argv.split_first()?;
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
    match command.spawn() {
        Ok(mut child) => match child.wait().await {
            Ok(status) => words::exit_note(name, status).map(Action::Note),
            Err(error) => Some(Action::Note(words::unwatched(name, error.kind()))),
        },
        Err(error) => Some(flashed(words::spawn_refused(name, error.kind()))),
    }
}
