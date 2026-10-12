//! The actor's one inbox: the front end's commands and a running core's live
//! **Core Settings** (ADR-0069) on a single queue, so the actor takes them in
//! the order they were sent. A command sent after a settings handle answered
//! [`TakesEffect::Now`](crate::TakesEffect::Now) is taken after that setting:
//! a download started straight after its directory changed runs under the new
//! one.
//!
//! The queue itself is unbounded, because a settings handle is synchronous
//! and must hand a live key over without waiting. Commands still meet
//! backpressure: each holds one of [`COMMAND_ROOM`] places from the moment it
//! is queued until the actor takes it, so a front end that outruns the actor
//! waits in [`Core::send`](crate::Core::send) as it always has.
//!
//! Only [`CommandDoor`] keeps the queue open. A settings handle holds a weak
//! [`SettingsDoor`], so dropping the `Core` still closes the inbox — the
//! actor's shutdown signal — and a handle that outlives its core finds no
//! door to knock on.

use std::sync::Arc;

use tokio::sync::{OwnedSemaphorePermit, Semaphore, mpsc};

use crate::CoreError;
use crate::service::CoreCommand;
use crate::settings::LiveSetting;

/// How many commands may wait for the actor before [`CommandDoor::send`]
/// waits too.
const COMMAND_ROOM: usize = 32;

/// One message the actor takes, in the order it was sent. A command is
/// boxed: it is many times the size of a live key.
pub(super) enum Letter {
    /// A front end's command.
    Command(Box<CoreCommand>),
    /// A live key a settings handle has already persisted.
    Setting(LiveSetting),
}

/// What the queue carries: a command keeps its place in [`COMMAND_ROOM`]
/// until the actor takes it.
enum Queued {
    Command(Box<CoreCommand>, OwnedSemaphorePermit),
    Setting(LiveSetting),
}

/// A new inbox: the door the `Core` sends through and the end the actor
/// reads.
pub(super) fn inbox() -> (CommandDoor, Inbox) {
    let (tx, rx) = mpsc::unbounded_channel();
    (
        CommandDoor {
            tx,
            room: Arc::new(Semaphore::new(COMMAND_ROOM)),
        },
        Inbox { rx },
    )
}

/// The `Core`'s side of the inbox, and the only one that keeps it open.
pub(super) struct CommandDoor {
    tx: mpsc::UnboundedSender<Queued>,
    room: Arc<Semaphore>,
}

impl CommandDoor {
    /// Queue `command` behind everything sent before it, once there is room.
    pub(super) async fn send(&self, command: CoreCommand) -> Result<(), CoreError> {
        // A stopped actor drops what it had queued, which frees the room, so
        // this wait always ends; the send below then reports the stop.
        let room = Arc::clone(&self.room)
            .acquire_owned()
            .await
            .map_err(|_| CoreError::ServiceStopped)?;
        self.tx
            .send(Queued::Command(Box::new(command), room))
            .map_err(|_| CoreError::ServiceStopped)
    }

    /// The door a settings handle hands live keys through.
    pub(super) fn settings_door(&self) -> SettingsDoor {
        SettingsDoor(self.tx.downgrade())
    }
}

/// A settings handle's side of the inbox. It does not keep the inbox open:
/// once the `Core` is gone, nothing more is taken up.
#[derive(Clone, Debug)]
pub(crate) struct SettingsDoor(mpsc::WeakUnboundedSender<Queued>);

impl SettingsDoor {
    /// Queue `setting` behind every command already sent, without waiting.
    /// `false` when the core has stopped and will take nothing more up.
    pub(crate) fn send(&self, setting: LiveSetting) -> bool {
        self.0
            .upgrade()
            .is_some_and(|tx| tx.send(Queued::Setting(setting)).is_ok())
    }
}

/// The actor's side of the inbox.
pub(super) struct Inbox {
    rx: mpsc::UnboundedReceiver<Queued>,
}

impl Inbox {
    /// The next message, or `None` once the `Core` is gone and everything it
    /// and its settings handles sent has been taken.
    pub(super) async fn recv(&mut self) -> Option<Letter> {
        self.rx.recv().await.map(|queued| match queued {
            // The command's place is given back as the actor takes it.
            Queued::Command(command, _room) => Letter::Command(command),
            Queued::Setting(setting) => Letter::Setting(setting),
        })
    }
}
