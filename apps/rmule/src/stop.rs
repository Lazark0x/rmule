//! The one stop path (ADR-0118): every way out of a run arrives here, and
//! nothing here needs the UI loop or the terminal. A [`Stop`] is a value any
//! thread sets without blocking: a signal, the terminal's loss, the input
//! pump's end, the operator's `q`. A request wakes the loop, starts the core's
//! quit whether the loop answers or not, and arms the deadline, past which
//! the process ends anyway.

use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::watch;

use crate::bridge::{BridgeHandle, CORE_SHUTDOWN_GRACE};
use crate::tui;

/// What the deadline allows the run once the core has stopped: the terminal's
/// restore and the runtime's own bound, with a margin.
const AFTER_THE_CORE: Duration = Duration::from_secs(5);
/// The exit status of a run the deadline ended.
const EXIT_PAST_DEADLINE: i32 = 1;

/// Whether a stop was asked for, and the deadline behind it. Clones share one
/// request.
#[derive(Clone, Default)]
pub struct Stop {
    asked: Arc<Asked>,
}

#[derive(Default)]
struct Asked {
    bell: watch::Sender<bool>,
    /// What the deadline's thread waits on, until a request starts it.
    deadline: Mutex<Option<mpsc::Receiver<()>>>,
    core_stopped: Mutex<Option<mpsc::Sender<()>>>,
}

impl Stop {
    /// The run's stop: a request arms a deadline that ends the process.
    /// [`Stop::default`], which arms nothing, is every test's.
    #[must_use]
    pub fn with_deadline() -> Self {
        let (core_stopped, waits) = mpsc::channel();
        Self {
            asked: Arc::new(Asked {
                bell: watch::Sender::default(),
                deadline: Mutex::new(Some(waits)),
                core_stopped: Mutex::new(Some(core_stopped)),
            }),
        }
    }

    /// Ask the run to stop. Safe on any thread, and it never blocks; a later
    /// request adds nothing.
    pub fn request(&self) {
        self.asked.bell.send_replace(true);
        let armed = self.asked.deadline.lock().take();
        if let Some(core_stopped) = armed {
            std::thread::spawn(move || {
                let _ = core_stopped.recv_timeout(CORE_SHUTDOWN_GRACE);
                std::thread::sleep(AFTER_THE_CORE);
                tui::leave();
                std::process::exit(EXIT_PAST_DEADLINE);
            });
        }
    }

    /// Whether a stop has been asked for.
    #[must_use]
    pub fn was_requested(&self) -> bool {
        *self.asked.bell.borrow()
    }

    /// Answers once a stop was asked for, however early it came.
    pub async fn requested(&self) {
        let mut bell = self.asked.bell.subscribe();
        let _ = bell.wait_for(|asked| *asked).await;
    }

    /// Run the core's quit on the first request, from a task of its own, so
    /// a stop does not wait on the UI loop to start it.
    pub fn quit_core_when_asked(&self, core: BridgeHandle) {
        let stop = self.clone();
        tokio::spawn(async move {
            stop.requested().await;
            core.graceful_shutdown().await;
            if let Some(core_stopped) = stop.asked.core_stopped.lock().take() {
                let _ = core_stopped.send(());
            }
        });
    }
}
