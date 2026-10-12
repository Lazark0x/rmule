//! The one ceiling a test puts on a wait for something that must happen.
//!
//! A test waits on the event, the datagram or the state it is about; this is
//! only the bound that turns a hang into a failure. It is generous because a
//! loaded machine (a parallel build, a CI runner) can stall a task or an OS
//! watcher for many seconds, and a bound tight enough to pace the test fails
//! then without anything being wrong. A wait that asserts something does
//! *not* happen is a window, not a hang guard, and keeps its own length.

use std::time::Duration;

/// How long a test waits for something that must happen before it calls the
/// wait hung.
pub const HANG_GUARD: Duration = Duration::from_secs(60);
