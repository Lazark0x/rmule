//! The serve activity: the sans-I/O **Serve State** brain ([`state`]) and the
//! `ServeTask` enactor ([`runner`]) that drives it against the live runtime —
//! the serve-side mirror of the [`download`](super::download) module split.
//! The core actor (`service.rs`) spawns one serve activity through this
//! module.

mod liveness;
mod runner;
mod source_exchange;
mod state;

pub(crate) use liveness::{BoundListener, SharedServeListener};
pub(crate) use runner::{ServeOutcome, ServeTask};
