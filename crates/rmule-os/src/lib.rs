//! The operating-system calls std does not expose, and the workspace's only
//! `unsafe` code (ADR-0111, "The operating-system calls live in `rmule-os`").
//!
//! - [`winsock`]: the ICMP-reset switch `rmule-net` sets on every unconnected
//!   UDP socket it binds.
//! - [`sparse`]: the sparse flag, the punch and the allocated size behind
//!   `rmule-core`'s part file. What to punch, and what a reading means, are
//!   core's.
//! - [`fs`]: the exclusive rename the completion move lands a finished file
//!   with, which never replaces one standing at its target.
//! - `default_app`, on macOS and Windows: which app the system opens a
//!   file-name extension with, for the TUI's Preview.
//!
//! The crate's lint table relaxes the workspace's `unsafe_code` ban to `deny`.
//! Only the functions `scripts/guards.sh` pins waive it, each for one `unsafe`
//! block under a `// SAFETY:` comment, and may declare the foreign function it
//! calls in one `unsafe extern` block under its own; a safe call is used
//! wherever one exists.

#![warn(missing_docs)]

#[cfg(any(target_os = "macos", windows))]
pub mod default_app;
pub mod fs;
pub mod sparse;
pub mod winsock;
