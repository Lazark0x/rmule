//! The operating-system calls std does not expose, and the workspace's only
//! `unsafe` code (ADR-0111, "The operating-system calls live in `rmule-os`").
//!
//! - [`winsock`]: the ICMP-reset switch `rmule-net` sets on every unconnected
//!   UDP socket it binds.
//! - [`sparse`]: the sparse flag, the punch and the allocated size behind
//!   `rmule-core`'s part file. What to punch, and what a reading means, are
//!   core's.
//!
//! The crate's lint table relaxes the workspace's `unsafe_code` ban to `deny`.
//! Only the functions `scripts/guards.sh` pins waive it, each for one `unsafe`
//! block under a `// SAFETY:` comment; a safe call is used wherever one exists.

#![warn(missing_docs)]

pub mod sparse;
pub mod winsock;
