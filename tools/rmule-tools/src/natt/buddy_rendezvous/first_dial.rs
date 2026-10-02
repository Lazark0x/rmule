//! The requester's **first-dial marker**: `rmule-natt-first-dial dials=<n>`,
//! printed the moment the NAT-T front's dial counter leaves zero, which is what
//! triggers the harness's in-flight **NAT Type Proof**.
//!
//! The requester is the only body ADR-0091 has dial at all — "both ends burst,
//! the requester dials" — and it dials either when its held burst is released
//! or when the target's own burst reaches it first. Either way the target's
//! burst has already answered the hint round trip, so this marker, watched from
//! the host side, is the earliest point at which the punch's mappings are
//! provably live: well inside the gateways' `nf_conntrack_udp_timeout` and
//! `@seen`-set timeout that the teardown dump, taken after the driver's whole
//! window, reads past.
//!
//! No event marks a dial, so the counter is polled. A **Watch** is armed before
//! whatever arms the rendezvous and rides every event loop the requester runs
//! after it. The rendezvous rows arm it before `ReachPeer`. The transfer rows
//! arm it before `StartDownload`, because there the download reaches the buddy
//! coordinator on its own clock. A poller that only one of those roads started
//! left a gap: the transfer requester never ran one, so no
//! `natt-buddy-transfer-cone` run ever took its in-flight proof.

use std::time::Duration;

use anyhow::Result;
use rmule_core::{Core, CoreEvent};
use tokio::time::Instant;

use super::row::BuddyRow;

/// How often the dial counter is read while the marker is still owed. One
/// second bounds how late the marker lands after the dial; the proof it
/// triggers has the gateways' three-minute mapping timeouts to land inside.
const POLL: Duration = Duration::from_secs(1);

/// The poll schedule of one body's first-dial marker.
pub(super) struct Watch {
    /// When the counter is next read; `None` once the marker is out, or for a
    /// body that never dials.
    next: Option<Instant>,
}

impl Watch {
    /// A watch whose first reading is due now.
    pub(super) fn armed() -> Self {
        Self {
            next: Some(Instant::now()),
        }
    }

    /// A watch that never reads — the event loops of bodies that do not dial.
    pub(super) fn off() -> Self {
        Self { next: None }
    }

    /// Resolve when the next reading is due; never, once none is owed.
    async fn due(&self) {
        match self.next {
            Some(at) => tokio::time::sleep_until(at).await,
            None => std::future::pending().await,
        }
    }

    /// Take one reading now, unless none is owed, and print the marker if the
    /// counter has left zero. Every event that arrives while the snapshot is
    /// awaited is still observed.
    ///
    /// # Errors
    /// If the diagnostics request cannot be sent.
    pub(super) async fn read(&mut self, core: &mut Core, row: &mut BuddyRow) -> Result<()> {
        if self.next.is_none() {
            return Ok(());
        }
        if let Some(snapshot) = super::await_snapshot(core, row).await? {
            let dials = snapshot.session.natt_dials_total;
            if dials >= 1 {
                println!("rmule-natt-first-dial dials={dials}");
                self.next = None;
                return Ok(());
            }
        }
        self.next = Some(Instant::now() + POLL);
        Ok(())
    }
}

/// The core's next event before `deadline`, taking every reading `watch` owes
/// on the way. `None` at the deadline or when the event stream ends.
///
/// # Errors
/// If a diagnostics request cannot be sent.
pub(super) async fn next_event(
    core: &mut Core,
    deadline: Instant,
    watch: &mut Watch,
    row: &mut BuddyRow,
) -> Result<Option<CoreEvent>> {
    loop {
        tokio::select! {
            () = tokio::time::sleep_until(deadline) => return Ok(None),
            () = watch.due() => {}
            event = core.next_event() => return Ok(event),
        }
        watch.read(core, row).await?;
    }
}
