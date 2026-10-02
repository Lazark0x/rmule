//! The **Pending Tunnel Claim** table (ADR-0091): what a download registers
//! when its Low-ID callback has gone silent for twelve seconds, so that the
//! **Dialer Tunnel** the punch may raise comes back to *it* instead of taking
//! the serve road.
//!
//! The ADR-0039 [`SharedCallbackTable`](super::SharedCallbackTable) pattern with a
//! different key. A callback is matched by what the server namespace can say
//! about a peer — `(connected_server, low_id)` — because that is what a
//! called-back peer's hello reports. A punch names nothing of the kind: the
//! rendezvous, the `0x61` introduction and the requester ledger are all keyed
//! by the target's **User Hash**, so that is this table's key.
//!
//! # Two roads, one key
//!
//! A silent callback does not *become* a punch — the punch runs beside it
//! (ADR-0091's "two deadlines, one key"). So the entry here carries the
//! [`CallbackKey`] its callback is held under, and an adoption down either road
//! reports that same key back to the brain. One `CancelCallbackTimeout` then
//! ends both: it drops both deadlines, retracts the callback's routing index,
//! and retracts this claim. Whichever connection lands first takes the slot;
//! the other road's registration is gone before a second one can.
//!
//! # The hello decides
//!
//! A claim is consulted only for a tunnel rmule **dialed** — one it asked for,
//! toward a hash it named. The endpoint proves nothing: behind a NAT the
//! address that answers a punch is a mapping, not an identity. So adoption is
//! granted only when the user hash the peer's hello reports equals the hash the
//! claim is keyed by; a mismatch closes the connection and leaves the claim
//! pending, because the download's target may still be on its way.
//!
//! # One claim per download
//!
//! One peer may hold two files the **Download Set** fetches, and both
//! downloads may fall to a punch toward it (ADR-0107). A Tunnel is one
//! connection, so the table keeps an ordered list per target with one claim per
//! download: the oldest takes a Tunnel, the others stay pending to their own
//! deadlines, a retirement reaches every claimant, and the attempt is abandoned
//! only when its last claimant lets go. No claim ever displaces another
//! download's.
//!
//! A candidate with no User Hash registers nothing: there is no key to hold it
//! under and no hello that could confirm it. Its fallback still runs — the
//! server coordinator needs only the id — and a Tunnel it raises takes the
//! serve road, counted as
//! [`natt_download_fallbacks_unclaimable_total`](crate::diagnostics::SessionCounters::natt_download_fallbacks_unclaimable_total).

use std::collections::HashMap;
use std::sync::Arc;

use rmule_peer::PartBitmap;
use rmule_primitives::{Ed2kFileLink, UserHash};
use tokio::sync::{Mutex, mpsc};

use crate::natt::front::{AttemptRetirement, NattRisenSender};

use super::inbound_triage::CallbackKey;
use super::peer_transfer::PeerWorker;
#[cfg(test)]
use super::serve_runtime::SharedTunnelAdmit;

/// One download's claim on the Dialer Tunnel its silent callback asked for.
pub(crate) struct PendingTunnelEntry {
    /// The file the adopted worker downloads — the triage knows only the key.
    pub(crate) file: Ed2kFileLink,
    /// What the download held when it made the claim — the adopted worker's
    /// connect-time name ask carries it.
    pub(crate) own_status: PartBitmap,
    /// Whether the adopted worker's connect-time request asks for sources —
    /// the download's decision when it claimed (ADR-0108).
    pub(crate) want_sources: bool,
    /// The callback this punch runs beside. Reported back with the adopted
    /// worker so the brain ends *one* pending callback whichever road landed,
    /// and so its `CancelCallbackTimeout` retracts both registrations.
    pub(crate) callback: CallbackKey,
    /// Back to the registering runner, tagged with [`Self::callback`].
    pub(crate) adopt_tx: mpsc::Sender<(CallbackKey, PeerWorker)>,
    /// The road not taken, tagged the same way: where the **NAT-T Front**
    /// reports that the **Traversal Attempt** toward this target retired, so
    /// the download hears it now instead of at its 30 s slot release.
    /// A channel of its own rather than a variant on `adopt_tx`,
    /// because the two carry opposite news and only one of them hands over a
    /// worker.
    pub(crate) retire_tx: mpsc::Sender<(CallbackKey, AttemptRetirement)>,
    /// The download also asked the target to **dial us** — a buddy callback
    /// (ADR-0061 route 4) — so a path nothing here aimed may be
    /// adopted too, when its hello names this hash. A punch's claim alone
    /// leaves it `false`, and an accepted path then takes the serve road
    /// (ADR-0091).
    pub(crate) dial_back: bool,
}

/// What the triage may do with a risen Dialer Tunnel.
pub(crate) enum TunnelClaimVerdict {
    /// A download claimed this target and the hello confirmed it: the claim is
    /// spent and the connection is that download's worker.
    Adopted(PendingTunnelEntry),
    /// A download claimed this target and the peer identified as somebody
    /// else. The claim stays pending — the real target may still arrive — and
    /// this connection is closed rather than served: nothing asked for it.
    HelloMismatch,
    /// Nobody claimed this target: the tunnel takes the serve road, exactly as
    /// it did before this table existed.
    Unclaimed,
}

/// The core-owned claim table, held the way [`SharedCallbackTable`](super::SharedCallbackTable) is: the
/// actor owns the `Arc`, the serve adapter clones one (the triage consults it)
/// and each download's runner clones one (it registers and retracts).
///
/// It carries its own diagnostics handle because the two facts only *it* sees
/// — an adoption granted and one refused on the hello — are decided in the
/// serve adapter's triage, which is built before the core's
/// [`DiagnosticsState`](crate::diagnostics::DiagnosticsState) exists. The
/// actor installs it afterwards, exactly as it installs the server
/// coordinator's; an uninstalled cell simply counts nothing.
#[derive(Clone, Default)]
pub(crate) struct SharedTunnelClaims {
    claims: Arc<Mutex<HashMap<UserHash, Vec<PendingTunnelEntry>>>>,
    diagnostics: Arc<std::sync::OnceLock<crate::diagnostics::DiagnosticsState>>,
    /// The front's own risen-tunnel sender, installed by the
    /// same front this table's `NattWiring.claims` clone was handed to: the
    /// seam an adoption's confirmed hello reports back through, exactly as a
    /// closed **Punched Path** does.
    risen: Arc<std::sync::OnceLock<NattRisenSender>>,
}

impl SharedTunnelClaims {
    /// Install where adoption outcomes are reported. Idempotent.
    pub(crate) fn install_diagnostics(&self, diagnostics: crate::diagnostics::DiagnosticsState) {
        let _ = self.diagnostics.set(diagnostics);
    }

    /// Install where a confirmed adoption's hello is reported.
    /// Idempotent, and installed by the front whose wiring holds this same
    /// table. A `SharedTunnelClaims` no front was ever built over — the
    /// non-`Core::new` constructors — simply reports nothing, exactly as an
    /// unset diagnostics handle counts nothing.
    pub(crate) fn install_risen(&self, risen: NattRisenSender) {
        let _ = self.risen.set(risen);
    }

    /// Report that `peer`'s own hello confirmed an adoption this table
    /// granted — every road, not only an accept an address alone could not
    /// attribute: the front's own `identified` is a no-op for a
    /// peer it never held an attempt or hold for, so paying that one cheap,
    /// idempotent call on every adoption is simpler than threading which road
    /// found the accept ambiguous down into this table, and it costs nothing
    /// extra on the far more common case where nothing was ambiguous at all.
    pub(crate) fn identified(&self, peer: UserHash) {
        if let Some(risen) = self.risen.get() {
            risen.identified(peer);
        }
    }

    /// Hold `target`'s next dialed Tunnel for the registering download.
    ///
    /// Two downloads falling back toward the same peer — one source serving
    /// two files — each hold a claim, in the order they registered (ADR-0107).
    /// The same download registering again replaces its own claim in place,
    /// keeping its turn; and a claim for the **same pending callback** keeps
    /// the dial-back the earlier one stated: the punch that rides beside a
    /// buddy callback is a second road to one slot, not a replacement for the
    /// first.
    pub(crate) async fn register(&self, target: UserHash, mut entry: PendingTunnelEntry) {
        let mut held = self.claims.lock().await;
        let claimants = held.entry(target).or_default();
        match claimants
            .iter_mut()
            .find(|prior| prior.adopt_tx.same_channel(&entry.adopt_tx))
        {
            Some(own) => {
                if own.callback == entry.callback {
                    entry.dial_back |= own.dial_back;
                }
                *own = entry;
            }
            None => claimants.push(entry),
        }
    }

    /// Spend `reported`'s claim on a path nothing here aimed, when the claim
    /// asked the target to dial us back (ADR-0061 route 4). The
    /// hello's User Hash is the only key: a Kad candidate's callback key is an
    /// id no hello carries. `None` — no claim, or a punch's claim alone — is
    /// the serve road.
    ///
    /// Of several downloads' claims the oldest that asked for a dial-back
    /// takes it.
    pub(crate) async fn adopt_dial_back(&self, reported: UserHash) -> Option<PendingTunnelEntry> {
        let mut held = self.claims.lock().await;
        let claimants = held.get_mut(&reported)?;
        let oldest = claimants.iter().position(|entry| entry.dial_back)?;
        let adopted = claimants.remove(oldest);
        if claimants.is_empty() {
            held.remove(&reported);
        }
        Some(adopted)
    }

    /// Drop `owner`'s claim on `target` — the callback landed first, the slot
    /// was released, or the attempt was retired. Idempotent: reports whether a
    /// claim was there to drop.
    ///
    /// Only the claim's **owner** may drop it — the runner whose `adopt_tx`
    /// registered it; another download's claim on the same
    /// target stays.
    ///
    /// When the last claimant lets go, the **NAT-T Front** is told and ends the
    /// attempt rather than dialing on for nobody. After a retirement that is a
    /// no-op there; after the callback landed or the slot lapsed it is the
    /// attempt's end.
    pub(crate) async fn retract(
        &self,
        target: UserHash,
        owner: &mpsc::Sender<(CallbackKey, PeerWorker)>,
    ) -> bool {
        let (retracted, last) = {
            let mut held = self.claims.lock().await;
            take_owned_on(&mut held, target, owner)
        };
        if retracted {
            self.claim_let_go(target, last);
        }
        retracted
    }

    /// Drop every claim `owner` still holds, without waiting: its download
    /// ended, so no Tunnel toward any of those targets will be adopted for it
    /// Synchronous so a `Drop` can run it on every exit, an
    /// abort included; `false` when the table is busy and nothing was
    /// dropped, for the caller to finish with [`Self::release_owner`].
    pub(crate) fn try_release_owner(
        &self,
        owner: &mpsc::Sender<(CallbackKey, PeerWorker)>,
    ) -> bool {
        let Ok(mut held) = self.claims.try_lock() else {
            return false;
        };
        let released = take_owned_by(&mut held, owner);
        drop(held);
        for (target, last) in released {
            self.claim_let_go(target, last);
        }
        true
    }

    /// [`Self::try_release_owner`], waiting for the table.
    pub(crate) async fn release_owner(&self, owner: &mpsc::Sender<(CallbackKey, PeerWorker)>) {
        let released = take_owned_by(&mut *self.claims.lock().await, owner);
        for (target, last) in released {
            self.claim_let_go(target, last);
        }
    }

    /// A claim on `target` was dropped by its claimant: count it, and when it
    /// was the `last` claimant tell the **NAT-T Front**, which ends the attempt
    /// rather than dialing on for nobody.
    fn claim_let_go(&self, target: UserHash, last: bool) {
        if let Some(diagnostics) = self.diagnostics.get() {
            diagnostics.count_natt_download_claim_retired();
        }
        if last && let Some(risen) = self.risen.get() {
            risen.abandoned(target);
        }
    }

    /// Tell every download that claimed `target` that the **Traversal
    /// Attempt** toward it retired, with the reason (ADR-0091; ADR-0107).
    /// Reports whether there was a claimant to tell.
    ///
    /// **The claims are left standing.** Retracting it is
    /// the download runner's `CallbackContext` job, downstream of the brain
    /// that is being told — one owner
    /// of the retraction rule is what keeps a landed connection on either road
    /// from leaving the other's registration behind (ADR-0091's "two roads,
    /// one key, one cancel").
    ///
    /// `try_send`, never `send`: the caller is the NAT-T front's own loop,
    /// which may not wait on a consumer it does not drain. A
    /// runner that has stopped draining loses its retirement notice and falls
    /// back on the callback's 30 s deadline, which is what bounded the claim
    /// before this path existed.
    pub(crate) async fn retire(&self, target: UserHash, reason: AttemptRetirement) -> bool {
        let told: Vec<_> = self
            .claims
            .lock()
            .await
            .get(&target)
            .map(|claimants| {
                claimants
                    .iter()
                    .map(|entry| (entry.callback, entry.retire_tx.clone()))
                    .collect()
            })
            .unwrap_or_default();
        for (callback, retire_tx) in &told {
            if retire_tx.try_send((*callback, reason)).is_err() {
                tracing::debug!(
                    ?target,
                    ?reason,
                    "a retired NAT-T attempt had nowhere to report; the callback's own deadline stands"
                );
            }
        }
        !told.is_empty()
    }

    /// Rule on a Tunnel rmule dialed toward `claimed` whose peer identified as
    /// `reported`. A claim is spent only by [`TunnelClaimVerdict::Adopted`] —
    /// the oldest, when several downloads claim the target (ADR-0107); a
    /// mismatch leaves every claim exactly where it was, because the target
    /// they are waiting for may still be coming.
    pub(crate) async fn rule(&self, claimed: UserHash, reported: UserHash) -> TunnelClaimVerdict {
        let verdict = {
            let mut held = self.claims.lock().await;
            match held.get_mut(&claimed) {
                None => TunnelClaimVerdict::Unclaimed,
                Some(_) if claimed != reported => TunnelClaimVerdict::HelloMismatch,
                Some(claimants) => {
                    let oldest = claimants.remove(0);
                    if claimants.is_empty() {
                        held.remove(&claimed);
                    }
                    TunnelClaimVerdict::Adopted(oldest)
                }
            }
        };
        if let Some(diagnostics) = self.diagnostics.get() {
            match verdict {
                TunnelClaimVerdict::Adopted(_) => diagnostics.count_natt_download_adoption(),
                TunnelClaimVerdict::HelloMismatch => {
                    diagnostics.count_natt_download_adoption_refused();
                }
                TunnelClaimVerdict::Unclaimed => {}
            }
        }
        verdict
    }
}

/// Remove `owner`'s claim on `target`: whether there was one, and whether it
/// was the target's last.
fn take_owned_on(
    held: &mut HashMap<UserHash, Vec<PendingTunnelEntry>>,
    target: UserHash,
    owner: &mpsc::Sender<(CallbackKey, PeerWorker)>,
) -> (bool, bool) {
    let Some(claimants) = held.get_mut(&target) else {
        return (false, false);
    };
    let before = claimants.len();
    claimants.retain(|entry| !entry.adopt_tx.same_channel(owner));
    let removed = claimants.len() != before;
    let last = claimants.is_empty();
    if last {
        held.remove(&target);
    }
    (removed, removed && last)
}

/// Remove every claim in `held` that `owner` registered, naming each target and
/// whether its last claimant went with it.
fn take_owned_by(
    held: &mut HashMap<UserHash, Vec<PendingTunnelEntry>>,
    owner: &mpsc::Sender<(CallbackKey, PeerWorker)>,
) -> Vec<(UserHash, bool)> {
    let targets: Vec<UserHash> = held
        .iter()
        .filter(|(_, claimants)| {
            claimants
                .iter()
                .any(|entry| entry.adopt_tx.same_channel(owner))
        })
        .map(|(target, _)| *target)
        .collect();
    targets
        .into_iter()
        .map(|target| (target, take_owned_on(held, target, owner).1))
        .collect()
}

#[cfg(test)]
mod tests;
