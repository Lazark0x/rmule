//! The counters that say whether `TAG_BUDDYHASH`'s other spelling ever
//! mattered (ADR-0061): aMule writes the tag big-endian — the
//! captured form rmule reads first and writes always — while eMule 0.70b and
//! eMuleAI write it word-ordered, a source reading no capture has pinned. Each
//! role counts its own leg apart, so a bench run can say whether an
//! eMule-family counterparty was ever on the other end.

use super::DiagnosticsState;

/// Per-session counts of the `TAG_BUDDYHASH` fallback spelling at work, one
/// per role.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BuddyHashSpellingCounters {
    /// Requester: buddy callbacks whose primary-spelling `0x52` drew no
    /// dial-back in the whole wait and were asked once more under the other
    /// spelling. A dial-back that follows one of these is the first evidence
    /// that an eMule-family publisher named its buddy that way.
    pub callback_fallback_spelling_sent_total: u64,
    /// Buddy/firewalled node: relayed `OP_CALLBACK`s (`0x99`) dialed back
    /// whose check ID matched our Kad ID only under the other spelling — a
    /// requester that read our aMule-spelled row the eMule way. A subset of
    /// `relayed_callbacks_dialed_total`.
    pub relayed_callbacks_swapped_spelling_total: u64,
    /// Open node serving a buddy: `0x52`s whose claimed ID matched our
    /// registered buddy only under the other spelling, relayed verbatim as
    /// `OP_CALLBACK` to the buddy — whose own check decides whether it dials.
    pub buddy_relays_swapped_spelling_total: u64,
}

impl DiagnosticsState {
    /// Count one fallback-spelling `0x52` a download sent.
    pub(crate) fn count_callback_fallback_spelling_sent(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        let counter = &mut inner
            .session
            .buddy_hash_spelling
            .callback_fallback_spelling_sent_total;
        *counter = counter.saturating_add(1);
    }

    /// Count one `0x52` relayed to our buddy under the other spelling of its
    /// ID.
    pub(crate) fn record_buddy_relay_swapped_spelling(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        let counter = &mut inner
            .session
            .buddy_hash_spelling
            .buddy_relays_swapped_spelling_total;
        *counter = counter.saturating_add(1);
    }

    /// Count one relayed `0x99` dialed back under the other spelling of our
    /// own Kad ID.
    pub(crate) fn record_relayed_callback_swapped_spelling(&self) {
        let mut inner = self.inner.lock().expect("diagnostics mutex poisoned");
        let counter = &mut inner
            .session
            .buddy_hash_spelling
            .relayed_callbacks_swapped_spelling_total;
        *counter = counter.saturating_add(1);
    }
}
