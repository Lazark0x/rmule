//! The outbound crypt decision (ADR-0049): what a dial knows of the peer's
//! crypt side ([`PeerCrypt`]) and aMule's rule for meeting it with ours
//! ([`OutboundCrypt`]).
//!
//! One rule for every outbound peer-TCP dial rmule makes — a download worker's
//! High-ID or rung-0 dial, the ADR-0061 `0x95` direct-callback dial-back and
//! the ADR-0058 firewall-check dial-back alike — so the peer's stated stance is
//! read the same way wherever a dial starts.

use crate::{CryptStance, SourceCryptOptions, UserHash};

/// What a dial knows of the peer's crypt side: the stance its record stated
/// and the User Hash an obfuscated dial toward it is keyed on.
///
/// [`Self::unknown`] — nothing stated, no hash — is what a source with no
/// crypt byte reads as (a plain `OP_FOUNDSOURCES` row, a Kad row without
/// `TAG_ENCRYPTION`): aMule's client object starts with every crypt light dark
/// and only a stated options byte lights them, so at the dial such a peer is
/// met exactly as one that said "no crypt". It is still **silence**, not a
/// statement: [`Self::fold_newer`] never lets it overwrite a stance another
/// record stated (ADR-0049).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerCrypt {
    /// The stance a record or hello stated; `None` when it stated none.
    stance: Option<CryptStance>,
    user_hash: Option<UserHash>,
}

impl PeerCrypt {
    /// A peer that stated nothing: every crypt light dark, no hash.
    #[must_use]
    pub const fn unknown() -> Self {
        Self {
            stance: None,
            user_hash: None,
        }
    }

    /// A peer's crypt side from its stance and (when known) its hash.
    #[must_use]
    pub const fn new(stance: CryptStance, user_hash: Option<UserHash>) -> Self {
        Self {
            stance: Some(stance),
            user_hash,
        }
    }

    /// A peer's crypt side as a source record names it: the connect-options
    /// byte's three low bits (aMule `SetConnectOptions`, `BaseClient.cpp`
    /// 4049-4054 at the Fork Pin) through [`CryptStance::new`]'s ladder — which
    /// is aMule's own getter ladder (`updownclient.h` 923-925:
    /// `RequestsCryptLayer() = SupportsCryptLayer() && m_fRequestsCryptLayer`,
    /// `RequiresCryptLayer() = RequestsCryptLayer() && m_fRequiresCryptLayer`).
    /// No byte states no stance, which the dial reads as all lights dark.
    #[must_use]
    pub const fn from_record(
        options: Option<SourceCryptOptions>,
        user_hash: Option<UserHash>,
    ) -> Self {
        let stance = match options {
            Some(options) => Some(options.crypt_stance()),
            None => None,
        };
        Self { stance, user_hash }
    }

    /// The stance the dial meets: the one the peer stated, all lights dark
    /// when it stated none.
    #[must_use]
    pub const fn stance(self) -> CryptStance {
        match self.stance {
            Some(stance) => stance,
            None => CryptStance::disabled(),
        }
    }

    /// The stance the peer or its record stated, or `None` when nothing
    /// did — where [`Self::stance`] reads silence as disabled. What a record
    /// kept for a later run must keep this way, so silence stays silence.
    #[must_use]
    pub const fn stated_stance(self) -> Option<CryptStance> {
        self.stance
    }

    /// Whether this names anything at all — a stance or a hash.
    #[must_use]
    pub const fn is_unknown(self) -> bool {
        self.stance.is_none() && self.user_hash.is_none()
    }

    /// Fold a `newer` third-party record of the peer into this one (ADR-0049):
    /// the newer **statement** wins, silence keeps what an
    /// earlier record stated — a record with no crypt byte never invents
    /// "no crypt" over a stance that was stated — and a newer record naming
    /// another User Hash replaces this one whole, since the endpoint changed
    /// owner and the earlier stance is not the new peer's.
    #[must_use]
    pub fn fold_newer(self, newer: Self) -> Self {
        match (self.user_hash, newer.user_hash) {
            (Some(held), Some(named)) if held != named => newer,
            _ => Self {
                stance: newer.stance.or(self.stance),
                user_hash: newer.user_hash.or(self.user_hash),
            },
        }
    }

    /// The hash an obfuscated dial toward the peer is keyed on, when known.
    #[must_use]
    pub const fn user_hash(self) -> Option<UserHash> {
        self.user_hash
    }

    /// aMule's outbound crypt rule, applied to this peer and `ours` — the
    /// stance this node runs under ([`CryptStance::disabled`] when obfuscation
    /// is off).
    ///
    /// **Refuse** — [`OutboundCrypt::Incompatible`], before any socket — when
    /// `(theirs.requires && !ours.supports) || (ours.requires &&
    /// !theirs.supports)`: aMule's contact precondition
    /// (`CheckContactPreconditions`, `BaseClient.cpp` 1913-1915 at the Fork
    /// Pin; `TryToConnect`,
    /// [`BaseClient.cpp#L1409`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/BaseClient.cpp#L1409)
    /// in 2.3.3), which then deletes the client — every road to that peer
    /// meets the same two stances.
    ///
    /// **Obfuscate** — keyed on the peer's hash — when `theirs.supports &&
    /// ours.supports && (theirs.requests || ours.requests)` and the hash is in
    /// hand: aMule's `Connect` (`BaseClient.cpp` 2341-2342 at the Fork Pin;
    /// [`#L1614`](https://github.com/amule-project/amule/blob/4e8f2b3c3f90cda23765730546b04c684a92e4f5/src/BaseClient.cpp#L1614)
    /// in 2.3.3), `HasValidHash()` its first conjunct. Someone has to ask: a
    /// peer that merely supports crypt, met by a node that merely supports it,
    /// is dialed **plaintext**. Obfuscation becomes a must — a failed
    /// handshake ends the dial either way, with no plaintext retry
    /// — when either side requires it; that distinction is not carried
    /// on [`OutboundCrypt::Obfuscated`] itself, since nothing
    /// downstream reads it.
    ///
    /// **Refuse** too — [`OutboundCrypt::Incompatible`] — when a side
    /// requires obfuscation and the peer's hash is not in hand:
    /// there is no key, and when either side requires, the dial is obfuscated
    /// or not made. aMule dials that peer plaintext because `HasValidHash()`
    /// gates `Connect` before the stances do; a requiring responder then cuts
    /// the plaintext opening (`EncryptedStreamSocket.cpp` 377-391 at the Fork
    /// Pin), and a requiring dialer would speak in the clear against its own
    /// policy.
    ///
    /// Otherwise **plaintext**.
    #[must_use]
    pub const fn outbound(self, ours: CryptStance) -> OutboundCrypt {
        let theirs = self.stance();
        if (theirs.requires() && !ours.supports()) || (ours.requires() && !theirs.supports()) {
            return OutboundCrypt::Incompatible;
        }
        // Past the refusal, a requiring side implies both support and one
        // requests, so `required` implies `asked`.
        let required = theirs.requires() || ours.requires();
        let asked = theirs.supports() && ours.supports() && (theirs.requests() || ours.requests());
        match self.user_hash {
            Some(toward) if asked => OutboundCrypt::Obfuscated { toward },
            None if required => OutboundCrypt::Incompatible,
            _ => OutboundCrypt::Plaintext,
        }
    }
}

impl Default for PeerCrypt {
    fn default() -> Self {
        Self::unknown()
    }
}

/// What [`PeerCrypt::outbound`] decides about one dial.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutboundCrypt {
    /// Dial in the clear.
    Plaintext,
    /// Run the crypt handshake as the initiator, keyed on the peer's hash.
    /// A failed handshake ends the dial either way — there is no plaintext
    /// retry — whether or not a side requires obfuscation, so
    /// that distinction is not carried here.
    Obfuscated {
        /// The peer's User Hash — the obfuscation key's seed, never ours.
        toward: UserHash,
    },
    /// The two stances cannot meet — or a side requires obfuscation and the
    /// peer's hash, its key, is not in hand; do not dial at all.
    Incompatible,
}

#[cfg(test)]
mod tests {
    use super::{OutboundCrypt, PeerCrypt};
    use crate::{CryptStance, SourceCryptOptions, UserHash};

    const HASH: UserHash = UserHash::from_bytes([0x5A; 16]);
    const OFF: CryptStance = CryptStance::disabled();
    const SUPPORTS: CryptStance = CryptStance::new(true, false, false);
    const REQUESTS: CryptStance = CryptStance::new(true, true, false);
    const REQUIRES: CryptStance = CryptStance::new(true, true, true);

    fn peer(options: u8) -> PeerCrypt {
        PeerCrypt::from_record(Some(SourceCryptOptions::from_byte(options)), Some(HASH))
    }

    fn obfuscated() -> OutboundCrypt {
        OutboundCrypt::Obfuscated { toward: HASH }
    }

    #[test]
    fn the_rule_reads_both_stances_as_amule_does() {
        let cases = [
            // Someone has to ask.
            (peer(0x01), SUPPORTS, OutboundCrypt::Plaintext),
            (peer(0x01), REQUESTS, obfuscated()),
            (peer(0x03), SUPPORTS, obfuscated()),
            // A requiring side makes the obfuscation a must (same verdict:
            // the unread `required` distinction is gone).
            (peer(0x07), SUPPORTS, obfuscated()),
            (peer(0x01), REQUIRES, obfuscated()),
            // A requiring side the other cannot meet refuses the pair.
            (peer(0x07), OFF, OutboundCrypt::Incompatible),
            (peer(0x00), REQUIRES, OutboundCrypt::Incompatible),
            (PeerCrypt::unknown(), REQUIRES, OutboundCrypt::Incompatible),
            // A peer's higher light without the lower is dark (the ladder).
            (peer(0x04), OFF, OutboundCrypt::Plaintext),
            // No hash, no key: an asked-for obfuscation dials plaintext...
            (
                PeerCrypt::new(REQUESTS, None),
                SUPPORTS,
                OutboundCrypt::Plaintext,
            ),
            // ...but a required one is refused, whichever side requires.
            (
                PeerCrypt::new(REQUIRES, None),
                SUPPORTS,
                OutboundCrypt::Incompatible,
            ),
            (
                PeerCrypt::new(SUPPORTS, None),
                REQUIRES,
                OutboundCrypt::Incompatible,
            ),
        ];
        for (theirs, ours, expected) in cases {
            assert_eq!(theirs.outbound(ours), expected, "{theirs:?} vs {ours:?}");
        }
    }

    /// Newest statement wins; silence keeps what was stated; another hash is
    /// another owner (ADR-0049).
    #[test]
    fn a_newer_record_folds_by_statement_not_by_arrival() {
        let other = UserHash::from_bytes([0x6B; 16]);
        let silent = PeerCrypt::from_record(None, Some(HASH));
        assert_eq!(peer(0x07).fold_newer(silent), peer(0x07));
        assert_eq!(peer(0x07).fold_newer(peer(0x01)), peer(0x01));
        assert_eq!(
            peer(0x07).fold_newer(PeerCrypt::from_record(None, Some(other))),
            PeerCrypt::from_record(None, Some(other))
        );
        assert_eq!(
            PeerCrypt::new(REQUIRES, None).fold_newer(silent),
            PeerCrypt::new(REQUIRES, Some(HASH))
        );
    }
}
