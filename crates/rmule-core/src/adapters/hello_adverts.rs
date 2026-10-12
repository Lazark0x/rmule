//! **Hello Adverts**: what every hello this node sends states about it — the
//! accept pump's answer, a download dial, the Kad firewall-check dial-back and
//! UDP-check helper dial, the firewalled front's buddy dial, a risen Tunnel
//! and a callback dial-back.
//!
//! aMule writes one hello for every outbound connect (`CClientTCPSocket::
//! OnConnect` → `SendHelloPacket`, `ClientTCPSocket.cpp:2036`) and one for
//! every answer, with `CT_EMULE_UDPPORTS` unconditionally among its tags
//! (`BaseClient.cpp:1482`). So a road that builds its hello from
//! [`ConnectOptions::default`](rmule_net::peer::ConnectOptions) tells its
//! peer something false: no reask port, no Kad port (and so no Kad-version
//! nibble), no IPv6, no crypt support, no Secure User Identification.
//! [`HelloAdverts::connect_options`] is the one place a connection's options
//! are started from, so no road can.

use std::sync::{Arc, OnceLock};

use rmule_net::peer::{ConnectOptions, ObfuscationConfig};
use rmule_peer::SecureIdentConfig;
use rmule_primitives::{PeerCrypt, SecureIdentKey};

use super::ipv6_advert::SharedIpv6Advert;
use super::udp_ports_advert::SharedUdpPortsAdvert;
use crate::firewalled::front::BuddyView;
use crate::obfuscation_policy::SharedObfuscationPolicy;
use crate::reachability::SharedSelfReach;

/// The live facts a hello states about this node, each read per connection
/// from its one owner rather than cached when a road was wired:
/// what is true when the peer is met is what the hello says.
///
/// One instance is built in `Core::builder` and cloned into every road that
/// sends a hello. Default/empty (no advert of any kind, crypt off) on the
/// adapter-level constructors a test builds.
#[derive(Clone, Default)]
pub struct HelloAdverts {
    /// `CT_EMULE_UDPPORTS` (ADR-0057): the reask/Kad ports, while served. The
    /// Kad-version nibble rides the Kad half (`rmule-peer` `handshake.rs`).
    pub(crate) udp_ports: SharedUdpPortsAdvert,
    /// `CT_MOD_IP_V6` (ADR-0087): the Advertised Endpoints chooser's verdict.
    pub(crate) ipv6: SharedIpv6Advert,
    /// `CT_EMULE_BUDDYIP` / `BUDDYUDP` / `SERVINGBUDDYIPV6`: the
    /// **Buddy Snapshot** the Firewalled Front publishes of its slot — the
    /// held link's advert, the same fact our source publishes name — and,
    /// beside it, the Kad pump's Recruit Status.
    pub(crate) buddy: BuddyView,
    /// **Self Reach** (ADR-0060), installed once by the core actor that
    /// weaves it: the buddy tags' `IsFirewalled()` gate and the
    /// `MiscOptions2` direct-callback bit, asked per hello. Empty — no tags,
    /// no bit — until then, as an unstarted core claims nothing.
    pub(crate) reach: Arc<OnceLock<SharedSelfReach>>,
    /// Our obfuscation policy (`CoreSettings::obfuscation`, ADR-0042/0046),
    /// the one cell a live change writes: the `MiscOptions2` crypt bits, the
    /// side of the outbound crypt rule that is ours, and the accept's byte-0
    /// rule, each read when its connection starts. `None` advertises no crypt,
    /// dials plaintext and accepts plain alone.
    pub(crate) obfuscation: SharedObfuscationPolicy,
    /// Our Secure User Identification keypair (ADR-0041): the `MiscOptions1`
    /// SUI nibble, and the key the `OP_SECIDENTSTATE` exchange signs with
    /// The Core's, loaded once by `Core::builder` from the store
    /// it is given and never replaced (ADR-0048 "Identity ownership")
    /// — aMule's `CClientCreditsList::InitalizeCrypting` shape. `None`
    /// only when that load failed, or on an adapter-level test build.
    ///
    /// aMule lights the SUI nibble on every hello it writes
    /// (`BaseClient.cpp:1508`, `:1522-1529`) and opens the exchange on every
    /// connection whose two info packets arrived (`:3255-3265`), so no road
    /// carries a key of its own.
    pub(crate) secure_ident: Option<Arc<SecureIdentKey>>,
}

/// A fresh random **SUI Challenge** for one connection (ADR-0041: the random
/// challenge is the anti-replay half of Secure User Identification; signing the
/// verifier's key is the anti-relay half). aMule draws one per
/// `SendSecIdentStatePacket` (`BaseClient.cpp:3215-3216`).
pub(crate) fn mint_sui_challenge() -> u32 {
    let mut bytes = [0u8; 4];
    getrandom::fill(&mut bytes).expect("OS entropy for SUI challenge");
    u32::from_le_bytes(bytes)
}

impl HelloAdverts {
    /// Install **Self Reach**, once: the owner the hello's buddy tags and
    /// direct-callback bit ask. A second install is ignored — one owner per
    /// core.
    pub(crate) fn install_reach(&self, reach: SharedSelfReach) {
        let _ = self.reach.set(reach);
    }

    /// The buddy our hello names: the snapshot's held-link advert under
    /// aMule's `GetBuddy() && IsFirewalled()` (`BaseClient.cpp:1031`,
    /// `4e8f2b3c`), the owner's union read now. A link held or lost on the
    /// front's task shows in the very next hello.
    fn serving_buddy(&self) -> Option<rmule_peer::ServingBuddyAdvert> {
        let firewalled = self.reach.get().is_some_and(SharedSelfReach::firewalled);
        firewalled.then(|| self.buddy.snapshot().serving).flatten()
    }

    /// The options one connection starts from: every advert read now, and our
    /// crypt policy met with `peer_crypt` — the peer's own stance and key, as
    /// far as the road knows them (ADR-0049's outbound rule; the accept side,
    /// which keys from its own hash, passes [`PeerCrypt::unknown`]).
    ///
    /// Secure User Identification rides with a challenge minted here, per
    /// call: a challenge belongs to the one connection that proves with it
    /// (ADR-0041), so options are built per connection and never reused.
    pub(crate) fn connect_options(&self, peer_crypt: PeerCrypt) -> ConnectOptions {
        ConnectOptions {
            udp_ports: self.udp_ports.get(),
            // The chooser's verdict changes with a prefix renumber, and a
            // hello built from a cached one would name an address we no longer
            // hold (ADR-0087).
            ipv6: self.ipv6.get(),
            // The buddy link is held and lost on the firewalled front's task,
            // and the tag must not outlive it.
            serving_buddy: self.serving_buddy(),
            // `MiscOptions2` bit 12: Self Reach at this hello.
            direct_udp_callback: self
                .reach
                .get()
                .is_some_and(SharedSelfReach::hello_direct_udp_callback),
            // The policy in force at this connection's start: a live change
            // reaches the next one, and this one keeps what it negotiates.
            obfuscation: self
                .obfuscation
                .get()
                .map(|policy| ObfuscationConfig { policy }),
            peer_crypt,
            secure_ident: self.secure_ident.clone().map(|key| SecureIdentConfig {
                key,
                challenge: mint_sui_challenge(),
            }),
            ..ConnectOptions::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every connection proves with its own challenge (ADR-0041's
    /// anti-replay half) — a signature captured on one link cannot answer the
    /// next, so no road may reuse one connection's options for another.
    #[test]
    fn each_connection_draws_its_own_sui_challenge() {
        let adverts = HelloAdverts {
            secure_ident: Some(Arc::new(SecureIdentKey::generate().expect("a SUI keypair"))),
            ..HelloAdverts::default()
        };
        let challenge = || {
            adverts
                .connect_options(PeerCrypt::unknown())
                .secure_ident
                .expect("SUI rides with the Core's key")
                .challenge
        };
        assert_ne!(challenge(), challenge());
    }
}
