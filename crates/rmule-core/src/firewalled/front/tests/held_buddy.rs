//! The held buddy through the front (`front::held_buddy`): the dial an adopt
//! starts and the adverts it states, the link it holds, the keepalive the
//! clock paces on that link, and every way the buddy is let go.

use super::*;

mod hello;
mod link_and_refusals;
mod release;

/// The buddy dial starts from the one Hello Adverts read every outbound
/// connection starts from — our ports, Kad version, IPv6, crypt support and
/// Secure User Identification — and names no buddy, because the buddy it
/// would name is the one this hello is dialing (aMule links `m_pBuddy` only
/// once the handshake completes). It dials the buddy's eD2k port within the
/// buddy dial's own timeout.
#[tokio::test(start_paused = true)]
async fn the_buddy_dial_states_every_advert_and_names_no_buddy() {
    let mut hello = crate::adapters::tests::hello_wire::live_adverts(BuddyView::default());
    hello.secure_ident = Some(std::sync::Arc::new(
        rmule_primitives::SecureIdentKey::generate().expect("a SUI keypair"),
    ));
    let mut h = ticking_harness(hello, TICK, true);
    h.kad_started();
    h.adopt(a_buddy()).await;

    let dial = h.next_dial().await;
    assert_eq!(dial.peer, PeerEndpoint::V4(a_buddy().tcp));
    let options = &dial.options;
    assert_eq!(options.connect_timeout, BUDDY_DIAL_TIMEOUT);
    assert_eq!(options.serving_buddy, None);
    assert_eq!(options.udp_ports, h.hello.udp_ports.get());
    assert!(options.udp_ports.is_some());
    assert_eq!(options.ipv6, h.hello.ipv6.get());
    assert!(options.ipv6.is_some());
    assert_eq!(
        options.obfuscation.map(|config| config.policy),
        Some(rmule_net::peer::ObfuscationPolicy::Supported)
    );
    assert!(options.secure_ident.is_some(), "SUI rides with the key");
}

/// The buddy dial follows the stance the `0x5A` stated. A buddy whose
/// connect-options byte asks for obfuscation (`0x03`: supports and
/// requests), met by our `Supported` policy, is dialled obfuscated toward the
/// hash the `0x5A` carried — aMule's `RequestBuddy` seats both on the client
/// it dials (`ClientList.cpp:1141-1144`).
#[tokio::test(start_paused = true)]
async fn an_obfuscation_requesting_buddy_is_dialled_obfuscated() {
    let mut h = live_harness();
    h.kad_started();
    let requesting =
        a_buddy_stating(rmule_primitives::SourceCryptOptions::from_byte(0x03).crypt_stance());
    assert_eq!(h.adopt(requesting).await.outcome, AdoptOutcome::Adopted);

    let dial = h.next_dial().await;
    assert_eq!(dial.options.peer_crypt, requesting.peer_crypt());
    let ours = rmule_net::peer::ObfuscationPolicy::stance_of(
        dial.options.obfuscation.map(|config| config.policy),
    );
    assert_eq!(
        dial.options.peer_crypt.outbound(ours),
        rmule_primitives::OutboundCrypt::Obfuscated {
            toward: buddy_hash()
        }
    );
}

/// The held link is kept alive on aMule's own ten-minute period, and the
/// front's clock is the one place the buddy level reaches the diagnostics:
/// the slot's state from the front's own slot, the walk and the last refusal
/// from the Kad pump's Recruit Status.
#[tokio::test(start_paused = true)]
async fn the_clock_pings_the_held_link_and_copies_the_buddy_level() {
    let mut h = harness();
    h.shared.publish_recruit(RecruitStatus {
        walking: true,
        refusal: None,
    });
    tick().await;
    assert_eq!(
        h.diagnostics.snapshot().session.buddy_state,
        BuddyState::Walking
    );
    h.shared.publish_recruit(RecruitStatus {
        walking: false,
        refusal: Some(crate::firewalled::recruit::RecruitRefusal::CryptRequired),
    });
    tick().await;
    let session = h.diagnostics.snapshot().session;
    assert_eq!(session.buddy_state, BuddyState::None);
    assert_eq!(
        session.buddy_last_recruit_refusal,
        Some(crate::firewalled::recruit::RecruitRefusal::CryptRequired),
        "a node that will never recruit says why"
    );

    let mut side = h.hold().await;
    tick().await;
    assert_eq!(
        h.diagnostics.snapshot().session.buddy_state,
        BuddyState::Held
    );
    assert!(
        side.commands.try_recv().is_err(),
        "the hold is the first ping"
    );
    tokio::time::sleep(crate::firewalled::link::BUDDY_PING_INTERVAL).await;
    settle().await;
    assert!(matches!(
        side.commands.try_recv(),
        Ok(PeerCommand::Side(SideCommand::SendBuddyPing))
    ));
    assert!(side.commands.try_recv().is_err(), "one ping per interval");
}
