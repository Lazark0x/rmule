//! An accepted hello settled against rmule's own dials (ADR-0107 invariant
//! 7): answered and filed when nothing crosses it; held, while a dial's hello
//! is out unanswered, until the far end shows which link it kept.

use rmule_net::peer::Connection as PeerConnection;
use rmule_peer::{ConnectionCommand, ConnectionEvent, PeerCommand, PeerEvent, PeerIdentity};
use tokio::sync::mpsc;

use super::InboundPeerDeps;
use crate::adapters::peer_link::{AcceptedLink, CrossedDial, DialSettled, LinkName, Meeting};
use crate::adapters::serve_runtime::ServeInput;
use crate::service::PortTestClosedBy;

/// How an accepted hello settled.
pub(super) enum Settled {
    /// The peer keeps this link: answered and filed.
    Answered(AcceptedLink),
    /// The link is gone, and this is who closed it.
    Closed(PortTestClosedBy),
}

/// Settle the hello `identity` read on `conn`. Its session's gate met rmule's
/// dials as it read it; a link with no such gate meets them here, its hello
/// answered already.
pub(super) async fn settle_hello(
    conn: &mut PeerConnection,
    identity: &PeerIdentity,
    event_tx: &mpsc::Sender<ServeInput>,
    deps: &InboundPeerDeps,
) -> Settled {
    let remote = conn.peer_endpoint();
    let names = LinkName::proven(remote, identity, None);
    let mut met = deps.peer_links.take_met(remote);
    let mut told = false;
    loop {
        let meeting = met
            .take()
            .unwrap_or_else(|| deps.peer_links.meet(remote, names.clone(), None));
        let crossed = match meeting {
            Meeting::Clear(accepted) => {
                let answer = PeerCommand::Connection(ConnectionCommand::AnswerHello);
                return match conn.send(answer).await {
                    Ok(()) => Settled::Answered(accepted),
                    // The driver stopped first: the peer hung up on the
                    // answer, and its paired `Disconnected` says so.
                    Err(_) => {
                        let closed_by = close_reason(conn).await;
                        let _ = event_tx.send(ServeInput::closed_here()).await;
                        Settled::Closed(closed_by)
                    }
                };
            }
            Meeting::Crossed(crossed) => crossed,
        };
        if !told {
            told = true;
            let _ = event_tx.send(ServeInput::CrossedHelloHeld).await;
        }
        match hold(conn, crossed).await {
            Held::DialEnded => {}
            Held::DialAnswered => {
                let _ = event_tx.send(ServeInput::CrossedLinkLetGo).await;
                let _ = event_tx.send(ServeInput::closed_here()).await;
                return Settled::Closed(PortTestClosedBy::Us);
            }
            Held::LinkClosed(closed_by) => {
                let _ = event_tx.send(ServeInput::closed_here()).await;
                return Settled::Closed(closed_by);
            }
        }
    }
}

/// Drain a connection whose driver has stopped, the peer having hung up before
/// its answer could go, to its paired `Disconnected`: who closed it.
async fn close_reason(conn: &mut PeerConnection) -> PortTestClosedBy {
    while let Some(event) = conn.next_event().await {
        if let PeerEvent::Connection(ConnectionEvent::Disconnected { reason }) = event {
            return PortTestClosedBy::from(&reason);
        }
    }
    PortTestClosedBy::DriverEnded
}

/// How a hold ended.
enum Held {
    /// The dial ended, or the bound gave it up: the hello is met again.
    DialEnded,
    /// The far end answered the dial.
    DialAnswered,
    /// The far end closed this link: it attached the dial.
    LinkClosed(PortTestClosedBy),
}

/// Wait for the first of the dial settling, this link closing and the bound.
/// The peer sends nothing more before its answer, so nothing read here is
/// anyone's but the close.
async fn hold(conn: &mut PeerConnection, mut crossed: CrossedDial) -> Held {
    let bound = tokio::time::sleep(crossed.hold());
    tokio::pin!(bound);
    loop {
        tokio::select! {
            settled = crossed.settled() => {
                return match settled {
                    DialSettled::Answered => Held::DialAnswered,
                    DialSettled::Ended => Held::DialEnded,
                };
            }
            () = &mut bound => {
                crossed.give_up();
                return Held::DialEnded;
            }
            event = conn.next_event() => match event {
                Some(PeerEvent::Connection(ConnectionEvent::Disconnected { reason })) => {
                    return Held::LinkClosed(PortTestClosedBy::from(&reason));
                }
                Some(_) => {}
                None => return Held::LinkClosed(PortTestClosedBy::DriverEnded),
            },
        }
    }
}
