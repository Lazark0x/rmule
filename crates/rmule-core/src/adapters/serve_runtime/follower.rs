//! The serve's **Session Follower**: the listener binds at attach, before any
//! server session exists, and the session it would announce to is the
//! operator's to make (ADR-0095, "Connecting is the operator's act"). So the
//! serve dials nothing. It follows: each session the operator establishes gets
//! the current share set announced (`OP_OFFERFILES`), as aMule re-sends its
//! list to every server it connects to (`ServerConnect.cpp:325`,
//! `SharedFileList.cpp:1588`) — unless the **Announce Policy** withholds it
//! from a server that grants related search (ADR-0093, "What is announced to
//! a server that answers related searches"). The follower sends no hellos:
//! the listener's read the live session at each connection
//! ([`HelloSource`](crate::server_session::HelloSource)), so a mid-session id
//! change is named at once.

use std::sync::Arc;

use rmule_ed2k::OfferedFile;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

use super::AnnounceOutcome;
use crate::CoreError;
use crate::diagnostics::SharesToServer;
use crate::server_session::{ServerSessionHandle, SharedServerSession};
use crate::service::SharesWithheld;

/// What the follower last told a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Told {
    /// The share set went out.
    Announced,
    /// Nothing went out, on purpose.
    Withheld,
}

/// What one announce decision does.
#[derive(Debug, PartialEq, Eq)]
enum Decision {
    /// Send the current share set.
    Send,
    /// Send nothing, and say why.
    Hold(SharesWithheld),
    /// Send nothing: the session already has the set.
    Keep,
}

/// The **Announce Policy** applied to one session (ADR-0099). `fresh_set` is
/// a changed share set, which a session told the old one must hear; a wake
/// for any other reason re-sends nothing it already has.
fn decide(withhold: bool, related_search: bool, told: Option<Told>, fresh_set: bool) -> Decision {
    match (withhold && related_search, told) {
        (true, Some(Told::Announced)) => {
            Decision::Hold(SharesWithheld::RelatedSearchGrantedAfterAnnounce)
        }
        (true, _) => Decision::Hold(SharesWithheld::RelatedSearchGranted),
        (false, Some(Told::Announced)) if !fresh_set => Decision::Keep,
        (false, _) => Decision::Send,
    }
}

/// The share set and what the live session was told of it, under one lock.
#[derive(Default)]
struct Announcing {
    /// The latest share set handed to [`announce`](SessionFollower::announce).
    /// The latest wins: `OP_OFFERFILES` is a whole-set statement, so an older
    /// set would be a lie the moment a newer one exists.
    share: Option<Vec<OfferedFile>>,
    /// What the follower told a session, with the session it was.
    told: Option<(ServerSessionHandle, Told)>,
    /// The last outcome said of a session, so a wake that changes nothing
    /// says nothing.
    said: Option<(ServerSessionHandle, AnnounceOutcome)>,
}

/// The follower one serve start spawns, and the share set it announces to
/// each session. Dropping it stops following.
pub(super) struct SessionFollower {
    /// The lock is held from reading or writing the set until its send is
    /// answered, by the follower and by `announce` alike, so the sets reach a
    /// session in the order they were set and the last one sent is the newest.
    state: Arc<Mutex<Announcing>>,
    session: SharedServerSession,
    /// What the follower's own tells — to sessions made after an announce —
    /// said, in order, until the serve takes it.
    session_told: Option<mpsc::UnboundedReceiver<AnnounceOutcome>>,
    task: JoinHandle<()>,
}

impl SessionFollower {
    /// Follow `session`: adopt the live session now if there is one, then
    /// every session the operator establishes from here on, and re-decide the
    /// live one whenever the Announce Policy changes.
    pub(super) fn spawn(session: &SharedServerSession) -> Self {
        let state: Arc<Mutex<Announcing>> = Arc::default();
        let follow_state = Arc::clone(&state);
        let follow_session = session.clone();
        // Subscribed before the first look, so a session installed in between
        // is a wake, not a miss.
        let mut changes = session.session_changes();
        let mut withhold = session.withhold_shares();
        let (said_tx, session_told) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            let mut live = follow_session.session_in_slot().await;
            loop {
                if let Some(handle) = &live {
                    let held = *withhold.borrow_and_update();
                    let mut state = follow_state.lock().await;
                    match tell(&follow_session, handle, &mut state, held, false).await {
                        Ok(AnnounceOutcome::Unsaid) => {}
                        Ok(outcome) => {
                            let _ = said_tx.send(outcome);
                        }
                        Err(error) => {
                            tracing::warn!(%error, "serve: announce to the new session failed");
                        }
                    }
                }
                tokio::select! {
                    changed = changes.changed() => {
                        if changed.is_err() {
                            return;
                        }
                    }
                    changed = withhold.changed() => {
                        if changed.is_err() {
                            return;
                        }
                    }
                    () = ended(live.as_ref()) => {}
                }
                live = follow_session.session_in_slot().await;
            }
        });
        Self {
            state,
            session: session.clone(),
            session_told: Some(session_told),
            task,
        }
    }

    /// Announce `files` to the live session as the Announce Policy allows,
    /// and keep them as the set every later session is told. With no session
    /// the set waits for the next one; that is not an error, since the
    /// announce has nowhere yet to go.
    pub(super) async fn announce(
        &self,
        files: Vec<OfferedFile>,
    ) -> Result<AnnounceOutcome, CoreError> {
        let mut state = self.state.lock().await;
        state.share = Some(files);
        match self.session.session_in_slot().await {
            Some(handle) => {
                let held = *self.session.withhold_shares().borrow();
                tell(&self.session, &handle, &mut state, held, true).await
            }
            None => Ok(AnnounceOutcome::Unsaid),
        }
    }

    /// Take the outcomes of the tells the follower makes on its own, to each
    /// session made after the set was handed over. `None` once taken.
    pub(super) fn take_session_told(&mut self) -> Option<mpsc::UnboundedReceiver<AnnounceOutcome>> {
        self.session_told.take()
    }
}

impl Drop for SessionFollower {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Decide what `handle`'s session is told, tell it, and say so on the level.
/// The outcome is [`Unsaid`](AnnounceOutcome::Unsaid) unless it is news: a
/// fresh set, or a session told something other than it was last said to be.
async fn tell(
    session: &SharedServerSession,
    handle: &ServerSessionHandle,
    state: &mut Announcing,
    withhold: bool,
    fresh_set: bool,
) -> Result<AnnounceOutcome, CoreError> {
    let told = state
        .told
        .as_ref()
        .filter(|(to, _)| to.same_session(handle))
        .map(|(_, told)| *told);
    let facts = session.server_facts();
    let outcome = match decide(withhold, handle.grants().related_search, told, fresh_set) {
        Decision::Keep => return Ok(AnnounceOutcome::Unsaid),
        Decision::Hold(reason) => {
            let level = match reason {
                SharesWithheld::RelatedSearchGranted => {
                    state.told = Some((handle.clone(), Told::Withheld));
                    SharesToServer::Withheld
                }
                SharesWithheld::RelatedSearchGrantedAfterAnnounce => {
                    SharesToServer::AnnouncedBeforeWithholding
                }
            };
            facts.shares_told(handle.server(), level);
            let Some(files) = state.share.as_ref() else {
                return Ok(AnnounceOutcome::Unsaid);
            };
            AnnounceOutcome::Withheld {
                file_count: files.len(),
                reason,
            }
        }
        Decision::Send => {
            let Some(files) = state.share.clone() else {
                return Ok(AnnounceOutcome::Unsaid);
            };
            let file_count = files.len();
            handle.announce(files).await?;
            state.told = Some((handle.clone(), Told::Announced));
            facts.shares_told(handle.server(), SharesToServer::Announced);
            AnnounceOutcome::Announced { file_count }
        }
    };
    let repeat = !fresh_set
        && state
            .said
            .as_ref()
            .is_some_and(|(to, said)| to.same_session(handle) && *said == outcome);
    state.said = Some((handle.clone(), outcome));
    Ok(if repeat {
        AnnounceOutcome::Unsaid
    } else {
        outcome
    })
}

/// Resolves when `handle`'s session ends; never, with no session.
async fn ended(handle: Option<&ServerSessionHandle>) {
    match handle {
        Some(handle) => handle.closed().await,
        None => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use rmule_ed2k::{Ed2kCommand, ServerGrants};
    use rmule_primitives::{Ed2kText, FileHash, ServerEndpoint};
    use tokio::sync::mpsc;

    use super::*;
    use crate::server_session::tests::fake_session;

    /// A file whose hash no other test file shares, nor any other byte of it.
    fn file(seed: u8, name: &str) -> OfferedFile {
        let mut bytes = [0u8; FileHash::BYTE_LEN];
        for (at, byte) in bytes.iter_mut().enumerate() {
            *byte = seed
                .wrapping_mul(31)
                .wrapping_add(u8::try_from(at).unwrap().wrapping_mul(17).wrapping_add(5));
        }
        OfferedFile::new(
            FileHash::from_bytes(bytes),
            9_728_000,
            Ed2kText::from_utf8(name),
        )
    }

    /// Put `handle` in the slot as an establishment does.
    async fn install(session: &SharedServerSession, handle: ServerSessionHandle) {
        *session.slot().lock().await = Some(handle);
        session.session_established();
    }

    /// The next `OP_OFFERFILES` the session put on the wire.
    async fn offered(sent: &mut mpsc::Receiver<Ed2kCommand>) -> Vec<OfferedFile> {
        match tokio::time::timeout(Duration::from_secs(5), sent.recv()).await {
            Ok(Some(Ed2kCommand::OfferFiles { files })) => files,
            other => panic!("expected an offer, got {other:?}"),
        }
    }

    /// The operator switches servers: the second session is told the share
    /// set as it stands then, including a file shared while no session was
    /// up — aMule re-sends its list to every server it connects to.
    #[tokio::test]
    async fn each_session_in_turn_is_told_the_current_share_set() {
        let session = SharedServerSession::default();
        let follower = SessionFollower::spawn(&session);
        let first = file(3, "first.avi");
        follower.announce(vec![first.clone()]).await.unwrap();

        let server_a = ServerEndpoint::new("198.51.100.7", 4661).unwrap();
        let (a, a_link, mut a_sent) = fake_session(server_a, ServerGrants::default());
        install(&session, a.clone()).await;
        assert_eq!(offered(&mut a_sent).await, vec![first.clone()]);

        drop(a_link);
        a.closed().await;
        let second = file(11, "second.mkv");
        follower
            .announce(vec![first.clone(), second.clone()])
            .await
            .unwrap();

        let server_b = ServerEndpoint::new("203.0.113.40", 4242).unwrap();
        let (b, _b_link, mut b_sent) = fake_session(server_b, ServerGrants::default());
        install(&session, b).await;
        assert_eq!(offered(&mut b_sent).await, vec![first, second]);
    }

    /// Wait until the level says `server` was told `shares`.
    async fn told(
        diagnostics: &crate::diagnostics::DiagnosticsState,
        server: &ServerEndpoint,
        shares: SharesToServer,
    ) {
        let said = || {
            diagnostics
                .snapshot()
                .share_announcement
                .is_some_and(|told| &told.server == server && told.shares == shares)
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            while !said() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{server:?} was never said to be {shares:?}"));
    }

    fn related_search() -> ServerGrants {
        ServerGrants {
            related_search: true,
            ..ServerGrants::default()
        }
    }

    /// With the Announce Policy on, a server that grants related search is
    /// told nothing — the one after it that does not is told the whole set.
    #[tokio::test]
    async fn a_related_search_server_is_told_nothing_while_the_policy_withholds() {
        let session = SharedServerSession::default();
        let (facts, diagnostics) = crate::server_list::test_facts(&[]);
        session.install_facts(facts);
        session.set_withhold_shares(true);
        let mut follower = SessionFollower::spawn(&session);
        let mut session_told = follower.take_session_told().unwrap();
        let shared = vec![file(7, "together-a.flac"), file(19, "together-b.flac")];
        assert_eq!(
            follower.announce(shared.clone()).await.unwrap(),
            AnnounceOutcome::Unsaid,
            "with no session nothing is said yet"
        );

        let server_b = ServerEndpoint::new("203.0.113.40", 4242).unwrap();
        let (b, b_link, mut b_sent) = fake_session(server_b.clone(), related_search());
        install(&session, b.clone()).await;
        told(&diagnostics, &server_b, SharesToServer::Withheld).await;
        assert!(b_sent.try_recv().is_err(), "nothing went on the wire");
        assert_eq!(
            next_told(&mut session_told).await,
            AnnounceOutcome::Withheld {
                file_count: 2,
                reason: SharesWithheld::RelatedSearchGranted
            }
        );

        drop(b_link);
        b.closed().await;
        let server_c = ServerEndpoint::new("198.51.100.9", 4661).unwrap();
        let (c, _c_link, mut c_sent) = fake_session(server_c, ServerGrants::default());
        install(&session, c).await;
        assert_eq!(offered(&mut c_sent).await, shared);
        assert_eq!(
            next_told(&mut session_told).await,
            AnnounceOutcome::Announced { file_count: 2 }
        );
        assert!(session_told.try_recv().is_err(), "each tell is said once");
    }

    /// The next outcome the follower said of a session it told on its own.
    async fn next_told(rx: &mut mpsc::UnboundedReceiver<AnnounceOutcome>) -> AnnounceOutcome {
        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("an outcome within 5s")
            .expect("the follower lives")
    }

    /// The bench's case: the preference on and a live session whose server
    /// grants related search (`0x40`). The announce says the set was
    /// withheld — never that it was announced — and nothing goes out.
    #[tokio::test]
    async fn an_announce_the_policy_withholds_from_the_live_session_says_withheld() {
        let session = SharedServerSession::default();
        let (facts, _diagnostics) = crate::server_list::test_facts(&[]);
        session.install_facts(facts);
        session.set_withhold_shares(true);
        let server = ServerEndpoint::new("198.51.100.61", 4661).unwrap();
        let (live, _link, mut sent) = fake_session(server, related_search());
        install(&session, live).await;
        let follower = SessionFollower::spawn(&session);

        let outcome = follower
            .announce(vec![file(29, "field-recording.wav")])
            .await
            .unwrap();
        assert_eq!(
            outcome,
            AnnounceOutcome::Withheld {
                file_count: 1,
                reason: SharesWithheld::RelatedSearchGranted
            }
        );
        assert!(sent.try_recv().is_err(), "nothing went on the wire");
    }

    /// Switched on after the set went out, the policy cannot take it back:
    /// nothing more is sent and the level says so. Switched off while the
    /// set is withheld, it goes out at once.
    #[tokio::test]
    async fn switching_the_policy_mid_session_sends_only_what_was_held() {
        let session = SharedServerSession::default();
        let (facts, diagnostics) = crate::server_list::test_facts(&[]);
        session.install_facts(facts);
        let follower = SessionFollower::spawn(&session);
        let shared = vec![file(23, "mixtape.ogg")];
        follower.announce(shared.clone()).await.unwrap();

        let server = ServerEndpoint::new("192.0.2.140", 4661).unwrap();
        let (live, _link, mut sent) = fake_session(server.clone(), related_search());
        install(&session, live).await;
        assert_eq!(offered(&mut sent).await, shared);

        session.set_withhold_shares(true);
        told(
            &diagnostics,
            &server,
            SharesToServer::AnnouncedBeforeWithholding,
        )
        .await;
        let outcome = follower
            .announce(vec![file(23, "mixtape.ogg"), file(41, "b-side.ogg")])
            .await
            .unwrap();
        assert!(sent.try_recv().is_err(), "a new set is held back too");
        assert_eq!(
            outcome,
            AnnounceOutcome::Withheld {
                file_count: 2,
                reason: SharesWithheld::RelatedSearchGrantedAfterAnnounce
            }
        );

        let other = ServerEndpoint::new("198.51.100.77", 5000).unwrap();
        let (second, _second_link, mut second_sent) = fake_session(other.clone(), related_search());
        install(&session, second).await;
        told(&diagnostics, &other, SharesToServer::Withheld).await;
        session.set_withhold_shares(false);
        assert_eq!(offered(&mut second_sent).await.len(), 2);
        told(&diagnostics, &other, SharesToServer::Announced).await;
    }

    /// The policy table of ADR-0099, whole.
    #[test]
    fn the_announce_decision_follows_the_policy_table() {
        use Decision::{Hold, Keep, Send};
        use SharesWithheld::{
            RelatedSearchGranted as Withheld,
            RelatedSearchGrantedAfterAnnounce as AnnouncedBeforeWithholding,
        };
        let cases = [
            ((false, true, None, false), Send),
            ((false, true, Some(Told::Announced), false), Keep),
            ((false, true, Some(Told::Announced), true), Send),
            ((false, true, Some(Told::Withheld), false), Send),
            ((true, false, None, false), Send),
            ((true, true, None, true), Hold(Withheld)),
            ((true, true, Some(Told::Withheld), true), Hold(Withheld)),
            (
                (true, true, Some(Told::Announced), true),
                Hold(AnnouncedBeforeWithholding),
            ),
        ];
        for ((withhold, related, told, fresh), expected) in cases {
            assert_eq!(
                decide(withhold, related, told, fresh),
                expected,
                "{withhold} {related} {told:?} {fresh}"
            );
        }
    }
}
