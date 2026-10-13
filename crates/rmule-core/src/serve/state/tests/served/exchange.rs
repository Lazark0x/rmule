//! A Served Download's source-exchange answers (ADR-0113): a Partial Share
//! answers from its run's pool, leaving out a source of unknown status, and
//! a download not offered answers none.

use super::*;

#[test]
fn a_partial_shares_exchange_answers_from_its_runs_pool_and_leaves_out_an_unknown_status() {
    use crate::served_downloads::ExchangePool;
    use rmule_primitives::{ClientId, PeerSource};

    let file = hash(0x02);
    let source = |octet: u8| {
        SourceSighting::plain(PeerSource::new(
            ClientId::from_u32(u32::from_le_bytes([10, 0, 0, octet])),
            4662,
        ))
    };
    let mut look = download(true, &[0], true);
    look.served.pool = ExchangePool {
        sources: vec![(source(1), Some(holding_real(&[1]))), (source(2), None)],
        known: 7,
    };
    let mut state = state_of(Vec::new(), vec![(file, look)]);
    let p = peer(4001);
    identify(&mut state, p, user(0x0B), Instant::now());
    let _ = ask(&mut state, p, name_ask(file));
    assert_eq!(
        ask(
            &mut state,
            p,
            ServerEvent::SourcesRequested { file_hash: file }
        ),
        [send(
            p,
            ServerCommand::AnswerSources {
                file_hash: file,
                sources: vec![source(1)],
            },
        )]
    );
}

#[test]
fn a_download_not_offered_answers_no_exchange() {
    let file = hash(0x02);
    let mut state = state_of(Vec::new(), vec![(file, download(true, &[], true))]);
    let p = peer(4001);
    identify(&mut state, p, user(0x0B), Instant::now());
    assert_eq!(
        ask(
            &mut state,
            p,
            ServerEvent::SourcesRequested { file_hash: file }
        ),
        []
    );
}

/// What a source advertising `parts` of a file of [`SIZE`] holds, over its
/// three real parts.
fn holding_real(parts: &[u32]) -> PartBitmap {
    let bits = parts.iter().fold(0u8, |bits, part| bits | 1 << part);
    PartBitmap::decode(3, &[bits]).unwrap()
}
