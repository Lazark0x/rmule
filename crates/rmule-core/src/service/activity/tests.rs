//! The Download Set and the restore queue through the ledger's own ops
//! (ADR-0093, ADR-0094).

use rmule_primitives::{FileHash, Ipv4Endpoint, PeerEndpoint};
use std::net::Ipv4Addr;
use tokio::sync::{mpsc, watch};

use super::{ActiveDownload, Activities};
use crate::download::StopReason;
use crate::download::source_seeds::{SeedRank, SourceSeed};
use crate::service::DownloadId;

fn id(n: u64) -> DownloadId {
    DownloadId::from_u64(n)
}

fn seed(last: u8) -> SourceSeed {
    SourceSeed {
        endpoint: PeerEndpoint::V4(Ipv4Endpoint::new(Ipv4Addr::new(10, 0, 0, last), 4662)),
        user_hash: None,
        crypt: None,
        rank: SeedRank::Known,
    }
}

fn run(number: u64) -> ActiveDownload {
    let (stop_tx, _) = watch::channel(StopReason::Pause);
    let (later_links, _) = mpsc::unbounded_channel();
    let (_, seeds) = watch::channel(Vec::new());
    ActiveDownload {
        run: number,
        file_hash: FileHash::from_bytes([1; 16]),
        stop_tx,
        handle: tokio::spawn(async {}),
        later_links,
        seeds,
    }
}

#[tokio::test]
async fn a_started_download_is_held_until_it_is_taken_once() {
    let mut set = Activities::<()>::default();
    assert!(set.downloads_idle());

    set.download_started(id(1), run(7));
    set.download_started(id(2), run(8));

    assert!(!set.downloads_idle());
    assert!(set.has_download(id(1)));
    assert_eq!(set.download(id(2)).map(|active| active.run), Some(8));
    assert_eq!(set.downloads().count(), 2);

    assert_eq!(set.take_download(id(1)).map(|active| active.run), Some(7));
    assert!(set.take_download(id(1)).is_none());
    assert!(!set.has_download(id(1)));
    assert!(set.download(id(2)).is_some());
}

#[test]
fn restoring_leaves_in_store_order_each_with_its_own_seeds() {
    let seeds = [(id(3), vec![seed(1)]), (id(4), Vec::new())].into();
    let mut set = Activities::<()>::restoring([id(3), id(4), id(5)].into(), seeds);
    assert!(set.restore_pending());

    assert_eq!(set.next_restoring(), Some((id(3), vec![seed(1)])));
    assert_eq!(set.next_restoring(), Some((id(4), Vec::new())));
    // No seeds were loaded for the third: it still restores, with none.
    assert_eq!(set.next_restoring(), Some((id(5), Vec::new())));
    assert_eq!(set.next_restoring(), None);
    assert!(!set.restore_pending());
}

#[test]
fn taking_a_restoring_download_takes_its_seeds_and_only_once() {
    let seeds = [(id(3), vec![seed(1)]), (id(4), vec![seed(2)])].into();
    let mut set = Activities::<()>::restoring([id(3), id(4)].into(), seeds);

    assert_eq!(set.take_restoring(id(4)), Some(vec![seed(2)]));
    assert_eq!(set.take_restoring(id(4)), None);
    // The other is untouched, queue and seeds together.
    assert_eq!(set.next_restoring(), Some((id(3), vec![seed(1)])));
}
