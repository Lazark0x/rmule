//! The **Held Places** (ADR-0116): the peers at whose upload queues the node's
//! downloads stand, each by the User Hash and address its record knows. Every
//! download run republishes its own after every step and withdraws them at its
//! end; the serve side reads them when it ranks its queue, and a waiter whose
//! link's address and hello's User Hash both name a held place scores by the
//! [`RECIPROCITY_FACTOR`] — what we upload to it raises our credit where we
//! wait.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, PoisonError};

use rmule_primitives::UserHash;

use crate::service::DownloadId;

/// aMule's Very High upload priority over its Normal one, 1.8 / 0.7 (stock
/// 2.3.3 `UploadClient.cpp:117-137`): the spread aMule lets an operator give
/// one file's waiters over another's, and the most a held place moves a
/// waiter past one that is not (ADR-0116).
pub(crate) const RECIPROCITY_FACTOR: f64 = 1.8 / 0.7;

/// One held place: the peer's User Hash and the address its record reaches it
/// at. Both must match a waiter, so claiming a hash alone earns nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct HeldPlace {
    /// The User Hash the source's record knows.
    pub(crate) user_hash: UserHash,
    /// The address the source stands at.
    pub(crate) ip: IpAddr,
}

/// The node's held places, by the download that holds each.
#[derive(Clone, Debug, Default)]
pub(crate) struct SharedHeldPlaces(Arc<Mutex<HashMap<DownloadId, HashSet<HeldPlace>>>>);

impl SharedHeldPlaces {
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<DownloadId, HashSet<HeldPlace>>> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether some download stands queued at the peer `user_hash` names at
    /// `ip`.
    pub(crate) fn holds(&self, user_hash: UserHash, ip: IpAddr) -> bool {
        let place = HeldPlace { user_hash, ip };
        self.lock().values().any(|places| places.contains(&place))
    }

    /// `download`'s seat: what it publishes replaces what it held, and its
    /// drop withdraws it.
    pub(crate) fn seat(&self, download: DownloadId) -> HeldPlacesSeat {
        HeldPlacesSeat {
            places: self.clone(),
            download,
        }
    }
}

/// One run's publication of its held places.
#[derive(Debug)]
pub(crate) struct HeldPlacesSeat {
    places: SharedHeldPlaces,
    download: DownloadId,
}

impl HeldPlacesSeat {
    /// Replace the run's held places with `now`.
    pub(crate) fn hold(&self, now: impl IntoIterator<Item = HeldPlace>) {
        let now: HashSet<HeldPlace> = now.into_iter().collect();
        let mut places = self.places.lock();
        if now.is_empty() {
            places.remove(&self.download);
        } else {
            places.insert(self.download, now);
        }
    }
}

impl Drop for HeldPlacesSeat {
    fn drop(&mut self) {
        self.places.lock().remove(&self.download);
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    /// A place is held while a run publishes it, under its address and hash
    /// together, and gone with the run.
    #[test]
    fn a_place_is_held_by_hash_and_address_until_its_run_ends() {
        let places = SharedHeldPlaces::default();
        let hash = UserHash::from_bytes([7; 16]);
        let at = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7));
        let seat = places.seat(DownloadId::from_u64(1));
        seat.hold([HeldPlace {
            user_hash: hash,
            ip: at,
        }]);
        assert!(places.holds(hash, at));
        assert!(!places.holds(hash, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 8))));
        assert!(!places.holds(UserHash::from_bytes([8; 16]), at));
        drop(seat);
        assert!(!places.holds(hash, at));
    }
}
