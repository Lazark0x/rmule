//! The **Hash Track**: which User Hash each client's place last proved a key
//! under or left a slot under, so a client coming back under another is seen
//! (aMule's tracked client list, `ClientList.cpp:494-503`,
//! `UploadQueue.cpp:525`, `BaseClient.cpp:2130`). A place is an
//! address and a listen port. An entry lasts stock's two hours and the table is
//! bounded, its oldest entry going first; a serve or process restart empties it.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use rmule_primitives::UserHash;

/// aMule's `KEEPTRACK_TIME` (`Constants.h:85`).
const KEEP_TRACK: Duration = Duration::from_secs(2 * 60 * 60);

/// The places held at once: past what a node meets in two hours of proofs.
const MAX_TRACKED: usize = 4096;

/// See the module docs.
#[derive(Debug, Default)]
pub(in crate::serve) struct HashTrack {
    places: HashMap<(IpAddr, u16), (UserHash, Instant)>,
}

impl HashTrack {
    /// The place `ip`:`port` stood for `user_hash` at `now`.
    pub(in crate::serve) fn note(
        &mut self,
        now: Instant,
        ip: IpAddr,
        port: u16,
        user_hash: UserHash,
    ) {
        let place = (ip.to_canonical(), port);
        if self.places.len() >= MAX_TRACKED && !self.places.contains_key(&place) {
            self.places
                .retain(|_, (_, seen)| now.saturating_duration_since(*seen) < KEEP_TRACK);
            if self.places.len() >= MAX_TRACKED {
                let oldest = self
                    .places
                    .iter()
                    .min_by_key(|(_, (_, seen))| *seen)
                    .map(|(place, _)| *place);
                if let Some(oldest) = oldest {
                    self.places.remove(&oldest);
                }
            }
        }
        self.places.insert(place, (user_hash, now));
    }

    /// Whether `ip`:`port` names `user_hash` inside the two hours after it
    /// was tracked under another (`CClientList::ComparePriorUserhash`).
    pub(in crate::serve) fn changed(
        &self,
        now: Instant,
        ip: IpAddr,
        port: u16,
        user_hash: UserHash,
    ) -> bool {
        self.places
            .get(&(ip.to_canonical(), port))
            .is_some_and(|(tracked, seen)| {
                *tracked != user_hash && now.saturating_duration_since(*seen) < KEEP_TRACK
            })
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    const IP: IpAddr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));

    fn hash(byte: u8) -> UserHash {
        UserHash::from_bytes([byte; UserHash::BYTE_LEN])
    }

    #[test]
    fn another_hash_at_a_tracked_place_is_a_change_for_two_hours() {
        let mut track = HashTrack::default();
        let t = Instant::now();
        track.note(t, IP, 4662, hash(1));

        assert!(track.changed(t, IP, 4662, hash(2)));
        assert!(!track.changed(t, IP, 4662, hash(1)), "the same hash");
        assert!(!track.changed(t, IP, 4663, hash(2)), "another listen port");
        assert!(
            !track.changed(t + KEEP_TRACK, IP, 4662, hash(2)),
            "two hours on, the change is allowed"
        );
    }

    #[test]
    fn a_full_table_lets_its_oldest_go() {
        let mut track = HashTrack::default();
        let t = Instant::now();
        for port in 0..MAX_TRACKED {
            let at = t + Duration::from_millis(port as u64);
            track.note(at, IP, port as u16, hash(1));
        }
        track.note(t + Duration::from_secs(60), IP, 60_000, hash(1));

        assert_eq!(track.places.len(), MAX_TRACKED);
        assert!(!track.changed(t, IP, 0, hash(2)), "the oldest went");
        assert!(track.changed(t, IP, 1, hash(2)));
    }
}
