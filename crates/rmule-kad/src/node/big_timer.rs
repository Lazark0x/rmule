//! The big-timer refresh: aMule's per-zone `CRoutingZone::OnBigTimer`, the
//! lookup that refills the table between searches (`Kademlia.cpp:238-250`,
//! `RoutingZone.cpp:700-706,819-827`). Stock walks a random ID of each leaf
//! zone hourly, one zone per 10 s, while connected. This table's zone is a
//! bucket, so the bucket quiet longest goes next, and only once it has been
//! quiet an hour.
//!
//! The clock lives in the table, as each bucket's last activity, and dies with
//! the node: a Kad or process restart starts it over, as stock's does.

use std::time::Duration;

use super::KadNode;
use crate::KadInstant;
use crate::lookup_walk::KadWalkPurpose;

impl KadNode {
    /// How long a bucket stays quiet before its refresh (`Kademlia.cpp:241`).
    pub const BIG_TIMER_INTERVAL: Duration = Duration::from_secs(60 * 60);

    /// Between two refreshes (`Kademlia.cpp:242`).
    pub const BIG_TIMER_SPACING: Duration = Duration::from_secs(10);

    pub(super) fn tick_big_timer(&mut self, now: KadInstant) {
        let Some(due) = self.next_big_timer else {
            return;
        };
        let Some(random_id) = self.refresh_target else {
            return;
        };
        if due > now {
            return;
        }
        self.next_big_timer = Some(now + Self::BIG_TIMER_SPACING);
        if !self.joined(now) {
            return;
        }
        let Some((bucket, quiet_since)) = self.routing.stalest_bucket() else {
            return;
        };
        let refresh_at = quiet_since + Self::BIG_TIMER_INTERVAL;
        if refresh_at > now {
            self.next_big_timer = Some(refresh_at);
            return;
        }
        self.routing.touch_bucket(bucket, now);
        let target = self.config.id.inside_bucket(bucket, random_id());
        self.start_walk(now, KadWalkPurpose::RefreshLookup { target });
    }
}
