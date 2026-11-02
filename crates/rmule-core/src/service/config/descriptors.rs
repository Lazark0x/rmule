//! The **Connection Ceiling** under the process's open-descriptor limit
//! (ADR-0116, "The Ceiling under the descriptor limit"): a binary reads the
//! limit once at its start and hands the core the configured Ceiling, held
//! under what the limit leaves room for by the reserve of aMule's
//! `GetRecommendedMaxConnections` (stock 2.3.3 `Preferences.cpp:1493-1509`).

use super::PeerConnections;

/// The Ceiling a binary lowered at its start because the descriptor limit
/// left no room for the configured one: said to the operator once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CeilingLowered {
    /// The open-descriptor limit in force.
    pub descriptors: u64,
    /// The Ceiling configured: the operator's, else the default 500.
    pub configured: usize,
    /// The Ceiling in force.
    pub ceiling: usize,
}

/// The connections an open-descriptor limit of `descriptors` leaves room
/// for, `None` when the system states no limit: the limit itself under 20,
/// the limit less 10 up to 256, the limit less 20 above — the reserve of
/// aMule's `GetRecommendedMaxConnections`, whose 500 for a larger or unknown
/// limit is the default Ceiling, not a bound.
#[must_use]
pub fn descriptor_room(descriptors: Option<u64>) -> Option<usize> {
    let room = match descriptors? {
        limit if limit < 20 => limit,
        limit if limit <= 256 => limit - 10,
        limit => limit - 20,
    };
    Some(usize::try_from(room).unwrap_or(usize::MAX))
}

impl PeerConnections {
    /// These knobs with the Ceiling held to what `descriptors`, the process's
    /// open-descriptor limit, leaves room for ([`descriptor_room`]): a
    /// configured Ceiling that fits stands, and so does every Ceiling when the
    /// system states no limit. When the limit lowered it, what the operator
    /// is told.
    #[must_use]
    pub fn within_descriptors(self, descriptors: Option<u64>) -> (Self, Option<CeilingLowered>) {
        let (Some(limit), Some(room)) = (descriptors, descriptor_room(descriptors)) else {
            return (self, None);
        };
        if self.max_connections <= room {
            return (self, None);
        }
        let lowered = CeilingLowered {
            descriptors: limit,
            configured: self.max_connections,
            ceiling: room,
        };
        let held = Self {
            max_connections: room,
            ..self
        };
        (held, Some(lowered))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// aMule's reserve, at the edges of its arms.
    #[test]
    fn the_room_is_the_limit_less_amules_reserve() {
        assert_eq!(descriptor_room(None), None);
        assert_eq!(descriptor_room(Some(19)), Some(19));
        assert_eq!(descriptor_room(Some(20)), Some(10));
        assert_eq!(descriptor_room(Some(256)), Some(246));
        assert_eq!(descriptor_room(Some(257)), Some(237));
        assert_eq!(descriptor_room(Some(520)), Some(500));
        assert_eq!(descriptor_room(Some(10_240)), Some(10_220));
    }

    /// A limit that leaves room for less lowers the default and says so; an
    /// operator's lower Ceiling stands, and nothing is said.
    #[test]
    fn a_lower_operator_ceiling_stands_and_a_lowered_default_is_told() {
        let (held, told) = PeerConnections::default().within_descriptors(Some(256));
        assert_eq!(held.max_connections, 246);
        assert_eq!(
            told,
            Some(CeilingLowered {
                descriptors: 256,
                configured: 500,
                ceiling: 246,
            })
        );
        let operator = PeerConnections {
            max_connections: 100,
            ..PeerConnections::default()
        };
        assert_eq!(operator.within_descriptors(Some(256)), (operator, None));
    }

    /// An operator's Ceiling past the default 500 stands wherever the limit
    /// has room for it, and wherever the system states none.
    #[test]
    fn an_operator_ceiling_past_the_default_stands_where_the_limit_has_room() {
        let operator = PeerConnections {
            max_connections: 1_000,
            ..PeerConnections::default()
        };
        assert_eq!(operator.within_descriptors(Some(10_240)), (operator, None));
        assert_eq!(operator.within_descriptors(None), (operator, None));
        let (held, _) = operator.within_descriptors(Some(1_000));
        assert_eq!(held.max_connections, 980);
    }
}
