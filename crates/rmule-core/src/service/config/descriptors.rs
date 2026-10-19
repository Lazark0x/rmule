//! The **Connection Ceiling** under the process's open-descriptor limit
//! (ADR-0116, "The Ceiling under the descriptor limit"): a binary reads the
//! limit once at its start and hands the core the lower of the configured
//! Ceiling and what the limit leaves room for, by aMule's
//! `GetRecommendedMaxConnections` (stock 2.3.3 `Preferences.cpp:1493-1509`).

use super::PeerConnections;

/// The Ceiling a binary lowered at its start because the descriptor limit
/// left no room for the configured one: said to the operator once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CeilingLowered {
    /// The open-descriptor limit in force, `None` when the system states
    /// none and aMule's default stood in for it.
    pub descriptors: Option<u64>,
    /// The Ceiling configured: the operator's, else the default 500.
    pub configured: usize,
    /// The Ceiling in force.
    pub ceiling: usize,
}

/// The Ceiling an open-descriptor limit of `descriptors` leaves room for —
/// `None` when the system states none — by the four arms of aMule's
/// `GetRecommendedMaxConnections`: unknown or above 520, 500; under 20, the
/// limit; up to 256, the limit less 10; above, the limit less 20.
#[must_use]
pub fn descriptor_ceiling(descriptors: Option<u64>) -> usize {
    let room = match descriptors {
        None => 500,
        Some(limit) if limit > 520 => 500,
        Some(limit) if limit < 20 => limit,
        Some(limit) if limit <= 256 => limit - 10,
        Some(limit) => limit - 20,
    };
    usize::try_from(room).unwrap_or(usize::MAX)
}

impl PeerConnections {
    /// These knobs with the Ceiling held to what `descriptors`, the process's
    /// open-descriptor limit, leaves room for ([`descriptor_ceiling`]): a
    /// configured Ceiling that fits stands. When the limit lowered it, what
    /// the operator is told.
    #[must_use]
    pub fn within_descriptors(self, descriptors: Option<u64>) -> (Self, Option<CeilingLowered>) {
        let room = descriptor_ceiling(descriptors);
        if self.max_connections <= room {
            return (self, None);
        }
        let lowered = CeilingLowered {
            descriptors,
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

    /// aMule's four arms, at their edges.
    #[test]
    fn the_ceiling_follows_amules_recommendation_over_the_limit() {
        assert_eq!(descriptor_ceiling(None), 500);
        assert_eq!(descriptor_ceiling(Some(521)), 500);
        assert_eq!(descriptor_ceiling(Some(10_240)), 500);
        assert_eq!(descriptor_ceiling(Some(19)), 19);
        assert_eq!(descriptor_ceiling(Some(20)), 10);
        assert_eq!(descriptor_ceiling(Some(256)), 246);
        assert_eq!(descriptor_ceiling(Some(257)), 237);
        assert_eq!(descriptor_ceiling(Some(520)), 500);
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
                descriptors: Some(256),
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
}
