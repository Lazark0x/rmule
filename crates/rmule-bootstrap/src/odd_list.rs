//! What makes a fetched list **odd** (ADR-0120): a shape no mirror serves.
//!
//! This is a cheap filter for lazy forgeries and broken mirrors, not proof of
//! origin. A careful forgery passes it, and what bounds that forgery is that a
//! fetched list adds to the seeds and never replaces them.

use std::collections::HashMap;
use std::net::IpAddr;

use thiserror::Error;

/// The most rows a list may hold. The cap on a body bounds memory; this bounds
/// the rows a list can lay on the server list and on every sweep over it.
const MAX_LIST_ROWS: usize = 4096;

/// The fewest usable rows the one-network rule reads anything into. A short
/// list is a small mirror, or a laboratory's.
const ONE_NETWORK_FLOOR: usize = 8;

/// Why a fetched list was refused whole.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum ListOddity {
    /// More rows than any mirror lists.
    #[error("{rows} rows, more than any mirror lists")]
    TooManyRows {
        /// The rows the list held.
        rows: usize,
    },
    /// No row is left that names a usable address.
    #[error("no row names a usable address")]
    NoUsableRow,
    /// More than half of the rows name an address no server can be at.
    #[error("{dropped} of {rows} rows name an address no server can be at")]
    MostlyUnusable {
        /// The rows dropped by the check of the list's host.
        dropped: usize,
        /// The rows the list held.
        rows: usize,
    },
    /// More than half of the usable rows sit in one IPv4 `/24` or IPv6 `/48`.
    #[error("{in_network} of {usable} rows sit in one network")]
    OneNetwork {
        /// The rows in the fullest network.
        in_network: usize,
        /// The usable rows the list held.
        usable: usize,
    },
}

/// One `/24` or `/48`. A mapped IPv4 address is the IPv4 host it wraps.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
enum Network {
    V4([u8; 3]),
    V6([u16; 3]),
}

impl Network {
    fn of(ip: IpAddr) -> Self {
        match ip.to_canonical() {
            IpAddr::V4(ip) => {
                let [a, b, c, _] = ip.octets();
                Self::V4([a, b, c])
            }
            IpAddr::V6(ip) => {
                let [a, b, c, ..] = ip.segments();
                Self::V6([a, b, c])
            }
        }
    }
}

/// Judge a list of `rows` rows of which `usable` passed the check of the
/// list's host.
pub(crate) fn judge(rows: usize, usable: &[IpAddr]) -> Result<(), ListOddity> {
    if rows > MAX_LIST_ROWS {
        return Err(ListOddity::TooManyRows { rows });
    }
    if usable.is_empty() {
        return Err(ListOddity::NoUsableRow);
    }
    let dropped = rows - usable.len();
    if dropped * 2 > rows {
        return Err(ListOddity::MostlyUnusable { dropped, rows });
    }
    if usable.len() >= ONE_NETWORK_FLOOR {
        let mut networks: HashMap<Network, usize> = HashMap::new();
        for ip in usable {
            *networks.entry(Network::of(*ip)).or_default() += 1;
        }
        let in_network = networks.values().copied().max().unwrap_or_default();
        if in_network * 2 > usable.len() {
            return Err(ListOddity::OneNetwork {
                in_network,
                usable: usable.len(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    /// `count` hosts, each in a `/24` of its own.
    fn spread(count: usize) -> Vec<IpAddr> {
        (0..count)
            .map(|index| {
                let [_, _, high, low] = u32::try_from(index).unwrap().to_be_bytes();
                IpAddr::V4(Ipv4Addr::new(198, high, low, 1))
            })
            .collect()
    }

    /// `count` hosts in one `/24`.
    fn crowded(count: usize) -> Vec<IpAddr> {
        (0..count)
            .map(|index| IpAddr::V4(Ipv4Addr::new(203, 0, 113, u8::try_from(index).unwrap())))
            .collect()
    }

    #[test]
    fn a_list_of_spread_hosts_is_not_odd() {
        assert_eq!(judge(40, &spread(40)), Ok(()));
    }

    #[test]
    fn a_list_past_the_row_ceiling_is_odd() {
        assert_eq!(judge(MAX_LIST_ROWS, &spread(MAX_LIST_ROWS)), Ok(()));
        assert_eq!(
            judge(MAX_LIST_ROWS + 1, &spread(MAX_LIST_ROWS + 1)),
            Err(ListOddity::TooManyRows {
                rows: MAX_LIST_ROWS + 1
            })
        );
    }

    #[test]
    fn a_list_with_nothing_usable_is_odd() {
        assert_eq!(judge(0, &[]), Err(ListOddity::NoUsableRow));
        assert_eq!(judge(3, &[]), Err(ListOddity::NoUsableRow));
    }

    #[test]
    fn a_list_mostly_dropped_by_its_host_is_odd() {
        assert_eq!(judge(4, &spread(2)), Ok(()), "half is not most");
        assert_eq!(
            judge(5, &spread(2)),
            Err(ListOddity::MostlyUnusable {
                dropped: 3,
                rows: 5
            })
        );
    }

    /// The rule needs eight rows: a short list is a small mirror.
    #[test]
    fn one_network_holding_most_of_a_list_is_odd() {
        assert_eq!(judge(7, &crowded(7)), Ok(()));
        assert_eq!(
            judge(8, &crowded(8)),
            Err(ListOddity::OneNetwork {
                in_network: 8,
                usable: 8
            })
        );
        let half: Vec<_> = crowded(4).into_iter().chain(spread(4)).collect();
        assert_eq!(judge(8, &half), Ok(()), "half is not most");
    }

    #[test]
    fn a_mapped_address_counts_in_its_ipv4_network_and_ipv6_in_its_48() {
        let mapped: Vec<_> = (1..=8u8)
            .map(|low| IpAddr::V6(Ipv4Addr::new(203, 0, 113, low).to_ipv6_mapped()))
            .collect();
        assert!(matches!(
            judge(8, &mapped),
            Err(ListOddity::OneNetwork { in_network: 8, .. })
        ));
        let v6: Vec<_> = (1..=8u16)
            .map(|low| IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 7, low, 0, 0, 0, 1)))
            .collect();
        assert!(matches!(
            judge(8, &v6),
            Err(ListOddity::OneNetwork { in_network: 8, .. })
        ));
    }
}
