//! The routing table's admission caps (ADR-0064): aMule's one contact per IPv4
//! address and ten per /24, both counted table-wide, and two per /24 inside one
//! bucket (`CRoutingBin::AddContact`, `CheckGlobalIPLimits` and
//! `ChangeContactIPAddress`, `RoutingBin.cpp:84-91`, `:269-317`, `:366-390`).
//!
//! The table-wide counts are tallies the table keeps in step with its buckets:
//! every stored contact is counted exactly once, under its current IP, from the
//! moment it is stored until it is evicted, replaced or moved. The per-bucket
//! count is read off the bucket itself. They cap how much of the table one
//! address or one /24 can occupy, which raises the price of an eclipse: an
//! attacker needs many addresses, not many IDs.

use std::collections::BTreeMap;
use std::net::Ipv4Addr;

use crate::net::is_lan_ip;

/// Which admission cap refused a contact (ADR-0064).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum KadAdmissionCap {
    /// The address already holds a contact: one per IPv4 address, table-wide
    /// (aMule `MAX_CONTACTS_IP`). Loopback is exempt.
    Ip,
    /// The address's /24 already holds ten contacts, table-wide (aMule
    /// `MAX_CONTACTS_SUBNET`). The private ranges and loopback are exempt.
    Subnet,
    /// The contact's bucket already holds two contacts from its /24. The
    /// private ranges and loopback are exempt.
    BucketSubnet,
}

/// Contacts one IPv4 address may hold across the table.
const MAX_CONTACTS_PER_IP: u16 = 1;

/// Contacts one /24 may hold across the table.
const MAX_CONTACTS_PER_SUBNET: u16 = 10;

/// Contacts one /24 may hold inside one bucket.
const MAX_CONTACTS_PER_BUCKET_SUBNET: usize = 2;

/// The /24 an address lies in, as its masked host-order word.
fn subnet(ip: Ipv4Addr) -> u32 {
    u32::from(ip) & 0xFFFF_FF00
}

/// The table-wide counts behind the per-IP and per-/24 caps, keyed by the
/// address and by its /24. Holds a count for every stored contact, exempt
/// addresses included, so an exemption is a judgement at the gate and never a
/// hole in the tally.
#[derive(Clone, Debug, Default)]
pub(super) struct AdmissionTally {
    per_ip: BTreeMap<Ipv4Addr, u16>,
    per_subnet: BTreeMap<u32, u16>,
}

impl AdmissionTally {
    /// The cap a contact arriving at `ip` would break, or `None` when it may
    /// be stored. `bucket` yields the IPs its bucket holds now. `leaving` is
    /// the IP of a stored contact the same mutation removes (the `Failed`
    /// contact it replaces, or the moving contact's old address), which no
    /// longer counts against it. aMule's order: the address, then the /24
    /// table-wide, then the /24 in the bucket.
    pub(super) fn refusal(
        &self,
        ip: Ipv4Addr,
        bucket: impl Iterator<Item = Ipv4Addr>,
        leaving: Option<Ipv4Addr>,
    ) -> Option<KadAdmissionCap> {
        if !ip.is_loopback() {
            let held = self.per_ip.get(&ip).copied().unwrap_or(0);
            let held = held.saturating_sub(u16::from(leaving == Some(ip)));
            if held >= MAX_CONTACTS_PER_IP {
                return Some(KadAdmissionCap::Ip);
            }
        }
        if is_lan_ip(ip) {
            return None;
        }
        let net = subnet(ip);
        let leaves_here = leaving.is_some_and(|left| subnet(left) == net);
        let held = self.per_subnet.get(&net).copied().unwrap_or(0);
        if held.saturating_sub(u16::from(leaves_here)) >= MAX_CONTACTS_PER_SUBNET {
            return Some(KadAdmissionCap::Subnet);
        }
        let in_bucket = bucket.filter(|held| subnet(*held) == net).count();
        if in_bucket.saturating_sub(usize::from(leaves_here)) >= MAX_CONTACTS_PER_BUCKET_SUBNET {
            return Some(KadAdmissionCap::BucketSubnet);
        }
        None
    }

    /// Count a contact just stored at `ip`.
    pub(super) fn count(&mut self, ip: Ipv4Addr) {
        *self.per_ip.entry(ip).or_default() += 1;
        *self.per_subnet.entry(subnet(ip)).or_default() += 1;
    }

    /// Stop counting a contact that left `ip`.
    pub(super) fn uncount(&mut self, ip: Ipv4Addr) {
        decrement(&mut self.per_ip, ip);
        decrement(&mut self.per_subnet, subnet(ip));
    }
}

/// Drop one from `key`'s count, forgetting the key at zero.
fn decrement<K: Ord>(counts: &mut BTreeMap<K, u16>, key: K) {
    if let std::collections::btree_map::Entry::Occupied(mut held) = counts.entry(key) {
        *held.get_mut() -= 1;
        if *held.get() == 0 {
            held.remove();
        }
    }
}
