//! emule-qt's own IPv6 client-UDP datagram against rmule's reader: the inbound
//! half of the 35-byte key (ADR-0087), from the bench capture
//! `emule-qt-73fff714-ipv6-udp-key-20261030`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use rmule_primitives::{
    ClientDecryptKeys, DatagramKeyFamily, DatagramSenderAddress, UserHash, decrypt_datagram_client,
};

const DATAGRAM: &[u8] = include_bytes!(
    "../fixtures/datagram_obfuscation/captured/emule-qt-73fff714-ipv6-udp-key-20261030/keyed_file_not_found.bin"
);
/// The driver's user hash, the key's receiver half.
const RECEIVER: UserHash = UserHash::from_bytes([0x42; 16]);
/// emule-qt's address on the bench.
const SENDER_V6: Ipv6Addr = Ipv6Addr::new(0x3fff, 0x0ed2, 1, 0, 0, 0, 0, 3);
/// The same container's IPv4 address.
const SENDER_V4: Ipv4Addr = Ipv4Addr::new(45, 55, 200, 3);

fn open(sender: IpAddr) -> Option<Vec<u8>> {
    let opened = decrypt_datagram_client(
        DATAGRAM,
        &ClientDecryptKeys {
            user_hash: Some(&RECEIVER),
            sender: DatagramSenderAddress::from_ip(sender),
            ..Default::default()
        },
    )?;
    assert_eq!(opened.family, DatagramKeyFamily::Ed2kUserHash);
    Some(opened.payload)
}

#[test]
fn emule_qts_keyed_answer_opens_under_its_ipv6_address_as_file_not_found() {
    assert_eq!(open(IpAddr::V6(SENDER_V6)), Some(vec![0xC5, 0x92]));
}

/// The address's width selects the key's layout, so the 23-byte key over the
/// same host's IPv4 address reads nothing.
#[test]
fn the_same_datagram_stays_shut_under_the_senders_ipv4_address() {
    assert_eq!(open(IpAddr::V4(SENDER_V4)), None);
}
