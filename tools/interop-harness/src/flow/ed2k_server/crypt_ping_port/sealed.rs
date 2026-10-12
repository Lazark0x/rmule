//! The `--sealed` reading of the crypt-ping-port tap: whether rmule seals
//! the server datagrams that follow an answered crypt-ping, and whether
//! Lugdunum answers them sealed.
//!
//! The crypt-ping's answer, opened under the ping's challenge, carries the
//! server's obfuscation UDP port and its `ServerUDPKey` (aMule
//! `ServerUDPSocket.cpp:211-215`). aMule then seals every server datagram
//! but the crypt-ping under that key and sends it to that port
//! (`ServerUDPSocket.cpp:366-374`): the `0xA2` description ask the answered
//! status fires first of all. The reading opens each later datagram rmule
//! sent to the obfuscation port under the key in the client-to-server
//! direction, each datagram the server sent rmule under the key in the
//! server-to-client direction, and lists every plain frame rmule still sent
//! the server.

use rmule_primitives::{ServerCryptDirection, decrypt_datagram_server};

use crate::flow::pcap::Udp4Datagram;

/// Where a `0x97` body keeps the obfuscation UDP port, then the TCP one,
/// then the key: after eight 32-bit fields (challenge … low-ID users).
const CRYPT_FACTS_AT: usize = 2 + 32;

/// The sealed exchange read off the tap, as one verdict line's fields.
pub(super) fn read_sealed(datagrams: &[Udp4Datagram], obfuscation_ping_port: u16) -> String {
    let Some(ping_at) = datagrams
        .iter()
        .position(|datagram| datagram.destination.port() == obfuscation_ping_port)
    else {
        return "sealed_verdict=NO-CRYPT-PING".to_owned();
    };
    let ping = &datagrams[ping_at];
    let (rmule, server_ip) = (ping.source, *ping.destination.ip());
    let Some(challenge) = ping.payload.get(..4) else {
        return "sealed_verdict=NO-CRYPT-PING".to_owned();
    };
    let challenge = u32::from_le_bytes([challenge[0], challenge[1], challenge[2], challenge[3]]);
    let Some(answer_at) = datagrams[ping_at + 1..]
        .iter()
        .position(|datagram| datagram.destination == rmule)
        .map(|offset| ping_at + 1 + offset)
    else {
        return "sealed_verdict=CRYPT-PING-UNANSWERED".to_owned();
    };
    let Some((obfuscation_port, key)) = crypt_facts(&datagrams[answer_at].payload, challenge)
    else {
        return "sealed_verdict=NO-KEY".to_owned();
    };

    let later = &datagrams[answer_at + 1..];
    let opcodes = |direction: ServerCryptDirection, sent: &dyn Fn(&Udp4Datagram) -> bool| {
        later
            .iter()
            .filter(|datagram| sent(datagram))
            .filter_map(|datagram| {
                let plain = decrypt_datagram_server(&datagram.payload, key, direction)?;
                Some((plain.get(1).copied()?, datagram.source.port()))
            })
            .collect::<Vec<_>>()
    };
    let requests = opcodes(ServerCryptDirection::ToServer, &|datagram| {
        datagram.source == rmule
            && *datagram.destination.ip() == server_ip
            && datagram.destination.port() == obfuscation_port
    });
    let answers = opcodes(ServerCryptDirection::FromServer, &|datagram| {
        datagram.destination == rmule && *datagram.source.ip() == server_ip
    });
    let plain_after_key: Vec<u8> = later
        .iter()
        .filter(|datagram| datagram.source == rmule && *datagram.destination.ip() == server_ip)
        .filter(|datagram| datagram.payload.first() == Some(&0xE3))
        .filter_map(|datagram| datagram.payload.get(1).copied())
        .collect();

    let verdict = match (requests.is_empty(), answers.is_empty()) {
        (false, false) => "SEALED-ANSWERED",
        (false, true) => "SEALED-UNANSWERED",
        (true, _) => "NOT-SEALED",
    };
    let list = |opcodes: &mut dyn Iterator<Item = u8>| {
        let joined = opcodes
            .map(|opcode| format!("{opcode:02x}"))
            .collect::<Vec<_>>()
            .join(",");
        if joined.is_empty() {
            "none".to_owned()
        } else {
            joined
        }
    };
    let answer_port = answers
        .first()
        .map_or_else(|| "none".to_owned(), |&(_, port)| port.to_string());
    format!(
        "sealed_verdict={verdict} obfuscation_udp_port={obfuscation_port} \
         sealed_requests={} sealed_answers={} sealed_answer_from_port={answer_port} \
         plain_after_key={}",
        list(&mut requests.iter().map(|&(opcode, _)| opcode)),
        list(&mut answers.iter().map(|&(opcode, _)| opcode)),
        list(&mut plain_after_key.into_iter()),
    )
}

/// The obfuscation UDP port and non-zero `ServerUDPKey` the crypt-ping's
/// `answer` carries once opened under its `challenge`; `None` for an answer
/// that does not open to a `0x97` or carries no key.
fn crypt_facts(answer: &[u8], challenge: u32) -> Option<(u16, u32)> {
    let status = decrypt_datagram_server(answer, challenge, ServerCryptDirection::FromServer)?;
    if status.get(..2) != Some(&[0xE3, 0x97]) {
        return None;
    }
    let facts = status.get(CRYPT_FACTS_AT..CRYPT_FACTS_AT + 8)?;
    let port = u16::from_le_bytes([facts[0], facts[1]]);
    let key = u32::from_le_bytes([facts[4], facts[5], facts[6], facts[7]]);
    (key != 0 && port != 0).then_some((port, key))
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4};

    use rmule_primitives::{DatagramNonce, encrypt_datagram_server};

    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|at| u8::from_str_radix(&text[at..at + 2], 16).expect("hex"))
            .collect()
    }

    fn datagram(source: SocketAddrV4, destination: SocketAddrV4, payload: Vec<u8>) -> Udp4Datagram {
        Udp4Datagram {
            at: 0.0,
            source,
            destination,
            payload,
        }
    }

    /// rmule's crypt-ping and Lugdunum's answer as run `1791422886`'s tap
    /// holds them (`reask.pcap`, 1791425616.174),
    /// then a sealed `0xA2` to the obfuscation port and a sealed `0xA3` back,
    /// sealed here under the key that answer carries.
    #[test]
    fn a_sealed_ask_and_its_sealed_answer_read_as_sealed_answered() {
        let rmule = SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 3), 56967);
        let server = Ipv4Addr::new(203, 0, 113, 2);
        let nonce = DatagramNonce {
            marker_byte: 0x51,
            random_key: 0xBEEF,
            padding: Vec::new(),
        };
        let seal = |frame: &[u8], direction| {
            encrypt_datagram_server(frame, 0x05A6_8835, direction, &nonce)
        };
        let tap = [
            datagram(
                rmule,
                SocketAddrV4::new(server, 4673),
                hex("7bb6dbb8dcb32d81900e"),
            ),
            datagram(
                SocketAddrV4::new(server, 4673),
                rmule,
                hex(
                    "eb63b259404adad665cc6eacbfd0262720eda82ca3e80e9eef6e18119e748911\
                     dc1f059f0bfcc8b2a7d688f22ac7caf4be2430e7639d35de771d1ccf52",
                ),
            ),
            datagram(
                rmule,
                SocketAddrV4::new(server, 4675),
                seal(
                    &[0xE3, 0xA2, 0xFF, 0xF0, 0x12, 0x34],
                    ServerCryptDirection::ToServer,
                ),
            ),
            datagram(
                SocketAddrV4::new(server, 4675),
                rmule,
                seal(
                    &[0xE3, 0xA3, 0xFF, 0xF0, 0x12, 0x34, 0, 0, 0, 0],
                    ServerCryptDirection::FromServer,
                ),
            ),
        ];

        assert_eq!(
            read_sealed(&tap, 4673),
            "sealed_verdict=SEALED-ANSWERED obfuscation_udp_port=4675 sealed_requests=a2 \
             sealed_answers=a3 sealed_answer_from_port=4675 plain_after_key=none"
        );
    }
}
