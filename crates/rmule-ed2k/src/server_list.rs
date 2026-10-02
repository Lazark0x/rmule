//! `OP_SERVERLIST` (0x32): the servers a server knows about, as a count-led
//! list of endpoints, optionally followed by an IPv6 block (ADR-0087 §4.6).
//!
//! The wire count is one byte, so the entry cap is validated at construction
//! and encoding stays infallible.
//!
//! The IPv4 array is self-terminating and a legacy server sends **nothing**
//! after it — not even a zero byte — so "no bytes remain" must read as "no
//! IPv6 block", never as a truncated one. That is why the tail is modelled as
//! three outcomes rather than an `Option`: *absent* is a legacy server,
//! *present and empty* is a capable server with nothing to offer, and
//! *malformed* is a diagnostic that costs only the IPv6 half.

use rmule_primitives::{Ipv4Endpoint, Ipv6Endpoint, Packet, PacketProtocol};

use crate::{Ed2kError, Opcode, Result};

/// How an `OP_SERVERLIST`'s optional trailing IPv6 block read (ADR-0087 §4.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ServerListTail {
    /// Nothing followed the IPv4 array — a legacy server, and the ordinary
    /// case. Distinct from an empty block: this server said nothing about
    /// IPv6, rather than saying it knows none.
    Absent,
    /// A well-formed block followed, carrying `count` entries (possibly zero).
    Read {
        /// How many IPv6 entries the block declared.
        count: usize,
    },
    /// Bytes followed the IPv4 array but did not form a block — the declared
    /// count outran the payload, or left bytes it does not account for (the
    /// frame is length-delimited, so a surplus means sender and reader
    /// disagree about the block). The IPv4 entries still stand; only the IPv6
    /// half is lost.
    Malformed {
        /// How many bytes followed the IPv4 array.
        trailing_len: usize,
    },
}

/// `OP_SERVERLIST`: other servers the connected server knows — how a client's
/// list grows without an out-of-band source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerList {
    servers: Vec<Ipv4Endpoint>,
    ipv6_servers: Vec<Ipv6Endpoint>,
    tail: ServerListTail,
}

impl ServerList {
    /// Construct an `OP_SERVERLIST` body from its decoded entries. The
    /// wire `count` field is a `u8`, so up to 255 entries are permitted;
    /// validating here rather than at encode time keeps `encode_packet`
    /// infallible.
    pub fn new(servers: Vec<Ipv4Endpoint>) -> Result<Self> {
        if servers.len() > usize::from(u8::MAX) {
            return Err(Ed2kError::InvalidPayload {
                opcode: Opcode::ServerList.as_u8(),
                reason: "OP_SERVERLIST entry count exceeds u8 wire ceiling (255)",
            });
        }
        Ok(Self {
            servers,
            ipv6_servers: Vec::new(),
            tail: ServerListTail::Absent,
        })
    }

    /// This list with an IPv6 block attached — the writer half of ADR-0087
    /// §4.6. Attaching an empty block is meaningful: it says the sender speaks
    /// the extension and knows no IPv6 servers.
    ///
    /// # Errors
    /// [`Ed2kError::InvalidPayload`] if the block exceeds the `u8` wire count.
    pub fn with_ipv6_servers(mut self, ipv6_servers: Vec<Ipv6Endpoint>) -> Result<Self> {
        if ipv6_servers.len() > usize::from(u8::MAX) {
            return Err(Ed2kError::InvalidPayload {
                opcode: Opcode::ServerList.as_u8(),
                reason: "OP_SERVERLIST IPv6 count exceeds u8 wire ceiling (255)",
            });
        }
        self.tail = ServerListTail::Read {
            count: ipv6_servers.len(),
        };
        self.ipv6_servers = ipv6_servers;
        Ok(self)
    }

    /// The offered endpoints, in the order the server sent them.
    #[must_use]
    pub fn servers(&self) -> &[Ipv4Endpoint] {
        &self.servers
    }

    /// The offered IPv6 endpoints, in the order the server sent them. Empty
    /// for a legacy list — see [`tail`](Self::tail) to tell "said nothing"
    /// from "knows none".
    #[must_use]
    pub fn ipv6_servers(&self) -> &[Ipv6Endpoint] {
        &self.ipv6_servers
    }

    /// How the trailing IPv6 block read.
    #[must_use]
    pub const fn tail(&self) -> ServerListTail {
        self.tail
    }

    /// Decode this packet's payload.
    ///
    /// # Errors
    /// [`Ed2kError::InvalidPayload`] if the protocol byte, the opcode, or the
    /// body layout is not this packet's.
    pub fn decode_packet(packet: &Packet) -> Result<Self> {
        let opcode = Opcode::ServerList.as_u8();
        if packet.protocol() != PacketProtocol::Edonkey {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "unsupported packet protocol",
            });
        }
        if packet.opcode() != opcode {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "wrong opcode for OP_SERVERLIST",
            });
        }

        let payload = packet.payload();
        if payload.is_empty() {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "OP_SERVERLIST payload missing count byte",
            });
        }
        let count = usize::from(payload[0]);
        let entries_len =
            count
                .checked_mul(Ipv4Endpoint::WIRE_LEN)
                .ok_or(Ed2kError::InvalidPayload {
                    opcode,
                    reason: "OP_SERVERLIST count overflow",
                })?;
        if payload.len() < 1 + entries_len {
            return Err(Ed2kError::InvalidPayload {
                opcode,
                reason: "OP_SERVERLIST declared count does not match payload",
            });
        }

        let mut servers = Vec::with_capacity(count);
        for i in 0..count {
            let start = 1 + i * Ipv4Endpoint::WIRE_LEN;
            let chunk: &[u8; Ipv4Endpoint::WIRE_LEN] = payload
                [start..start + Ipv4Endpoint::WIRE_LEN]
                .try_into()
                .expect("validated server list slice length");
            servers.push(Ipv4Endpoint::decode(chunk));
        }
        let (ipv6_servers, tail) = decode_ipv6_block(&payload[1 + entries_len..]);
        Ok(Self {
            servers,
            ipv6_servers,
            tail,
        })
    }

    /// The packet form, ready to frame and send.
    #[must_use]
    pub fn encode_packet(&self) -> Packet {
        // Invariant maintained by `Self::new` and `Self::decode_packet`:
        // `servers.len() <= u8::MAX`, so the `try_from` cannot fail.
        let count = u8::try_from(self.servers.len()).expect("ServerList invariant: len <= 255");
        let mut payload = Vec::with_capacity(1 + self.servers.len() * Ipv4Endpoint::WIRE_LEN);
        payload.push(count);
        for endpoint in &self.servers {
            payload.extend_from_slice(&endpoint.encode());
        }
        // A legacy list ends here, with nothing after the array — writing a
        // zero byte would make every v4-only list one byte longer than the
        // wire has ever carried. Only a list that *read* a block writes one
        // back, so a decode → encode round trip of a legacy list stays
        // byte-exact.
        if let ServerListTail::Read { .. } = self.tail {
            let count =
                u8::try_from(self.ipv6_servers.len()).expect("ServerList invariant: len <= 255");
            payload.push(count);
            for endpoint in &self.ipv6_servers {
                payload.extend_from_slice(&endpoint.addr_bytes());
                payload.extend_from_slice(&endpoint.port.to_le_bytes());
            }
        }
        Packet::new(PacketProtocol::Edonkey, Opcode::ServerList.as_u8(), payload)
    }
}

/// The bytes that follow the IPv4 array, read as ADR-0087 §4.6's block.
///
/// Three outcomes, and none of them fails the packet: the IPv4 array is
/// already parsed and valid, so a bad tail costs the IPv6 half and nothing
/// else. The `count × 18 <= remaining` bound is checked **before** reading,
/// because a count byte from a foreign server is untrusted arithmetic.
fn decode_ipv6_block(tail: &[u8]) -> (Vec<Ipv6Endpoint>, ServerListTail) {
    /// Sixteen address bytes plus the two-byte little-endian port.
    const ENTRY_LEN: usize = Ipv6Endpoint::ADDR_WIRE_LEN + 2;

    let Some((&count, entries)) = tail.split_first() else {
        return (Vec::new(), ServerListTail::Absent);
    };
    let count = usize::from(count);
    let Some(needed) = count.checked_mul(ENTRY_LEN) else {
        return (
            Vec::new(),
            ServerListTail::Malformed {
                trailing_len: tail.len(),
            },
        );
    };
    if entries.len() != needed {
        return (
            Vec::new(),
            ServerListTail::Malformed {
                trailing_len: tail.len(),
            },
        );
    }
    let servers = entries[..needed]
        .chunks_exact(ENTRY_LEN)
        .map(|entry| {
            let address: [u8; Ipv6Endpoint::ADDR_WIRE_LEN] = entry[..Ipv6Endpoint::ADDR_WIRE_LEN]
                .try_into()
                .expect("chunk is exactly one entry");
            let port = u16::from_le_bytes([
                entry[Ipv6Endpoint::ADDR_WIRE_LEN],
                entry[Ipv6Endpoint::ADDR_WIRE_LEN + 1],
            ]);
            Ipv6Endpoint::from_addr_bytes(address, port)
        })
        .collect();
    (servers, ServerListTail::Read { count })
}
