//! The stock aMule requester's own Kad datagrams, **read by decoding them**
//! rather than by a BPF test on the plaintext `0xE4` byte.
//!
//! With aMule's crypt layer on (`AMULE_KAD_CRYPT=1`), every Kad send toward a
//! contact of version ≥ 6 leaves keyed on that contact's Kad ID:
//! `SendPacket(…, from->GetUDPKey(), &clientID)` at the FINDSOURCE `0x52`
//! (`Search.cpp:1103-1110`, kno `ab483654`), and the same family on the walk
//! and the source search. `CMuleUDPSocket::SendPacket` encrypts whenever a
//! crypt target ID is given and the layer is supported
//! (`MuleUDPSocket.cpp:282-284`). The envelope opens with a random marker, not
//! `0xE4`, so no filter can pick the opcode out; the tap's datagrams between
//! two hosts are lifted whole and each is decoded here — plaintext as is, a
//! crypt envelope under the recipient's own Kad ID (the only key the bench
//! can hold for it: a key the harness does not hold decodes nothing, and is
//! counted as such rather than guessed at). A plaintext run reads the same
//! counts the old `0xE4` filters did.

use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use rmule_primitives::ClientDecryptKeys;

use crate::docker::Docker;
use crate::flow::evidence::{KadFrameFacts, kad_frame_facts, write_pcap_all_matches};
use crate::flow::identity::hex_lower;
use crate::flow::kad_buddy::callback::Judged;
use crate::flow::kad_buddy::core::KAD_CORE_BUDDY_RMULE_KAD_ID;
use crate::flow::pcap::udp_payloads;

/// `KADEMLIA2_REQ` — the `FINDSOURCE` walk.
const KADEMLIA2_REQ: u8 = 0x21;
/// `KADEMLIA2_SEARCH_SOURCE_REQ`.
const KADEMLIA2_SEARCH_SOURCE_REQ: u8 = 0x34;
/// `KADEMLIA_CALLBACK_REQ`.
const KADEMLIA_CALLBACK_REQ: u8 = 0x52;
/// The row that shows the `FINDSOURCE` walk: a `KADEMLIA2_REQ` to the rmule
/// buddy whose target is the buddy ID (`<0xE4><0x21><count 1><target 16>
/// <receiver 16>`, `Search.cpp` `SendFindValue`).
pub(crate) const FINDSOURCE_WALK_ROW: &str = "requester_findsource_walk_0x21_to_buddy";

/// The requester's datagrams flow M judges, off two taps: toward the buddy on
/// both ends of the hop, and toward the placed storer at the requester.
pub(crate) struct RequesterDatagrams {
    /// Requester → buddy, on the buddy's own tap.
    at_buddy: Datagrams,
    /// Requester → buddy, on the requester's tap.
    to_buddy: Datagrams,
    /// Requester → placed storer, on the requester's tap.
    to_storer: Datagrams,
}

impl RequesterDatagrams {
    /// Lift and decode the three hops. `requester` is the requester tap's
    /// sidecar, pcap and host directory; `substitute` fills the flow's `{q}`,
    /// `{r}` and `{s}` hosts; `file_hash` places the storer's Kad ID.
    ///
    /// # Errors
    /// If a hop cannot be lifted or read.
    pub(crate) fn read(
        judged: &Judged<'_>,
        (tap, pcap, dir): (&str, &str, &Path),
        substitute: &dyn Fn(&str) -> String,
        file_hash: [u8; 16],
    ) -> Result<Self> {
        let to_buddy_filter = substitute("udp and src host {q} and dst host {r}");
        let storer_kad_id = crate::kad_seed::storer_kad_id_for_file_hash(file_hash);
        Ok(Self {
            at_buddy: Datagrams::read(
                judged.docker,
                (judged.buddy_tap, judged.buddy_pcap),
                &to_buddy_filter,
                &judged.buddy_host_dir.join("requester-to-buddy.pcap"),
                &KAD_CORE_BUDDY_RMULE_KAD_ID,
            )?,
            to_buddy: Datagrams::read(
                judged.docker,
                (tap, pcap),
                &to_buddy_filter,
                &dir.join("requester-to-buddy.pcap"),
                &KAD_CORE_BUDDY_RMULE_KAD_ID,
            )?,
            to_storer: Datagrams::read(
                judged.docker,
                (tap, pcap),
                &substitute("udp and src host {q} and dst host {s}"),
                &dir.join("requester-to-storer.pcap"),
                &storer_kad_id,
            )?,
        })
    }

    /// The counted rows these hops answer; `walk` adds the `FINDSOURCE` walk's.
    pub(crate) fn rows(&self, walk: bool) -> Vec<(&'static str, &'static str, u64)> {
        let mut rows = vec![
            (
                "requester_search_source_req_0x34_out",
                "KADEMLIA2_SEARCH_SOURCE_REQ leaving the requester for the placed storer",
                self.to_storer.count(KADEMLIA2_SEARCH_SOURCE_REQ),
            ),
            (
                "requester_callback_req_0x52_out",
                "KADEMLIA_CALLBACK_REQ leaving the requester for the buddy",
                self.to_buddy.count(KADEMLIA_CALLBACK_REQ),
            ),
            (
                "requester_callback_req_0x52_buddy_tap",
                "KADEMLIA_CALLBACK_REQ from the aMule requester, at the buddy",
                self.at_buddy.count(KADEMLIA_CALLBACK_REQ),
            ),
        ];
        if walk {
            let target = KAD_CORE_BUDDY_RMULE_KAD_ID;
            let walked = self
                .to_buddy
                .with_opcode(KADEMLIA2_REQ)
                .filter(|it| it.facts.payload.get(3..19) == Some(&target[..]))
                .count() as u64;
            rows.push((
                FINDSOURCE_WALK_ROW,
                "KADEMLIA2_REQ from the requester to the buddy, targeting the buddy ID",
                walked,
            ));
        }
        for (key, label, count) in &rows {
            println!("kad-amule-requester row {key} ({label}) = {count}");
        }
        rows
    }

    /// The first `0x52` that reached the buddy, kept in `dir` as
    /// `amule-callback-req-0x52.bin` (and its envelope, when keyed); returns
    /// its plaintext.
    ///
    /// # Errors
    /// If the body cannot be written.
    pub(crate) fn callback_req(&self, dir: &Path) -> Result<Option<Vec<u8>>> {
        let Some(first) = self.at_buddy.with_opcode(KADEMLIA_CALLBACK_REQ).next() else {
            return Ok(None);
        };
        keep(first, dir, "amule-callback-req-0x52")?;
        Ok(Some(first.facts.payload.clone()))
    }

    /// Whether the first `0x52` at the buddy crossed keyed on its Kad ID.
    pub(crate) fn callback_req_keyed(&self) -> bool {
        self.at_buddy
            .with_opcode(KADEMLIA_CALLBACK_REQ)
            .next()
            .is_some_and(Datagram::keyed)
    }

    /// The verdict's `[requester_crypt]` table: the first `0x52`'s envelope
    /// and trailer, and how every hop crossed.
    pub(crate) fn crypt_toml(&self, requested: bool) -> String {
        let mut out = format!("\n[requester_crypt]\nrequested = {requested}\n");
        let first = self.at_buddy.with_opcode(KADEMLIA_CALLBACK_REQ).next();
        let (envelope, key, receiver, sender) = match first {
            Some(it) if it.keyed() => (
                hex_lower(&it.wire),
                format!("kad-id {}", hex_lower(&KAD_CORE_BUDDY_RMULE_KAD_ID)),
                format!("{:#010x}", it.facts.receiver_verify_key.unwrap_or(0)),
                format!("{:#010x}", it.facts.sender_verify_key.unwrap_or(0)),
            ),
            Some(_) => (
                String::new(),
                "plaintext".to_owned(),
                String::new(),
                String::new(),
            ),
            None => (
                String::new(),
                "absent".to_owned(),
                String::new(),
                String::new(),
            ),
        };
        out.push_str(&format!("callback_req_0x52_envelope = \"{envelope}\"\n"));
        out.push_str(&format!("callback_req_0x52_key = \"{key}\"\n"));
        out.push_str(&format!(
            "callback_req_0x52_receiver_verify_key = \"{receiver}\"\n"
        ));
        out.push_str(&format!(
            "callback_req_0x52_sender_verify_key = \"{sender}\"\n"
        ));
        for (hop, read) in [
            ("at_buddy", &self.at_buddy),
            ("to_buddy", &self.to_buddy),
            ("to_storer", &self.to_storer),
        ] {
            out.push_str(&format!(
                "{hop} = {{ keyed = {}, undecoded = {} }}\n",
                read.keyed(),
                read.undecoded
            ));
        }
        out
    }
}

/// One datagram off the tap: its bytes on the wire and what they decode to.
pub(crate) struct Datagram {
    pub(crate) wire: Vec<u8>,
    pub(crate) facts: KadFrameFacts,
}

impl Datagram {
    /// Whether it crossed the wire inside a crypt envelope.
    pub(crate) fn keyed(&self) -> bool {
        self.facts.marker.is_some()
    }
}

/// Every datagram one filter selected on one tap, decoded for one recipient.
pub(crate) struct Datagrams {
    decoded: Vec<Datagram>,
    /// Datagrams that were neither plaintext Kad nor keyed on the recipient's
    /// Kad ID.
    pub(crate) undecoded: u32,
}

impl Datagrams {
    /// Lift every UDP datagram `filter` selects off `(tap, pcap)` to `out` (a
    /// pcap in the tap's own host directory) and decode each as a Kad
    /// datagram addressed to the node whose Kad ID is `recipient`.
    ///
    /// # Errors
    /// If tcpdump cannot run in the sidecar or the lifted pcap cannot be read.
    pub(crate) fn read(
        docker: &Docker,
        (tap, pcap): (&str, &str),
        filter: &str,
        out: &Path,
        recipient: &[u8; 16],
    ) -> Result<Self> {
        let name = out
            .file_name()
            .and_then(|name| name.to_str())
            .context("a lifted pcap needs a file name")?;
        write_pcap_all_matches(docker, tap, pcap, filter, name)?;
        Ok(Self::decode(udp_payloads(out)?, recipient))
    }

    fn decode(payloads: Vec<Vec<u8>>, recipient: &[u8; 16]) -> Self {
        let keys = ClientDecryptKeys {
            kad_id: Some(recipient),
            ..Default::default()
        };
        let mut decoded = Vec::new();
        let mut undecoded = 0;
        for wire in payloads {
            match kad_frame_facts(&wire, &keys) {
                Some(facts) => decoded.push(Datagram { wire, facts }),
                None => undecoded += 1,
            }
        }
        Self { decoded, undecoded }
    }

    /// The decoded datagrams carrying `opcode`, in capture order.
    pub(crate) fn with_opcode(&self, opcode: u8) -> impl Iterator<Item = &Datagram> {
        self.decoded
            .iter()
            .filter(move |datagram| datagram.facts.opcode == opcode)
    }

    /// How many decoded datagrams carry `opcode`.
    pub(crate) fn count(&self, opcode: u8) -> u64 {
        self.with_opcode(opcode).count() as u64
    }

    /// How many decoded datagrams crossed keyed.
    pub(crate) fn keyed(&self) -> u64 {
        self.decoded.iter().filter(|it| it.keyed()).count() as u64
    }
}

/// Keep a lifted datagram: its plaintext Kad datagram as `<stem>.bin` and,
/// when it crossed keyed, the envelope as it crossed the wire as
/// `<stem>-envelope.bin`.
///
/// # Errors
/// If a file cannot be written.
pub(crate) fn keep(datagram: &Datagram, dir: &Path, stem: &str) -> Result<()> {
    let plain = dir.join(format!("{stem}.bin"));
    fs::write(&plain, &datagram.facts.payload)
        .with_context(|| format!("write {}", plain.display()))?;
    if datagram.keyed() {
        let envelope = dir.join(format!("{stem}-envelope.bin"));
        fs::write(&envelope, &datagram.wire)
            .with_context(|| format!("write {}", envelope.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use rmule_primitives::{ClientEncryptKey, DatagramNonce, encrypt_datagram_client};

    use super::Datagrams;

    const BUDDY: [u8; 16] = [0xFF; 16];
    const STRANGER: [u8; 16] = [0x11; 16];
    const CALLBACK_REQ: [u8; 4] = [0xE4, 0x52, 0x01, 0x02];

    fn keyed_for(kad_id: &[u8; 16]) -> Vec<u8> {
        encrypt_datagram_client(
            &CALLBACK_REQ,
            &ClientEncryptKey::KadNode {
                kad_id,
                receiver_verify_key: 0,
                sender_verify_key: 0x0102_0304,
            },
            &DatagramNonce {
                marker_byte: 0x20,
                random_key: 0x3412,
                padding: Vec::new(),
            },
        )
    }

    /// A plaintext datagram and one keyed on the recipient both count; one
    /// keyed on somebody else's ID is not read as anything.
    #[test]
    fn a_datagram_keyed_on_the_recipient_decodes_and_a_foreign_key_does_not() {
        let read = Datagrams::decode(
            vec![
                CALLBACK_REQ.to_vec(),
                keyed_for(&BUDDY),
                keyed_for(&STRANGER),
            ],
            &BUDDY,
        );
        assert_eq!(read.count(0x52), 2);
        assert_eq!(read.keyed(), 1);
        assert_eq!(read.undecoded, 1);
        let keyed = read.with_opcode(0x52).nth(1).expect("the keyed one");
        assert_eq!(keyed.facts.payload, CALLBACK_REQ);
        assert_eq!(keyed.facts.sender_verify_key, Some(0x0102_0304));
    }
}
