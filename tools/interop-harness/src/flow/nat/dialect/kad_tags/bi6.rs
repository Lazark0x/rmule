//! The `bi6` leg of `ipv6-kad-tags`: a **firewalled** rmule
//! publishes the same 2 MiB file kno stores for as aMule's type-3 buddy row,
//! closed with `bi6` — the buddy's IPv6, upper-case hex — and then searches
//! kno for it.
//!
//! The body is `kad join-node` naming its buddy by `--publish-buddy-id`,
//! `--publish-buddy-udp` and `--publish-buddy-ipv6`: the row a real `Core`'s
//! slot publishes once its held buddy link knows the buddy's IPv6, stated as
//! **Stimulus** rather than earned behind a gateway. The named buddy is the
//! direction-1 publisher's dual-stack body; no buddy link exists. What the leg
//! measures is kno's side of the bytes, never the relationship.
//!
//! kno's storer path indexes every tag it does not recognise verbatim
//! (`KademliaUDPListener.cpp:1402`, "TODO: Filter tags"), so the `0x3B` it
//! answers with is the evidence that it stored and returned our `bi6`. Its
//! search-result reader (`Search.cpp:1205-1224`) would validate the tag and
//! drop it — "no IPv6 transport in this build" — never passing the address to
//! `KademliaSearchFile`; that path needs kno to *search*, which nothing on this
//! bench makes it do, so it stays source-derived.

use std::net::Ipv6Addr;
use std::time::Duration;

use anyhow::{Context, Result};
use rmule_kad::{KadPublishedSource, KadSourceCandidate};

use super::{
    JOIN_NODE_READY_MARKER, PUBLISHER_DONE_MARKER, PUBLISHER_WINDOW_SECS, join_node_args, subdir,
};
use crate::flow::bench::Bench;
use crate::flow::gate::wait_for_container_log;
use crate::flow::identity::hex_lower;
use crate::flow::nat::dialect::BODY_CLIENT_UDP_PORT;
use crate::flow::nat::dialect::bench::{
    HOST_KAD_FW_PUBLISHER, HOST_KAD_PUBLISHER, Ipv6DialectOptions, Stage, start_detached_driver,
};
use crate::flow::nat::dialect::verdict::{Claim, Evidence};

/// The body's leg-dir name and role.
pub(super) const FW_PUBLISHER_ROLE: &str = "v6kad-fw-publisher";
/// Its user hash.
const FW_PUBLISHER_USER_HASH: &str = "46464646464646464646464646464646";
/// Its Kad ID: far from both file keys, and not the direction-1 publisher's.
const FW_PUBLISHER_KAD_ID: [u8; 16] = [
    0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE, 0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01,
];
/// The `bi6` tag's header: string type, three-byte name, 32 characters.
const BI6_TAG_HEADER: [u8; 8] = [0x02, 0x03, 0x00, b'b', b'i', b'6', 0x20, 0x00];

/// Run the firewalled publisher to completion: publish, kno's ack, search,
/// kno's answer. Returns its container name and whether its search decoded.
///
/// # Errors
/// If the driver cannot start.
pub(super) fn drive(
    bench: &mut Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
) -> Result<(String, bool)> {
    let published = stage.published.as_ref().context("the published file")?;
    subdir(&stage.leg_dir, FW_PUBLISHER_ROLE)?;
    let mut args = join_node_args(
        stage,
        FW_PUBLISHER_ROLE,
        FW_PUBLISHER_KAD_ID,
        FW_PUBLISHER_USER_HASH,
        PUBLISHER_WINDOW_SECS,
    );
    args.extend([
        "--publish-file-hash".to_owned(),
        published.file_hash.to_lowercase(),
        "--publish-file-size".to_owned(),
        published.size.to_string(),
        // `~ourKadID`, as a firewalled aMule names its buddy relationship
        // (`Search.cpp:841-842`).
        "--publish-buddy-id".to_owned(),
        hex_lower(&FW_PUBLISHER_KAD_ID.map(|byte| !byte)),
        "--publish-buddy-udp".to_owned(),
        format!("{}:{BODY_CLIENT_UDP_PORT}", stage.v4(HOST_KAD_PUBLISHER)),
        "--publish-buddy-ipv6".to_owned(),
        buddy_ipv6(stage).to_string(),
    ]);
    let (publisher, _) = start_detached_driver(
        bench,
        options,
        stage,
        FW_PUBLISHER_ROLE,
        HOST_KAD_FW_PUBLISHER,
        &args,
        JOIN_NODE_READY_MARKER,
    )?;
    let searched = wait_for_container_log(
        &bench.docker,
        &publisher,
        PUBLISHER_DONE_MARKER,
        Duration::from_secs(PUBLISHER_WINDOW_SECS + 30),
    )
    .is_ok();
    Ok((publisher, searched))
}

/// The IPv6 the row names for its buddy: the direction-1 publisher's.
pub(super) fn buddy_ipv6(stage: &Stage) -> Ipv6Addr {
    stage
        .v6(HOST_KAD_PUBLISHER)
        .parse()
        .expect("the bench plan hands out parseable IPv6 addresses")
}

/// What the leg lifted off kno's tap, each already read through rmule's own
/// decoders beside its raw bytes.
pub(super) struct Bi6Frames<'a> {
    /// rmule's firewalled `0x44` to kno — Stimulus.
    pub(super) ours: Option<(&'a [u8], KadPublishedSource)>,
    /// kno's `0x3B` to the firewalled publisher.
    pub(super) answer: Option<(&'a [u8], Vec<KadSourceCandidate>)>,
    /// kno's own `0x44`, from direction 2.
    pub(super) kno_publish: Option<&'a [u8]>,
}

/// The leg's three claims.
pub(super) fn claims(frames: &Bi6Frames<'_>, buddy: Ipv6Addr) -> Vec<Claim> {
    let our_tag = frames.ours.and_then(|(bytes, _)| bi6_tag(bytes));
    let ours_named = frames.ours.as_ref().and_then(|(_, source)| {
        source
            .buddy
            .and_then(|contact| contact.buddy_ipv6)
            .map(|address| (source.source_type, address))
    });
    let returned_tag = frames.answer.as_ref().and_then(|(bytes, _)| bi6_tag(bytes));
    let rows = frames.answer.as_ref().map(|(_, rows)| rows.as_slice());
    let returned = rows.into_iter().flatten().find_map(|row| {
        row.facts()
            .and_then(|facts| facts.buddy)
            .and_then(|contact| contact.buddy_ipv6)
            .map(|address| (row.peer_source(), address))
    });
    let kno_bi6 = frames.kno_publish.map(|bytes| bi6_tag(bytes).is_some());

    vec![
        // rmule's own 0x44 is Stimulus; it is checked here only so a missing
        // tag in kno's answer can be told apart from one we never sent.
        Claim::about(
            "amule-kno-stores-and-returns-the-bi6-tag",
            ours_named == Some((Some(3), buddy)) && our_tag.is_some() && returned_tag == our_tag,
            Evidence::Captured,
            format!(
                "Stimulus: rmule's firewalled 0x44 to kno ({} bytes) read as (source type, bi6) \
                 {ours_named:?}, tag {:?}. kno's 0x3B ({} bytes) carried the tag {:?} — \
                 verbatim, case included, is the storer's verbatim-index path \
                 (KademliaUDPListener.cpp:1402).",
                frames.ours.map_or(0, |(bytes, _)| bytes.len()),
                our_tag.map(String::from_utf8_lossy),
                frames.answer.as_ref().map_or(0, |(bytes, _)| bytes.len()),
                returned_tag.map(String::from_utf8_lossy),
            ),
        ),
        Claim::about(
            "a-buddy-row-parsed-back-with-its-bi6",
            returned.is_some_and(|(peer_source, address)| {
                address == buddy
                    && !matches!(peer_source, Some(rmule_primitives::PeerSource::Ipv6(_)))
            }),
            Evidence::Captured,
            format!(
                "decode_source_result on kno's bytes: (peer source, bi6) {returned:?} among {} \
                 row(s). bi6 rides the row's buddy contact and never rescues the row into a \
                 direct IPv6 source — it names the buddy, not the file's holder.",
                rows.map_or(0, <[KadSourceCandidate]>::len)
            ),
        ),
        Claim::about(
            "amule-kno-writes-no-bi6",
            kno_bi6 == Some(false),
            Evidence::DocumentedAbsence,
            format!(
                "kno's own 0x44 carries a bi6 tag: {kno_bi6:?}. Its publisher appends one IPv6 \
                 tag, ip6 (Search.cpp:901); bi6 is read only, in CSearch::ProcessResultFile \
                 (Search.cpp:1205-1224), which validates it and drops it without passing it to \
                 KademliaSearchFile. eMuleAI (Search.cpp:920-923) and emule-qt \
                 (KadSearch.cpp:1419-1421) write it; neither runs Kad on this bench."
            ),
        ),
    ]
}

/// The 32 value characters of the first `bi6` tag in `frame`.
pub(super) fn bi6_tag(frame: &[u8]) -> Option<&[u8]> {
    let at = frame
        .windows(BI6_TAG_HEADER.len())
        .position(|window| window == BI6_TAG_HEADER)?;
    frame.get(at + BI6_TAG_HEADER.len()..at + BI6_TAG_HEADER.len() + 32)
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use rmule_kad::{
        Kad2Message, KadBuddyContact, KadId, KadPublishedSource, KadSourceRow, encode_source_result,
    };
    use rmule_primitives::Ipv4Endpoint;

    use super::{Bi6Frames, claims};
    use crate::flow::nat::dialect::kad_tags::{published_source, search_rows};

    const BUDDY: Ipv6Addr = Ipv6Addr::new(0x3fff, 0x0ed2, 1, 0, 0, 0, 0, 8);

    fn contact() -> KadBuddyContact {
        KadBuddyContact {
            buddy_id: KadId::from_bytes([0xEF; 16]),
            buddy_udp: Some(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 8), 4672)),
            buddy_ipv6: Some(BUDDY),
            buddy_udp_ipv6: None,
        }
    }

    /// rmule's own firewalled `0x44`, from rmule's encoder.
    fn our_publish() -> Vec<u8> {
        Kad2Message::PublishSourceReq {
            file: KadId::from_bytes([0x11; 16]),
            source_id: [0x46; 16],
            source: KadPublishedSource {
                source_type: Some(3),
                tcp_port: Some(4662),
                buddy: Some(contact()),
                ..KadPublishedSource::default()
            },
        }
        .encode()
        .encode()
    }

    /// A storer's one-row `0x3B` for that publish, with `bi6` appended to the
    /// row exactly as a verbatim-indexing storer re-serves it. rmule's own
    /// storer writes the typed tags; the appended tag is the part under test.
    fn re_serve(bi6_value: &[u8]) -> Vec<u8> {
        let row = KadSourceRow {
            source_id: [0x46; 16],
            source_type: 3,
            ip: Ipv4Addr::new(45, 55, 200, 7),
            tcp_port: 4662,
            udp_port: 4672,
            encryption: None,
            buddy: Some(KadBuddyContact {
                buddy_ipv6: None,
                buddy_udp_ipv6: None,
                ..contact()
            }),
            ipv6: None,
        };
        let mut bytes = encode_source_result(
            KadId::from_bytes([0x22; 16]),
            KadId::from_bytes([0x11; 16]),
            &[row],
        )[0]
        .encode();
        // [E4 3B][sender 16][key 16][count 2][source id 16] -> the row's tag count.
        bytes[2 + 16 + 16 + 2 + 16] += 1;
        bytes.extend_from_slice(&[0x02, 0x03, 0x00, b'b', b'i', b'6', 0x20, 0x00]);
        bytes.extend_from_slice(bi6_value);
        bytes
    }

    fn outcomes(ours: &[u8], answer: &[u8], kno_publish: &[u8]) -> Vec<&'static str> {
        let frames = Bi6Frames {
            ours: Some((ours, published_source(ours).unwrap())),
            answer: Some((answer, search_rows(answer).unwrap())),
            kno_publish: Some(kno_publish),
        };
        claims(&frames, BUDDY)
            .iter()
            .map(|claim| claim.outcome)
            .collect()
    }

    /// The store-and-return claim is byte-level: a storer that returned the
    /// address re-spelled — the case changed — still parses back, but is not
    /// the verbatim re-serve the claim attributes to kno's index path. And a
    /// `0x44` that carries a `bi6` anywhere breaks the kno-writes-none zero.
    #[test]
    fn the_bi6_leg_holds_only_on_a_verbatim_re_serve() {
        let ours = our_publish();
        let verbatim = re_serve(b"3FFF0ED2000100000000000000000008");
        let recased = re_serve(b"3fff0ed2000100000000000000000008");
        let no_bi6 = [0xE4, 0x44];

        assert_eq!(
            outcomes(&ours, &verbatim, &no_bi6),
            ["held", "held", "held"]
        );
        assert_eq!(
            outcomes(&ours, &recased, &no_bi6),
            ["absent", "held", "held"]
        );
        assert_eq!(outcomes(&ours, &verbatim, &ours)[2], "absent");
    }
}
