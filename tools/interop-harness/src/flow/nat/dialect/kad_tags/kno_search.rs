//! The kno-searches leg of `ipv6-kad-tags`: kno **searches** on
//! an rmule storer for the 2 MiB file whose firewalled row the [`super::bi6`]
//! publisher wrote with `bi6`, and reads the row rmule's storer re-serves.
//!
//! A second rmule storer is pinned beside kno at that file's key — the last
//! word flipped, so the XOR distance's top word is zero and both tolerance
//! gates pass: rmule's own for the WAN publish, and kno's `SEARCHTOLERANCE`
//! for the search (`Search.cpp:626-629`). kno's `nodes.dat` names it, so the
//! firewalled publisher's walk finds it through kno and publishes there too.
//! Once that publisher is done, the flow opens the image's download gate
//! (`AMULE_DOWNLOAD_LINK` + `AMULE_DOWNLOAD_GATE`): kno adds the file's link
//! and its part file's Kad source search (`PartFile.cpp:1864-1893`) sends
//! `KADEMLIA2_SEARCH_SOURCE_REQ` to the storer.
//!
//! kno's reader validates the row's `bi6` and drops it (`Search.cpp:1205-1224`).
//! Its log line for that is an `AddDebugLogLineN`, compiled out of the pinned
//! image's Release build (`Logger.h:457-465`; `__DEBUG__` only under a Debug
//! build, `cmake/options.cmake:254`), so the leg reads kno's behaviour
//! instead: a type-3 source built from the row's IPv4 buddy trio alone
//! (`Search.cpp:1231-1242`, `DownloadQueue.cpp:1761-1779`), whose callback
//! request — `KADEMLIA_CALLBACK_REQ`, `0x52`, in the clear — goes to the
//! trio's endpoint (`BaseClient.cpp:2133-2160`), and nothing of kno's to the
//! `bi6` address.

use std::fs;
use std::net::Ipv6Addr;
use std::time::Duration;

use anyhow::{Context, Result};
use rmule_kad::KadSourceCandidate;

use super::{JOIN_NODE_READY_MARKER, STORER_INDEXED_MARKER, STORER_WINDOW_SECS, join_node_args};
use crate::flow::bench::Bench;
use crate::flow::gate::wait_for_container_log;
use crate::flow::identity::parse_ipv4_octets;
use crate::flow::mesh::KAD_CONTACT_VERSION;
use crate::flow::nat::dialect::bench::{
    HOST_KAD_BI6_STORER, Ipv6DialectOptions, Stage, start_detached_driver,
};
use crate::flow::nat::dialect::verdict::{Claim, Evidence};
use crate::flow::nat::dialect::{BODY_CLIENT_UDP_PORT, BODY_PEER_TCP_PORT};
use crate::kad_seed::KadContact;

/// The storer's leg-dir name and role.
pub(super) const BI6_STORER_ROLE: &str = "v6kad-bi6-storer";
/// Its user hash.
const BI6_STORER_USER_HASH: &str = "42424242424242424242424242424242";
/// The gate file's name in kno's `/seed` mount; its appearance adds the link.
pub(super) const DOWNLOAD_GATE: &str = "add-download";
/// kno's line once the link is added.
const KNO_DOWNLOAD_ADDED_MARKER: &str = "rmule-amule-download-added";
/// How long kno is given after the link is added: its search's own 45 s
/// lifetime, then the new source's first connection attempt.
const KNO_SEARCH_WINDOW_SECS: u64 = 90;

/// The storer's Kad ID: the file's key with its least significant word
/// changed, so the XOR distance's top word stays zero.
pub(super) fn storer_kad_id(key: [u8; 16]) -> [u8; 16] {
    let mut id = key;
    id[12] ^= 0x5A;
    id
}

/// Start the storer before kno boots, so kno's first hello to its seeded
/// contact lands. Returns the contact kno's `nodes.dat` names.
///
/// # Errors
/// If the storer cannot start or never binds its socket.
pub(super) fn start_storer(
    bench: &mut Bench,
    options: &Ipv6DialectOptions<'_>,
    stage: &Stage,
    key: [u8; 16],
) -> Result<KadContact> {
    let kad_id = storer_kad_id(key);
    super::subdir(&stage.leg_dir, BI6_STORER_ROLE)?;
    let (storer, ready) = start_detached_driver(
        bench,
        options,
        stage,
        BI6_STORER_ROLE,
        HOST_KAD_BI6_STORER,
        &join_node_args(
            stage,
            BI6_STORER_ROLE,
            kad_id,
            BI6_STORER_USER_HASH,
            STORER_WINDOW_SECS,
        ),
        JOIN_NODE_READY_MARKER,
    )?;
    if !ready {
        anyhow::bail!("the rmule bi6 storer {storer} never bound its socket");
    }
    Ok(KadContact {
        kad_id,
        ipv4: parse_ipv4_octets(stage.v4(HOST_KAD_BI6_STORER))?,
        udp_port: BODY_CLIENT_UDP_PORT,
        tcp_port: BODY_PEER_TCP_PORT,
        version: KAD_CONTACT_VERSION,
    })
}

/// Open kno's download gate once the storer holds a row, and give kno its
/// search window. Returns whether the storer indexed a row and whether kno
/// added the link.
///
/// # Errors
/// If the gate file cannot be written.
pub(super) fn drive(bench: &Bench, stage: &Stage, kno: &str, storer: &str) -> Result<(bool, bool)> {
    let indexed = wait_for_container_log(
        &bench.docker,
        storer,
        STORER_INDEXED_MARKER,
        Duration::from_secs(60),
    )
    .is_ok();
    let gate = stage.leg_dir.join("kno-seed").join(DOWNLOAD_GATE);
    fs::write(&gate, b"").with_context(|| format!("write {}", gate.display()))?;
    let added = wait_for_container_log(
        &bench.docker,
        kno,
        KNO_DOWNLOAD_ADDED_MARKER,
        Duration::from_secs(60),
    )
    .is_ok();
    if added {
        std::thread::sleep(Duration::from_secs(KNO_SEARCH_WINDOW_SECS));
    }
    Ok((indexed, added))
}

/// What the leg lifted off kno's tap.
pub(super) struct KnoSearchFrames<'a> {
    /// The `bi6` value the firewalled publisher's `0x44` to kno carried.
    pub(super) published_bi6: Option<&'a [u8]>,
    /// kno's `0x34` to the storer.
    pub(super) search: Option<&'a [u8]>,
    /// The storer's `0x3B` to kno, logical packet, with its decoded rows.
    pub(super) answer: Option<(&'a [u8], Vec<KadSourceCandidate>)>,
    /// kno's first `0x52` to the buddy trio's endpoint.
    pub(super) callback: Option<&'a [u8]>,
    /// Packets kno sent to the `bi6` address, over the whole run.
    pub(super) to_bi6: u64,
}

/// The leg's four claims. `key` is the file's Kad key in wire order — what
/// kno's search and its `0x52` both carry.
pub(super) fn claims(frames: &KnoSearchFrames<'_>, key: [u8; 16], buddy: Ipv6Addr) -> Vec<Claim> {
    let searched = frames
        .search
        .and_then(|bytes| bytes.get(2..18))
        .is_some_and(|target| target == key);
    let re_served = frames
        .answer
        .as_ref()
        .and_then(|(bytes, _)| super::bi6::bi6_tag(bytes));
    let row_buddy = frames.answer.as_ref().and_then(|(_, rows)| {
        rows.iter()
            .filter_map(|row| row.facts().and_then(|facts| facts.buddy))
            .find(|contact| contact.buddy_ipv6 == Some(buddy))
    });
    // `0x52`: <buddyID 16><fileHash 16><tcpPort 2>, both IDs in Kad wire order.
    let called = frames.callback.and_then(|bytes| bytes.get(2..34));
    let called_back = row_buddy.zip(called).is_some_and(|(contact, payload)| {
        payload[..16] == *contact.buddy_id.as_bytes() && payload[16..] == key
    });

    vec![
        Claim::about(
            "amule-kno-searches-rmules-storer-for-the-bi6-row",
            searched,
            Evidence::Captured,
            format!(
                "kno's 0x34 to the rmule storer ({} bytes) targets the 2 MiB file's key: \
                 {searched} — its part file's Kad source search (PartFile.cpp:1864-1893), \
                 sent once the image's download gate added the link.",
                frames.search.map_or(0, <[u8]>::len)
            ),
        ),
        Claim::about(
            "rmule-storer-re-serves-the-stored-bi6",
            re_served.is_some() && re_served == frames.published_bi6,
            Evidence::RmuleOnly,
            format!(
                "rmule's 0x3B to kno carried bi6 {:?}; the firewalled publisher's 0x44 carried \
                 {:?}. Byte for byte, case included (ADR-0087's amendment).",
                re_served.map(String::from_utf8_lossy),
                frames.published_bi6.map(String::from_utf8_lossy),
            ),
        ),
        Claim::about(
            "amule-kno-calls-back-through-the-rows-ipv4-buddy-trio",
            called_back,
            Evidence::Captured,
            format!(
                "kno's first 0x52 to the row's TAG_SERVERIP:TAG_SERVERPORT ({} bytes) names \
                 buddy and file {:02X?}; the re-served row's buddy contact was {row_buddy:?}. \
                 The row reached KademliaSearchFile as a type-3 source built from the IPv4 \
                 trio (Search.cpp:1231-1242, DownloadQueue.cpp:1761-1779), its bi6 beside it.",
                frames.callback.map_or(0, <[u8]>::len),
                called,
            ),
        ),
        Claim::about(
            "amule-kno-sends-nothing-to-the-bi6-address",
            frames.callback.is_some() && frames.to_bi6 == 0,
            Evidence::DocumentedAbsence,
            format!(
                "kno sent {} packet(s) to {buddy} over the run, with its callback on the wire. \
                 Search.cpp:1205-1224 validates bi6 and drops it — never passed to \
                 KademliaSearchFile; the line it logs is compiled out of this Release image \
                 (Logger.h:457-465), so the zero is the observable. Held only beside a \
                 callback, so a kno that never read the row cannot pass it.",
                frames.to_bi6
            ),
        ),
    ]
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use rmule_kad::{KadBuddyContact, KadId, KadSourceRow, encode_source_result};
    use rmule_primitives::Ipv4Endpoint;

    use super::{KnoSearchFrames, claims};
    use crate::flow::nat::dialect::kad_tags::search_rows;

    const BUDDY: Ipv6Addr = Ipv6Addr::new(0x3fff, 0x0ed2, 1, 0, 0, 0, 0, 8);
    const KEY: [u8; 16] = [0x11; 16];
    const BI6: &[u8; 32] = b"3FFF0ED2000100000000000000000008";

    /// rmule's storer's answer to kno, from rmule's encoder: the firewalled
    /// row with its `bi6` through the store.
    fn answer() -> Vec<u8> {
        let row = KadSourceRow {
            source_id: [0x46; 16],
            source_type: 3,
            ip: Ipv4Addr::new(45, 55, 200, 7),
            tcp_port: 4662,
            udp_port: 4672,
            encryption: None,
            buddy: Some(KadBuddyContact {
                buddy_id: KadId::from_bytes([0xEF; 16]),
                buddy_udp: Some(Ipv4Endpoint::new(Ipv4Addr::new(45, 55, 200, 8), 4672)),
                buddy_ipv6: Some(BUDDY),
                buddy_udp_ipv6: None,
            }),
            ipv6: None,
        };
        encode_source_result(
            KadId::from_bytes([0x22; 16]),
            KadId::from_bytes(KEY),
            &[row],
        )[0]
        .encode()
    }

    fn callback(buddy_id: [u8; 16]) -> Vec<u8> {
        [&[0xE4, 0x52][..], &buddy_id, &KEY, &4662u16.to_le_bytes()].concat()
    }

    fn outcomes(callback: Option<&[u8]>, to_bi6: u64) -> Vec<&'static str> {
        let answer = answer();
        let search = [&[0xE4, 0x34][..], &KEY, &[0; 10]].concat();
        let frames = KnoSearchFrames {
            published_bi6: Some(BI6),
            search: Some(&search),
            answer: Some((&answer, search_rows(&answer).unwrap())),
            callback,
            to_bi6,
        };
        claims(&frames, KEY, BUDDY)
            .iter()
            .map(|claim| claim.outcome)
            .collect()
    }

    /// The callback claim holds only on the row's own buddy ID and file key,
    /// and the zero toward `bi6` means something only beside a callback: a
    /// kno that never acted on the row cannot pass for one that dropped the
    /// tag, and one packet to the address breaks it.
    #[test]
    fn the_kno_search_leg_needs_the_callback_to_name_the_rows_buddy() {
        let good = callback([0xEF; 16]);
        let stranger = callback([0xAB; 16]);
        assert_eq!(outcomes(Some(&good), 0), ["held", "held", "held", "held"]);
        assert_eq!(
            outcomes(Some(&stranger), 0),
            ["held", "held", "absent", "held"]
        );
        assert_eq!(outcomes(None, 0)[2..], ["absent", "absent"]);
        assert_eq!(outcomes(Some(&good), 1)[3], "absent");
    }
}
