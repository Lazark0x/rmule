//! Client Software read off hellos: the captured ones decode to what their
//! counterparty is, and derived hellos stand in for the families no archive
//! holds (MLDonkey, Shareaza, eDonkey, eDonkey Hybrid, an unknown code).

use crate::fixture::{client_version as version, hello_body};

use rmule_peer::{
    ClientFamily, ClientMod, ClientSoftware, Hello, HelloAnswer, PeerHelloBody, PeerIdentity,
};
use rmule_primitives::{Ed2kText, Packet, Tag, TagName, TagValue, UserHash};

/// Stock aMule 2.3.3 dialing rmule (flow N, 2026-07-28).
const AMULE_233_HELLO: &[u8] = include_bytes!(
    "../fixtures/direct_callback/captured/amule-233-directcallback-20260728/\
     callback_dial_hello_0x01.bin"
);

/// emule-qt `73fff714` answering an IPv6 dial (run `1789992543`).
const EMULEQT_ANSWER: &[u8] =
    include_bytes!("../fixtures/ipv6_dialect/emuleqt_op_helloanswer_ipv6.bin");

/// kno's aMule `ab483654` answering over IPv4 (run `1790202940`).
const AMULE_KNO_ANSWER: &[u8] = include_bytes!(
    "../fixtures/client_software/captured/amule-kno-ab483654-helloanswer-20260923/\
     amule_kno_op_helloanswer.bin"
);

fn software_of(frame: &[u8]) -> ClientSoftware {
    let packet = Packet::decode_exact(frame).expect("a whole captured frame");
    let body = match packet.opcode() {
        0x01 => Hello::decode_packet(&packet).expect("hello").into_body(),
        _ => HelloAnswer::decode_packet(&packet)
            .expect("hello answer")
            .into_body(),
    };
    PeerIdentity::from_hello_body(&body).software().clone()
}

fn named_mod(text: &str) -> Option<ClientMod> {
    Some(ClientMod::Named(Ed2kText::from_utf8(text)))
}

#[test]
fn captured_stock_amule_233_is_amule_2_3_3_without_a_mod() {
    let software = software_of(AMULE_233_HELLO);
    assert_eq!(software.family(), ClientFamily::Amule);
    assert_eq!(software.version(), version(2, 3, 3));
    assert_eq!(software.client_mod(), None);
}

#[test]
fn captured_emule_qt_is_emule_0_70b_with_its_mod_name() {
    let software = software_of(EMULEQT_ANSWER);
    assert_eq!(software.family(), ClientFamily::Emule);
    assert_eq!(software.version(), version(0, 70, 1));
    assert_eq!(software.client_mod(), named_mod("eMule Qt 0.4.2").as_ref());
}

#[test]
fn captured_kno_amule_is_amule_3_0_1_with_its_mod_name() {
    let software = software_of(AMULE_KNO_ANSWER);
    assert_eq!(software.family(), ClientFamily::Amule);
    assert_eq!(software.version(), version(3, 0, 1));
    assert_eq!(software.client_mod(), named_mod("aMule GIT").as_ref());
}

// Derived vectors below: hellos built from the two references' rules, for
// families no archive holds. They pin rmule's reading of those rules, not any
// counterparty's bytes.

/// A hash carrying eMule's mark (`[5] = 14`, `[14] = 111`), or another mark.
fn hash_with(mark5: u8, mark14: u8) -> UserHash {
    let mut bytes = [0x42; UserHash::BYTE_LEN];
    bytes[5] = mark5;
    bytes[14] = mark14;
    UserHash::from_bytes(bytes)
}

fn id_tag(id: u8, value: TagValue) -> Tag {
    Tag::new(TagName::compact_id(id), value)
}

fn name(text: &str) -> Tag {
    id_tag(0x01, TagValue::String(Ed2kText::from_utf8(text)))
}

fn emule_version(code: u8, major: u32, minor: u32, update: u32) -> Tag {
    let word = (u32::from(code) << 24) | (major << 17) | (minor << 10) | (update << 7);
    id_tag(0xFB, TagValue::U32(word))
}

fn identify(user_hash: UserHash, tags: Vec<Tag>) -> ClientSoftware {
    ClientSoftware::from_hello_body(&hello_body(user_hash, 0x0100_000A, tags))
}

#[test]
fn derived_compatible_codes_name_their_families() {
    let emule = hash_with(14, 111);
    for (code, family) in [
        (1, ClientFamily::Cdonkey),
        (4, ClientFamily::Shareaza),
        (0x28, ClientFamily::Shareaza),
        (0x0A, ClientFamily::MlDonkey),
        (0x14, ClientFamily::Lphant),
    ] {
        let software = identify(emule, vec![name("peer"), emule_version(code, 2, 1, 0)]);
        assert_eq!(software.family(), family, "code {code:#x}");
        assert_eq!(software.version(), version(2, 1, 0));
    }
}

#[test]
fn derived_unnamed_code_stays_raw() {
    let software = identify(
        hash_with(14, 111),
        vec![name("peer"), emule_version(0xF0, 0, 49, 2)],
    );
    assert_eq!(software.family(), ClientFamily::Compatible(0xF0));
    assert_eq!(software.version(), version(0, 49, 2));
}

#[test]
fn derived_mule_tag_behind_an_unmarked_hash_is_still_a_mule() {
    // eMule's rule (`m_bEmuleProtocol`); aMule would read this as eDonkey.
    let software = identify(
        hash_with(0, 0),
        vec![name("peer"), emule_version(3, 2, 3, 3)],
    );
    assert_eq!(software.family(), ClientFamily::Amule);
}

#[test]
fn derived_emule_mod_naming_xmule_is_xmule() {
    let tags = vec![
        name("peer"),
        emule_version(0, 0, 50, 0),
        id_tag(0x55, TagValue::String(Ed2kText::from_utf8("xMule 1.9"))),
    ];
    assert_eq!(
        identify(hash_with(14, 111), tags).family(),
        ClientFamily::Xmule
    );
}

#[test]
fn derived_pre_mule_hellos_fall_to_the_hash_and_tag_heuristics() {
    let legacy = |v| id_tag(0x11, TagValue::U32(v));
    let mldonkey = identify(hash_with(b'M', b'L'), vec![name("peer"), legacy(61)]);
    assert_eq!(mldonkey.family(), ClientFamily::MlDonkeyOld);
    assert_eq!(mldonkey.version(), version(0, 61, 0));

    let old = identify(hash_with(13, 110), vec![name("peer"), legacy(30)]);
    assert_eq!(old.family(), ClientFamily::EmuleOld);

    let pr = Tag::new(TagName::text("pr").expect("a text name"), TagValue::U32(1));
    let hybrid = identify(hash_with(0, 0), vec![name("peer"), legacy(10_300), pr]);
    assert_eq!(hybrid.family(), ClientFamily::EdonkeyHybrid);
    assert_eq!(hybrid.version(), version(1, 3, 0));

    let edonkey = identify(hash_with(0, 0), vec![name("peer"), legacy(60)]);
    assert_eq!(edonkey.family(), ClientFamily::Edonkey);
    assert_eq!(edonkey.version(), version(0, 60, 0));
}

#[test]
fn derived_nameless_hello_is_unknown() {
    let software = identify(hash_with(14, 111), vec![emule_version(3, 2, 3, 3)]);
    assert_eq!(software.family(), ClientFamily::Unknown);
    assert_eq!(software.version(), None);
}

#[test]
fn software_sorts_by_family_rank_then_version_not_by_label() {
    let emule = hash_with(14, 111);
    let amule_old = identify(emule, vec![name("a"), emule_version(3, 2, 2, 0)]);
    let amule_new = identify(emule, vec![name("a"), emule_version(3, 2, 3, 3)]);
    let emule_new = identify(emule, vec![name("e"), emule_version(0, 0, 70, 1)]);
    let unknown_code = identify(emule, vec![name("c"), emule_version(0xF0, 9, 0, 0)]);
    let mut all = vec![
        unknown_code.clone(),
        amule_new.clone(),
        emule_new.clone(),
        amule_old.clone(),
    ];
    all.sort();
    assert_eq!(all, vec![emule_new, amule_old, amule_new, unknown_code]);
}

// One rmule recognising another (ADR-0047): rmule's hello keeps
// aMule 2.3.3's word and names itself in `CT_MOD_VERSION`.

fn mod_tag(text: &str) -> Tag {
    Tag::new(
        TagName::length_prefixed_id(0x55),
        TagValue::String(Ed2kText::from_utf8(text)),
    )
}

#[test]
fn rmules_own_hello_names_rmule_at_its_own_version() {
    let ours = PeerHelloBody::from_handshake_context(
        &rmule_testkit::peer_session::serverless_ctx(),
        &rmule_peer::HelloAdvert::default(),
    );
    let software = ClientSoftware::from_hello_body(&ours);
    assert_eq!(software.family(), ClientFamily::Rmule);
    let [major, minor, update] = [
        env!("CARGO_PKG_VERSION_MAJOR"),
        env!("CARGO_PKG_VERSION_MINOR"),
        env!("CARGO_PKG_VERSION_PATCH"),
    ]
    .map(|n| n.parse().expect("a number"));
    assert_eq!(software.version(), version(major, minor, update));
    // What every other reader keys on is unchanged: aMule's compatible code and
    // version word, the mod name last, as aMule's own builds place it.
    let word = ours
        .tags
        .iter()
        .find_map(|t| match (t.name().id(), t.value()) {
            (Some(0xFB), TagValue::U32(word)) => Some(*word),
            _ => None,
        });
    assert_eq!(word, Some(0x0304_0D80));
    assert_eq!(
        ours.tags.last().map(Tag::encode),
        Some(mod_tag(concat!("rmule ", env!("CARGO_PKG_VERSION"))).encode())
    );
}

#[test]
fn derived_rmule_mod_behind_another_code_is_only_a_mod() {
    let emule = hash_with(14, 111);
    let software = identify(
        emule,
        vec![
            name("peer"),
            emule_version(0, 0, 70, 1),
            mod_tag("rmule 1.2.3"),
        ],
    );
    assert_eq!(software.family(), ClientFamily::Emule);
    assert_eq!(software.client_mod(), named_mod("rmule 1.2.3").as_ref());
}

#[test]
fn derived_rmule_mod_without_a_version_is_rmule_without_one() {
    let emule = hash_with(14, 111);
    let software = identify(
        emule,
        vec![
            name("peer"),
            emule_version(3, 2, 3, 3),
            mod_tag("rmule dev"),
        ],
    );
    assert_eq!(
        (software.family(), software.version()),
        (ClientFamily::Rmule, None)
    );
}

// The OP_HELLO each bench client sends when it dials rmule (run `1790611695`,
// `peer-hello-surface`): read strictly, named as its answer names it, nothing
// after the connected server, and re-encoded to the client's own bytes.

const DIALED_DIR: &str = "fixtures/client_software/captured/hello-surface-op-hello-20260928";

#[test]
fn captured_dialing_hellos_name_each_client_and_reencode_byte_exact() {
    for (file, family, version, client_mod) in [
        (
            "op_hello_amule_233.bin",
            ClientFamily::Amule,
            version(2, 3, 3),
            None,
        ),
        (
            "op_hello_amule_kno.bin",
            ClientFamily::Amule,
            version(3, 0, 1),
            named_mod("aMule GIT"),
        ),
        (
            "op_hello_emuleqt.bin",
            ClientFamily::Emule,
            version(0, 70, 1),
            named_mod("eMule Qt 0.4.2"),
        ),
    ] {
        let frame = crate::fixture::load(DIALED_DIR, file);
        let packet = Packet::decode_exact(&frame).expect("a whole captured frame");
        let hello = Hello::decode_packet(&packet).unwrap_or_else(|e| panic!("{file}: {e}"));
        assert_eq!(hello.trailer(), rmule_peer::HelloTrailer::Absent, "{file}");
        assert_eq!(
            hello.encode_packet().encode(),
            frame,
            "{file}: byte-faithful"
        );
        let software = software_of(&frame);
        assert_eq!(
            (software.family(), software.version(), software.client_mod()),
            (family, version, client_mod.as_ref()),
            "{file}"
        );
    }
}
