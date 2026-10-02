//! **Source-derived, not captured**: the `TAG_BUDDYHASH` an eMule 0.70b or
//! eMuleAI publisher would write, read by rmule's row reader.
//!
//! Neither client is on the bench, so no frame here was ever sent by one. The
//! eMule spelling is the reading of eMuleAI's writer:
//! `md4str(uServingBuddyID.GetData())` (`srchybrid/kademlia/kademlia/Search.cpp:888`),
//! where `GetData()` returns the raw `m_uData[4]` words
//! (`srchybrid/kademlia/utils/UInt128.h:66`) and aMule's captured form comes
//! from `ToByteArray`, which byte-swaps each of those words
//! (`UInt128.h:214-220`). On a little-endian host the eMule string is
//! therefore the ID's Kad wire order, one per-word swap from aMule's.
//!
//! The frame is the captured aMule `0x44` with only its 32 hash characters
//! respelled that way, for the same pinned buddy ID the capture used — so the
//! one thing this leg asserts beyond the capture is what the source says.

use rmule_kad::{Kad2Message, KadId};
use rmule_primitives::kad_wire_id;

use super::buddy_publish_capture::{RMULE_KAD_ID, frame};

/// The captured frame with its `TAG_BUDDYHASH` value respelled in the
/// eMule `GetData()` order: the buddy ID's wire bytes, hex, upper case.
fn source_derived_emule_frame() -> Vec<u8> {
    let mut f = frame();
    let tag = f
        .windows(4)
        .position(|w| w == [0x02, 0x01, 0x00, 0xF8])
        .expect("the captured row carries TAG_BUDDYHASH");
    let emule: String = RMULE_KAD_ID.iter().map(|b| format!("{b:02X}")).collect();
    f[tag + 6..tag + 38].copy_from_slice(emule.as_bytes());
    assert_ne!(f, frame(), "the respelling changed the hash characters");
    f
}

/// Source-derived: an eMule-family row's primary reading is the wrong ID
/// (aMule's big-endian decode of a word-ordered string), and its fallback is
/// the true one — the buddy ID the publisher actually holds.
#[test]
fn source_derived_emule_spelling_reads_the_true_buddy_id_as_the_fallback() {
    let rmule_kad::KadDecoded::Plain(envelope) =
        rmule_kad::decode_exact(&source_derived_emule_frame()).expect("well-formed")
    else {
        panic!("a plain publish");
    };
    let Kad2Message::PublishSourceReq { source, .. } =
        Kad2Message::decode(&envelope).expect("rmule's codec reads the respelled row")
    else {
        panic!("0x44 decodes to a publish");
    };
    let buddy = source.buddy.expect("a type-3 row names a buddy");
    assert_eq!(
        buddy.buddy_id,
        KadId::from_bytes(kad_wire_id(RMULE_KAD_ID)),
        "the aMule-spelling primary misreads an eMule row by one word swap",
    );
    assert_eq!(
        buddy.fallback_buddy_id(),
        Some(KadId::from_bytes(RMULE_KAD_ID)),
        "the fallback is the buddy ID the eMule publisher meant",
    );
}
