//! How fast and in what batches a connection may publish (ADR-0099).
//!
//! aMule sends at most 200 files per `OP_OFFERFILES`, a batch a minute
//! (`SharedFileList.cpp:707-710`, `ED2KREPUBLISHTIME`). OFFERFILES v1 lets a
//! server say otherwise: a client asks with a login tag, and the server answers
//! in the connection's first `OP_SERVERIDENT` and holds it to the answer
//! (ed2k-server README, *OFFERFILES v1*). The advertisement is all or nothing,
//! and a snapshot for the life of the connection.

use std::time::Duration;

use rmule_primitives::{Tag, TagName, TagValue};

use crate::server_met::figures::{ST_HARDFILES, ST_SOFTFILES};

/// The capability version rmule implements.
const OFFERFILES_VERSION: u32 = 1;
const TAG_VERSION: &str = "offerfiles_v";
const TAG_BATCH_MAX: &str = "offerfiles_batch_max";
const TAG_MIN_INTERVAL_MS: &str = "offerfiles_min_interval_ms";

/// aMule's most records in one packet.
const LEGACY_BATCH: u32 = 200;
/// aMule's least time between two packets (`ED2KREPUBLISHTIME`).
const LEGACY_INTERVAL: Duration = Duration::from_secs(60);
/// The most records rmule puts in one packet, whatever a server allows.
const LOCAL_BATCH_CAP: u32 = 1_000;

/// The login tag that asks for OFFERFILES v1. Text-named, which the old tag
/// format every login tag rides spells, and which a server that does not know
/// it skips.
pub(crate) fn offer_pace_request_tag() -> Tag {
    Tag::new(
        TagName::text(TAG_VERSION).expect("a constant tag name fits"),
        TagValue::U32(OFFERFILES_VERSION),
    )
}

/// Whether `tag` is [`offer_pace_request_tag`]'s, which only the login writes.
pub(crate) fn is_offer_pace_request(tag: &Tag) -> bool {
    tag.name().text_value() == Some(TAG_VERSION)
}

/// A server's file limits as far as they are known. 0 reads as unknown, as
/// aMule reads a soft limit of 0.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServerFileLimits {
    /// `ST_SOFTFILES`.
    pub soft: Option<u32>,
    /// `ST_HARDFILES`: every packet must declare fewer records.
    pub hard: Option<u32>,
}

/// What one connection may publish, settled once for its life.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OfferPace {
    /// aMule's rule, under the limits known of the server.
    Legacy(ServerFileLimits),
    /// What the server advertised, and will hold this connection to.
    Negotiated(OfferAdvert),
}

/// A complete, valid OFFERFILES v1 advertisement.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OfferAdvert {
    soft: u32,
    hard: u32,
    batch_max: u32,
    min_interval_ms: u32,
}

impl OfferPace {
    /// The pace a connection's first `OP_SERVERIDENT` settles: an advert in
    /// `tags`, or else legacy under the limits `tags` state and, where they
    /// state none, the ones already `known`.
    #[must_use]
    pub fn from_ident(tags: &[Tag], known: ServerFileLimits) -> Self {
        OfferAdvert::read(tags).map_or_else(
            || {
                Self::Legacy(ServerFileLimits {
                    soft: stated_limit(tags, ST_SOFTFILES).or(known.soft),
                    hard: stated_limit(tags, ST_HARDFILES).or(known.hard),
                })
            },
            Self::Negotiated,
        )
    }

    /// The most records one batch may hold.
    #[must_use]
    pub fn batch(self) -> u32 {
        let (first, hard) = match self {
            Self::Legacy(limits) => (
                limits.soft.map_or(LEGACY_BATCH, |s| s.min(LEGACY_BATCH)),
                limits.hard,
            ),
            Self::Negotiated(advert) => (advert.batch_max.min(LOCAL_BATCH_CAP), Some(advert.hard)),
        };
        hard.map_or(first, |hard| first.min(hard.saturating_sub(1)))
            .max(1)
    }

    /// How many more new files the connection may publish, having published
    /// `told`: a budget only a negotiated connection is held to. A legacy one
    /// runs to the end of its share, as aMule's does.
    #[must_use]
    pub fn new_files_left(self, told: usize) -> Option<usize> {
        match self {
            Self::Legacy(_) => None,
            Self::Negotiated(advert) => Some(
                usize::try_from(advert.soft)
                    .unwrap_or(usize::MAX)
                    .saturating_sub(told),
            ),
        }
    }

    /// How long a batch of `records` holds up the next one: a bucket in
    /// records that refills one [`batch`](Self::batch) per interval, as the
    /// server keeps its own, so a small batch costs a small part of it.
    #[must_use]
    pub fn gap_after(self, records: usize) -> Duration {
        let (per, interval) = match self {
            Self::Legacy(_) => (self.batch(), LEGACY_INTERVAL),
            Self::Negotiated(advert) => (
                advert.batch_max,
                Duration::from_millis(u64::from(advert.min_interval_ms)),
            ),
        };
        interval.saturating_mul(u32::try_from(records).unwrap_or(u32::MAX)) / per.max(1)
    }
}

impl OfferAdvert {
    /// The advertisement in `tags`, if a whole and valid one is there. Anything
    /// else is no advertisement, and the connection is legacy on both sides.
    fn read(tags: &[Tag]) -> Option<Self> {
        let once = |is_it: &dyn Fn(&TagName) -> bool| -> Option<u32> {
            let mut found = tags.iter().filter(|tag| is_it(tag.name()));
            let tag = found.next()?;
            match (tag.value(), found.next()) {
                (TagValue::U32(value), None) => Some(*value),
                _ => None,
            }
        };
        let by_name = |name: &'static str| move |tag: &TagName| tag.text_value() == Some(name);
        let by_id = |id: u8| move |tag: &TagName| tag.id() == Some(id);
        let advert = Self {
            soft: once(&by_id(ST_SOFTFILES))?,
            hard: once(&by_id(ST_HARDFILES))?,
            batch_max: once(&by_name(TAG_BATCH_MAX))?,
            min_interval_ms: once(&by_name(TAG_MIN_INTERVAL_MS))?,
        };
        let valid = once(&by_name(TAG_VERSION))? == OFFERFILES_VERSION
            && advert.soft > 0
            && advert.batch_max > 0
            && advert.min_interval_ms > 0
            && advert.hard > advert.batch_max;
        valid.then_some(advert)
    }
}

/// A limit a tag states, at any integer width; 0 states nothing.
fn stated_limit(tags: &[Tag], id: u8) -> Option<u32> {
    let tag = tags.iter().find(|tag| tag.name().id() == Some(id))?;
    match *tag.value() {
        TagValue::U8(value) => Some(u32::from(value)),
        TagValue::U16(value) => Some(u32::from(value)),
        TagValue::U32(value) => Some(value),
        _ => None,
    }
    .filter(|limit| *limit > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id_tag(id: u8, value: u32) -> Tag {
        Tag::new(TagName::compact_id(id), TagValue::U32(value))
    }

    fn name_tag(name: &str, value: TagValue) -> Tag {
        Tag::new(TagName::text(name).unwrap(), value)
    }

    fn advert(soft: u32, hard: u32, batch_max: u32, interval_ms: u32) -> Vec<Tag> {
        vec![
            id_tag(ST_SOFTFILES, soft),
            id_tag(ST_HARDFILES, hard),
            name_tag(TAG_VERSION, TagValue::U32(1)),
            name_tag(TAG_BATCH_MAX, TagValue::U32(batch_max)),
            name_tag(TAG_MIN_INTERVAL_MS, TagValue::U32(interval_ms)),
        ]
    }

    fn pace(tags: &[Tag]) -> OfferPace {
        OfferPace::from_ident(tags, ServerFileLimits::default())
    }

    /// "A client must treat a missing, partial, duplicated or wrongly typed
    /// advertisement as absent", and the server's four validity rules.
    #[test]
    fn an_advert_that_is_not_whole_and_valid_is_no_advert() {
        let whole = advert(5_000, 7_500, 200, 500);
        assert!(matches!(pace(&whole), OfferPace::Negotiated(_)));

        for missing in 0..whole.len() {
            let mut tags = whole.clone();
            tags.remove(missing);
            assert!(matches!(pace(&tags), OfferPace::Legacy(_)), "{missing}");
        }
        for duplicated in 0..whole.len() {
            let mut tags = whole.clone();
            tags.push(whole[duplicated].clone());
            assert!(matches!(pace(&tags), OfferPace::Legacy(_)), "{duplicated}");
        }
        let mut wrong_type = whole.clone();
        wrong_type[3] = name_tag(TAG_BATCH_MAX, TagValue::U16(200));
        let mut wrong_version = whole.clone();
        wrong_version[2] = name_tag(TAG_VERSION, TagValue::U32(2));
        for tags in [
            wrong_type,
            wrong_version,
            advert(0, 7_500, 200, 500),
            advert(5_000, 7_500, 0, 500),
            advert(5_000, 7_500, 200, 0),
            advert(5_000, 200, 200, 500),
        ] {
            assert!(matches!(pace(&tags), OfferPace::Legacy(_)), "{tags:?}");
        }
    }

    /// The smallest of what the server allows and rmule's own cap, kept under
    /// `ST_HARDFILES` for a legacy server too, whose limit is otherwise the
    /// close of the session.
    #[test]
    fn a_batch_is_the_smallest_of_the_limits() {
        assert_eq!(pace(&advert(5_000, 7_500, 300, 500)).batch(), 300);
        assert_eq!(pace(&advert(5_000, 9_000, 8_000, 500)).batch(), 1_000);
        let legacy = |soft, hard| OfferPace::Legacy(ServerFileLimits { soft, hard }).batch();
        assert_eq!(legacy(None, None), 200);
        assert_eq!(legacy(Some(5_000), Some(7_500)), 200);
        assert_eq!(legacy(Some(120), None), 120);
        assert_eq!(legacy(None, Some(50)), 49);
    }

    /// A limit the ident states beats one known from a status answer, and an
    /// ident that states none leaves it.
    #[test]
    fn an_ident_states_the_limits_of_a_legacy_connection() {
        let known = ServerFileLimits {
            soft: Some(4_000),
            hard: Some(5_000),
        };
        let tags = [id_tag(ST_SOFTFILES, 100), id_tag(ST_HARDFILES, 0)];
        assert_eq!(
            OfferPace::from_ident(&tags, known),
            OfferPace::Legacy(ServerFileLimits {
                soft: Some(100),
                hard: Some(5_000),
            })
        );
    }

    /// A partial batch costs its share of the interval, on either pace.
    #[test]
    fn a_small_batch_holds_the_next_for_its_share_of_the_interval() {
        let negotiated = pace(&advert(5_000, 7_500, 200, 500));
        assert_eq!(negotiated.gap_after(200), Duration::from_millis(500));
        assert_eq!(negotiated.gap_after(20), Duration::from_millis(50));
        let legacy = OfferPace::Legacy(ServerFileLimits::default());
        assert_eq!(legacy.gap_after(200), Duration::from_secs(60));
        assert_eq!(legacy.gap_after(2), Duration::from_millis(600));
    }

    #[test]
    fn only_a_negotiated_connection_has_a_budget() {
        let negotiated = pace(&advert(3, 100, 2, 100));
        assert_eq!(negotiated.new_files_left(1), Some(2));
        assert_eq!(negotiated.new_files_left(9), Some(0));
        assert_eq!(pace(&[]).new_files_left(9), None);
    }
}
