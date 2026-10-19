//! The link the flow hands rmule when it names the seeds as sources.

use rmule_primitives::Ed2kLink;

use super::verdict::SeedRow;
use super::with_sources;

/// The sources ride aMule's `|/|sources,ip:port,…|/` tail, which rmule's own
/// link reader takes, and the file fields stay as they were.
#[test]
fn the_seeds_ride_the_link_as_sources_rmule_reads() {
    let link = "ed2k://|file|stream.mkv|116736000|266E88A5A30B60E640839EFC74622B52|/";
    let seed = |ip: &str| SeedRow {
        role: "a".to_owned(),
        ip: ip.parse().unwrap(),
        holding: "complete".to_owned(),
        container: String::new(),
        max_upload_kib: 0,
    };
    let sourced = with_sources(link, &[seed("172.18.0.3"), seed("172.18.0.4")]);
    let Ed2kLink::File(file) = Ed2kLink::parse(&sourced).unwrap() else {
        panic!("not a file link: {sourced}");
    };
    assert_eq!(file.size, 116_736_000);
    assert_eq!(file.sources.peers().len(), 2);
}

/// A link stripped of its part hashes reads with no hash set and keeps its
/// file fields, so the download has to ask a seed for the set. The link is
/// a run's own, whose `p=` set is the file hash's.
#[test]
fn a_link_without_part_hashes_carries_no_hash_set() {
    let link = "ed2k://|file|stream.mkv|116736000|CE97D534DF548A599E6047787C014FD6|\
                p=C69E1A2BB6BB8B462B339A78FD3C93BC:133EDCE960E4880A1FB638831E5D9A4F:\
                28ECB379D9CD4A0062B9253B5ED9215A:7335F9880A06CF41B466470F7BC3F300:\
                C4224B985A3EA066B034F4AE4DDFC10C:4D02BC1BBEB5A6FD9EADFA0AA8E8F9B1:\
                62D28EC9C587D97AED9518CAC827FBE2:713B687B922925F844628B408B4635A3:\
                D50384133878EAE7FC47D64E19718E30:A4C714E5AE622DBC82E633FFB1EFC0BB:\
                950A54E3CBE4059235A1E0B93ADC9E72:7026D1AE206CCE53246867F5C9976C7D:\
                31D6CFE0D16AE931B73C59D7E0C089C0|/";
    let Ed2kLink::File(whole) = Ed2kLink::parse(link).unwrap() else {
        panic!("not a file link: {link}");
    };
    assert!(whole.part_hash_set.is_some());
    let bare = super::without_part_hashes(link);
    let Ed2kLink::File(file) = Ed2kLink::parse(&bare).unwrap() else {
        panic!("not a file link: {bare}");
    };
    assert_eq!((file.size, file.file_hash), (whole.size, whole.file_hash));
    assert!(file.part_hash_set.is_none(), "{bare}");
}
