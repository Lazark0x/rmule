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
