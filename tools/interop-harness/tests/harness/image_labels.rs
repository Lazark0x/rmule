//! Every harness image's final stage carries `org.rmule.bench=1`, read off the
//! shipped Dockerfiles: the bench-image cleanup selects on that label and
//! nothing else, so an unlabeled final stage leaves its tagged images to pile
//! up forever.

use std::fs;
use std::path::Path;

/// Base images that are themselves harness images and hand the label down.
const LABELED_BASES: [&str; 1] = ["rmule/interop-amule:local"];

#[test]
fn every_final_stage_carries_the_bench_label() {
    let images = Path::new(env!("CARGO_MANIFEST_DIR")).join("images");
    let mut checked = 0;
    for entry in fs::read_dir(&images).expect("list images/") {
        let dockerfile = entry.expect("read images/ entry").path().join("Dockerfile");
        let Ok(text) = fs::read_to_string(&dockerfile) else {
            continue;
        };
        let lines: Vec<&str> = text.lines().map(str::trim).collect();
        let last_from = lines
            .iter()
            .rposition(|line| line.starts_with("FROM "))
            .unwrap_or_else(|| panic!("{} has no FROM", dockerfile.display()));
        let inherited = LABELED_BASES
            .iter()
            .any(|base| lines[last_from].contains(base));
        let labeled = lines[last_from..]
            .iter()
            .any(|line| line.starts_with("LABEL org.rmule.bench=1"));
        assert!(
            inherited || labeled,
            "{}: the final stage carries no `org.rmule.bench=1`",
            dockerfile.display()
        );
        checked += 1;
    }
    assert!(
        checked >= 10,
        "only {checked} Dockerfiles found under images/"
    );
}
