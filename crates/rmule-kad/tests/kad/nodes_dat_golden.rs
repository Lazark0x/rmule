//! Cross-validate the v2 `nodes.dat` normal reader against an **aMule-authored**
//! golden (flow H leg 3).
//!
//! These bytes were written by a real aMule 2.3.3's `CRoutingZone::WriteFile` on
//! the interop Docker bench — the ADR-0065/ADR-0066 shared-asset "v2 nodes.dat"
//! (32-byte-plus-extension rows: `id ip udp tcp version UDPKey verified`). An
//! eD2k-only aMule can never produce one (no Kad → `WriteFile` never fires), so
//! this is the only path to a real v2 capture. The test decodes the golden and
//! asserts it yields the exact contact count aMule logged and that every contact
//! is a queryable, verified Kad2 contact — proving rmule's normal reader parses
//! aMule's real writer output (the 8-byte UDP key + verified byte extension, the
//! version filter, the streaming row bounds) rather than a crate-built vector.
//!
//! No-op if no golden is present, so the deterministic tier still passes on a
//! checkout that has not landed a capture.

use std::fs;
use std::path::{Path, PathBuf};

use rmule_kad::NodesDat;

#[test]
fn amule_authored_v2_nodes_dat_goldens_decode_to_their_recorded_contacts() {
    let goldens = golden_dirs();
    if goldens.is_empty() {
        eprintln!(
            "note: no aMule-authored nodes.dat goldens under \
             crates/rmule-kad/tests/fixtures/nodes_dat/captured/*/; \
             harvest one with tools/interop-harness v2-nodes-dat-harvest — \
             this test is a no-op until one lands"
        );
        return;
    }

    for dir in goldens {
        let meta_raw = fs::read_to_string(dir.join("metadata.toml"))
            .unwrap_or_else(|e| panic!("read {}/metadata.toml: {e}", dir.display()));
        let meta: toml::Value = toml::from_str(&meta_raw)
            .unwrap_or_else(|e| panic!("{}/metadata.toml: {e}", dir.display()));
        let str_field = |key: &str| {
            meta.get(key)
                .and_then(toml::Value::as_str)
                .unwrap_or_default()
        };
        assert!(
            !str_field("provenance").is_empty() && !str_field("reason").is_empty(),
            "{}: a captured golden must carry its provenance",
            dir.display()
        );
        let expected_contacts = meta
            .get("contact_count")
            .and_then(toml::Value::as_integer)
            .unwrap_or_else(|| panic!("{}: metadata needs contact_count", dir.display()))
            as usize;
        // aMule refuses to write nodes.dat below 25 contacts, so a real v2 golden
        // MUST carry at least that many — anything less means the harvest didn't
        // clear CRoutingZone::WriteFile's own gate and is not a genuine capture.
        assert!(
            expected_contacts >= 25,
            "{}: a real WriteFile golden has >= 25 contacts (recorded {expected_contacts})",
            dir.display()
        );

        let bytes = fs::read(dir.join("nodes.dat.bin"))
            .unwrap_or_else(|e| panic!("read {}/nodes.dat.bin: {e}", dir.display()));
        // aMule's v2 header: [u32 0][u32 2] — the old-client guard then version 2.
        assert_eq!(
            &bytes[0..8],
            &[0, 0, 0, 0, 2, 0, 0, 0],
            "{}: golden must start with aMule's v2 header (0-marker + version 2)",
            dir.display()
        );

        let nodes = NodesDat::decode(&bytes).unwrap_or_else(|e| {
            panic!(
                "{}: rmule failed to decode aMule's WriteFile output: {e:?}",
                dir.display()
            )
        });
        let contacts = nodes.contacts();
        assert_eq!(
            contacts.len(),
            expected_contacts,
            "{}: aMule's v2 rows must decode to exactly the contact count it wrote \
             (a mis-sized 34-byte row would drop or duplicate contacts)",
            dir.display()
        );
        for contact in contacts {
            // Every row aMule wrote is a Kad2 contact (version > 1 — Kad1 rows are
            // skipped on read) that entered the v1-seeded table verified (aMule's
            // all-verified heuristic), with a dialable UDP endpoint.
            assert!(
                contact.version() > 1,
                "{}: v2 nodes.dat carries only Kad2 contacts, got version {}",
                dir.display(),
                contact.version()
            );
            assert!(
                contact.verified(),
                "{}: a v1-seeded table's contacts persist verified through WriteFile",
                dir.display()
            );
            assert_ne!(
                contact.endpoint().udp_port(),
                0,
                "{}: decoded contact has a zero UDP port — row mis-decoded",
                dir.display()
            );
        }

        // The writer proof: re-encoding the contacts aMule wrote
        // must reproduce aMule's own bytes verbatim. A bootstrap-loaded table's
        // rows carry a zero UDP key and a set verified bit — exactly what
        // `encode_v2` emits — so a genuine WriteFile golden round-trips
        // byte-for-byte. This is the strong-direction proof: rmule's writer is
        // the exact inverse of a real aMule writer's output.
        let reencoded = NodesDat::encode_v2(contacts);
        assert_eq!(
            reencoded,
            bytes,
            "{}: encode_v2 of the decoded contacts must reproduce aMule's WriteFile bytes",
            dir.display()
        );
    }
}

fn golden_dirs() -> Vec<PathBuf> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/nodes_dat/captured");
    let mut out = Vec::new();
    let Ok(dirs) = fs::read_dir(&root) else {
        return out;
    };
    for dir in dirs.flatten() {
        if dir.path().is_dir() && dir.path().join("nodes.dat.bin").is_file() {
            out.push(dir.path());
        }
    }
    out.sort();
    out
}
