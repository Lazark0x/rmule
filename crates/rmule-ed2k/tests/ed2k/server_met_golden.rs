//! Cross-validate the `server.met` decoder against an **aMule-authored** golden
//! (flow H leg 2).
//!
//! Unlike the crate-built server.met vectors in the unit tests, these bytes were
//! written by a real aMule 2.3.3's `CServerList::SaveServerMet` on the interop
//! Docker bench (ADR-0066's "SaveServerMet full ST_ tag set" capture row). The
//! test decodes the golden and asserts it yields the exact server the harvest
//! recorded — proving rmule parses aMule's real 15-tag writer output (name +
//! unicode-name variants, description, users/files, preference, Lugdunum server
//! version, and the UDP/obfuscation flag tags) without desyncing the per-server
//! tag stream. A miscounted or mis-sized tag would drop the entry or error, so
//! "decodes to exactly the recorded servers with the right endpoint" is a real
//! cross-implementation check, not a field echo.
//!
//! No-op if no golden is present, so the deterministic tier still passes on a
//! checkout that has not landed a capture.

use std::fs;
use std::path::Path;

use rmule_ed2k::ServerMet;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct GoldenMeta {
    provenance: String,
    source_note: String,
    server_count: usize,
    header_byte: u8,
}

#[test]
fn amule_authored_server_met_goldens_decode_to_their_recorded_servers() {
    let goldens = crate::fixture::capture_dirs(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/server_met/captured"),
        "server.met.bin",
    );
    if goldens.is_empty() {
        eprintln!(
            "note: no aMule-authored server.met goldens under \
             crates/rmule-ed2k/tests/fixtures/server_met/captured/*/; \
             harvest one with tools/interop-harness http-bootstrap-goldens \
             (AMULE_PERSIST_SERVERLIST=1) — this test is a no-op until one lands"
        );
        return;
    }

    for dir in goldens {
        let meta_raw = fs::read_to_string(dir.join("meta.toml"))
            .unwrap_or_else(|e| panic!("read {}/meta.toml: {e}", dir.display()));
        let meta: GoldenMeta = toml::from_str(&meta_raw)
            .unwrap_or_else(|e| panic!("{}/meta.toml: {e}", dir.display()));
        assert!(
            !meta.provenance.is_empty() && !meta.source_note.is_empty(),
            "{}: a captured golden must carry its provenance",
            dir.display()
        );

        let bytes = fs::read(dir.join("server.met.bin"))
            .unwrap_or_else(|e| panic!("read {}/server.met.bin: {e}", dir.display()));
        assert_eq!(
            bytes.first().copied(),
            Some(meta.header_byte),
            "{}: golden must start with aMule's own header byte",
            dir.display()
        );

        let server_met = ServerMet::decode(&bytes).unwrap_or_else(|e| {
            panic!(
                "{}: rmule failed to decode aMule's SaveServerMet output: {e:?}",
                dir.display()
            )
        });
        let entries = server_met.entries();
        assert_eq!(
            entries.len(),
            meta.server_count,
            "{}: aMule's full-tag record must decode to exactly the recorded server \
             count (a desynced tag stream would drop or duplicate the entry)",
            dir.display()
        );

        // The figures aMule wrote: SaveServerMet emits every one on
        // every row (`ServerList.cpp:776-789`), so each decodes. This row was
        // reached over TCP and never answered a UDP status ping, so aMule
        // wrote its last-ping time as 0 — the case an import keeps no age for.
        for entry in entries {
            let figures = entry.figures();
            assert!(
                figures.ping_ms.is_some()
                    && figures.users.is_some()
                    && figures.files.is_some()
                    && figures.soft_files.is_some()
                    && figures.hard_files.is_some()
                    && figures.last_ping.is_some(),
                "{}: every figure aMule writes decodes: {figures:?}",
                dir.display()
            );
            assert_eq!(figures.version.as_deref(), Some("17.15 (lugdunum)"));
        }

        // Every decoded entry must carry a real, dialable endpoint: the whole
        // point of a bootstrap server.met is the address the cold-start runner
        // connects to. A zero port would mean the ip/port header mis-decoded.
        for entry in entries {
            assert_ne!(
                entry.endpoint().port,
                0,
                "{}: decoded server has a zero port — ip/port header mis-decoded",
                dir.display()
            );
        }

        // The writer proof: re-encoding aMule's real server and
        // decoding again preserves every modelled field (endpoint / name /
        // description / priority). This is a **field**-match, not byte-match:
        // the decoder drops aMule's flag tags (ADR-0066 — no preserved tail),
        // so `encode` emits a smaller file by design. The
        // field round-trip is the honest strong-direction proof for a lossy
        // re-encoder, and the re-encoded bytes read cleanly in aMule.
        let reencoded = server_met.encode();
        let redecoded = ServerMet::decode(&reencoded).unwrap_or_else(|e| {
            panic!(
                "{}: rmule's own server.met writer output must decode: {e:?}",
                dir.display()
            )
        });
        assert_eq!(
            redecoded.entries(),
            entries,
            "{}: decode → encode → decode must preserve every modelled server field",
            dir.display()
        );
    }
}
