//! A datagram cut at any byte is an error, never a panic and never a short
//! read taken for a whole one. Every captured Kad datagram under
//! `tests/fixtures/` is fed, cut at every offset, to each payload decoder that
//! accepts it whole — the decoders all read through the shared bounds-checked
//! reader, so one walk covers the lot.

use std::path::{Path, PathBuf};

use rmule_kad::keyword_store::{
    decode_publish_key_req, decode_search_key_req, decode_search_key_res,
};
use rmule_kad::notes::{decode_publish_notes_req, decode_search_notes_req};
use rmule_kad::search_tree::SearchTree;
use rmule_kad::{
    Kad2Message, KadDecoded, KadEnvelope, NodesDat, decode_exact, decode_source_result,
};

type Decoder = fn(&KadEnvelope) -> bool;

const DECODERS: [(&str, Decoder); 7] = [
    ("Kad2 message", |e| Kad2Message::decode(e).is_ok()),
    ("source result", |e| decode_source_result(e).is_ok()),
    ("keyword publish", |e| decode_publish_key_req(e).is_ok()),
    ("keyword search", |e| decode_search_key_req(e).is_ok()),
    ("keyword result", |e| decode_search_key_res(e).is_ok()),
    ("notes search", |e| decode_search_notes_req(e).is_ok()),
    ("notes publish", |e| decode_publish_notes_req(e).is_ok()),
];

fn fixtures_named(extension: &str) -> Vec<PathBuf> {
    fn walk(dir: &Path, extension: &str, out: &mut Vec<PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read fixtures").flatten() {
            let path = entry.path();
            if path.is_dir() {
                walk(&path, extension, out);
            } else if path.extension().is_some_and(|e| e == extension) {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures"),
        extension,
        &mut out,
    );
    out.sort();
    out
}

#[test]
fn a_captured_payload_cut_anywhere_is_rejected_by_every_decoder_that_takes_it_whole() {
    let mut accepted = 0;
    for path in fixtures_named("bin") {
        let bytes = std::fs::read(&path).expect("read fixture");
        let Ok(KadDecoded::Plain(envelope) | KadDecoded::Packed(envelope)) = decode_exact(&bytes)
        else {
            continue;
        };
        for (name, decoder) in DECODERS {
            if !decoder(&envelope) {
                continue;
            }
            accepted += 1;
            for cut in 0..envelope.payload().len() {
                let short =
                    KadEnvelope::plain(envelope.opcode(), envelope.payload()[..cut].to_vec());
                assert!(
                    !decoder(&short),
                    "{}: the {name} decoder took a payload cut to {cut} of {} bytes",
                    path.display(),
                    envelope.payload().len()
                );
            }
        }
    }
    assert!(
        accepted > 30,
        "the captures exercise the decoders: {accepted}"
    );
}

#[test]
fn a_captured_search_tree_cut_anywhere_is_an_error() {
    let path = fixtures_named("bin")
        .into_iter()
        .find(|p| p.ends_with("search_key_req_tree_0x33.bin"))
        .expect("the restrictive keyword request is checked in");
    let KadDecoded::Plain(request) =
        decode_exact(&std::fs::read(path).expect("read fixture")).expect("a plain envelope")
    else {
        panic!("a plain datagram");
    };
    // Keyword id (16) and the start-position word (2) precede the tree.
    let tree = &request.payload()[18..];
    SearchTree::decode(tree).expect("the whole tree decodes");
    for cut in 0..tree.len() {
        assert!(
            SearchTree::decode(&tree[..cut]).is_err(),
            "a tree cut to {cut} of {} bytes decoded",
            tree.len()
        );
    }
}

#[test]
fn a_captured_contact_file_cut_anywhere_never_gains_a_contact() {
    for path in fixtures_named("bin")
        .into_iter()
        .filter(|p| p.ends_with("nodes.dat.bin"))
    {
        let bytes = std::fs::read(&path).expect("read fixture");
        let whole = NodesDat::decode(&bytes)
            .expect("the golden decodes")
            .contacts()
            .len();
        assert!(whole > 0);
        for cut in 0..bytes.len() {
            if let Ok(partial) = NodesDat::decode(&bytes[..cut]) {
                assert!(
                    partial.contacts().len() < whole,
                    "{}: a cut to {cut} of {} bytes kept all {whole} contacts",
                    path.display(),
                    bytes.len()
                );
            }
        }
    }
}
