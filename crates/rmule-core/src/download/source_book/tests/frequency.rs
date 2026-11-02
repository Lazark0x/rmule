//! **Part Frequency** asserted through the **Source Book**'s interface
//! (ADR-0112 §2): per part, the number of records whose Advertised Parts hold
//! it, after every write, replace, merge and removal.

use rmule_peer::PartBitmap;

use super::*;

/// Advertised Parts of the book's three-part file, bit `i` of `mask` part `i`.
fn parts(mask: u8) -> Option<PartBitmap> {
    Some(PartBitmap::decode(3, &[mask]).unwrap())
}

fn frequency(book: &SourceBook) -> (Vec<u32>, u32) {
    (book.part_frequency().to_vec(), book.parts_known())
}

#[test]
fn part_frequency_counts_the_records_holding_each_part() {
    let mut book = empty_book();
    let _ = sight(&mut book, plain(1));
    let one = work(&mut book);
    let _ = sight(
        &mut book,
        SourceSighting::plain(PeerSource::Ipv6(v6(1)), rmule_primitives::Informant::Own),
    );
    let one_v6 = work(&mut book);
    let _ = sight(&mut book, plain(2));
    let two = work(&mut book);
    let _ = sight(
        &mut book,
        SourceSighting::plain(PeerSource::Ipv6(v6(2)), rmule_primitives::Informant::Own),
    );
    let two_v6 = work(&mut book);

    book.write_parts(one_v6, parts(0b001));
    book.write_parts(two, parts(0b011));
    book.write_parts(two_v6, parts(0b110));
    assert_eq!(frequency(&book), (vec![2, 2, 1], 3));

    book.write_parts(two, parts(0b010));
    assert_eq!(frequency(&book), (vec![1, 2, 1], 3), "a write replaces");

    // Peer 1's older record held nothing: it keeps the newer record's parts.
    let _ = sight(&mut book, dual(1, 1));
    assert_eq!(frequency(&book), (vec![1, 2, 1], 3));
    assert_eq!(book.parts(one), parts(0b001).as_ref());
    // Peer 2's older record held parts: the newer record's leave with it.
    let _ = sight(&mut book, dual(2, 2));
    assert_eq!(frequency(&book), (vec![1, 1, 0], 2));
    assert_eq!(book.parts(two_v6), parts(0b010).as_ref());

    assert_eq!(
        book.end_worker(two, false, ours()),
        Some(WorkerEnd::Release(Release::Gone))
    );
    assert_eq!(frequency(&book), (vec![1, 0, 0], 1), "a removal subtracts");
}
