//! One store behind an `Arc`, written and read from several threads at
//! once — the shape every seam takes now that no mutex wraps the handle
//! (ADR-0083). The `Send + Sync` assertion guards that invariant at compile
//! time; the threads prove it at run time.

use std::sync::Arc;
use std::thread;

use rmule_store::Store;

use crate::fixture::{DOWNLOADS, V1, download, on_each_backend, schema_v1};

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn an_arc_store_serves_writers_and_readers_on_other_threads() {
    assert_send_sync::<Store>();
    on_each_backend(|backend| {
        let store = Arc::new(backend.open(&schema_v1(), &V1).unwrap());
        let writers: Vec<_> = (1..=4u64)
            .map(|lane| {
                let store = Arc::clone(&store);
                thread::spawn(move || {
                    for n in 0..5u64 {
                        let id = lane * 100 + n;
                        let txn = store.begin_write().unwrap();
                        DOWNLOADS.insert(&txn, &id, &download(id)).unwrap();
                        txn.commit().unwrap();
                    }
                })
            })
            .collect();
        for writer in writers {
            writer.join().unwrap();
        }
        let reader = {
            let store = Arc::clone(&store);
            thread::spawn(move || DOWNLOADS.len(&store.begin_read().unwrap()).unwrap())
        };
        assert_eq!(reader.join().unwrap(), 20);
    });
}
